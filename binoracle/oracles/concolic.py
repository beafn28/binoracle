"""Concolic loop: drive angr from a REAL dynamic trace instead of blind symbolic exploration
from `main()`, so verification scales past toy binaries. ROADMAP v0.3: "Concolic loop. Drive
angr from a real dynamic trace (symbolic-assisted crash triage), so verification scales past
toy binaries."

`symbolic_angr.py`'s existing `angr_reachable` explores from the entry state with NOTHING
constraining which branch to take at each choice point -- fine for a tiny CTF binary, but a
blind `explore()` state-splits at every branch (menus, loops) and the state count can blow up
long before it reaches anything interesting (the module's own docstring already documents
having to fork a child process with a hard deadline just to keep that bounded). The concolic
idea: run the REAL binary with a REAL (concrete) crashing input under gdb, record the actual
sequence of basic blocks it executed, then replay that EXACT path through angr
(`angr.exploration_techniques.Tracer`) with the input bytes left SYMBOLIC. Since the path is
forced by the real trace, there is exactly one path to follow -- no explosion -- and because the
input bytes are symbolic, the final state lets the solver ask "which bytes control the crash,
and what value do they need for a CHOSEN target" with real constraint solving instead of a
cyclic-pattern guess.

Two real bugs found and fixed while building this (not inherited from elsewhere in the
project -- this module's own):

1. `Tracer(trace=...)` wants a trace at the granularity angr itself steps at (one entry per
   BASIC BLOCK), not one entry per INSTRUCTION. Feeding it gdb's raw `stepi`-level trace
   desyncs almost immediately (`AngrTracerError: Trace desynced on jumping into ...`) because
   angr's own block-stepping consumes several of those entries in one step and the index
   tracking falls behind. Fixed by collapsing the instruction trace to block boundaries with
   capstone: keep an address only when it is NOT the instruction immediately following the
   previous one in a straight run (i.e. a real branch/call/ret landed there).
2. `state.memory.load(addr, size)` with NO `endness` returns the bytes in the claripy
   convention (first byte in memory = most-significant bit of the BV) -- NOT the architecture's
   actual load order. Solving `retval == target` with that default produced a payload whose
   bytes were reversed relative to what the x86-64 `ret` instruction actually pops into RIP
   (confirmed live: the solved payload put `target_addr`'s bytes in big-endian order at the
   stack slot, and replaying it for real landed nowhere near `target_addr`). Fixed by loading
   with `endness=archinfo.Endness.LE` (the architecture's real load order) before constraining.

Scope of this first increment: the classic linear-stack-overflow-controls-the-return-address
shape (the value popped by `ret` at the point the real trace ends). Verified END TO END against
`samples/bin/ret2win`: fed a crashing seed input, replayed its real trace through angr with
symbolic stdin, solved for `win()`'s address at the return-address slot, and confirmed with a
SEPARATE real execution (a breakpoint at the target address, not an inference) that the solved
payload actually lands there. PIE binaries are ALSO covered now (closed gap, see
ROADMAP.md): `_capture_trace` propagates the real ASLR-disabled load base from gdb's own
`info proc mappings`, `_block_trace` subtracts it before indexing `.text`, and `angr.Project`
is forced to load the main object at that SAME base (`main_opts={'base_addr': ...}`) so the
Tracer replay matches the real trace address-for-address -- `target_addr` is still given (and
reported) as the binary's STATIC address (same convention as `find_win()`/nm/readelf
elsewhere in this project), translated internally. Verified end to end against
`samples/bin/ret2win_pie`. Not yet covered (tracked in ROADMAP.md): indirect call/jump
hijacks and heap-pointer-controlled crashes."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult

try:
    import angr  # type: ignore
    import archinfo  # type: ignore
    from angr import claripy  # type: ignore
    from angr.exploration_techniques import Tracer  # type: ignore
    from .. import _quiet_angr
    _quiet_angr()
    _HAVE_ANGR = True
except Exception:
    _HAVE_ANGR = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # type: ignore
    _HAVE_CAPSTONE = True
except Exception:
    _HAVE_CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_ELFTOOLS = True
except Exception:
    _HAVE_ELFTOOLS = False


_GDB_TRACE_SCRIPT = r'''\
import gdb

LOG = {log_path!r}
INFILE = {infile!r}
MAX_STEPS = {max_steps!r}
f = open(LOG, "w")

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set disable-randomization on")
gdb.execute("tbreak _start")
try:
    gdb.execute("run < %s" % INFILE)
except gdb.error as e:
    f.write("RUN_ERR %s\n" % e)

lo = hi = None
try:
    out = gdb.execute("info proc mappings", to_string=True)
    name = {basename!r}
    for line in out.splitlines():
        if name in line:
            parts = line.split()
            a, b = int(parts[0], 16), int(parts[1], 16)
            if lo is None or a < lo:
                lo = a
            if hi is None or b > hi:
                hi = b
except gdb.error as e:
    f.write("MAP_ERR %s\n" % e)
f.write("RANGE %s %s\n" % (lo, hi))

trace = []
count = 0
try:
    while count < MAX_STEPS:
        pc = int(gdb.selected_frame().pc())
        if lo is not None and lo <= pc < hi:
            trace.append(pc)
        gdb.execute("stepi", to_string=True)
        count += 1
except gdb.error:
    pass
except Exception as e:
    f.write("STEP_ERR %s\n" % e)

f.write("STEPS %d\n" % count)
f.write("TRACE " + ",".join(hex(x) for x in trace) + "\n")
f.close()
'''

_GDB_BPCHECK_SCRIPT = r'''\
import gdb

LOG = {log_path!r}
INFILE = {infile!r}
TARGET = {target!r}
f = open(LOG, "w")

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set disable-randomization on")

class _Hit(gdb.Breakpoint):
    def stop(self):
        f.write("HIT 0x%x\n" % TARGET)
        f.flush()
        return True

try:
    _Hit("*0x%x" % TARGET)
except gdb.error as e:
    f.write("BP_ERR %s\n" % e)

try:
    gdb.execute("run < %s" % INFILE)
except gdb.error as e:
    f.write("RUN_ERR %s\n" % e)
f.write("DONE\n")
f.close()
'''


class ConcolicOracle(Oracle):
    name = "concolic"

    def __init__(self, binary: str):
        self.binary = binary
        self.gdb = shutil.which("gdb")

    def available(self) -> bool:
        return (_HAVE_ANGR and _HAVE_CAPSTONE and _HAVE_ELFTOOLS and bool(self.gdb)
                and os.path.exists(self.binary))

    def why_unavailable(self) -> str:
        missing = []
        if not _HAVE_ANGR:
            missing.append("angr (pip install 'binoracle[symbolic]')")
        if not _HAVE_CAPSTONE:
            missing.append("capstone (pip install 'binoracle[disasm]')")
        if not _HAVE_ELFTOOLS:
            missing.append("pyelftools (pip install 'binoracle[elf]')")
        if not self.gdb:
            missing.append("gdb")
        return "falta: " + ", ".join(missing) if missing else "el binario no existe"

    def tools(self) -> List[Tool]:
        return [
            Tool(
                "concolic_solve_rip_control",
                "Loop concolico: toma un stdin REAL que crashea el binario con RIP controlado "
                "(overflow lineal clasico), reconstruye ese camino de ejecucion con gdb, lo "
                "reproduce en angr con el stdin SIMBOLICO (angr.exploration_techniques.Tracer -- "
                "sin la explosion de estados de una exploracion ciega desde main), y resuelve "
                "por constraint-solving el payload exacto que hace que la direccion de retorno "
                "sea target_addr. Verifica el resultado con una ejecucion real SEPARADA (un "
                "breakpoint en target_addr, no una inferencia). Alcance: solo el caso de "
                "overflow lineal -> direccion de retorno (no hijacks de llamada/salto indirecto).",
                [ToolParam("stdin_text", "stdin REAL que crashea el binario con RIP controlado (seed)"),
                 ToolParam("target_addr", "direccion objetivo a la que debe saltar (hex o int), p.ej. "
                           "win(). Dala como la direccion ESTATICA del binario (la que reporta nm/"
                           "readelf/r2, con o sin PIE) -- si el binario es PIE, el tool la traslada "
                           "internamente a la direccion real de runtime (ASLR desactivado para la "
                           "captura/verificacion), no hace falta calcularla a mano."),
                 ToolParam("budget_s", "limite de tiempo en segundos (por defecto 60)",
                           required=False, default=60)],
                lambda stdin_text, target_addr, budget_s=60: self._solve_rip(stdin_text, target_addr, budget_s),
                self.name,
            ),
        ]

    def _capture_trace(self, stdin_text, budget_s):
        data = stdin_text.encode("utf-8", "backslashreplace") if isinstance(stdin_text, str) else bytes(stdin_text)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
            infile = tf.name
        log_path = infile + ".tracelog"
        script_path = None
        try:
            script = _GDB_TRACE_SCRIPT.format(
                log_path=log_path, infile=infile, max_steps=400000,
                basename=os.path.basename(self.binary))
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as sf:
                sf.write(script)
                script_path = sf.name
            try:
                subprocess.run([self.gdb, "-q", "-batch", "-x", script_path, self.binary],
                               capture_output=True, text=True, timeout=budget_s)
            except subprocess.TimeoutExpired:
                return None, None, "gdb no volvio dentro de budget_s (el objetivo pudo quedarse esperando entrada)"
            try:
                with open(log_path) as lf:
                    log_text = lf.read()
            except OSError:
                log_text = ""
        finally:
            for p in (infile, log_path, script_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
        m = re.search(r"^TRACE (.*)$", log_text, re.MULTILINE)
        if not m or not m.group(1).strip():
            return None, None, "no se capturo ningun paso dentro del binario principal (RUN_ERR/MAP_ERR en el log)"
        trace = [int(x, 16) for x in m.group(1).split(",")]
        # base de carga REAL en runtime (de "info proc mappings", ya con ASLR desactivado por el
        # propio script): para un binario PIE (ET_DYN) esto es necesario para traducir las
        # direcciones del trace real a las direcciones estaticas del ELF (sh_addr) -- para no-PIE
        # (ET_EXEC) coincide con 0 y no cambia nada (ver _block_trace/_solve_rip).
        mr = re.search(r"^RANGE (\S+) (\S+)$", log_text, re.MULTILINE)
        runtime_lo = int(mr.group(1)) if mr and mr.group(1) != "None" else None
        return trace, runtime_lo, None

    def _block_trace(self, trace, runtime_base=None):
        with open(self.binary, "rb") as f:
            elf = ELFFile(f)
            is_pie = elf.header["e_type"] == "ET_DYN"
            text = elf.get_section_by_name(".text")
            data = text.data()
            base = text["sh_addr"]
        # para PIE, las direcciones del trace (reales, en runtime) llevan sumado el sesgo de
        # carga (runtime_base, capturado de "info proc mappings" con ASLR desactivado) sobre la
        # direccion ESTATICA del ELF (sh_addr) -- hay que restarlo antes de indexar en .text. Para
        # no-PIE el ELF ya fija su propia direccion de carga y el sesgo es 0 (sin cambios).
        bias = runtime_base if (is_pie and runtime_base is not None) else 0
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        def insn_len(addr):
            off = addr - bias - base
            if off < 0 or off >= len(data):
                return None
            for ins in md.disasm(data[off:off + 16], addr):
                return ins.size
            return None

        block_trace = [trace[0]]
        for i in range(1, len(trace)):
            prev = trace[i - 1]
            length = insn_len(prev)
            expected = prev + length if length else None
            if trace[i] != expected:
                block_trace.append(trace[i])
        return block_trace

    def _verify_real(self, payload: bytes, target_addr: int, budget_s: float) -> bool:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(payload)
            infile = tf.name
        log_path = infile + ".bplog"
        script_path = None
        try:
            script = _GDB_BPCHECK_SCRIPT.format(log_path=log_path, infile=infile, target=target_addr)
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as sf:
                sf.write(script)
                script_path = sf.name
            try:
                subprocess.run([self.gdb, "-q", "-batch", "-x", script_path, self.binary],
                               capture_output=True, text=True, timeout=budget_s)
            except subprocess.TimeoutExpired:
                return False
            try:
                with open(log_path) as lf:
                    log_text = lf.read()
            except OSError:
                log_text = ""
            return "HIT " in log_text
        finally:
            for p in (infile, log_path, script_path):
                if p:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def _solve_rip(self, stdin_text, target_addr, budget_s=60) -> ToolResult:
        try:
            budget_s = float(budget_s)
        except (TypeError, ValueError):
            budget_s = 60.0
        try:
            static_ta = int(str(target_addr), 0) if not isinstance(target_addr, int) else target_addr
        except ValueError:
            return ToolResult(False, "concolic_solve_rip_control", "",
                              error="target_addr debe ser una direccion (hex o int)")

        seed = (stdin_text.encode("utf-8", "backslashreplace")
                if isinstance(stdin_text, str) else bytes(stdin_text))

        trace, runtime_base, err = self._capture_trace(seed, budget_s / 2.0)
        if trace is None:
            return ToolResult(True, "concolic: captura de trace via gdb", "",
                              error=None,
                              meta={"verified": False, "note": f"no aplicable: {err}"})
        try:
            block_trace = self._block_trace(trace, runtime_base)
        except Exception as e:
            return ToolResult(False, "concolic: reduccion de trace a bloques", "",
                              error=f"fallo reduciendo el trace a bloques: {e}")

        try:
            with open(self.binary, "rb") as f:
                is_pie = ELFFile(f).header["e_type"] == "ET_DYN"
            # para PIE, angr debe cargar el binario principal EXACTAMENTE en la misma base que
            # uso el trace real (runtime_base, con ASLR desactivado) -- si no, el Tracer nunca
            # ve coincidir ninguna direccion del trace con los bloques que angr va pisando con
            # su propia base PIE por defecto, y desincroniza de inmediato. Para no-PIE, la
            # direccion de carga ya viene fija en el propio ELF (sin cambios).
            main_opts = {"base_addr": runtime_base} if (is_pie and runtime_base is not None) else {}
            # target_addr se da (y se reporta) como la direccion ESTATICA del ELF -- la misma
            # convencion que find_win()/nm/readelf usan en el resto del proyecto, para que el
            # llamador no tenga que calcular a mano el sesgo de carga ASLR-off de este binario.
            # Para PIE se traslada aqui a la direccion REAL (misma base que el trace/angr).
            ta = static_ta + runtime_base if (is_pie and runtime_base is not None) else static_ta
            proj = angr.Project(self.binary, auto_load_libs=False, main_opts=main_opts)
            sym_bytes = [claripy.BVS("stdin_b%d" % i, 8) for i in range(len(seed))]
            sym_stdin = claripy.Concat(*sym_bytes) if len(sym_bytes) > 1 else sym_bytes[0]
            state = proj.factory.entry_state(
                stdin=angr.SimFileStream(name="stdin", content=sym_stdin, has_end=True))
            simgr = proj.factory.simgr(state)
            simgr.use_technique(Tracer(trace=block_trace))
            simgr.run()
        except Exception as e:
            return ToolResult(True, "concolic: replay del trace real en angr", "",
                              meta={"verified": False,
                                   "note": f"angr no pudo reproducir el camino real: {e}"})

        traced = simgr.stashes.get("traced") or []
        if not traced:
            return ToolResult(True, "concolic: replay del trace real en angr", "",
                              meta={"verified": False,
                                   "note": "angr no llego al final del trace real (desync)"})
        st = traced[0]
        retv = st.memory.load(st.regs.rsp, 8, endness=archinfo.Endness.LE)
        if not retv.symbolic:
            return ToolResult(True, "concolic: dependencia simbolica de RIP", "",
                              meta={"verified": False,
                                   "note": "la direccion de retorno en este punto NO depende "
                                           "del stdin segun este modelo (no es el patron de "
                                           "overflow lineal que este tool cubre)"})

        # el nombre real de la variable claripy es "stdin_b{indice}_{contador}_{bits}" (p.ej.
        # "stdin_b72_0_8") -- un split()+int() ingenuo sobre "72_0_8" "funcionaba" sin lanzar
        # excepcion porque Python acepta "_" como separador de miles en literales int(), dando
        # un numero BASURA (72728 en vez de 72). Hay que capturar solo el primer grupo de digitos.
        offsets = sorted({int(mo.group(1)) for mo in
                          (re.match(r"stdin_b(\d+)_", v) for v in retv.variables) if mo})
        st.solver.add(retv == ta)
        if not st.solver.satisfiable():
            return ToolResult(True, "concolic: constraint-solving sobre el trace real", "",
                              meta={"verified": False,
                                   "note": f"0x{static_ta:x} (runtime 0x{ta:x}) no es alcanzable "
                                           f"desde este punto segun el modelo simbolico (unsat)",
                                   "controlled_offsets": offsets})
        try:
            solved = st.solver.eval(sym_stdin, cast_to=bytes)
        except Exception as e:
            return ToolResult(False, "concolic: eval del stdin resuelto", "",
                              error=f"sat pero no se pudo evaluar un ejemplo concreto: {e}")

        verified = self._verify_real(solved, ta, budget_s / 2.0)
        offs_txt = f"{min(offsets)}..{max(offsets)}" if offsets else "?"
        if verified:
            data_out = (f"CONFIRMADO: el payload resuelto por constraint-solving sobre el "
                       f"trace real redirige la ejecucion a 0x{static_ta:x} de verdad (breakpoint "
                       f"disparado en una ejecucion separada). Offset(s) de la direccion de "
                       f"retorno controlados por el stdin: bytes {offs_txt}.")
        else:
            data_out = (f"El payload se resolvio (sat) pero la verificacion REAL (breakpoint en "
                       f"0x{static_ta:x}) no disparo -- no se confirma. Offset(s) candidatos: {offs_txt}.")
        meta = {"verified": verified, "target_addr": hex(static_ta), "controlled_offsets": offsets,
               "payload_hex": solved.hex()}
        if is_pie and runtime_base is not None:
            meta["pie"] = True
            meta["target_addr_runtime"] = hex(ta)
        return ToolResult(
            True, "concolic: gdb trace real -> angr Tracer -> constraint-solving -> verificacion real",
            data_out, meta=meta)
