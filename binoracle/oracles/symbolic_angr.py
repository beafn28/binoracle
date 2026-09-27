"""Symbolic reachability oracle backed by angr (optional).

This is the strongest grounding for "is this dangerous sink actually reachable?": instead
of the model guessing, angr tries to find a path (and, if asked, a concrete input) that
reaches a target address."""
from __future__ import annotations

from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult

try:
    import angr  # type: ignore
    import logging as _logging
    _logging.getLogger("angr").setLevel(_logging.ERROR)
    _logging.getLogger("cle").setLevel(_logging.ERROR)
    _HAVE_ANGR = True
except Exception:
    _HAVE_ANGR = False


class AngrOracle(Oracle):
    name = "symbolic_angr"

    def __init__(self, binary: str):
        self.binary = binary
        self._proj = None

    def available(self) -> bool:
        return _HAVE_ANGR

    def why_unavailable(self) -> str:
        return "angr not installed (pip install 'binoracle[symbolic]')"

    def _project(self):
        if self._proj is None:
            self._proj = angr.Project(self.binary, auto_load_libs=False)
        return self._proj

    def tools(self) -> List[Tool]:
        return [
            Tool(
                "angr_reachable",
                "Prove whether an address is reachable from entry, and if so synthesize a concrete input that reaches it.",
                [ToolParam("addr", "target address, e.g. 0x401234"),
                 ToolParam("avoid", "optional comma-separated addresses to avoid", required=False)],
                lambda addr, avoid=None: self._reachable(addr, avoid),
                self.name,
            ),
        ]

    def _reachable(self, addr, avoid=None) -> ToolResult:
        try:
            target = int(str(addr), 0)
        except ValueError:
            return ToolResult(False, "angr", "", error=f"bad address {addr!r}")
        avoid_list = []
        if avoid:
            for a in str(avoid).split(","):
                a = a.strip()
                if a:
                    try:
                        avoid_list.append(int(a, 0))
                    except ValueError:
                        pass
        try:
            proj = self._project()
            # rebasa target/avoid del espacio de r2 (un PIE se reporta como si cargase en base 0,
            # p.ej. un sink en 0x11a6) al espacio de angr (que SIEMPRE carga en su propia base fija,
            # tipicamente 0x400000) -- mismo bug ya encontrado y arreglado en reachability.py:
            # sin esto, `target` caia fuera del rango de direcciones cargado y explore() NUNCA podia
            # tener exito en NINGUN binario PIE (que es el modo de compilacion por defecto hoy en
            # dia), asi que auto_verify jamas promocionaba un hallazgo de grounded a verified ahi.
            if proj.loader.main_object.pic:
                base = proj.loader.main_object.mapped_base or 0
                if target < base:
                    target += base
                avoid_list = [(a + base if a < base else a) for a in avoid_list]
            state = proj.factory.full_init_state(
                stdin=angr.SimFileStream if hasattr(angr, "SimFileStream") else None
            ) if False else proj.factory.entry_state()
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(find=target, avoid=avoid_list or None, num_find=1)
            if simgr.found:
                found = simgr.found[0]
                try:
                    concrete = found.posix.dumps(0)
                    shown = concrete[:200]
                    inp = repr(shown)
                except Exception:
                    inp = "(reachable; input not recoverable)"
                return ToolResult(
                    True, f"angr: explore(find={hex(target)})",
                    f"REACHABLE from entry.\nconcrete stdin that reaches it: {inp}",
                    meta={"reachable": True, "addr": hex(target)},
                )
            return ToolResult(
                True, f"angr: explore(find={hex(target)})",
                f"NOT reachable within explored bounds (deadended={len(simgr.deadended)}).",
                meta={"reachable": False, "addr": hex(target)},
            )
        except Exception as e:
            return ToolResult(False, "angr", "", error=f"angr error: {e}")
