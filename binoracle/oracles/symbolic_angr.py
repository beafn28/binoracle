"""Symbolic reachability oracle backed by angr (optional).

This is the strongest grounding for "is this dangerous sink actually reachable?": instead
of the model guessing, angr tries to find a path (and, if asked, a concrete input) that
reaches a target address."""
from __future__ import annotations

import time
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult

try:
    import angr  # type: ignore
    from angr import claripy  # type: ignore
    from .. import _quiet_angr
    _quiet_angr()
    _HAVE_ANGR = True
except Exception:
    _HAVE_ANGR = False


def _is_pe(binary: str) -> bool:
    try:
        with open(binary, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


if _HAVE_ANGR:
    class _SimpleMingwRead(angr.SimProcedure):
        """Reemplaza fgets()/gets() del modelo generico de angr para binarios PE/mingw.

        Bug real encontrado en vivo construyendo esto: el `fgets` generico de angr construye
        una expresion `ite` ANIDADA (una rama por cada posible longitud de linea hasta el
        salto de linea) para el buffer resultante. Esa expresion, combinada con el `strcmp()`
        posterior sobre un secreto fijo, resulto en un resultado CONCRETO (no symbolic) en vez
        de bifurcar en dos sucesores -- confirmado contra samples/bin/win_chall.exe:
        `explore(find=win)` nunca encontraba `win()` (los 64 estados activos terminaban en
        deadend sin ninguna bifurcacion real en el `strcmp`), exactamente el motivo por el que
        este item del ROADMAP ("SimProcedures for the MSVCRT/mingw runtime so angr_reachable
        works properly on PE") seguia sin funcionar. El reemplazo es deliberadamente simple:
        lee `size-1` (o un tope fijo para `gets`, que no recibe tamano) bytes DIRECTAMENTE del
        fd 0 simbolico de angr (como hace el propio `SIM_PROCEDURES['posix']['read']`), sin la
        busqueda de salto de linea -- con eso, `explore()` SI bifurca en el strcmp y resuelve
        el secreto exacto por constraint-solving (confirmado: ~2.5s), Y el stdin concreto
        reportado (`found.posix.dumps(0)`) sigue siendo el real, porque el dato leido queda
        enganchado al propio modelo de fd 0, no a una variable simbolica suelta."""
        def run(self, s, size=None, stream=None):
            cap = 256
            if size is not None:
                try:
                    cap = min(self.state.solver.eval(size) - 1, cap)
                except Exception:
                    pass
            cap = max(cap, 0)
            simfd = self.state.posix.get_fd(0)
            n = simfd.read(s, cap) if simfd is not None else 0
            self.state.memory.store(s + n, claripy.BVV(0, 8))
            return s


def _hook_mingw_io(proj) -> None:
    """Enganchado solo para proyectos PE (mingw/MSVCRT): sustituye fgets/gets por el modelo
    simplificado de _SimpleMingwRead. No se toca nada en binarios ELF."""
    for name in ("fgets", "gets"):
        sym = proj.loader.find_symbol(name)
        if sym is not None:
            try:
                proj.hook_symbol(name, _SimpleMingwRead())
            except Exception:
                pass


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

    def _reachable(self, addr, avoid=None, budget_s: float = 45.0, max_active: int = 80) -> ToolResult:
        """Bug real encontrado en vivo: un binario con un bucle (p.ej. un menu re-mostrado hasta
        que el usuario elige salir) puede hacer que angr explore un numero de caminos que crece sin
        limite -- `simgr.explore(...)` de una sola llamada, sin ningun tope de tiempo ni de estados
        activos, se quedaba corriendo minuto tras minuto (CPU al 100%, sin avisar de nada) en vez de
        devolver un resultado acotado. Mismo patron de fallo que el `pdg` de r2 sin timeout
        (r2session.cmd_timeout): un oraculo grounded no debe poder colgar el pipeline entero.

        El bucle con deadline+tope de estados (ver `_reachable_impl`) solo comprueba el reloj
        ENTRE llamadas a `simgr.explore(...)` -- si una SOLA llamada se bloquea mucho mas de lo
        normal (resolucion de restricciones dura, confirmado en vivo: un step que deberia tardar
        ~1s tardo mas de 2 HORAS bajo throttling de CPU severo), ese bucle no puede interrumpirla
        y budget_s se vuelve una cota blanda. Por eso la busqueda real corre en un proceso HIJO
        (fork) con un deadline DURO: si sigue vivo tras budget_s + margen, se MATA en vez de
        colgar el proceso llamador."""
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
        import multiprocessing as mp
        try:
            ctx = mp.get_context("fork")
        except ValueError:
            ctx = mp.get_context()
        q = ctx.Queue()
        p = ctx.Process(target=_reachable_worker,
                        args=(self.binary, target, avoid_list, budget_s, max_active, q))
        p.start()
        p.join(budget_s + 30.0)
        if p.is_alive():
            p.terminate()
            p.join(5.0)
            if p.is_alive():
                p.kill()
                p.join()
            return ToolResult(
                True, f"angr: explore(find={hex(target)})",
                f"NOT reachable within budget ({budget_s:.0f}s; proceso forzado a terminar, "
                f"el budget_s pedido era una cota dura).",
                meta={"reachable": False, "addr": hex(target)},
            )
        try:
            return q.get_nowait()
        except Exception:
            return ToolResult(False, "angr", "",
                              error="angr: el proceso termino sin devolver resultado")


def _reachable_impl(binary: str, target: int, avoid_list: list, budget_s: float,
                    max_active: int) -> ToolResult:
    """Cuerpo real de la busqueda, pensado para correr dentro del proceso hijo que levanta
    `AngrOracle._reachable` -- construye su PROPIO Project (no puede compartir el `self._proj`
    cacheado del proceso padre al otro lado de un fork+exploracion larga)."""
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        if _is_pe(binary):
            _hook_mingw_io(proj)
        # rebasa target/avoid del espacio de r2 (un PIE se reporta como si cargase en base 0,
        # p.ej. un sink en 0x11a6) al espacio de angr (que SIEMPRE carga en su propia base fija,
        # tipicamente 0x400000) -- mismo bug ya encontrado y arreglado en reachability.py: sin
        # esto, `target` caia fuera del rango de direcciones cargado y explore() NUNCA podia
        # tener exito en NINGUN binario PIE (que es el modo de compilacion por defecto hoy en
        # dia), asi que auto_verify jamas promocionaba un hallazgo de grounded a verified ahi.
        if proj.loader.main_object.pic:
            base = proj.loader.main_object.mapped_base or 0
            if target < base:
                target += base
            avoid_list = [(a + base if a < base else a) for a in avoid_list]
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        deadline = time.time() + budget_s
        while time.time() < deadline:
            if not simgr.active:
                break
            simgr.explore(find=target, avoid=avoid_list or None, n=1, num_find=1)
            if simgr.found:
                break
            # controla la explosion de estados (p.ej. un bucle en el binario que multiplica
            # caminos activos sin limite): recorta a los primeros `max_active`.
            if len(simgr.active) > max_active:
                simgr.active[:] = simgr.active[:max_active]
            if not simgr.active:
                break
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
            f"NOT reachable within budget ({budget_s:.0f}s; deadended="
            f"{len(simgr.deadended)}, active={len(simgr.active)}).",
            meta={"reachable": False, "addr": hex(target)},
        )
    except Exception as e:
        return ToolResult(False, "angr", "", error=f"angr error: {e}")


def _reachable_worker(binary, target, avoid_list, budget_s, max_active, q) -> None:
    try:
        q.put(_reachable_impl(binary, target, avoid_list, budget_s, max_active))
    except Exception as e:
        q.put(ToolResult(False, "angr", "", error=f"angr error: {e}"))
