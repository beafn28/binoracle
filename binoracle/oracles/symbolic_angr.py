"""Symbolic reachability oracle backed by angr (optional).

This is the strongest grounding for "is this dangerous sink actually reachable?": instead
of the model guessing, angr tries to find a path (and, if asked, a concrete input) that
reaches a target address."""
from __future__ import annotations

import time
from fractions import Fraction
from typing import Dict, List

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
            Tool(
                "angr_call_function",
                "Call a function in isolation with concrete integer arguments and return its concrete "
                "return value -- for a pure function (checksum, hash, transform, keygen routine) you "
                "need the OUTPUT of, not whether it's reachable. Do NOT use this for a function whose "
                "own recursion/loop count scales with its argument (e.g. naive unmemoized recursion): "
                "it will not finish within budget and you will get an honest 'did not complete' "
                "instead of a value -- for THAT case use angr_extrapolate_recurrence instead.",
                [ToolParam("target", "function address (e.g. 0x401234) or symbol name (e.g. sym.recurrence or recurrence)"),
                 ToolParam("args", "comma-separated integer arguments, e.g. 729 or 1,2")],
                lambda target, args: self._call_function(target, args),
                self.name,
            ),
            Tool(
                "angr_extrapolate_recurrence",
                "For a single-integer-argument pure function too EXPENSIVE to call directly for the "
                "value you need (angr_call_function timed out, or the disassembly shows unmemoized "
                "recursion / a loop whose trip count scales with the argument -- e.g. a naive "
                "Fibonacci-style keystream generator, a common CTF trick): samples the function at "
                "small, cheap arguments, fits the smallest linear recurrence that exactly explains "
                "every sample, and extrapolates to the large argument you actually need with exact "
                "arithmetic in O(n) instead of calling the real function. Reports the fitted formula "
                "so it's auditable. If no small-order linear recurrence fits, says so honestly -- it "
                "does not guess.",
                [ToolParam("target", "function address or symbol name"),
                 ToolParam("n", "the argument value you actually need the result for, e.g. 729")],
                lambda target, n: self._extrapolate_recurrence(target, n),
                self.name,
            ),
        ]

    def _call_function(self, target, args, budget_s: float = 30.0) -> ToolResult:
        try:
            parsed_args = [int(a.strip(), 0) for a in str(args).split(",") if a.strip() != ""]
        except ValueError:
            return ToolResult(False, "angr", "", error=f"bad args {args!r}: must be comma-separated integers")
        timeout_msg = ToolResult(
            True, f"angr: callable({target})({parsed_args})",
            f"did NOT complete within budget ({budget_s:.0f}s) -- this function likely has "
            "recursion or a loop whose cost scales with the argument (e.g. unmemoized "
            "Fibonacci-style recursion). Do not retry with the same argument; try "
            "angr_extrapolate_recurrence instead, or derive the recurrence yourself and compute "
            "it iteratively (dynamic programming).",
            meta={"completed": False},
        )
        return _run_forked(_call_function_worker, (self.binary, str(target), parsed_args, budget_s),
                           budget_s, timeout_msg)

    def _extrapolate_recurrence(self, target, n, budget_s: float = 45.0) -> ToolResult:
        try:
            n_int = int(str(n).strip(), 0)
        except ValueError:
            return ToolResult(False, "angr", "", error=f"bad n {n!r}: must be an integer")
        timeout_msg = ToolResult(
            True, f"angr: extrapolate_recurrence({target}, n={n_int})",
            f"did NOT complete within budget ({budget_s:.0f}s) -- even sampling this function at "
            "SMALL arguments is too expensive (it may not be a simple low-order recurrence at "
            "all). Fall back to reading the disassembly by hand.",
            meta={"completed": False},
        )
        return _run_forked(_extrapolate_recurrence_worker, (self.binary, str(target), n_int, budget_s),
                           budget_s, timeout_msg)

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
            # num_find=3 (no 1): mas de un camino puede alcanzar la MISMA direccion con
            # dependencias de stdin distintas -- confirmado en vivo que un caso real (PE +
            # _hook_mingw_io) tiene un segundo camino que llega sin depender del stdin (dumps(0)
            # vacio), prueba mas debil que uno que SI lo necesita; recolectar unos pocos permite
            # preferir el testigo mas fuerte abajo sin cambiar el veredicto reachable en ningun
            # caso ni el coste de exploracion de forma relevante.
            simgr.explore(find=target, avoid=avoid_list or None, n=1, num_find=3)
            if simgr.found:
                break
            # controla la explosion de estados (p.ej. un bucle en el binario que multiplica
            # caminos activos sin limite): recorta a los primeros `max_active`.
            if len(simgr.active) > max_active:
                simgr.active[:] = simgr.active[:max_active]
            if not simgr.active:
                break
        if simgr.found:
            # Preferir un testigo cuyo stdin concreto realmente dependa de la entrada
            # (posix.dumps(0) no vacio) sobre uno vacio: un camino que alcanza target SIN leer
            # nada de stdin es una prueba de alcanzabilidad mas debil (no demuestra que el
            # INPUT controle nada) que uno que si lo necesita -- preferirlo cuando ambos existen,
            # sin cambiar reachable=True en ningun caso (solo mejora que ejemplo se reporta).
            found = None
            for cand in simgr.found:
                try:
                    if cand.posix.dumps(0):
                        found = cand
                        break
                except Exception:
                    continue
            if found is None:
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


def _run_forked(worker, args: tuple, budget_s: float, timeout_result: "ToolResult") -> "ToolResult":
    """Shared hard-deadline wrapper for every angr call this oracle can't bound from the
    inside (a single Callable invocation, or angr_reachable's own explore() loop): angr has
    no universal cooperative-cancellation hook, so the only way to GUARANTEE the agent loop
    never blocks past its budget is to run the real work in a forked child process and kill
    it if it outlives `budget_s` -- confirmed live (angr_reachable's own fork, now reused here
    for the newer tools instead of copy-pasting the same mechanics a second and third time)."""
    import multiprocessing as mp
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context()
    q = ctx.Queue()
    p = ctx.Process(target=worker, args=(*args, q))
    p.start()
    p.join(budget_s + 15.0)
    if p.is_alive():
        p.terminate()
        p.join(5.0)
        if p.is_alive():
            p.kill()
            p.join()
        return timeout_result
    try:
        return q.get_nowait()
    except Exception:
        return ToolResult(False, "angr", "", error="angr: el proceso termino sin devolver resultado")


def _resolve_target(proj, target: str) -> int:
    s = str(target).strip()
    try:
        addr = int(s, 0)
    except ValueError:
        name = s[4:] if s.startswith("sym.") else s
        sym = proj.loader.find_symbol(name)
        if sym is None:
            raise ValueError(f"no symbol named {name!r}")
        return sym.rebased_addr
    if proj.loader.main_object.pic:
        base = proj.loader.main_object.mapped_base or 0
        if addr < base:
            addr += base
    return addr


def _call_function_impl(binary: str, target: str, args: list, budget_s: float) -> ToolResult:
    """Runs INSIDE the forked worker (own fresh Project, same reason _reachable_impl does: it
    can't share the parent's cached self._proj across a fork). Deliberately does NOT pass
    step_limit to Callable: angr's own step_limit handling silently promotes a truncated,
    never-actually-returned state into the "result" with no signal that it was cut short
    (confirmed live: reading angr's Callable.perform_call source -- a step_limited state is
    just re-stashed as "active" and used exactly like a real deadend). Relying only on this
    worker's hard wall-clock budget (enforced by the parent killing the whole process) means a
    truncated call NEVER gets reported as a value -- it just never returns, and the parent's
    timeout path reports that honestly instead."""
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        addr = _resolve_target(proj, target)
        cc = proj.factory.callable(addr)
        result_bv = cc(*args)
        value = cc.result_state.solver.eval(result_bv)
        return ToolResult(
            True, f"angr: callable({hex(addr)})({args})",
            f"returned {value} (0x{value:x})",
            meta={"completed": True, "addr": hex(addr), "args": args, "value": value},
        )
    except Exception as e:
        return ToolResult(False, "angr", "", error=f"angr error calling {target}{tuple(args)}: {e}")


def _call_function_worker(binary, target, args, budget_s, q) -> None:
    try:
        q.put(_call_function_impl(binary, target, args, budget_s))
    except Exception as e:
        q.put(ToolResult(False, "angr", "", error=f"angr error: {e}"))


def _fit_linear_recurrence(samples: Dict[int, int], order: int):
    """Finds rational coefficients c_1..c_order such that, for every consecutive window of
    `order+1` samples present, R(i) = c_1*R(i-1) + ... + c_order*R(i-order) -- EXACTLY, not a
    least-squares approximation (these come from integer machine arithmetic, so a real
    low-order linear recurrence fits perfectly or not at all). Solves the first `order`
    equations with exact Fraction Gaussian elimination, then VERIFIES every other available
    equation against the fitted coefficients before accepting -- a fit that only explains the
    equations it was solved from proves nothing (an order-k fit to exactly k equations is
    always "perfect" by construction). Returns `coeffs` (list[Fraction], length `order`) or
    None if there aren't enough consecutive samples or the fit doesn't hold everywhere."""
    xs = sorted(samples)
    windows = [i for i in xs if all((i - 1 - j) in samples for j in range(order))]
    if len(windows) < order + 2:   # need `order` to solve + at least 2 more to verify, not 0
        return None
    fit_idx = windows[:order]
    rows = [[Fraction(samples[i - 1 - j]) for j in range(order)] for i in fit_idx]
    rhs = [Fraction(samples[i]) for i in fit_idx]
    coeffs = _solve_exact(rows, rhs)
    if coeffs is None:
        return None
    for i in windows[order:]:
        predicted = sum(c * samples[i - 1 - j] for j, c in enumerate(coeffs))
        if predicted != samples[i]:
            return None
    return coeffs


def _solve_exact(rows: List[List[Fraction]], rhs: List[Fraction]):
    """Tiny exact Gaussian elimination over Fraction for a small (order <= ~6) square system --
    no numpy/sympy dependency needed for something this size, and exact Fraction arithmetic
    means no floating-point tolerance guesswork when later VERIFYING the fit against held-out
    samples (a near-miss from float rounding could silently hide a wrong recurrence)."""
    n = len(rows)
    m = [row[:] + [rhs[i]] for i, row in enumerate(rows)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if m[r][col] != 0), None)
        if pivot is None:
            return None   # singular: this many equations don't pin down `order` unknowns
        m[col], m[pivot] = m[pivot], m[col]
        pv = m[col][col]
        m[col] = [v / pv for v in m[col]]
        for r in range(n):
            if r != col and m[r][col] != 0:
                factor = m[r][col]
                m[r] = [a - factor * b for a, b in zip(m[r], m[col])]
    return [m[i][n] for i in range(n)]


def _extrapolate_impl(binary: str, target: str, n: int, budget_s: float) -> ToolResult:
    """Runs inside the forked worker. Samples the target function at small, cheap arguments
    0..max_order*2+1 within a SINGLE angr Project/state setup (reusing the project across
    calls, unlike `_call_function` which is a one-shot process -- sampling a dozen small
    values needs to stay cheap), tries the smallest linear recurrence order first (1 through
    4 covers every CTF "recursive keystream" pattern seen so far: linear congruential, Fibonacci-
    style, and small hand-rolled variants), and only extrapolates with a recurrence that is
    verified against every sample beyond the ones used to fit it."""
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        addr = _resolve_target(proj, target)
        samples: Dict[int, int] = {}
        max_order = 4
        for i in range(0, max_order * 2 + 2):
            cc = proj.factory.callable(addr)
            result_bv = cc(i)
            samples[i] = cc.result_state.solver.eval(result_bv)
        for order in range(1, max_order + 1):
            coeffs = _fit_linear_recurrence(samples, order)
            if coeffs is None:
                continue
            initial = [samples[i] for i in range(order)]
            value = _iterate_recurrence(coeffs, initial, n)
            terms = " + ".join(f"{c}*R(i-{j + 1})" for j, c in enumerate(coeffs))
            formula = f"R(i) = {terms}, with R(0..{order - 1}) = {initial}"
            return ToolResult(
                True, f"angr: extrapolate_recurrence({target})",
                f"Fitted and verified order-{order} linear recurrence from real samples of "
                f"the function: {formula}. Extrapolated R({n}) = {value} (0x{value:x}"
                f"{', low byte 0x' + format(value & 0xFF, '02x') if value > 0xFF else ''}).",
                meta={"completed": True, "order": order, "coeffs": [str(c) for c in coeffs],
                      "initial": initial, "n": n, "value": value},
            )
        sampled_str = ", ".join(f"R({i})={v}" for i, v in sorted(samples.items()))
        return ToolResult(
            True, f"angr: extrapolate_recurrence({target})",
            f"No linear recurrence of order 1-{max_order} exactly explains the real samples "
            f"({sampled_str}) -- this function is not a simple linear recurrence (or needs a "
            "higher order / is nonlinear). Read the disassembly by hand instead.",
            meta={"completed": True, "fit_found": False, "samples": samples},
        )
    except Exception as e:
        return ToolResult(False, "angr", "", error=f"angr error extrapolating {target}: {e}")


def _iterate_recurrence(coeffs: List[Fraction], initial: List[int], n: int) -> int:
    """O(n) exact extrapolation -- Python ints never overflow, so this is exact even for the
    astronomically large intermediate values a fast-growing recurrence produces well before
    reaching the requested n (confirmed live: R(n) for this session's real CTF recurrence
    overtakes 64-bit range well before n=100, long before the n=729 actually needed)."""
    order = len(coeffs)
    vals = list(initial)
    for i in range(order, n + 1):
        nxt = sum(c * vals[i - 1 - j] for j, c in enumerate(coeffs))
        assert nxt.denominator == 1, "recurrence produced a non-integer -- fit was not exact"
        vals.append(nxt.numerator)
    return vals[n]


def _extrapolate_recurrence_worker(binary, target, n, budget_s, q) -> None:
    try:
        q.put(_extrapolate_impl(binary, target, n, budget_s))
    except Exception as e:
        q.put(ToolResult(False, "angr", "", error=f"angr error: {e}"))
