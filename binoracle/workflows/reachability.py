"""Alcanzabilidad por ejecucion simbolica (angr): genera el INPUT CONCRETO que lleva la ejecucion
hasta un sink peligroso (o una rama-objetivo). Sube un hallazgo de 'grounded' (patron estatico) a
'verified' (alcanzabilidad probada) aportando la entrada exacta que lo dispara.

Casos de uso:
- Sink de ejecucion (system/execve/popen) protegido por un chequeo (password/flag/longitud): angr
  RESUELVE la entrada que satisface el chequeo y llega al sink.
- Sink de overflow (read/gets/strcpy): demuestra el camino de entrada con un input concreto.

Grounded/verified: si angr encuentra un estado en la direccion objetivo, la entrada devuelta es una
solucion REAL del solver, no una suposicion. Acotado por tiempo y numero de estados para no colgar
la auditoria. Best-effort: sin angr o si no converge, no rompe (se queda en grounded).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ReachResult:
    ok: bool = False
    target: int = 0
    target_name: str = ""
    stdin: bytes = b""
    steps: int = 0
    note: str = ""

    @property
    def stdin_hex(self) -> str:
        return self.stdin.hex()

    @property
    def stdin_printable(self) -> str:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in self.stdin)


# sinks por prioridad: ejecucion (lo mas jugoso, suelen estar tras un gate) > overflow
_EXEC_SINKS = ("system", "execve", "execl", "execlp", "execvp", "popen")
_OVF_SINKS = ("gets", "read", "fgets", "scanf", "isoc99_scanf", "strcpy", "strcat", "sprintf")


def _r2(binary: str):
    try:
        from ..oracles.r2session import get as _get
        return _get(binary)
    except Exception:
        return None


def _sink_callsites(binary: str) -> list:
    """[(sink, addr_de_la_llamada)] a sinks peligrosos, ejecucion primero. Direcciones del binario
    (link addr); se rebasan a la base de angr en find_input_to."""
    r = _r2(binary)
    if r is None:
        return []
    import json
    out = []
    for group in (_EXEC_SINKS, _OVF_SINKS):
        for s in group:
            try:
                xs = json.loads(r.cmd(f"axtj @ sym.imp.{s}") or "[]")
            except Exception:
                xs = []
            for x in xs:
                a = x.get("from")
                if isinstance(a, int):
                    out.append((s, a))
    return out


def _find_input_to_impl(binary: str, target: int, avoid: tuple = (), stdin_len: int = 200,
                        budget_s: float = 45.0, max_active: int = 80) -> Optional[ReachResult]:
    """Ejecuta angr desde el entrypoint con stdin simbolico y busca un estado en `target`. Devuelve
    la entrada concreta que lo alcanza, o None. Acotado por tiempo y numero de estados."""
    try:
        import angr  # noqa
        try:
            import claripy  # angr < 10 lo expone como paquete top-level
        except Exception:
            claripy = angr.claripy   # angr >= 10 lo re-exporta
        import logging as _lg
        for n in ("angr", "cle", "pyvex", "claripy"):
            _lg.getLogger(n).setLevel(_lg.ERROR)
    except Exception:
        return None
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        # rebasa target/avoid del espacio del binario (r2, direcciones de fichero/link) al de angr
        # (direcciones cargadas). BUG previo: ambas ramas del condicional devolvian `a` sin cambios
        # (no-op) y ademas nunca se llamaba -- en un binario PIE, r2 reporta las direcciones como si
        # se cargase en base 0 (p.ej. un sink en 0x11a6), pero angr SIEMPRE lo carga en su propia
        # base fija (mapped_base, tipicamente 0x400000). Sin el rebase, el 'target' pedido a angr
        # caia FUERA del espacio de direcciones cargado y la busqueda no podia tener exito NUNCA --
        # reachable_findings quedaba inerte (0 verificaciones) en todo binario PIE, que es el modo de
        # compilacion por defecto en toolchains modernos. Confirmado con ret2win_pie: angr carga en
        # 0x400000+ pero el sink de r2 estaba en 0x11a6, fuera de rango. En no-PIE el ELF ya trae su
        # base fija horneada en el vaddr y coincide directamente con angr (no hace falta rebase).
        if proj.loader.main_object.pic:
            base = proj.loader.main_object.mapped_base or 0
            def rb(a):
                return a + base
        else:
            def rb(a):
                return a
        tgt = rb(target)
        av = [rb(a) for a in avoid]
        # stdin simbolico de longitud acotada
        flag = claripy.BVS("stdin", 8 * stdin_len)
        stdin = angr.SimFileStream(name="stdin", content=flag, has_end=True)
        st = proj.factory.full_init_state(
            stdin=stdin,
            add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        simgr = proj.factory.simulation_manager(st)
        deadline = time.time() + budget_s
        steps = 0
        while time.time() < deadline:
            if not simgr.active:
                break
            simgr.explore(find=tgt, avoid=av or None, n=1, num_find=1)
            steps += 1
            if simgr.found:
                break
            # controla la explosion de estados
            if len(simgr.active) > max_active:
                simgr.active[:] = simgr.active[:max_active]
            if not simgr.active:
                break
        if not simgr.found:
            return ReachResult(ok=False, target=target, note="no alcanzado en el presupuesto")
        found = simgr.found[0]
        data = found.posix.dumps(0)
        # recorta el relleno nulo final
        data = data.rstrip(b"\x00") or data[:1]
        return ReachResult(ok=True, target=target, stdin=data[:stdin_len], steps=steps,
                           note="alcanzado por ejecucion simbolica")
    except Exception as e:
        return ReachResult(ok=False, target=target, note=f"angr: {e.__class__.__name__}")


def _find_input_to_worker(binary, target, avoid, stdin_len, budget_s, max_active, q) -> None:
    try:
        q.put(_find_input_to_impl(binary, target, avoid, stdin_len, budget_s, max_active))
    except Exception as e:
        q.put(ReachResult(ok=False, target=target, note=f"angr: {e.__class__.__name__}"))


def find_input_to(binary: str, target: int, avoid: tuple = (), stdin_len: int = 200,
                  budget_s: float = 45.0, max_active: int = 80) -> Optional[ReachResult]:
    """Envoltorio de `_find_input_to_impl` con un deadline DURO via subproceso. El bucle interno
    (`while time.time() < deadline`) solo comprueba el reloj ENTRE llamadas a `simgr.explore(...)`
    -- si una sola llamada se bloquea mucho mas de lo normal (un step de angr con resolucion de
    restricciones dura, en un binario real/CPU muy limitada: confirmado en vivo, un step que
    deberia tardar ~1s tardo mas de 2 HORAS bajo throttling de CPU severo), ese bucle no tiene
    forma de interrumpirla -- budget_s se convertia en una cota blanda, no dura. Aqui se ejecuta
    la busqueda real en un proceso HIJO (fork, para no repetir el import de angr) y se le da
    budget_s mas un margen generoso para el propio arranque/parada del proceso; si para entonces
    sigue vivo, se MATA (terminate -> kill) y se devuelve 'no alcanzado', en vez de bloquear al
    proceso llamador indefinidamente. En el camino normal (el 99% de los casos, donde cada step
    es rapido) esto no cambia nada: el hijo termina solo, bien dentro de budget_s."""
    import multiprocessing as mp
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context()   # plataformas sin fork (no Linux): usa el metodo por defecto
    q = ctx.Queue()
    p = ctx.Process(target=_find_input_to_worker,
                    args=(binary, target, avoid, stdin_len, budget_s, max_active, q))
    p.start()
    p.join(budget_s + 30.0)
    if p.is_alive():
        p.terminate()
        p.join(5.0)
        if p.is_alive():
            p.kill()
            p.join()
        return ReachResult(ok=False, target=target,
                           note="angr: excedio el presupuesto de tiempo (proceso forzado a "
                                "terminar, el budget_s pedido era una cota dura)")
    try:
        return q.get_nowait()
    except Exception:
        return ReachResult(ok=False, target=target,
                           note="angr: el proceso termino sin devolver resultado")


def _f(title_es, title_en, sev, ev, rat_es, rat_en, rec_es, rec_en, lang, loc):
    from ..store.session import Finding
    return Finding(title=title_es if lang == "es" else title_en, severity=sev, verdict="verified",
                   evidence=ev, location=loc,
                   rationale=rat_es if lang == "es" else rat_en,
                   recommendation=rec_es if lang == "es" else rec_en,
                   rationale_en=rat_en, recommendation_en=rec_en)


def reachable_findings(binary: str, reg=None, lang: str = "es", budget_s: float = 45.0,
                       max_targets: int = 3) -> List:
    """Para los sinks peligrosos del binario, intenta generar con angr el input concreto que los
    alcanza. Cada exito es un hallazgo VERIFIED (alcanzabilidad probada) con la entrada. Best-effort."""
    try:
        import angr  # noqa
    except Exception:
        return []
    es = lang == "es"
    sites = _sink_callsites(binary)
    if not sites:
        return []
    findings = []
    seen = set()
    per = max(10.0, budget_s / max(1, min(len(sites), max_targets)))
    tried = 0
    for sink, addr in sites:
        if tried >= max_targets:
            break
        if (sink, addr) in seen:
            continue
        seen.add((sink, addr))
        tried += 1
        # evita otras llamadas al mismo sink que no sean el objetivo (para forzar ESTE camino)
        r = find_input_to(binary, addr, avoid=(), budget_s=per)
        if not r or not r.ok:
            continue
        gated = sink in _EXEC_SINKS
        findings.append(_f(
            (f"Sink alcanzable con input concreto: {sink} @ {hex(addr)}" if es
             else f"Sink reachable with a concrete input: {sink} @ {hex(addr)}"),
            (f"Sink reachable with a concrete input: {sink} @ {hex(addr)}"),
            "high" if gated else "medium",
            f"[angr]\nobjetivo: {sink} @ {hex(addr)}\ninput (hex): {r.stdin_hex[:160]}\n"
            f"input (repr): {r.stdin_printable[:80]}",
            (f"Ejecucion simbolica: existe una entrada CONCRETA que lleva el flujo hasta `{sink}`"
             + (" (sink de ejecucion, posiblemente tras un chequeo que angr ha resuelto)." if gated
                else " (sink de riesgo).")
             + " La alcanzabilidad esta PROBADA por el solver, no inferida." if es else
             f"Symbolic execution: a CONCRETE input drives the flow to `{sink}`"
             + (" (exec sink, possibly behind a check angr solved)." if gated else " (risky sink).")
             + " Reachability is PROVEN by the solver, not inferred."),
            (f"Symbolic execution found a concrete input reaching `{sink}`; reachability proven."),
            ("Valida y sanea la entrada antes de que alcance el sink; anade limites de tamano y "
             "escapado. El input adjunto reproduce el camino." if es else
             "Validate and sanitize input before it reaches the sink; add size bounds and escaping. "
             "The attached input reproduces the path."),
            ("Validate and sanitize input before it reaches the sink."), lang,
            f"{sink} @ {hex(addr)}"))
    return findings
