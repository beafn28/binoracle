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
    if want("ret2win") and win is not None:
        log("[combo] ret2win (autopoc): construyendo y verificando en sandbox...")
        try:
            r = autopoc(binary, run=run)
            res.attempts.append(("ret2win", r.verified, f"offset={r.offset} win={hex(win)}"))
            res.win_exploit = res.win_exploit or r.verified
            log(f"[combo] ret2win -> {'FUNCIONA (verificado)' if r.verified else ('construido, no verificado' if r.ok else 'no aplicable')}")
            learn(f"ret2win verified={r.verified} offset={r.offset} win={hex(win)}")
        except Exception as e:
            res.attempts.append(("ret2win", False, str(e)))
            log(f"[combo] ret2win error: {e}")
    elif want("ret2win"):
        log("[combo] ret2win: no hay funcion gift -> se omite")

    # combo B: ROP chain (ret2libc / execve)
    if want("rop-chain"):
      log("[combo] cadena ROP: intentando construir...")
      try:
        from .autopoc import autorop
        rr = autorop(binary, run=run)
        verdict = True if rr.get("verified") else (None if rr.get("ok") else False)
        detail = (rr.get("strategy", "") + (" -> SHELL verificada" if rr.get("verified") else
                  " (construida)" if rr.get("ok") else "")) or rr.get("note", "")
        res.attempts.append(("rop-chain", verdict, detail or rr.get("note", "")))
        res.win_exploit = res.win_exploit or bool(rr.get("verified"))
        log(f"[combo] cadena ROP -> {'SHELL VERIFICADA' if rr.get('verified') else ('construida' if rr.get('ok') else 'no automatica')}")
        learn(f"rop verified={rr.get('verified')} strategy={rr.get('strategy')} offset={rr.get('offset')}")
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

    # combo D: format-string
    if want("format-string") and any(s in sink_names for s in ("printf", "fprintf", "snprintf")):
        res.attempts.append(("format-string", None, "sink printf presente -> fuga/escritura posible"))
        log("[combo] printf sink -> format-string (leak/write) posible")
        learn("format-string posible (printf sink)")

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


def render_autopwn(res: AutopwnResult, lang: str = "es") -> str:
    out = [f"## Auto-explotacion de `{res.binary}`\n"]
    if res.win_exploit:
        techs = [n for n, ok, _ in res.attempts if ok is True]
        out.append("> EXPLOIT VERIFICADO: se ejecuto un exploit (" + ", ".join(techs) +
                   ") en sandbox y se consiguio el objetivo.\n")
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
