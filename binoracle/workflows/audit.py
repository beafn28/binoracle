"""Autonomous audit: the local LLM drives the whole thing.

The model recons the binary, forms hypotheses, and actually builds and RUNS exploits
(try_ret2win / build_rop / run_input) in the sandbox, step by step, until it can deliver a
verified working exploit or the strongest evidence-backed finding. It is the agent loop
(hypothesis -> tool -> observation -> next step) with exploitation tools enabled."""
from __future__ import annotations

from ..oracles import build_registry
from ..agent.loop import AgentLoop, AgentResult

AUDIT_TASK = (
    "Audita este binario de principio a fin como un pentester: primero recon (formato, "
    "mitigaciones, sinks peligrosos, funciones interesantes), luego localiza la "
    "vulnerabilidad, y despues CONSTRUYE y EJECUTA un exploit para probarla. Si hay una "
    "funcion gift (win/shell) y un overflow, usa try_ret2win para construir y verificar el "
    "exploit en el sandbox. Entrega un exploit VERIFICADO con su evidencia si es posible, o "
    "el hallazgo mas fuerte respaldado por evidencia real."
)


def run_audit(binary: str, llm, config, store=None, on_step=None) -> AgentResult:
    reg = build_registry(binary, enable_dynamic=True, enable_exploit=True)
    loop = AgentLoop(llm, reg, config, store=store, on_step=on_step)
    res = loop.run(AUDIT_TASK, mode="audit")

    # Attach deterministic ground truth so the report has real evidence + mitigations,
    # regardless of how well the (small) local model wrote its own findings.
    try:
        from .triage import run_triage
        from .vulnhunt import run_hunt
        from .verify import auto_verify
        triage = run_triage(reg, binary, store=store)
        hunt = run_hunt(reg, binary, llm=None, config=config, store=store)
        dfindings, _ = auto_verify(reg, hunt.findings, store=store)
        res.findings = dfindings          # real evidence, code-verified verdicts
        res.triage = triage               # so the report shows arch + mitigations
    except Exception:
        res.triage = None

    # Deterministic backstop: the AI drives, but if it did not actually verify an exploit and
    # the binary has a gift function reachable via overflow, we run the auto-PoC ourselves so
    # the audit reliably ends in a VERIFIED exploit (or an honest "could not").
    already = "EXPLOIT VERIFICADO" in (res.answer or "") or \
              any("sandbox-verified" in s or "REACHABLE" in d for s, d in
                  [(e.source, e.data) for e in res.ledger.entries])
    try:
        from .autopoc import autopoc, find_win
        from ..store.session import Finding
        if not already and find_win(binary) is not None:
            r = autopoc(binary, run=True)
            res.ledger.record(res.steps + 1, "try_ret2win (backstop)",
                              "autopoc: ret2win (sandbox)", r.run_output or "(sin salida)")
            if r.verified:
                res.answer += (f"\n\n---\n\n### Exploit verificado (backstop automatico)\n"
                               f"La IA no lo ejecuto, pero binoracle construyo y VERIFICO un ret2win: "
                               f"offset={r.offset}, win={hex(r.win)}. Objetivo alcanzado en sandbox. "
                               f"[src: try_ret2win]")
                fnd = Finding(
                    title="Exploit ret2win verificado", severity="critical", verdict="verified",
                    location=f"win={hex(r.win)}", evidence=f"offset={r.offset}\n{r.run_output[:400]}",
                    rationale="Exploit construido automaticamente y ejecutado en sandbox: alcanza win().",
                    recommendation="Anadir stack canary y PIE; eliminar gets.")
                res.findings.append(fnd)
                if store:
                    store.add_finding(fnd)
            elif r.ok:
                res.answer += (f"\n\n---\n\n### Auto-PoC (backstop)\nExploit ret2win construido "
                               f"(offset={r.offset}, win={hex(r.win)}) pero no verificado en sandbox.")
        # if still no verified exploit, try an autonomous ROP-to-shell
        verified_now = "EXPLOIT VERIFICADO" in (res.answer or "") or "SHELL VERIFICADA" in (res.answer or "")
        if not verified_now and find_win(binary) is None:
            from .autopoc import autorop
            rr = autorop(binary, run=True)
            if rr.get("verified"):
                res.ledger.record(res.steps + 2, "try_rop (backstop)", "autorop (sandbox)",
                                  rr.get("run_output") or "")
                res.answer += (f"\n\n---\n\n### SHELL VERIFICADA via ROP (backstop)\n"
                               f"Cadena {rr.get('strategy')} (offset={rr.get('offset')}) ejecutada en "
                               f"sandbox: shell obtenida. [src: try_rop]")
            else:
                from .autolibc import autolibc
                rl = autolibc(binary)
                if rl.get("verified"):
                    res.ledger.record(res.steps + 3, "try_ret2libc (backstop)", "autolibc (sandbox)",
                                      rl.get("output") or "")
                    res.answer += (f"\n\n---\n\n### SHELL VERIFICADA via ret2libc (backstop)\n"
                                   f"{rl.get('detail','')}. Fuga de libc + system('/bin/sh') ejecutado en "
                                   f"sandbox. [src: try_ret2libc]")
    except Exception:
        pass
    return res
