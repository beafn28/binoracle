"""Autonomous audit: the local LLM drives the whole thing.

The model recons the binary, forms hypotheses, and actually builds and RUNS exploits
(try_ret2win / build_rop / run_input) in the sandbox, step by step, until it can deliver a
verified working exploit or the strongest evidence-backed finding. It is the agent loop
(hypothesis -> tool -> observation -> next step) with exploitation tools enabled."""
from __future__ import annotations

from ..oracles import build_registry
from ..agent.loop import AgentLoop, AgentResult


def _kb_hint(reg, store=None) -> str:
    """Build the RAG hint for this binary: curated exploitation cheat sheets selected from the
    binary's real facts (checksec + sinks + gift funcs) PLUS, if a store is given, facts
    binoracle has already VERIFIED on similar targets (same arch, overlapping sinks). The
    curated part is reference; the learned part is prior verified evidence. Never raises."""
    try:
        from ..rag import get_kb, query_from_facts
        facts = {"mitigations": {}, "imports": [], "primitives": [], "arch": "", "format": ""}
        arch = "?"
        cs = reg.get("r2_checksec")
        if cs:
            r = cs.run()
            if r.ok:
                arch = r.meta.get("arch", "?")
                facts["arch"] = arch
                facts["format"] = r.meta.get("format", "") or r.meta.get("bintype", "")
                facts["mitigations"] = {
                    "NX": r.meta.get("nx", "unknown"),
                    "PIE": r.meta.get("pic", "unknown"),
                    "Canary": r.meta.get("canary", "unknown"),
                    "RELRO": r.meta.get("relro", "unknown"),
                }
        sinks = []
        sk = reg.get("r2_sinks")
        if sk:
            r = sk.run()
            if r.ok:
                sinks = r.meta.get("sinks", [])
                facts["imports"] = sinks
        win = reg.get("r2_win")
        if win:
            r = win.run()
            if r.ok and (r.meta.get("win_funcs", 0) > 0 or "/bin/sh" in r.data):
                facts["primitives"].append("ret2win")

        hint = get_kb().context_for(query_from_facts(facts), k=5, max_chars=2200)

        # Learned layer: verified facts from similar binaries in the local corpus.
        if store is not None:
            try:
                learned = store.relevant_facts(arch, sinks, limit=6)
            except Exception:
                learned = []
            if learned:
                block = ("\n\n[aprendido / verificado en targets similares (misma arch, "
                         "sinks solapados) — evidencia previa, no del binario actual]\n"
                         + "\n".join("- " + x for x in learned))
                hint = (hint + block) if hint else block.lstrip()
        return hint
    except Exception:
        return ""

AUDIT_TASK = (
    "Audita este binario de principio a fin como un pentester: primero recon (formato, "
    "mitigaciones, sinks peligrosos, funciones interesantes), luego localiza la "
    "vulnerabilidad, y despues CONSTRUYE y EJECUTA un exploit para probarla. Si hay una "
    "funcion gift (win/shell) y un overflow, usa try_ret2win para construir y verificar el "
    "exploit en el sandbox. Entrega un exploit VERIFICADO con su evidencia si es posible, o "
    "el hallazgo mas fuerte respaldado por evidencia real."
)


_OVERFLOW_SINKS = ("read", "gets", "fgets", "scanf", "isoc99_scanf", "strcpy", "strcat",
                   "sprintf", "recv", "memcpy")


def _decompile_vuln_funcs(reg, binary, llm, limit: int = 2):
    """Decompila y anota las funciones que llaman a un sink de overflow (la superficie real).
    Si no hay ninguna, cae a main. Devuelve lista de DecompiledFunc o None."""
    from .decompile import decompile_explain
    funcs = []
    try:
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"]); r.cmd("aaa")
        import json as _j
        for sink in _OVERFLOW_SINKS:
            xr = r.cmd(f"axtj @ sym.imp.{sink}") or ""
            try:
                for x in _j.loads(xr) if xr.strip() else []:
                    fn = x.get("fcn_name")
                    if fn and fn not in funcs:
                        funcs.append(fn)
            except Exception:
                pass
        if not funcs:
            funcs = ["main"]
        r.quit()
    except Exception:
        funcs = ["main"]
    out = []
    for fn in funcs[:limit]:
        d = decompile_explain(binary, fn, llm=llm)
        if d.ok:
            out.append(d)
    return out or None


def run_audit(binary: str, llm, config, store=None, on_step=None) -> AgentResult:
    reg = build_registry(binary, enable_dynamic=True, enable_exploit=True)
    kb_hint = _kb_hint(reg, store=store)
    loop = AgentLoop(llm, reg, config, store=store, on_step=on_step, kb_hint=kb_hint)
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
        # Capas extra de una auditoria de pentest completa: credenciales/secretos, proteccion
        # insuficiente de ficheros/permisos, y seguridad de comunicaciones/criptografia.
        _lang = getattr(config, "lang", "es")
        for _mod, _fn in (("secrets", "scan_secrets"), ("fileperms", "scan_file_perms"),
                          ("commsec", "scan_comms")):
            try:
                import importlib
                extra = getattr(importlib.import_module(f".{_mod}", __package__), _fn)(
                    reg, binary, lang=_lang)
                for xf in extra:
                    if store:
                        store.add_finding(xf)
                dfindings = dfindings + extra
            except Exception:
                pass
        res.findings = dfindings          # real evidence, code-verified verdicts
        res.triage = triage               # so the report shows arch + mitigations
    except Exception:
        res.triage = None

    # Decompilacion aumentada de la funcion vulnerable: pseudo-C limpio + explicacion (para el
    # informe). Best-effort; no rompe la auditoria si falla.
    try:
        res.decompiled = _decompile_vuln_funcs(reg, binary, llm)
    except Exception:
        res.decompiled = None
    # Grafo de flujo interactivo de la funcion vulnerable (o main) para el informe.
    try:
        from .cfg import function_cfg
        fn = res.decompiled[0].func if getattr(res, "decompiled", None) else "main"
        res.cfg = function_cfg(binary, fn)
    except Exception:
        res.cfg = None

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

    # Curation: verified findings become durable knowledge (per-binary + anonymized global),
    # so the learned RAG layer improves on every audit. Only VERIFIED facts are kept.
    if store is not None:
        try:
            cs = reg.get("r2_checksec")
            csr = cs.run() if cs else None
            arch = csr.meta.get("arch", "?") if (csr and csr.ok) else "?"
            bits = csr.meta.get("bits", "?") if (csr and csr.ok) else "?"
            mit = csr.data if (csr and csr.ok) else ""
            store.save_verified_facts(res.findings or [], arch, bits, mit)
        except Exception:
            pass
    return res
