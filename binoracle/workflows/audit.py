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
                         "sinks solapados): evidencia previa, no del binario actual]\n"
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
    Si no hay ninguna, cae a main. Devuelve lista de DecompiledFunc o None.

    Bug real encontrado en vivo (mismo que reachability._sink_callsites, ver su fix): `axtj @
    sym.imp.<sink>` para un simbolo que el binario no importa puede colgar r2 indefinidamente --
    cada llamada a r.cmd() aqui pasa por r2session.cmd_timeout_on() en vez del `r.cmd()` crudo."""
    from .decompile import decompile_explain
    from ..oracles.r2session import cmd_timeout_on
    funcs = []
    try:
        import r2pipe
        r = r2pipe.open(binary, flags=["-2"])
        cmd_timeout_on(r, "aaa", 180.0)
        import json as _j
        for sink in _OVERFLOW_SINKS:
            xr = cmd_timeout_on(r, f"axtj @ sym.imp.{sink}", 20.0)
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


def _is_apk(path: str) -> bool:
    """True si el fichero es un APK (ZIP con classes.dex / AndroidManifest.xml)."""
    try:
        if path.lower().endswith(".apk"):
            return True
        import zipfile
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        return any(n == "AndroidManifest.xml" or n.endswith(".dex") for n in names)
    except Exception:
        return False


def run_audit(binary: str, llm, config, store=None, on_step=None) -> AgentResult:
    """Auditoria autonoma. Enruta por tipo: un APK va a la auditoria ANDROID (manifest + Java
    decompilado + patrones inseguros), un ELF/PE/Mach-O al desarrollo de exploits de memoria.
    Si Ghidra + el plugin estan instalados y no hay servidor arriba, binoracle ARRANCA el servidor
    Ghidra headless automaticamente para este binario y lo APAGA al terminar; si falta, sigue con r2."""
    if _is_apk(binary):
        from .androidaudit import run_android_audit
        return run_android_audit(binary, llm=llm, config=config, store=store, on_step=on_step)
    _gh = None
    try:
        from ..oracles import ghidra_server
        _gh = ghidra_server.start(binary)
        if _gh and on_step:
            on_step("Ghidra headless arrancado automaticamente (decompilacion grado Ghidra)")
    except Exception:
        _gh = None
    try:
        return _run_audit_impl(binary, llm, config, store=store, on_step=on_step)
    finally:
        try:
            from ..oracles import ghidra_server
            ghidra_server.stop(_gh)
        except Exception:
            pass
        try:
            from ..oracles.r2session import close_all
            close_all()   # cierra la sesion r2 compartida de la auditoria
        except Exception:
            pass


def _run_audit_impl(binary: str, llm, config, store=None, on_step=None) -> AgentResult:
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
                          ("commsec", "scan_comms"), ("backdoors", "scan_backdoors"),
                          ("dotnet", "scan_dotnet"), ("versions", "scan_versions"),
                          ("authcheck", "scan_auth"), ("logging_check", "scan_logging"),
                          ("hardening", "scan_hardening"), ("injection", "scan_injection"),
                          ("authz", "scan_authz")):
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
        # Analisis dinamico real: ejecuta el binario en el sandbox e intercepta red/ficheros/exec
        # (LD_PRELOAD). Lo observado es comportamiento VERIFICADO en ejecucion. Best-effort.
        try:
            from .dynamictrace import dynamic_trace, dynamic_findings
            dt = dynamic_trace(binary, stdin=b"A" * 64, timeout=8)
            if dt.ok:
                dynf = dynamic_findings(dt, lang=_lang)
                for xf in dynf:
                    if store:
                        store.add_finding(xf)
                dfindings = dfindings + dynf
                summary = (f"conexiones={len(dt.connects)} bind={len(dt.binds)} "
                           f"exec={len(dt.execs)} ficheros_sensibles="
                           f"{sum(1 for f in dt.files if any(s in f for s in ('passwd','shadow','.ssh','id_rsa')))}")
                res.ledger.record(res.steps + 1, "dynamic_trace",
                                  "analisis dinamico (LD_PRELOAD, sandbox)",
                                  summary + ("\n" + dt.note if dt.note else ""))
                res.dyntrace = dt
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
    # Exploit Chain Analyzer: primitivas + gadgets reales + cadenas candidatas con factibilidad,
    # puntuacion tecnica y simulacion en sandbox de las factibles. Best-effort.
    try:
        from .chainanalyzer import analyze_chains
        _lang2 = getattr(config, "lang", "es")
        res.chains = analyze_chains(binary, reg, verify=True, lang=_lang2)
        # Retroalimentacion: cada cadena VERIFICADA por el analizador se convierte en un hallazgo de
        # primera clase (verdict=verified con su prueba), asi fluye a findings, CVSS, SARIF/JSON y el
        # informe. Ademas marca el answer para que el backstop no meta un exploit duplicado.
        from ..store.session import Finding as _F
        _es2 = _lang2 == "es"
        _any_verified = False
        for ch in (res.chains.chains if res.chains else []):
            if not getattr(ch, "verified", False):
                continue
            _any_verified = True
            pr = ch.proof or {}
            det = "  ".join(f"{k}={v}" for k, v in pr.items() if k != "output" and v not in (None, ""))
            title = (f"Cadena de explotacion verificada: {ch.name}" if _es2
                     else f"Verified exploit chain: {ch.name}")
            if any(getattr(x, "title", "") == title for x in res.findings):
                continue
            fnd = _F(
                title=title, severity="critical", verdict="verified",
                location=f"{ch.target} ({pr.get('strategy', '')})",
                evidence=f"[chainanalyzer]\n{det}\n{(pr.get('output', '') or '')[:300]}",
                rationale=(f"La cadena {ch.name} hacia {ch.target} se construyo y EJECUTO en un sandbox "
                           f"aislado y alcanzo el objetivo (marcador {pr.get('marker', '')}). La "
                           "explotabilidad esta probada por ejecucion, no inferida." if _es2 else
                           f"The {ch.name} chain to {ch.target} was built and EXECUTED in an isolated "
                           f"sandbox and reached the goal (marker {pr.get('marker', '')}). Exploitability "
                           "is proven by execution, not inferred."),
                recommendation=("Corrige la causa raiz (canary + PIE + NX, eliminar el sink inseguro); "
                                "el informe incluye un script pwntools reproducible de esta cadena." if _es2
                                else "Fix the root cause (canary + PIE + NX, remove the unsafe sink); the "
                                "report ships a reproducible pwntools script for this chain."),
                rationale_en=(f"The {ch.name} chain to {ch.target} was built and EXECUTED in an isolated "
                              "sandbox and reached the goal; exploitability is proven by execution."),
                recommendation_en=("Fix the root cause (canary + PIE + NX, remove the unsafe sink)."))
            res.findings.append(fnd)
            if store:
                store.add_finding(fnd)
        if _any_verified:
            res.answer = (res.answer or "") + "\n\nEXPLOIT VERIFICADO (analizador de cadenas)"
    except Exception:
        res.chains = None

    # Alcanzabilidad simbolica (angr): genera el INPUT concreto que lleva a un sink peligroso
    # (resuelve gates tipo password) -> hallazgos VERIFIED con la entrada. Best-effort, acotado.
    try:
        import os as _os
        if _os.environ.get("BINORACLE_ANGR_REACH", "1").lower() not in ("0", "false", "no"):
            from .reachability import reachable_findings
            for xf in reachable_findings(binary, reg, lang=getattr(config, "lang", "es"),
                                         budget_s=float(_os.environ.get("BINORACLE_ANGR_BUDGET", "45")),
                                         max_targets=2):
                res.findings.append(xf)
                if store:
                    store.add_finding(xf)
    except Exception:
        pass

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
        # if still no verified exploit and no gift function, cascade the shell backstops:
        # ROP -> ret2libc -> format-string. Re-check after each so a pure format-string binary
        # (no win, no ROP, no leak path) still ends the audit with a VERIFIED exploit.
        def _verified_now():
            a = res.answer or ""
            return "EXPLOIT VERIFICADO" in a or "SHELL VERIFICADA" in a

        def _add_verified(title, location, evidence, rationale, recommendation):
            """A sandbox-verified backstop exploit is a critical VERIFIED finding, not just a
            line in the prose (so the report, the findings JSON and the learned corpus all
            record it consistently)."""
            fnd = Finding(title=title, severity="critical", verdict="verified",
                          location=location, evidence=(evidence or "")[:400],
                          rationale=rationale, recommendation=recommendation)
            res.findings.append(fnd)
            if store:
                store.add_finding(fnd)

        # Canary + gift but plain ret2win did not verify (a stack canary stops the linear
        # overflow): try the canary-LEAK bypass -- leak the canary via a %s echo, then overflow
        # past it to win(). Only when there is a win() and nothing is verified yet.
        if not _verified_now() and find_win(binary) is not None:
            try:
                from .autocanary import autocanary
                rc = autocanary(binary)
            except Exception as e:
                rc = {"note": f"error: {e}"}
            if rc.get("verified"):
                res.ledger.record(res.steps + 2, "try_canary (backstop)",
                                  "autocanary (sandbox-verified)",
                                  rc.get("detail") or rc.get("output", ""))
                res.answer += ("\n\n---\n\n### SHELL VERIFICADA via bypass de canary (backstop)\n"
                               f"{rc.get('detail','')}. Fuga del stack canary + overflow a win() "
                               "ejecutado en sandbox. [src: try_canary]")
                _add_verified("Exploit bypass de stack canary verificado", rc.get("detail", ""),
                              f"{rc.get('detail','')}\n{rc.get('output','')}",
                              "Canary filtrado por un %s y reescrito; overflow a win() en sandbox.",
                              "No imprimir el buffer con %s (fuga del canary); PIE + full RELRO.")

        tried = []   # (label, reason) of backstop exploits attempted but not verified
        if not _verified_now() and find_win(binary) is None:
            from .autopoc import autorop
            from .autolibc import autolibc
            from .autofmt import autofmt
            from .autopie import autopie_rop

            def _summary(r):
                s = r.get("detail")
                if not s and r.get("strategy"):
                    s = f"estrategia={r.get('strategy')} offset={r.get('offset')}"
                return (s or "").strip()

            # (runner, src tag for the citation, ledger source, human label, finding title, fix)
            backstops = [
                (autorop, "try_rop", "autorop (sandbox-verified)", "ROP",
                 "Exploit ROP a shell verificado",
                 "Habilitar PIE + full RELRO; evitar el overflow de pila."),
                (autolibc, "try_ret2libc", "autolibc (sandbox-verified)", "ret2libc",
                 "Exploit ret2libc a shell verificado",
                 "Habilitar PIE + full RELRO; evitar el overflow de pila."),
                (autofmt, "try_fmt", "autofmt (sandbox-verified)", "format-string",
                 "Exploit format-string a shell verificado",
                 "No pasar entrada del usuario como formato de printf; full RELRO."),
                (autopie_rop, "try_rop_pie", "autopie_rop (sandbox-verified)", "ROP en PIE",
                 "Exploit ROP en PIE a shell verificado",
                 "Full RELRO + stack canary; evitar el overflow de pila."),
            ]
            # For a PIE binary the right technique is ROP-PIE; try it FIRST so it runs on a
            # fresh sandbox (as it does standalone) instead of after autorop/ret2libc/fmt have
            # loaded the machine -- which was making a standalone-verified exploit miss here.
            try:
                from elftools.elf.elffile import ELFFile
                with open(binary, "rb") as _f:
                    if ELFFile(_f)["e_type"] == "ET_DYN":
                        backstops.sort(key=lambda b: 0 if b[1] == "try_rop_pie" else 1)
            except Exception:
                pass
            step = res.steps + 1
            for fn, tag, ledger_src, label, title, rec in backstops:
                if _verified_now():
                    break
                try:
                    r = fn(binary)
                except Exception as e:
                    tried.append((label, f"error: {e}")); continue
                if not r.get("verified"):
                    tried.append((label, r.get("note") or "no verificado")); continue
                step += 1
                summ = _summary(r)
                out = r.get("output") or r.get("run_output") or ""
                res.ledger.record(step, f"{tag} (backstop)", ledger_src, out or summ)
                res.answer += (f"\n\n---\n\n### SHELL VERIFICADA via {label} (backstop)\n"
                               f"{summ}. Ejecutado en sandbox: shell obtenida. [src: {tag}]")
                _add_verified(title, summ, f"{summ}\n{out}",
                              f"Exploit {label} construido y ejecutado en sandbox: shell obtenida.", rec)
        # heap-to-shell: run regardless of find_win (a heap binary often has a win() but is not
        # a stack overflow, so neither the ret2win attempt nor the cascade above covers it).
        if not _verified_now():
            try:
                from .autoheap import autoheap_shell
                rh = autoheap_shell(binary)
            except Exception as e:
                rh = {"note": f"error: {e}"}
            if rh.get("verified"):
                res.ledger.record(res.steps + 6, "try_heap (backstop)",
                                  "autoheap (sandbox-verified)",
                                  rh.get("output") or rh.get("detail") or "")
                menu = rh.get("menu") or {}
                menu_txt = (f" Menu detectado: new={menu.get('new')} free={menu.get('free')} "
                            f"edit={menu.get('edit')} show={menu.get('show')} "
                            f"prompt={menu.get('prompt')!r}." if menu else "")
                res.answer += (f"\n\n---\n\n### SHELL VERIFICADA via heap (tcache-UAF, backstop)\n"
                               f"{rh.get('detail','')}. Envenenamiento de tcache + free@GOT=win "
                               f"ejecutado en sandbox: shell obtenida.{menu_txt} [src: try_heap]")
                _add_verified("Exploit heap (tcache-UAF) a shell verificado", rh.get("detail", ""),
                              f"{rh.get('detail','')}\n{rh.get('output','')}",
                              "tcache poisoning + free@GOT=win ejecutado en sandbox: shell obtenida.",
                              "Limpia el puntero al liberar (evita UAF); full RELRO para que free@GOT no sea escribible.")
            elif rh.get("note") and "no aplicable" not in rh.get("note", ""):
                tried.append(("heap (tcache-UAF)", rh.get("note")))

        # Visibility: if the backstop actually attempted exploits but none verified, say so with
        # the per-technique reason, instead of leaving the report silent about the attempts.
        if not _verified_now() and tried:
            notes = "; ".join(f"{l}: {n}" for l, n in tried)
            res.ledger.record(res.steps + 7, "backstop (sin verificacion)",
                              "backstop: intentos de exploit", notes)
            res.answer += ("\n\n---\n\n### Backstop de explotacion (sin shell verificada)\n"
                           "binoracle intento construir y ejecutar un exploit, pero no logro "
                           "verificarlo en el sandbox:\n"
                           + "\n".join(f"- **{l}**: {n}" for l, n in tried)
                           + "\n\nComprueba la imagen `binoracle-pwn` (make pwn-image), o la "
                             "emulacion (heap->shell necesita un host x86-64 nativo), o pasa el "
                             "offset/objetivo manualmente.")
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
