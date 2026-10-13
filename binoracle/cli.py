"""binoracle command line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_config
from .llm import make_backend
from .oracles import build_registry
from .store.session import SessionStore
from .workflows.triage import run_triage
from .workflows.vulnhunt import run_hunt
from .workflows.primitives import run_primitives
from .workflows.skeleton import generate_skeleton
from .workflows.explain import run_explain
from .workflows.patchdiff import run_patchdiff, render_patchdiff
from .agent.loop import AgentLoop
from .report.render import render_triage, render_agent_result
from .report.html import render_html
from .report.render import findings_to_json, findings_to_sarif
from .workflows.verify import auto_verify, verify_address
from .workflows.enrich import enrich_findings, executive_summary
from .workflows.rop import build_rop_chain
from .workflows.shellcode import gen_shellcode
from .workflows.fuzz import generate_fuzz
from .workflows.fmtstring import fmtstring_help
from .workflows.autopoc import autopoc, render_poc
from .workflows.autopwn import autopwn, render_autopwn
from .workflows.audit import run_audit
from .workflows.regress import run_regress, render_regress
from .agent.grounding import GroundingLedger


def _eprint(*a):
    print(*a, file=sys.stderr)


def _step_printer(step: int, action: dict):
    act = action.get("action")
    if act == "tool":
        args = action.get("args", {})
        arg_s = " ".join(f"{k}={v}" for k, v in args.items())
        _eprint(f"  [step {step}] tool: {action.get('tool')} {arg_s}".rstrip())
    elif act == "final":
        _eprint(f"  [step {step}] final answer")
    elif act == "malformed":
        _eprint(f"  [step {step}] (model reply was not valid protocol; nudging)")


def _require_binary(path: str) -> str:
    p = Path(path)
    if not p.exists():
        _eprint(f"error: no such file: {path}")
        sys.exit(2)
    return str(p)


def cmd_cveplan(args, config):
    """Esquema de explotacion a partir de una CVE / descripcion (a la inversa: de la vuln al exploit).
    Con --binary, concreta las mitigaciones desde checksec."""
    from .workflows.cveplan import plan, plan_for_binary, render_plan
    if getattr(args, "binary", None):
        # concreta el esquema con el binario (offset/gadgets reales) y verifica en sandbox
        pl = plan_for_binary(args.binary, text=args.text, cve=getattr(args, "cve", ""),
                             lang=config.lang, verify=not getattr(args, "no_verify", False))
    else:
        pl = plan(args.text, {}, cve=getattr(args, "cve", ""), lang=config.lang)
    if getattr(args, "json", False):
        # salida estructurada (una linea JSON): la usa el trainer/dataset para correr cada binario
        # como subproceso con presupuesto de tiempo.
        import json as _json
        print(_json.dumps({"ok": pl.ok, "verified": pl.verified, "vuln_class": pl.vuln_class,
                           "primitive": pl.primitive, "concrete": pl.concrete, "proof": pl.proof,
                           "script": pl.script}))
        return
    print(render_plan(pl, config.lang))
    # exporta el exploit DESARROLLADO (script pwntools reproducible) a un fichero ejecutable
    out = getattr(args, "out", None)
    if out:
        if not pl.script:
            print(("\n[!] sin exploit desarrollado que exportar (no hubo cadena verificada; "
                   "usa --binary y no pases --no-verify)" if config.lang == "es" else
                   "\n[!] no developed exploit to export (no verified chain; use --binary without "
                   "--no-verify)"))
        else:
            import os as _os
            with open(out, "w") as fh:
                fh.write(pl.script + "\n")
            try:
                _os.chmod(out, 0o755)
            except OSError:
                pass
            print(("\n[+] exploit desarrollado escrito en " if config.lang == "es" else
                   "\n[+] developed exploit written to ") + out
                  + (" (verificado en sandbox)" if pl.verified and config.lang == "es" else
                     (" (sandbox-verified)" if pl.verified else "")))


def cmd_doctor(args, config):
    print("binoracle doctor\n" + "=" * 40)
    llm = make_backend(config)
    print(f"LLM backend: {llm.info()}")
    print()
    target = args.binary or __file__  # doctor can run without a real target
    reg = build_registry(target, enable_dynamic=True)
    print("Oracles:")
    for line in reg.status():
        print("  " + line)
    print()
    # Conocimiento que la IA consulta (todo hilado: cheat sheets + herramientas + ingesta).
    try:
        from .rag import get_kb
        kb = get_kb()
        tools = sum(1 for c in kb.chunks if c.doc.startswith("tools/"))
        print("Conocimiento (RAG):")
        print("  " + kb.status())
        print("  fuentes: " + kb.sources_summary())
        print(f"  herramientas hiladas en el RAG: {tools}")
        # Salud/integridad del conocimiento: evita que el RAG meta 'cosas falsas' (dups/chino sin
        # traducir). El RAG es SOLO referencia; los hallazgos salen de oraculos, no del RAG.
        try:
            h = kb.health()
            estado = "LIMPIO" if h["clean"] else "REVISAR"
            print(f"  salud: [{estado}] {h['docs']} docs, {h['sources']} fuentes, "
                  f"duplicados={h['duplicates']}, chunks con chino sin traducir={h['cjk_chunks']}")
            if not h["clean"] and h.get("cjk_docs"):
                print("    revisar (CJK): " + ", ".join(h["cjk_docs"]))
        except Exception:
            pass
        print("  el RAG es referencia; cada hallazgo del informe se ata a un oraculo (verified = "
              "probado por ejecucion, grounded = evidencia estatica).")
        print("  aprende material nuevo con: binoracle learn <carpeta> --apply")
        print()
    except Exception:
        pass
    _print_toolchain_status()
    if not llm.available():
        print("hint: no local model reachable. `ollama serve` + `ollama pull <model>`,")
        print("      or set BINORACLE_BACKEND=openai for an OpenAI-compatible local server.")


def _print_toolchain_status() -> None:
    """Estado de la cadena de reversing aumentada (Ghidra / decai / sandbox / cvss), con la accion
    concreta para activar lo que falte. Best-effort: nunca rompe el doctor."""
    import shutil
    ok = lambda b: "[ok]  " if b else "[--]  "
    print("Cadena de reversing aumentada:")
    # Ghidra (decompilacion grado Ghidra + auto-arranque headless)
    try:
        from .oracles import ghidra as _gh, ghidra_server as _gs
        cfg = _gs._cfg()
        up = _gh.available(timeout=1.5)
        install = _gs._install_dir(cfg)
        jdk = _gs._jdk_home(cfg)
        plugin = bool(install and _gs._plugin_installed(install))
        auto = _gs.autostart_enabled(cfg)
        print(f"  {ok(up)}Ghidra server: " + (f"activo en {_gh.base_url()}" if up else "no activo"))
        print(f"  {ok(bool(install))}Ghidra install: " + (install or "no encontrado (instala Ghidra o define GHIDRA_INSTALL_DIR)"))
        print(f"  {ok(plugin)}plugin GhidraMCP: " + ("instalado" if plugin else "no instalado (construye/instala la extension)"))
        print(f"  {ok(bool(jdk))}JDK 21+: " + (jdk or "no encontrado (define BINORACLE_GHIDRA_JDK)"))
        print(f"  {ok(auto)}auto-arranque: " + ("activado" if auto else "desactivado (BINORACLE_GHIDRA_AUTOSTART=1)")
              + (" -> binoracle levantara Ghidra solo en el audit" if (auto and plugin and install and jdk and not up) else ""))
    except Exception:
        pass
    # decai (fuente de decompilacion alternativa)
    try:
        from .oracles import decai as _dc
        inst = _dc.installed()
        ready = _dc._llm_ready() if inst else False
        print(f"  {ok(inst)}decai (r2ai): " + ("instalado" if inst else "no instalado (r2pm -Uci decai)"))
        if inst:
            print(f"  {ok(_dc.enabled())}decai activo: " + ("si" if _dc.enabled() else "no (necesita ollama arriba o una API key)"))
    except Exception:
        pass
    # sandbox dinamico (docker) + cvss
    docker = shutil.which("docker")
    img = False
    if docker:
        try:
            import subprocess as _sp
            img = _sp.run([docker, "image", "inspect", "binoracle-pwn"], capture_output=True).returncode == 0
        except Exception:
            img = False
    print(f"  {ok(bool(docker))}docker (sandbox dinamico/exploits): " + ("disponible" if docker else "no (instala Docker)"))
    if docker:
        print(f"  {ok(img)}imagen binoracle-pwn: " + ("construida" if img else "no construida (docker build -f .docker/Dockerfile.pwn -t binoracle-pwn .)"))
    try:
        import cvss  # noqa: F401
        print(f"  {ok(True)}CVSS 4.0 (paquete cvss): disponible")
    except Exception:
        print(f"  {ok(False)}CVSS 4.0 (paquete cvss): no (pip install cvss)")
    print()


def cmd_triage(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    store = SessionStore(config.db_path(), binary)
    report = run_triage(reg, binary, store=store)
    findings = None
    if args.explain:
        llm = make_backend(config)
        if llm.available():
            loop = AgentLoop(llm, reg, config, store=store, on_step=_step_printer)
            res = loop.run(
                "Given the triage facts you can gather with the tools, summarize what this "
                "binary is, its attack surface, and where a reviewer should look first.",
                mode="ask",
            )
            print(render_triage(report))
            print("\n## LLM narrative (grounded)\n")
            print(res.answer)
            _write_if(args.output, render_triage(report) + "\n## LLM narrative\n" + res.answer)
            store.close()
            return
        _eprint("(no local model up; printing facts-only triage)")
    out = render_triage(report, findings)
    print(out)
    _write_if(args.output, out)
    if getattr(args, "html", None):
        _write_html(args.html, binary, triage=report, findings=store.findings(), lang=config.lang)
    store.close()


def cmd_hunt(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary, enable_dynamic=args.dynamic)
    store = SessionStore(config.db_path(), binary)
    llm = make_backend(config)
    res = run_hunt(reg, binary, llm=llm, config=config, store=store, on_step=_step_printer, lang=config.lang)
    # deterministic verification pass (angr) unless disabled
    if not args.no_verify:
        res.findings, vnotes = auto_verify(reg, res.findings, store=store)
        for n in vnotes:
            _eprint("  [verify] " + n)
    # AI enrichment (professional analysis + executive summary) if a model is up
    if llm is not None and llm.available() and res.findings:
        _eprint("  [ai] redactando analisis profesional...")
        res.findings = enrich_findings(llm, res.findings, lang=config.lang)
        summary = executive_summary(llm, binary, res.findings, lang=config.lang)
        if summary:
            res.answer = summary
    out = render_agent_result(binary, res)
    print(out)
    _write_if(args.output, out)
    if getattr(args, "html", None):
        _write_html(args.html, binary, findings=res.findings, ledger=res.ledger, answer=res.answer, lang=config.lang)
    if getattr(args, "json", None):
        Path(args.json).write_text(findings_to_json(binary, res.findings, res.ledger))
        _eprint(f"(JSON written to {args.json})")
    store.close()


def cmd_ask(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary, enable_dynamic=args.dynamic)
    store = SessionStore(config.db_path(), binary)
    llm = make_backend(config)
    if not llm.available():
        _eprint("error: no local model reachable. Run `binoracle doctor`.")
        sys.exit(3)
    loop = AgentLoop(llm, reg, config, store=store, on_step=_step_printer)
    res = loop.run(args.question, mode="ask")
    out = render_agent_result(binary, res)
    print(out)
    _write_if(args.output, out)
    if getattr(args, "html", None):
        _write_html(args.html, binary, findings=res.findings, ledger=res.ledger, answer=res.answer)
    store.close()


def cmd_chat(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary, enable_dynamic=args.dynamic)
    store = SessionStore(config.db_path(), binary)
    llm = make_backend(config)
    if not llm.available():
        _eprint("error: no local model reachable. Run `binoracle doctor`.")
        sys.exit(3)
    loop = AgentLoop(llm, reg, config, store=store, on_step=_step_printer)
    print(f"binoracle chat on {binary} (empty line or 'quit' to exit)\n")
    while True:
        try:
            q = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not q or q.lower() in ("quit", "exit"):
            break
        res = loop.run(q, mode="ask")
        print("\nbinoracle>\n" + res.answer + "\n")
    store.close()


def cmd_report(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    store = SessionStore(config.db_path(), binary)
    report = run_triage(reg, binary, store=store)
    findings = store.findings()
    out = render_triage(report, findings)
    dest = args.output or "binoracle_report.md"
    Path(dest).write_text(out)
    print(f"wrote {dest} ({len(out)} bytes, {len(findings)} finding(s))")
    store.close()


def _write_if(path, text):
    if path:
        Path(path).write_text(text)
        _eprint(f"(written to {path})")



def cmd_primitives(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary, enable_dynamic=args.dynamic)
    store = SessionStore(config.db_path(), binary)
    llm = make_backend(config)
    res = run_primitives(reg, binary, llm=llm, config=config, store=store, on_step=_step_printer)
    out = render_agent_result(binary, res)
    print(out)
    _write_if(args.output, out)
    if getattr(args, "html", None):
        _write_html(args.html, binary, findings=res.findings, ledger=res.ledger, answer=res.answer)
    store.close()


def cmd_gadgets(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    tool = reg.get("r2_rop")
    if not tool:
        _eprint("error: radare2 rop search unavailable")
        sys.exit(3)
    res = tool.run(filter=args.filter)
    print(f"[{res.source}]  ({res.meta.get('count', 0)} gadget(s))\n")
    print(res.data)


def cmd_cyclic(args, config):
    binary = args.binary if args.binary and Path(args.binary).exists() else __file__
    reg = build_registry(binary)
    if args.find is not None:
        res = reg.get("cyclic_offset").run(value=args.find)
    else:
        res = reg.get("cyclic").run(length=args.length)
    print(f"[{res.source}]\n{res.data}")


def cmd_skeleton(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    script = generate_skeleton(reg, binary, offset=args.offset, primitive=args.primitive)
    if args.output:
        Path(args.output).write_text(script)
        print(f"wrote {args.output}")
    else:
        print(script)


def cmd_explain(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    store = SessionStore(config.db_path(), binary)
    llm = make_backend(config)
    if not llm.available():
        _eprint("error: no local model reachable. Run `binoracle doctor`.")
        sys.exit(3)
    res = run_explain(reg, args.function, llm, config, store=store, on_step=_step_printer)
    out = render_agent_result(binary, res)
    print(out)
    _write_if(args.output, out)
    store.close()


def cmd_diff(args, config):
    old = _require_binary(args.old)
    new = _require_binary(args.new)
    llm = make_backend(config)
    res = run_patchdiff(old, new, llm=llm, config=config)
    out = render_patchdiff(res)
    print(out)
    _write_if(args.output, out)




def _write_html(path, binary, triage=None, findings=None, ledger=None, answer="", open_it=False,
                lang="es", decompiled=None, cfg=None, chains=None):
    html = render_html(binary, triage=triage, findings=findings, ledger=ledger, answer=answer,
                       lang=lang, decompiled=decompiled, cfg=cfg, chains=chains)
    Path(path).write_text(html)
    _eprint(f"(HTML written to {path})")
    if open_it:
        import subprocess, sys as _sys
        opener = "open" if _sys.platform == "darwin" else "xdg-open"
        try:
            subprocess.run([opener, path], check=False)
        except Exception:
            pass
    return path

def cmd_view(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    store = SessionStore(config.db_path(), binary)
    report = run_triage(reg, binary, store=store)

    # build a grounding ledger from the triage facts so the evidence trail is populated
    ledger = GroundingLedger()
    for i, (title, source, text) in enumerate(report.sections, 1):
        ledger.record(i, title, source, text)

    # grounded findings without a model, then deterministic angr verification
    hunt = run_hunt(reg, binary, llm=None, config=config, store=store, lang=config.lang)
    findings, vnotes = auto_verify(reg, hunt.findings, store=store)
    for n in vnotes:
        _eprint("  [verify] " + n)

    # if a local model is up, add professional AI analysis + executive summary
    answer = hunt.answer
    llm = make_backend(config)
    if llm.available() and findings:
        _eprint("  [ai] redactando analisis profesional en " + config.lang + "...")
        findings = enrich_findings(llm, findings, lang=config.lang)
        mit = next((t for (ti, sr, t) in report.sections if "checksec" in (sr+ti).lower()), "")
        summary = executive_summary(llm, binary, findings, mitigations=mit, lang=config.lang)
        if summary:
            answer = summary

    dest = args.output or "binoracle_report.html"
    _write_html(dest, binary, triage=report, findings=findings, ledger=ledger,
                answer=answer, open_it=not args.no_open, lang=config.lang)
    print(f"wrote {dest} ({len(findings)} finding(s))")
    store.close()


def cmd_verify(args, config):
    binary = _require_binary(args.binary)
    reg = build_registry(binary)
    if args.reach:
        reachable, _inp, ev = verify_address(reg, args.reach)
        print(f"address {args.reach}: {'REACHABLE' if reachable else 'not proven reachable'}")
        print(ev)
        sys.exit(0 if reachable else 1)
    store = SessionStore(config.db_path(), binary)
    findings = store.findings()
    if not findings:
        _eprint("no stored findings; run `binoracle hunt` first")
        sys.exit(2)
    findings, notes = auto_verify(reg, findings, store=store)
    for n in notes:
        print("[verify] " + n)
    verified = [f for f in findings if f.verdict == "verified"]
    print(f"\n{len(verified)}/{len(findings)} finding(s) verified")
    store.close()


def cmd_rop(args, config):
    binary = _require_binary(args.binary)
    print(build_rop_chain(binary, goal=args.goal, libc_path=args.libc))


def cmd_shellcode(args, config):
    nx = None
    binary = args.binary
    if binary and Path(binary).exists():
        reg = build_registry(binary)
        cs = reg.get("r2_checksec")
        if cs:
            r = cs.run()
            nx = str(r.meta.get("nx", "")).lower() in ("true", "1")
    print(gen_shellcode(arch=args.arch, kind=args.kind, arg=args.arg, nx=nx))


def cmd_fuzz(args, config):
    binary = _require_binary(args.binary)
    print(generate_fuzz(binary, target_func=args.func, mode=args.mode))


def cmd_fmtstring(args, config):
    print(fmtstring_help(offset=args.offset, target_addr=args.addr, value=args.value))


def cmd_analyze(args, config):
    """One-shot: accept a .c/.cpp source (compile it) OR a binary, then full report."""
    src = args.file
    binary = src
    ext = Path(src).suffix.lower()
    if ext in (".c", ".cc", ".cpp", ".cxx", ".c++"):
        if not Path(src).exists():
            _eprint(f"error: no such source: {src}")
            sys.exit(2)
        import subprocess, tempfile, shutil
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            _eprint("error: no C compiler on PATH (cc/gcc/clang)")
            sys.exit(3)
        out_bin = str(Path(tempfile.mkdtemp()) / (Path(src).stem))
        cxx = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++") or cc
        compiler = cxx if ext in (".cc", ".cpp", ".cxx", ".c++") else cc
        flags = ["-fno-stack-protector", "-no-pie", "-w"]
        _eprint(f"[compile] {compiler} {' '.join(flags)} -o {out_bin} {src}")
        r = subprocess.run([compiler, *flags, "-o", out_bin, src], capture_output=True, text=True)
        if r.returncode != 0:
            _eprint("compilation failed:\n" + r.stderr)
            sys.exit(4)
        binary = out_bin
        _eprint(f"[compile] ok -> {binary}")
    # delegate to the full view pipeline
    class _A:  # minimal args shim for cmd_view
        pass
    a = _A()
    a.binary = binary
    a.output = args.output
    a.no_open = args.no_open
    cmd_view(a, config)


def cmd_serve(args, config):
    from .web import serve
    serve(host=args.host, port=args.port, open_browser=not args.no_open)


def cmd_mcp(args, config):
    # stdio MCP server: speaks JSON-RPC on stdin/stdout, so nothing must be printed to stdout here.
    from .mcp_server import serve
    serve()


def cmd_autopoc(args, config):
    binary = _require_binary(args.binary)
    r = autopoc(binary, offset=args.offset, run=not args.no_run)
    out = render_poc(r, lang=config.lang)
    print(out)
    _write_if(args.output, out)


def cmd_autopwn(args, config):
    binary = _require_binary(args.binary)
    store = SessionStore(config.db_path(), binary)
    res = autopwn(binary, config=config, store=store, on_step=lambda m: _eprint("  " + m),
                  run=not args.no_run, llm=make_backend(config))
    out = render_autopwn(res, lang=config.lang)
    print(out)
    _write_if(args.output, out)
    if getattr(args, "json", None):
        from .workflows.autopwn import autopwn_to_json
        Path(args.json).write_text(autopwn_to_json(res)); _eprint(f"(JSON -> {args.json})")
    store.close()


def cmd_audit(args, config):
    binary = _require_binary(args.binary)
    store = SessionStore(config.db_path(), binary)
    llm = make_backend(config)
    if not llm.available():
        _eprint("error: no local model reachable. Run `binoracle doctor`.")
        sys.exit(3)
    res = run_audit(binary, llm, config, store=store, on_step=_step_printer)
    out = render_agent_result(binary, res)
    print(out)
    _write_if(args.output, out)
    if getattr(args, "html", None):
        _write_html(args.html, binary, triage=getattr(res, "triage", None), findings=res.findings,
                    ledger=res.ledger, answer=res.answer, lang=config.lang,
                    decompiled=getattr(res, "decompiled", None), cfg=getattr(res, "cfg", None),
                    chains=getattr(res, "chains", None))
    if getattr(args, "json", None):
        Path(args.json).write_text(findings_to_json(binary, res.findings, res.ledger)); _eprint(f"(JSON -> {args.json})")
    if getattr(args, "sarif", None):
        Path(args.sarif).write_text(findings_to_sarif(binary, res.findings, res.ledger)); _eprint(f"(SARIF -> {args.sarif})")
    store.close()


def cmd_regress(args, config):
    old = _require_binary(args.old); new = _require_binary(args.new)
    res = run_regress(old, new, config)
    out = render_regress(res)
    print(out)
    _write_if(args.output, out)


def cmd_heap(args, config):
    binary = _require_binary(args.binary)
    from .workflows.autoheap import autoheap, render_heap
    print(render_heap(autoheap(binary)))


def cmd_tools(args, config):
    from .toolcheck import check_tools, render
    print(render(check_tools(), lang=config.lang))


def cmd_rag(args, config):
    from .rag import get_kb, configure
    def _tri(v):
        if v is None:
            return None
        return v.lower() in ("1", "on", "true", "yes")
    if any(x is not None for x in (args.embed, args.expand, args.rerank)):
        status = configure(embed=_tri(args.embed), expand=_tri(args.expand),
                           rerank=_tri(args.rerank))
    else:
        status = get_kb().status()
    kb = get_kb()
    print("RAG: " + status)
    print("conocimiento: " + kb.sources_summary())


def cmd_learn(args, config):
    from .ingest import learn
    rep = learn(args.path, name=args.name, apply=args.apply)
    print(rep.summary())
    if rep.applied:
        from .rag import reload_kb
        kb = reload_kb()
        print("\nRAG recargado con lo aprendido: " + kb.status())
        print("conocimiento: " + kb.sources_summary())
    elif rep.kept:
        print("\n(dry-run) para que lo aprenda de verdad: "
              f"binoracle learn {args.path} --apply")


def cmd_train(args, config):
    """Agente entrenador: desarrolla + verifica exploits sobre un corpus y cura lo verificado,
    subiendo la habilidad de forma medible. Sin binarios, usa el corpus de ejemplo del repo."""
    from .workflows.exploit_trainer import train, render_training, export_playbook
    bins = list(getattr(args, "binaries", None) or [])
    rep = train(binaries=bins or None, config=config,
                verify=not getattr(args, "no_verify", False),
                on_step=lambda m: print("  " + m), lang=config.lang,
                budget_s=float(getattr(args, "budget", 240) or 240))
    print("\n" + render_training(rep, config.lang))
    pb = getattr(args, "export_playbook", None)
    if pb is not None:
        from .workflows.exploit_trainer import default_playbook_path
        dest = pb or default_playbook_path()
        n = export_playbook(rep, dest or None, config.lang)
        print(f"\n[+] playbook: {n} tecnicas verificadas escritas en {dest}" if n
              else "\n[!] playbook no escrito (ninguna tecnica verificada)")


def cmd_autofuzz(args, config):
    """Auto-fuzzing: descubre dinamicamente que input dispara el fallo (stdin/argv/format-string),
    confirmado por crash en el sandbox. Devuelve el vector y la clase; el offset/exploit los resuelve
    el pipeline."""
    from .workflows.autofuzz import autofuzz, render_fuzz
    binary = _require_binary(args.binary)
    res = autofuzz(binary, on_step=lambda m: print("  " + m), lang=config.lang)
    print("\n" + render_fuzz(res, config.lang))


def cmd_fetch(args, config):
    """Extrae un binario real desde una imagen Docker (para conseguir el binario vulnerable de una
    CVE). No ejecuta el entrypoint de la imagen: docker create + cp."""
    from .workflows.dockerfetch import fetch_from_image, render_fetch
    res = fetch_from_image(args.image, args.path, dest_dir=getattr(args, "out", "") or "",
                           on_step=lambda m: print("  " + m))
    print("\n" + render_fetch(res, config.lang))


def cmd_investigate(args, config):
    """Agente de investigacion guiado por LLM: de la CVE al exploit, investigando y probando. El LLM
    razona y propone; si das --binary, prueba y VERIFICA en sandbox; el informe es honesto sobre lo
    verificado y lo bloqueado."""
    from .workflows.cve_agent import investigate_cve, render_investigation
    inv = investigate_cve(args.cve, binary=getattr(args, "binary", "") or "",
                          config=config, on_step=lambda m: print("  " + m), lang=config.lang,
                          budget_s=float(getattr(args, "budget", 300) or 300))
    print("\n" + render_investigation(inv, config.lang))


def cmd_dataset(args, config):
    """Genera el dataset SFT (JSONL de chat) para fine-tunear un LLM que desarrolle exploits:
    pares (vulnerabilidad + mitigaciones) -> exploit pwntools VERIFICADO. Con --include-templates
    anade tambien las plantillas desarrolladas (mas cobertura, menor calidad)."""
    from .workflows.exploit_dataset import build_dataset, render_dataset
    bins = list(getattr(args, "binaries", None) or [])
    rep = build_dataset(binaries=bins or None, out_path=args.out,
                        include_templates=getattr(args, "include_templates", False),
                        config=config, on_step=lambda m: print("  " + m), lang=config.lang,
                        budget_s=float(getattr(args, "budget", 240) or 240))
    print("\n" + render_dataset(rep, config.lang))


def cmd_kb(args, config):
    from .rag import get_kb
    kb = get_kb()
    if getattr(args, "list", False) or not args.query:
        docs = sorted({c.doc for c in kb.chunks})
        print(f"knowledge base: {len(kb.chunks)} secciones en {len(docs)} cheat sheets\n")
        for d in docs:
            titles = [c.title for c in kb.chunks if c.doc == d]
            print(f"  {d:<16} {len(titles)} secciones")
        print("\nuso: binoracle kb \"<consulta>\"   (p.ej. \"double free tcache glibc 2.35\")")
        return
    query = " ".join(args.query)
    hits = kb.retrieve(query, k=args.k)
    if not hits:
        print(f"sin coincidencias para: {query}")
        return
    print(f"# RAG: top {len(hits)} para \"{query}\"\n")
    for c, score in hits:
        print(f"## [{c.doc} / {c.title}]  (score {score:.3f})")
        print(c.text.strip())
        print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="binoracle",
                                description="Local, oracle-grounded LLM copilot for binary RE and exploitation.")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="show oracle + LLM availability")
    d.add_argument("binary", nargs="?", help="optional target to probe")
    d.set_defaults(func=cmd_doctor)

    cp = sub.add_parser("cveplan", help="exploitation schema from a CVE/vulnerability description")
    cp.add_argument("text", help="CVE id or vulnerability description text")
    cp.add_argument("--binary", help="binary to concretize the plan (real offset/gadgets) + verify")
    cp.add_argument("--cve", default="", help="CVE id label for the plan")
    cp.add_argument("--no-verify", action="store_true", help="do not run the sandbox verification")
    cp.add_argument("--out", help="write the developed pwntools exploit script to this file (executable)")
    cp.add_argument("--json", action="store_true", help="emit the plan as one JSON line (for tooling)")
    cp.set_defaults(func=cmd_cveplan)

    t = sub.add_parser("triage", help="grounded facts + mitigations (no model needed)")
    t.add_argument("binary")
    t.add_argument("--explain", action="store_true", help="add a local-LLM narrative")
    t.add_argument("-o", "--output", help="also write markdown here")
    t.add_argument("--html", help="also write an interactive HTML report here")
    t.set_defaults(func=cmd_triage)

    h = sub.add_parser("hunt", help="find + verify vulnerabilities")
    h.add_argument("binary")
    h.add_argument("--dynamic", action="store_true", help="allow running the target under a debugger")
    h.add_argument("-o", "--output", help="also write markdown here")
    h.add_argument("--html", help="also write an interactive HTML report here")
    h.add_argument("--json", help="also write findings as JSON (for CI)")
    h.add_argument("--no-verify", action="store_true", help="skip the automatic angr verification pass")
    h.set_defaults(func=cmd_hunt)

    a = sub.add_parser("ask", help="ask a grounded question about the binary")
    a.add_argument("binary")
    a.add_argument("question")
    a.add_argument("--dynamic", action="store_true")
    a.add_argument("-o", "--output")
    a.add_argument("--html", help="also write an interactive HTML report here")
    a.set_defaults(func=cmd_ask)

    c = sub.add_parser("chat", help="interactive grounded REPL")
    c.add_argument("binary")
    c.add_argument("--dynamic", action="store_true")
    c.set_defaults(func=cmd_chat)

    r = sub.add_parser("report", help="write full markdown report from stored session")
    r.add_argument("binary")
    r.add_argument("-o", "--output")
    r.set_defaults(func=cmd_report)
    pr = sub.add_parser("primitives", help="reason about the likely exploitation primitive")
    pr.add_argument("binary")
    pr.add_argument("--dynamic", action="store_true")
    pr.add_argument("-o", "--output")
    pr.add_argument("--html", help="also write an interactive HTML report here")
    pr.set_defaults(func=cmd_primitives)

    g = sub.add_parser("gadgets", help="search ROP gadgets")
    g.add_argument("binary")
    g.add_argument("-f", "--filter", help="substring/regex, e.g. 'pop rdi'")
    g.set_defaults(func=cmd_gadgets)

    cy = sub.add_parser("cyclic", help="De Bruijn pattern generate / offset find")
    cy.add_argument("binary", nargs="?", help="optional (not needed)")
    cy.add_argument("-n", "--length", type=int, default=200, help="pattern length")
    cy.add_argument("--find", help="value that overwrote RIP/reg (0x-hex, int, or 4 chars)")
    cy.set_defaults(func=cmd_cyclic)

    sk = sub.add_parser("exploit-skeleton", help="generate a pwntools skeleton for an authorized target")
    sk.add_argument("binary")
    sk.add_argument("--offset", type=int, help="known offset to return address")
    sk.add_argument("--primitive", default="auto")
    sk.add_argument("-o", "--output")
    sk.set_defaults(func=cmd_skeleton)

    ex = sub.add_parser("explain", help="explain a function, grounded in its disassembly")
    ex.add_argument("binary")
    ex.add_argument("function", help="function name or address, e.g. sym.main")
    ex.add_argument("-o", "--output")
    ex.set_defaults(func=cmd_explain)

    df = sub.add_parser("diff", help="patch-diff two binaries (n-day analysis)")
    df.add_argument("old")
    df.add_argument("new")
    df.add_argument("-o", "--output")
    df.set_defaults(func=cmd_diff)

    vf = sub.add_parser("verify", help="deterministically verify reachability with angr")
    vf.add_argument("binary")
    vf.add_argument("--reach", help="prove a specific address is reachable, e.g. 0x401176")
    vf.set_defaults(func=cmd_verify)

    v = sub.add_parser("view", help="build an interactive HTML report and open it in the browser")
    v.add_argument("binary")
    v.add_argument("-o", "--output", help="HTML output path (default binoracle_report.html)")
    v.add_argument("--no-open", action="store_true", help="do not auto-open the browser")
    v.set_defaults(func=cmd_view)

    rp2 = sub.add_parser("rop", help="build a ROP chain (ret2libc / execve) with pwntools")
    rp2.add_argument("binary")
    rp2.add_argument("--goal", default="auto", choices=["auto", "system", "execve", "ret2libc", "syscall"])
    rp2.add_argument("--libc", help="path to libc.so.6 for ret2libc")
    rp2.set_defaults(func=cmd_rop)

    sc = sub.add_parser("shellcode", help="generate shellcode (execve /bin/sh, cat) with pwntools")
    sc.add_argument("binary", nargs="?", help="optional target (reads NX to warn you)")
    sc.add_argument("--arch", default="amd64", help="amd64|i386|aarch64|arm|mips")
    sc.add_argument("--kind", default="sh", choices=["sh", "cat", "execve"])
    sc.add_argument("--arg", help="argument for cat/execve, e.g. /flag")
    sc.set_defaults(func=cmd_shellcode)

    fz = sub.add_parser("fuzz", help="generate a fuzzing harness (libfuzzer) or afl command")
    fz.add_argument("binary")
    fz.add_argument("--mode", default="afl", choices=["afl", "libfuzzer"])
    fz.add_argument("--func", help="target function for the libfuzzer harness")
    fz.set_defaults(func=cmd_fuzz)

    fs = sub.add_parser("fmtstring", help="format-string leak/write helper (infoleak)")
    fs.add_argument("binary", nargs="?")
    fs.add_argument("--offset", type=int, help="known printf arg offset")
    fs.add_argument("--addr", help="target address for a write (e.g. GOT entry)")
    fs.add_argument("--value", help="value to write")
    fs.set_defaults(func=cmd_fmtstring)

    an = sub.add_parser("analyze", help="one-shot: give a .c source or a binary, get the full report")
    an.add_argument("file", help="path to a .c/.cpp source or a compiled binary")
    an.add_argument("-o", "--output", help="HTML output path")
    an.add_argument("--no-open", action="store_true")
    an.set_defaults(func=cmd_analyze)

    sv = sub.add_parser("serve", help="launch the local web interface (dashboard)")
    sv.add_argument("--host", default="127.0.0.1", help="bind host (localhost only by default)")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--no-open", action="store_true", help="do not auto-open the browser")
    sv.set_defaults(func=cmd_serve)

    mc = sub.add_parser("mcp", help="run the binoracle MCP server (stdio) so any agent can drive its tools")
    mc.set_defaults(func=cmd_mcp)

    ap = sub.add_parser("autopoc", help="auto-generate + verify a ret2win exploit in a sandbox")
    ap.add_argument("binary")
    ap.add_argument("--offset", type=int, help="offset to return address (else angr finds it)")
    ap.add_argument("--no-run", action="store_true", help="build the exploit but do not run it")
    ap.add_argument("-o", "--output")
    ap.set_defaults(func=cmd_autopoc)

    aw = sub.add_parser("autopwn", help="autonomously try exploitation combinations and verify")
    aw.add_argument("binary")
    aw.add_argument("--no-run", action="store_true", help="do not run PoCs in the sandbox")
    aw.add_argument("-o", "--output")
    aw.add_argument("--json", help="also write results as JSON")
    aw.set_defaults(func=cmd_autopwn)

    au = sub.add_parser("audit", help="let the local LLM autonomously audit AND exploit the binary")
    au.add_argument("binary")
    au.add_argument("-o", "--output")
    au.add_argument("--html", help="also write an interactive HTML report here")
    au.add_argument("--json", help="also write findings as JSON")
    au.add_argument("--sarif", help="also write findings as SARIF 2.1.0 (code-scanning/CI)")
    au.set_defaults(func=cmd_audit)

    rg = sub.add_parser("regress", help="compare two builds for security regressions")
    rg.add_argument("old"); rg.add_argument("new")
    rg.add_argument("-o", "--output")
    rg.set_defaults(func=cmd_regress)

    tl = sub.add_parser("tools", help="detect the installed binary-pentest toolchain")
    tl.set_defaults(func=cmd_tools)

    rg2 = sub.add_parser("rag", help="show or toggle the RAG retrieval layers (status/sources)")
    rg2.add_argument("--embed", choices=["on", "off"], help="force semantic embeddings")
    rg2.add_argument("--expand", choices=["on", "off"], help="force LLM query expansion")
    rg2.add_argument("--rerank", choices=["on", "off"], help="force LLM rerank")
    rg2.set_defaults(func=cmd_rag)

    kbp = sub.add_parser("kb", help="query the local exploitation knowledge base (RAG)")
    kbp.add_argument("query", nargs="*", help="what to look up (empty = list cheat sheets)")
    kbp.add_argument("-k", type=int, default=4, help="number of snippets to return")
    kbp.add_argument("--list", action="store_true", help="list available cheat sheets")
    kbp.set_defaults(func=cmd_kb)

    lp = sub.add_parser("learn", help="aprende de una carpeta de skills/docs: filtra binario-RE, "
                                      "descarta web/routers, y lo mete en el conocimiento")
    lp.add_argument("path", help="carpeta con material (.md) a aprender")
    lp.add_argument("--name", help="nombre del corpus en kb/skills (por defecto, el de la carpeta)")
    lp.add_argument("--apply", action="store_true", help="aplica (por defecto es dry-run)")
    lp.set_defaults(func=cmd_learn)

    hp = sub.add_parser("heap", help="confirm heap corruption (double-free/overflow) by execution")
    hp.add_argument("binary")
    hp.set_defaults(func=cmd_heap)

    tp = sub.add_parser("train", help="training agent: develop+verify exploits on a corpus and "
                                      "curate what works, raising the skill measurably")
    tp.add_argument("binaries", nargs="*", help="binaries to train on (default: repo sample corpus)")
    tp.add_argument("--no-verify", action="store_true", help="skip sandbox verification (faster)")
    tp.add_argument("--budget", type=float, default=240,
                    help="per-binary time budget in seconds (skip if exceeded; default 240)")
    tp.add_argument("--export-playbook", nargs="?", const="", default=None, metavar="PATH",
                    help="write a curated RAG playbook of the VERIFIED techniques (default path: "
                         "binoracle/kb/verified-playbook.md) so the learned knowledge ships")
    tp.set_defaults(func=cmd_train)

    dp = sub.add_parser("dataset", help="build the SFT JSONL to fine-tune an LLM to develop exploits "
                                        "(pairs vuln+mitigations -> verified pwntools exploit)")
    dp.add_argument("binaries", nargs="*", help="binaries (default: repo sample corpus)")
    dp.add_argument("--out", default="exploit_sft.jsonl", help="output JSONL path")
    dp.add_argument("--include-templates", action="store_true",
                    help="also include developed (unverified) templates, not just verified exploits")
    dp.add_argument("--budget", type=float, default=240,
                    help="per-binary time budget in seconds (skip if exceeded; default 240)")
    dp.set_defaults(func=cmd_dataset)

    afp = sub.add_parser("autofuzz", help="discover the crashing input (trigger) dynamically: fuzz "
                                          "stdin/argv/format-string in the sandbox, report vector+class")
    afp.add_argument("binary")
    afp.set_defaults(func=cmd_autofuzz)

    fp = sub.add_parser("fetch", help="extract a real binary from a Docker image (get the vulnerable "
                                      "binary of a CVE); does NOT run the image entrypoint")
    fp.add_argument("image", help="Docker image, e.g. ubuntu:16.04 or debian:10")
    fp.add_argument("path", help="absolute path in the image (/usr/sbin/nscd) or a binary name (nscd)")
    fp.add_argument("--out", help="destination directory (default ./fetched)")
    fp.set_defaults(func=cmd_fetch)

    ip = sub.add_parser("investigate", help="LLM-driven exploitation research agent: from a CVE, "
                                            "reason + develop + (with --binary) verify in sandbox")
    ip.add_argument("cve", help="CVE id (e.g. CVE-2024-33599) or vulnerability description")
    ip.add_argument("--binary", help="vulnerable binary to actually try + verify against")
    ip.add_argument("--budget", type=float, default=300,
                    help="sandbox verification budget in seconds (default 300)")
    ip.set_defaults(func=cmd_investigate)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    return args.func(args, config)


if __name__ == "__main__":
    main()
