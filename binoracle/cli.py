"""binoracle command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# REGRESION encontrada en vivo (`binoracle investigate ... --method POST` perdia "POST" de
# sys.argv): pwntools escanea y MUTA sys.argv al importarse (busca sus propios flags de
# log-level/terminal), y los imports de abajo (p.ej. .workflows.rop) tiran de pwntools a nivel
# de MODULO. El entry point instalado (`binoracle = "binoracle.cli:main"`, ver pyproject.toml)
# hace `from binoracle.cli import main` antes de llamar a main() -- para cuando main() lee
# sys.argv, ya esta mutado. Se captura ANTES de que ese import chain corra (primera linea
# ejecutable del modulo, antes de cualquier `from .workflows...`), y main() lo usa por defecto
# en vez de releer sys.argv. Protege tanto el entry point instalado como `python -m binoracle`.
_ARGV = sys.argv[1:]

from . import colorlog
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
from .workflows.autofuzz_afl import autofuzz_afl, render_autofuzz_afl
from .workflows.fmtstring import fmtstring_help
from .workflows.autopoc import autopoc, render_poc
from .workflows.autopwn import autopwn, render_autopwn
from .workflows.audit import run_audit
from .workflows.regress import run_regress, render_regress, autoregress_test, render_regression_tests
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
    has_poc = getattr(args, "has_public_exploit", False)
    poc_url = getattr(args, "poc_url", "") or ""
    if getattr(args, "binary", None):
        # concreta el esquema con el binario (offset/gadgets reales) y verifica en sandbox
        pl = plan_for_binary(args.binary, text=args.text, cve=getattr(args, "cve", ""),
                             lang=config.lang, verify=not getattr(args, "no_verify", False),
                             has_public_exploit=has_poc, poc_ref_url=poc_url)
    else:
        pl = plan(args.text, {}, cve=getattr(args, "cve", ""), lang=config.lang,
                 has_public_exploit=has_poc, poc_ref_url=poc_url)
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
        _dc._llm_ready() if inst else False
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


def cmd_arsenal(args, config):
    from .workflows.chainanalyzer import analyze_arsenal, render_arsenal
    binary = _require_binary(args.binary)
    out = render_arsenal(analyze_arsenal(binary, None, lang="es"), lang="es")
    print(out)
    _write_if(args.output, out)


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
    if getattr(args, "run", False):
        r = autofuzz_afl(binary, source=args.source, budget_s=args.budget_s)
        print(render_autofuzz_afl(r))
        return
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


def cmd_go(args, config):
    from .workflows.goinspect import inspect_go, render_go
    binary = _require_binary(args.binary)
    out = render_go(inspect_go(binary))
    print(out)
    _write_if(args.output, out)


def cmd_rust(args, config):
    from .workflows.rustinspect import inspect_rust, render_rust
    binary = _require_binary(args.binary)
    out = render_rust(inspect_rust(binary))
    print(out)
    _write_if(args.output, out)


def cmd_rawshellcode(args, config):
    from .workflows.rawshellcode import analyze_raw_shellcode, render_raw_shellcode
    path = _require_binary(args.path)
    with open(path, "rb") as f:
        data = f.read()
    out = render_raw_shellcode(analyze_raw_shellcode(data))
    print(out)
    _write_if(args.output, out)


def cmd_core(args, config):
    import os
    from .workflows.coredump import inspect_core, render_core
    if not os.path.exists(args.core):
        _eprint(f"core no encontrado: {args.core}")
        sys.exit(2)
    out = render_core(inspect_core(args.core))
    print(out)
    _write_if(args.output, out)


def cmd_elf(args, config):
    from .workflows.elflayout import inspect_elf, render_elf
    binary = _require_binary(args.binary)
    out = render_elf(inspect_elf(binary))
    print(out)
    _write_if(args.output, out)


def cmd_wasm(args, config):
    from .workflows.wasminspect import inspect_wasm, render_wasm
    binary = _require_binary(args.binary)
    out = render_wasm(inspect_wasm(binary))
    print(out)
    _write_if(args.output, out)


def cmd_sqlite(args, config):
    from .workflows.sqliteinspect import inspect_sqlite, render_sqlite
    binary = _require_binary(args.binary)
    out = render_sqlite(inspect_sqlite(binary))
    print(out)
    _write_if(args.output, out)


def cmd_evm(args, config):
    from .workflows.evminspect import inspect_evm, render_evm
    binary = _require_binary(args.binary)
    out = render_evm(inspect_evm(binary))
    print(out)
    _write_if(args.output, out)


def cmd_har(args, config):
    from .workflows.harinspect import inspect_har, render_har
    binary = _require_binary(args.binary)
    out = render_har(inspect_har(binary))
    print(out)
    _write_if(args.output, out)


def cmd_java(args, config):
    from .workflows.jarinspect import inspect_jar, render_jar
    binary = _require_binary(args.binary)
    out = render_jar(inspect_jar(binary))
    print(out)
    _write_if(args.output, out)


def cmd_secrets(args, config):
    from .workflows.iocscan import scan_iocs, render_iocs
    binary = _require_binary(args.binary)
    out = render_iocs(scan_iocs(binary))
    print(out)
    _write_if(args.output, out)


def cmd_asar(args, config):
    from .workflows.asarinspect import inspect_asar, render_asar
    binary = _require_binary(args.binary)
    out = render_asar(inspect_asar(binary))
    print(out)
    _write_if(args.output, out)


def cmd_plist(args, config):
    from .workflows.plistinspect import inspect_plist, render_plist
    binary = _require_binary(args.binary)
    out = render_plist(inspect_plist(binary))
    print(out)
    _write_if(args.output, out)


def cmd_dotnet(args, config):
    from .workflows.dotnetinspect import inspect_dotnet, render_dotnet
    binary = _require_binary(args.binary)
    out = render_dotnet(inspect_dotnet(binary))
    print(out)
    _write_if(args.output, out)


def cmd_macho(args, config):
    from .workflows.machoinspect import inspect_macho, render_macho
    binary = _require_binary(args.binary)
    out = render_macho(inspect_macho(binary))
    print(out)
    _write_if(args.output, out)


def cmd_apk(args, config):
    from .workflows.apkinspect import inspect_apk, render_apk
    binary = _require_binary(args.binary)
    out = render_apk(inspect_apk(binary))
    print(out)
    _write_if(args.output, out)


def cmd_pe(args, config):
    from .workflows.peinspect import inspect_pe, render_pe
    binary = _require_binary(args.binary)
    out = render_pe(inspect_pe(binary))
    print(out)
    _write_if(args.output, out)


def cmd_jeb(args, config):
    from .workflows.jebconnect import jeb_list_tools, jeb_call, render_jeb
    if args.call:
        import json as _json
        arguments = _json.loads(args.arguments) if args.arguments else {}
        r = jeb_call(args.call, arguments, url=args.url)
    else:
        r = jeb_list_tools(url=args.url)
    out = render_jeb(r)
    print(out)
    _write_if(args.output, out)


def cmd_js(args, config):
    from .workflows.jsinspect import inspect_js, render_js
    target = args.binary
    import os as _os
    if not _os.path.exists(target):
        _eprint(f"error: no existe {target}"); sys.exit(2)
    out = render_js(inspect_js(target))
    print(out)
    _write_if(args.output, out)


def cmd_dynamic(args, config):
    from .workflows import dynamic as dyn
    k = args.kind
    if k == "adb-devices":
        r = dyn.adb_devices()
    elif k == "adb-packages":
        r = dyn.adb_packages(serial=args.serial)
    elif k == "adb-processes":
        r = dyn.adb_processes(serial=args.serial)
    elif k == "adb-logcat":
        r = dyn.adb_logcat(serial=args.serial, lines=args.lines or 200)
    elif k == "adb-getprop":
        r = dyn.adb_getprop(serial=args.serial)
    elif k == "adb-apk-path":
        r = dyn.adb_apk_path(args.target or "", serial=args.serial)
    elif k == "frida-devices":
        r = dyn.frida_devices()
    elif k == "frida-ps":
        r = dyn.frida_processes()
    elif k == "browser":
        r = dyn.browser_observe(args.target or "", screenshot=args.screenshot)
    else:
        _eprint(f"error: kind desconocido {k}"); sys.exit(2)
    out = dyn.render_dynamic(k, r)
    print(out)
    _write_if(args.output, out)


def cmd_caller_tool(args, config):
    from .workflows import callertools as ct
    binary = _require_binary(args.binary)
    fn = {"wat": ct.wat_disassemble, "pcap": ct.pcap_summary, "firmware": ct.firmware_scan,
          "one_gadget": ct.one_gadget, "capinfos": ct.pcap_fileinfo,
          "manifest": ct.apktool_manifest, "jadx": ct.jadx_decompile,
          "ghidra": ct.ghidra_decompile}[args.kind]
    out = ct.render_caller(args.kind, fn(binary))
    print(out)
    _write_if(args.output, out)


def cmd_identify(args, config):
    from .workflows.identify import identify, render_identify
    binary = _require_binary(args.binary)
    out = render_identify(identify(binary))
    print(out)
    _write_if(args.output, out)


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


def cmd_runs(args, config):
    from .store.runs import list_targets, list_runs, diff_latest_two, render_run_diff, render_targets
    if not getattr(args, "target", None):
        out = render_targets(list_targets(config.db_path()))
    elif getattr(args, "diff", False):
        out = render_run_diff(diff_latest_two(config.db_path(), args.target))
    else:
        runs = list_runs(config.db_path(), args.target)
        import time as _time
        out = "\n".join([f"## Runs para `{args.target}`\n"] +
                        (["Sin runs registradas para este target."] if not runs else
                         [f"- run #{r['run_id']}: {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(r['ts']))} -- "
                          f"{r['n_findings']} hallazgo(s)" for r in runs]))
    print(out)
    _write_if(args.output, out)


def cmd_ci_gate(args, config):
    old = _require_binary(args.old); new = _require_binary(args.new)
    from .workflows.ci_gate import run_ci_gate, render_ci_gate
    r = run_ci_gate(old, new, config, gen_test=getattr(args, "gen_test", False))
    out = render_ci_gate(r)
    print(out)
    _write_if(args.output, out)
    if not r.ok:
        sys.exit(2)       # el pipeline grounded no pudo correr -- no es un veredicto, es un error
    sys.exit(0 if r.passed else 1)


def cmd_regress(args, config):
    old = _require_binary(args.old); new = _require_binary(args.new)
    res = run_regress(old, new, config)
    out = render_regress(res)
    if getattr(args, "gen_test", False):
        # mas lento (corre autopwn de verdad en OLD y re-intenta cada tecnica verificada en
        # NEW) -- opt-in, no en cada "regress" por defecto.
        tests = autoregress_test(old, new, config=config)
        out += "\n\n" + render_regression_tests(old, new, tests)
    print(out)
    _write_if(args.output, out)


def cmd_funcid(args, config):
    stripped = _require_binary(args.stripped)
    reference = _require_binary(args.reference)
    from .workflows.funcid import identify_stripped_functions, render_funcid
    res = identify_stripped_functions(stripped, reference, min_similarity=args.min_similarity)
    out = render_funcid(res)
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
    verificado y lo bloqueado. Para una CVE WEB, --source/--cms/--version/--endpoint/--method/--params
    dejan aportar lo que YA sabes del aviso oficial (el slug/endpoint reales) en vez de depender de
    que el LLM los adivine; con --source + --endpoint apuntando a un plugin de WordPress o un modulo
    de Drupal vulnerable a missing-authorization/IDOR, intenta ademas la VERIFICACION DINAMICA
    (WordPress+MySQL o Drupal+MySQL efimeros en Docker, ver wpverify.py/drupalverify.py)."""
    from .workflows.cve_agent import investigate_cve, render_investigation
    hints = {}
    if getattr(args, "vuln_class", None):
        hints["vuln_class"] = args.vuln_class
    if getattr(args, "source", None):
        hints["source_url"] = args.source
    if getattr(args, "cms", None):
        hints["cms"] = args.cms
    if getattr(args, "version", None):
        hints["affected_version"] = args.version
    if getattr(args, "endpoint", None):
        hints["endpoint"] = args.endpoint
    if getattr(args, "method", None):
        hints["http_method"] = args.method
    if getattr(args, "params", None):
        hints["parameters"] = [p.strip() for p in args.params.split(",") if p.strip()]
    if getattr(args, "sqli_param", None):
        hints["sqli_param"] = args.sqli_param
    if getattr(args, "keep_lab_on_failure", False):
        hints["keep_lab_on_failure"] = True
    if getattr(args, "functions", None):
        hints["vulnerable_functions"] = [f.strip() for f in args.functions.split(",") if f.strip()]
    if getattr(args, "table_name", None):
        hints["table_name"] = args.table_name
    if getattr(args, "column_name", None):
        hints["column_name"] = args.column_name
    if getattr(args, "id_column", None):
        hints["id_column"] = args.id_column
    if getattr(args, "burp_mcp_url", None):
        from .workflows.burpmcp import BurpMCPError
        from .workflows.genericverify import configure_burp_mcp
        try:
            configure_burp_mcp(args.burp_mcp_url)
            colorlog.ok(f"conectado al servidor MCP de Burp en {args.burp_mcp_url} -- las "
                       f"peticiones de los verificadores genericos pasaran por Burp")
        except BurpMCPError as e:
            colorlog.warn(f"no se pudo conectar a Burp ({e}) -- se sigue sin Burp, peticiones "
                         f"directas", file=sys.stderr)
    inv = investigate_cve(args.cve, binary=getattr(args, "binary", "") or "",
                          config=config, on_step=lambda m: colorlog.line(m), lang=config.lang,
                          budget_s=float(getattr(args, "budget", 300) or 300), hints=hints or None,
                          use_cache=not getattr(args, "no_cache", False))
    # el terminal no puede pintar imagenes: embed_images=False cambia cada captura por un aviso
    # corto en vez de volcar decenas de KB de base64 como texto ilegible. El export HTML (abajo)
    # SI usa embed_images=True (el default), esas son las que de verdad se pintan como <img>.
    print("\n" + render_investigation(inv, config.lang, embed_images=False))
    if getattr(args, "html", None):
        from .report.html import render_investigation_page
        md_full = render_investigation(inv, config.lang)
        Path(args.html).write_text(
            render_investigation_page(md_full, script=inv.developed_script, cve=args.cve,
                                      lang=config.lang, poc_kind=inv.poc_kind))
        _eprint(f"(HTML written to {args.html})")
    if getattr(args, "json", None):
        # el markdown/HTML SIEMPRE recorta los cuerpos de respuesta reales a unos cientos de
        # caracteres (para que el informe sea legible) -- confirmado en vivo multiples veces hoy
        # mismo: diagnosticar un negativo (CVE-2024-3552) exigio pedir comandos `grep` a mano
        # dentro del contenedor porque la evidencia COMPLETA (listas enteras de intentos, cuerpos
        # de respuesta sin recortar) nunca llegaba a salir del objeto Investigation. asdict()
        # vuelca TODO tal cual esta, sin que render_investigation decida que mostrar y que omitir.
        from dataclasses import asdict as _asdict
        Path(args.json).write_text(json.dumps(_asdict(inv), indent=2, ensure_ascii=False))
        _eprint(f"(full evidence JSON written to {args.json})")


def _connect_shared_burp_mcp(args, context_note: str) -> None:
    """Conecta una vez al MCP de Burp (si --burp-mcp-url se dio), compartido por TODAS las
    investigaciones que vengan despues en el mismo proceso -- usado tanto por investigate-batch
    (un lote fijo) como por investigate-watch (lotes sucesivos a medida que llegan CVEs nuevas
    del canal vigilado)."""
    if not getattr(args, "burp_mcp_url", None):
        return
    from .workflows.burpmcp import BurpMCPError
    from .workflows.genericverify import configure_burp_mcp
    try:
        configure_burp_mcp(args.burp_mcp_url)
        colorlog.ok(f"conectado al servidor MCP de Burp en {args.burp_mcp_url} -- compartido "
                   f"por {context_note}")
    except BurpMCPError as e:
        colorlog.warn(f"no se pudo conectar a Burp ({e}) -- se sigue sin Burp, peticiones "
                     f"directas", file=sys.stderr)


def _run_investigate_batch_and_report(cve_ids, config, parallel: int, budget_s: float,
                                      out_dir: Path, html_dir, use_cache: bool):
    """Nucleo compartido de investigate-batch e investigate-watch: lanza investigate_cves_batch
    sobre `cve_ids`, escribe un informe por CVE en `out_dir` (y en `html_dir` si se da), imprime
    el progreso en vivo y la tabla resumen al final. Devuelve los BatchItem resultantes."""
    from .workflows.cve_agent import (investigate_cves_batch, render_batch_summary,
                                      render_investigation)

    colorlog.info(f"lanzando {len(cve_ids)} investigaciones con paralelismo {parallel}...")

    def on_event(ev):
        cve_id = ev["cve_id"]
        if ev["type"] == "start":
            colorlog.info(f"[{cve_id}] iniciando...")
        elif ev["type"] == "step":
            colorlog.line(f"[{cve_id}] {ev['message']}")
        elif ev["type"] == "finish":
            if ev["status"] == "error":
                colorlog.error(f"[{cve_id}] ERROR ({ev['elapsed_s']:.0f}s): {ev['error']}")
            else:
                colorlog.ok(f"[{cve_id}] terminado ({ev['elapsed_s']:.0f}s)")

    items = investigate_cves_batch(
        cve_ids, config=config, lang=config.lang, budget_s=budget_s, parallel=parallel,
        on_event=on_event, use_cache=use_cache)

    for it in items:
        if it.investigation is None:
            continue
        md = render_investigation(it.investigation, config.lang, embed_images=False)
        (out_dir / f"{it.cve_id}.md").write_text(md)
        # evidencia COMPLETA (sin recortar) junto al markdown -- mismo motivo que --json en
        # 'investigate': el informe renderizado siempre trunca los cuerpos de respuesta reales,
        # y en un lote no hay forma de pedir --json por CVE individualmente.
        from dataclasses import asdict as _asdict
        (out_dir / f"{it.cve_id}.json").write_text(
            json.dumps(_asdict(it.investigation), indent=2, ensure_ascii=False))
        if html_dir:
            from .report.html import render_investigation_page
            md_full = render_investigation(it.investigation, config.lang)
            (html_dir / f"{it.cve_id}.html").write_text(
                render_investigation_page(md_full, script=it.investigation.developed_script,
                                          cve=it.cve_id, lang=config.lang,
                                          poc_kind=it.investigation.poc_kind))

    print("\n" + render_batch_summary(items, config.lang))
    colorlog.info(f"informes individuales en {out_dir}/" +
                 (f" y HTML en {html_dir}/" if html_dir else ""))
    return items


def cmd_investigate_batch(args, config):
    """Lanza varias investigaciones de CVE EN PARALELO (ver investigate_cves_batch en
    cve_agent.py), con un tope de concurrencia (--parallel) -- pensado para explorar varias CVEs
    sin tener que abrir una terminal por cada una. Cada CVE es independiente: una fallando no
    tumba el lote. Cada informe se escribe a --out-dir/<CVE-ID>.md (y .html en --html-dir si se
    da), y al final se imprime una tabla resumen de todo el lote."""
    _connect_shared_burp_mcp(args, "todas las investigaciones del lote")
    out_dir = Path(getattr(args, "out_dir", None) or "./binoracle_batch_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    html_dir = Path(args.html_dir) if getattr(args, "html_dir", None) else None
    if html_dir:
        html_dir.mkdir(parents=True, exist_ok=True)
    parallel = int(getattr(args, "parallel", 2) or 2)
    _run_investigate_batch_and_report(
        args.cves, config, parallel, float(getattr(args, "budget", 300) or 300), out_dir,
        html_dir, not getattr(args, "no_cache", False))


def cmd_investigate_watch(args, config):
    """Vigila un canal publico de Telegram que notifica CVEs nuevas en cuanto se publican (por
    defecto @CVENotify, ver cvefeed.py) y, cada vez que aparece una mencion nueva, lanza
    automaticamente el MISMO pipeline completo que investigate-batch sobre ella: codigo real
    descargado, laboratorio Docker efimero, verificacion dinamica, capturas -- pensado para que
    el desarrollo/verificacion de exploits arranque solo en cuanto se publica una CVE nueva, sin
    tener que estar mirando el canal a mano.

    Por defecto es GENERICO: procesa cualquier CVE que el canal mencione, de cualquier
    tecnologia, no solo CMS -- investigate_cve() siempre desarrolla una hipotesis + PoC aunque
    la clase no tenga verificacion dinamica automatica hoy (eso solo existe hoy para
    missing-authorization/IDOR, SQLi, XXE, path-traversal y deserializacion en WordPress/
    Drupal/Joomla, ver wpverify.py/drupalverify.py/joomlaverify.py), y ese desarrollo de exploit
    es exactamente el objetivo de este comando. --cms-only activa el filtro inverso (solo
    procesar las que tengan pinta de CMS), para cuando se quiere priorizar las que SI pueden
    llegar a VERIFICADO de principio a fin y no gastar tiempo/Docker en el resto."""
    import time
    from .workflows.cvefeed import poll_new_cve_mentions

    _connect_shared_burp_mcp(args, "todas las investigaciones que lance este watch")
    out_dir = Path(getattr(args, "out_dir", None) or "./binoracle_batch_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    html_dir = Path(args.html_dir) if getattr(args, "html_dir", None) else None
    if html_dir:
        html_dir.mkdir(parents=True, exist_ok=True)
    parallel = int(getattr(args, "parallel", 2) or 2)
    budget_s = float(getattr(args, "budget", 300) or 300)
    use_cache = not getattr(args, "no_cache", False)
    channel = getattr(args, "channel", None) or "CVENotify"
    interval = float(getattr(args, "interval", 300) or 300)
    cms_only = bool(getattr(args, "cms_only", False))

    colorlog.info(f"vigilando el canal de Telegram @{channel} (sondeo cada {interval:.0f}s" +
                 (", solo las de pinta CMS" if cms_only else ", TODAS las CVEs (generico)") +
                 ", Ctrl+C para parar)...")
    first_cycle = True
    while True:
        try:
            mentions = poll_new_cve_mentions(channel)
        except Exception as e:
            colorlog.error(f"fallo sondeando @{channel} ({e}) -- se reintenta en el siguiente "
                          f"ciclo", file=sys.stderr)
            mentions = []

        if cms_only and mentions:
            skipped = [m for m in mentions if not m.cms_related]
            mentions = [m for m in mentions if m.cms_related]
            if skipped:
                colorlog.warn(f"{len(skipped)} CVE(s) nueva(s) ignorada(s) (--cms-only activo, "
                             f"sin pinta de CMS): " + ", ".join(m.cve_id for m in skipped))

        if mentions:
            colorlog.ok(f"{len(mentions)} CVE(s) nueva(s) en @{channel}: " +
                       ", ".join(m.cve_id for m in mentions))
            _run_investigate_batch_and_report(
                [m.cve_id for m in mentions], config, parallel, budget_s, out_dir, html_dir,
                use_cache)
        elif not first_cycle:
            colorlog.info(f"sin novedades relevantes en @{channel}")
        first_cycle = False

        if getattr(args, "once", False):
            return
        time.sleep(interval)


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
    p.add_argument("--debug", action="store_true",
                  help="on an unexpected error, show the full Python traceback instead of a "
                       "one-line summary (useful for reporting a bug)")
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
    cp.add_argument("--has-public-exploit", action="store_true",
                    help="this CVE already has a documented public exploit -- prepend a notice "
                         "pointing to it instead of presenting the generic per-class template "
                         "as if it were this CVE's actual technique")
    cp.add_argument("--poc-url", default="", help="URL of the known public exploit (with --has-public-exploit)")
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

    ar2 = sub.add_parser("arsenal", help="ROP arsenal: best gadget per arg reg, syscall, pivot, write, ret2csu, one_gadget")
    ar2.add_argument("binary", help="path to the ELF")
    ar2.add_argument("-o", "--output")
    ar2.set_defaults(func=cmd_arsenal)

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
    fz.add_argument("--run", action="store_true",
                    help="actually BUILD and DRIVE afl-fuzz (coverage-guided) instead of just "
                         "printing a template, and feed any crash found back into "
                         "dbg_run_input for confirmation")
    fz.add_argument("--source", help="C source to auto-build with afl-clang-fast (with --run); "
                                     "without it, falls back to QEMU/black-box mode")
    fz.add_argument("--budget-s", type=int, default=60, dest="budget_s",
                    help="afl-fuzz time budget in seconds (with --run)")
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

    go = sub.add_parser("go", help="read a Go binary's build info (version, modules, build settings) statically")
    go.add_argument("binary")
    go.add_argument("-o", "--output")
    go.set_defaults(func=cmd_go)

    ru = sub.add_parser("rust", help="Rust binary heuristics: rustc commit, Cargo dependency crates, mangled symbols")
    ru.add_argument("binary")
    ru.add_argument("-o", "--output")
    ru.set_defaults(func=cmd_rust)

    rs = sub.add_parser("rawshellcode", help="disassemble a raw shellcode blob (no ELF/PE container), ranking candidate architectures")
    rs.add_argument("path")
    rs.add_argument("-o", "--output")
    rs.set_defaults(func=cmd_rawshellcode)

    co = sub.add_parser("core", help="inspect an ELF core dump: signal, per-thread registers, mappings")
    co.add_argument("core", help="path to the core dump (ELF ET_CORE)")
    co.add_argument("-o", "--output")
    co.set_defaults(func=cmd_core)

    el = sub.add_parser("elf", help="offline ELF layout + static mitigation candidates (sections/segments/symbols)")
    el.add_argument("binary")
    el.add_argument("-o", "--output")
    el.set_defaults(func=cmd_elf)

    wa = sub.add_parser("wasm", help="inspect a WebAssembly module statically (sections, types, imports, exports)")
    wa.add_argument("binary", help="path to the .wasm module")
    wa.add_argument("-o", "--output")
    wa.set_defaults(func=cmd_wasm)

    sq = sub.add_parser("sqlite", help="inspect a SQLite database read-only (schema + bounded row sample)")
    sq.add_argument("binary", help="path to the .sqlite/.db file")
    sq.add_argument("-o", "--output")
    sq.set_defaults(func=cmd_sqlite)

    ev = sub.add_parser("evm", help="inspect EVM bytecode statically (selectors, opcodes, Solidity metadata)")
    ev.add_argument("binary", help="path to the EVM bytecode (raw or hex)")
    ev.add_argument("-o", "--output")
    ev.set_defaults(func=cmd_evm)

    hr = sub.add_parser("har", help="inspect a saved HAR network capture (requests, hosts, exposed secrets)")
    hr.add_argument("binary", help="path to the .har file")
    hr.add_argument("-o", "--output")
    hr.set_defaults(func=cmd_har)

    jv = sub.add_parser("java", help="inspect a Java JAR or .class statically (manifest, classes, framework, bytecode version)")
    jv.add_argument("binary", help="path to the .jar or .class")
    jv.add_argument("-o", "--output")
    jv.set_defaults(func=cmd_java)

    se = sub.add_parser("secrets", help="scan ANY artifact for embedded IOCs/secrets (URLs, creds, keys, high-entropy tokens)")
    se.add_argument("binary", help="path to any file")
    se.add_argument("-o", "--output")
    se.set_defaults(func=cmd_secrets)

    ar = sub.add_parser("asar", help="inspect an Electron ASAR archive statically (file tree, package.json, entry point)")
    ar.add_argument("binary", help="path to the .asar archive")
    ar.add_argument("-o", "--output")
    ar.set_defaults(func=cmd_asar)

    pl = sub.add_parser("plist", help="inspect an Apple property-list (Info.plist) statically (bundle id, usage keys, URL schemes)")
    pl.add_argument("binary", help="path to the .plist file (binary bplist00 or XML)")
    pl.add_argument("-o", "--output")
    pl.set_defaults(func=cmd_plist)

    dn = sub.add_parser("dotnet", help="inspect a .NET/CLI managed assembly statically (metadata, tables, names)")
    dn.add_argument("binary", help="path to the managed .dll/.exe")
    dn.add_argument("-o", "--output")
    dn.set_defaults(func=cmd_dotnet)

    mo = sub.add_parser("macho", help="inspect a Mach-O (macOS) statically (arch, segments, dylibs, mitigations)")
    mo.add_argument("binary", help="path to the Mach-O binary")
    mo.add_argument("-o", "--output")
    mo.set_defaults(func=cmd_macho)

    ak = sub.add_parser("apk", help="inspect an Android APK statically (DEX, native libs, framework, signing)")
    ak.add_argument("binary", help="path to the .apk file")
    ak.add_argument("-o", "--output")
    ak.set_defaults(func=cmd_apk)

    pei = sub.add_parser("pe", help="inspect a Windows PE statically (mitigations, sections, imports, capabilities)")
    pei.add_argument("binary", help="path to the .exe/.dll")
    pei.add_argument("-o", "--output")
    pei.set_defaults(func=cmd_pe)

    jb = sub.add_parser("jeb", help="connect to a caller-started JEB MCP server (external engine); list/call its tools")
    jb.add_argument("--url", help="JEB MCP endpoint (else $BINORACLE_JEB_MCP_URL)")
    jb.add_argument("--call", help="tool name to call (omit to list tools)")
    jb.add_argument("--arguments", help="JSON object of arguments for --call")
    jb.add_argument("-o", "--output")
    jb.set_defaults(func=cmd_jeb)

    jsp = sub.add_parser("js", help="inspect JavaScript/Electron statically (source maps, imports, IPC/Electron boundaries, native add-ons)")
    jsp.add_argument("binary", help="path to a .js, a .js.map, or an extracted app directory")
    jsp.add_argument("-o", "--output")
    jsp.set_defaults(func=cmd_js)

    dy = sub.add_parser("dynamic", help="RUNTIME analysis (separate from the static core): adb device / frida / live browser — authorized targets only, caller-supplied")
    dy.add_argument("kind", choices=["adb-devices", "adb-packages", "adb-processes", "adb-logcat",
                                     "adb-getprop", "adb-apk-path", "frida-devices", "frida-ps", "browser"])
    dy.add_argument("target", nargs="?", help="URL (browser) or package name (adb-apk-path)")
    dy.add_argument("-s", "--serial", help="adb device serial")
    dy.add_argument("--lines", type=int, help="adb-logcat: number of lines")
    dy.add_argument("--screenshot", help="browser: save a full-page screenshot to this path")
    dy.add_argument("-o", "--output")
    dy.set_defaults(func=cmd_dynamic)

    ct = sub.add_parser("caller-tool", help="optional caller-supplied integrations (wat/pcap/firmware); degrade if tool absent")
    ct.add_argument("kind", choices=["wat", "pcap", "firmware", "one_gadget", "capinfos", "manifest", "jadx", "ghidra"])
    ct.add_argument("binary", help="path to the artifact (.wasm / .pcap / firmware / libc / .apk / native binary)")
    ct.add_argument("-o", "--output")
    ct.set_defaults(func=cmd_caller_tool)

    idf = sub.add_parser("identify", help="detect any artifact's format and route it to the right reader")
    idf.add_argument("binary", help="path to any file")
    idf.add_argument("-o", "--output")
    idf.set_defaults(func=cmd_identify)

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
    rg.add_argument("--gen-test", action="store_true",
                    help="also generate+RUN a real regression test: re-run every autopwn "
                         "technique verified on OLD against NEW (slower; needs the sandbox)")
    rg.set_defaults(func=cmd_regress)

    rn = sub.add_parser("runs", help="regression dashboard: persistent run history per target, "
                        "diff-between-runs (new/fixed/reintroduced findings)")
    rn.add_argument("target", nargs="?", help="target path (omit to list all targets with run history)")
    rn.add_argument("--diff", action="store_true", help="diff the two latest runs for this target")
    rn.add_argument("-o", "--output")
    rn.set_defaults(func=cmd_runs)

    cg = sub.add_parser("ci-gate", help="CI gate for a GitHub Action: exit 0 (pass)/1 (fail) on "
                        "new verified findings or security regressions between OLD and NEW builds")
    cg.add_argument("old"); cg.add_argument("new")
    cg.add_argument("--gen-test", action="store_true",
                    help="also re-verify every autopwn technique that verified on OLD against "
                         "NEW in the sandbox (slower, strongest signal)")
    cg.add_argument("-o", "--output")
    cg.set_defaults(func=cmd_ci_gate)

    fi = sub.add_parser("funcid", help="stripped-binary function ID: BinDiff-style "
                        "signature matching to recover names before analysis")
    fi.add_argument("stripped", help="stripped binary missing local symbol names")
    fi.add_argument("reference", help="named reference (same program, any build/opt level)")
    fi.add_argument("-o", "--output")
    fi.add_argument("--min-similarity", type=float, default=0.6,
                    help="umbral de similitud de mnemonics para el fallback heuristico (0-1)")
    fi.set_defaults(func=cmd_funcid)

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
    ip.add_argument("--vuln-class", help="known vulnerability class (e.g. missing-authorization, "
                                         "idor, sqli, rce, stack-overflow...) when the advisory text "
                                         "already states it; lets the web/HTTP-PoC path trigger even "
                                         "without NVD access or a local LLM to classify the text")
    ip.add_argument("--source", help="known source for a web CVE: a WordPress.org plugin slug "
                                     "(e.g. divi-form-builder), a Drupal.org module machine name "
                                     "(e.g. webform), a git URL, or a local/remote .zip/.tar.gz; "
                                     "overrides the LLM's guess")
    ip.add_argument("--cms", choices=["wordpress", "drupal"],
                    help="disambiguates --source when it could be either a WordPress.org slug "
                         "or a Drupal.org module machine name (e.g. a single word with no "
                         "hyphen/underscore); without it, binoracle guesses from the slug's "
                         "shape and tries the other one too if the first guess fails")
    ip.add_argument("--version", help="affected version for --source (e.g. 5.1.8)")
    ip.add_argument("--endpoint", help="exact vulnerable endpoint/route for a web CVE")
    ip.add_argument("--method", help="HTTP method for --endpoint (default POST)")
    ip.add_argument("--params", help="comma-separated request parameter names (e.g. user_id,email,pass)")
    ip.add_argument("--sqli-param", help="for --vuln-class sqli: the exact parameter name to "
                                         "inject into, overriding the automatic guess -- needed "
                                         "when --params also carries OTHER required parameters "
                                         "(e.g. a real directory/resource id the endpoint "
                                         "validates before reaching the vulnerable sink) whose "
                                         "name would otherwise be picked over the real "
                                         "injectable one by the generic id/search/sort heuristic")
    ip.add_argument("--functions", help="comma-separated vulnerable function/method names to confirm "
                                        "against the fetched source (e.g. update_user,handle_register_submission)")
    ip.add_argument("--table-name", help="for WordPress deserialization: the plugin's own DB "
                                         "table where the attacker-controlled value is stored "
                                         "via raw SQL ($wpdb->insert/update, not the Options API) "
                                         "-- when given together with --column-name, triggers the "
                                         "two-step store+force-unserialize() verifier instead of "
                                         "the direct one (e.g. wp_myplugin_tokens)")
    ip.add_argument("--column-name", help="column within --table-name holding the serialized value")
    ip.add_argument("--id-column", help="primary-key column of --table-name used to pick the "
                                        "most recently stored row (default: id)")
    ip.add_argument("--burp-mcp-url", help="connect to the official Burp Suite MCP extension "
                                           "(github.com/PortSwigger/mcp-server, SSE URL from its "
                                           "MCP tab, e.g. http://127.0.0.1:9876) so every "
                                           "request the generic (CMS-agnostic) verifiers send "
                                           "shows up in Burp's Proxy/Repeater -- requires the "
                                           "extension loaded and enabled in Burp first")
    ip.add_argument("-o", "--html", help="also export the full report (including any real "
                                         "screenshots from a dynamic verification) as a standalone "
                                         "HTML file at this path -- the terminal output cannot "
                                         "render images, only this file can")
    ip.add_argument("--json", help="also dump the COMPLETE Investigation object as JSON at this "
                                   "path -- unlike the markdown/HTML report (which truncates every "
                                   "response body to a few hundred chars for readability), this has "
                                   "every captured attempt/response in full; useful to diagnose a "
                                   "dynamic-verification negative without re-running anything")
    ip.add_argument("--no-cache", action="store_true",
                    help="force a fresh investigation even if this exact CVE id was already "
                         "investigated before and its result is cached locally (ignored with "
                         "--binary or any of --source/--endpoint/etc., which never use the "
                         "cache) -- useful after a binoracle bug fix that should change the "
                         "outcome, since the cache has no time-based expiry otherwise")
    ip.add_argument("--keep-lab-on-failure", action="store_true",
                    help="WordPress SQLi only: if the automatic dynamic verification does NOT "
                         "confirm, leave the ephemeral WordPress+MySQL Docker lab ALIVE (no "
                         "retry, since a retry would destroy it to spin up a new one) instead "
                         "of tearing it down -- useful when the target silently swallows the "
                         "real MySQL error (e.g. an AJAX handler that catches it and always "
                         "returns clean JSON) and you need to inspect wp-content/debug.log "
                         "yourself inside the container. The report gives the lab's base URL "
                         "and admin credentials; you are responsible for tearing it down "
                         "afterwards (docker network/volume/container matching the printed tag)")
    ip.set_defaults(func=cmd_investigate)

    ipb = sub.add_parser("investigate-batch", help="run several 'investigate's IN PARALLEL "
                                                    "(bounded concurrency) -- same pipeline as a "
                                                    "single investigate (real source, Docker lab, "
                                                    "dynamic verification, screenshots), just "
                                                    "several CVEs at once instead of one terminal "
                                                    "per CVE")
    ipb.add_argument("cves", nargs="+", help="CVE ids to investigate (e.g. CVE-2024-1071 "
                                             "CVE-2024-3552 CVE-2025-9501)")
    ipb.add_argument("--parallel", type=int, default=2,
                     help="how many investigations run at the same time (default 2, hard cap 6 "
                          "-- each one can spin up its own WordPress+MySQL Docker lab, so more "
                          "than a few at once is more likely to exhaust your machine's RAM/CPU "
                          "than to finish faster)")
    ipb.add_argument("--budget", type=float, default=300,
                     help="sandbox verification budget in seconds, per CVE (default 300)")
    ipb.add_argument("--burp-mcp-url", help="connect to the official Burp Suite MCP extension "
                                            "once, shared by every investigation in the batch "
                                            "(same flag as 'investigate', see its help)")
    ipb.add_argument("--out-dir", default="./binoracle_batch_reports",
                     help="directory to write one <CVE-ID>.md report per CVE into (default "
                          "./binoracle_batch_reports, created if missing)")
    ipb.add_argument("--html-dir", help="also export each report as <CVE-ID>.html (with any real "
                                        "screenshots) into this directory")
    ipb.add_argument("--no-cache", action="store_true",
                     help="force a fresh investigation for every CVE in the batch even if "
                          "already cached locally from a previous run (same flag as "
                          "'investigate', see its help)")
    ipb.set_defaults(func=cmd_investigate_batch)

    ipw = sub.add_parser("investigate-watch", help="watch a public Telegram CVE feed (default "
                                                   "@CVENotify) and automatically run the same "
                                                   "full pipeline as investigate-batch on every "
                                                   "new CVE it posts -- so exploit development "
                                                   "starts on its own as soon as a CVE drops")
    ipw.add_argument("--channel", default="CVENotify",
                     help="Telegram channel to watch, without the @ (default CVENotify) -- read "
                          "via its public web preview (t.me/s/<channel>), no bot token needed")
    ipw.add_argument("--interval", type=float, default=300,
                     help="seconds between polls of the channel (default 300 = 5 min)")
    ipw.add_argument("--once", action="store_true",
                     help="poll exactly once and exit instead of looping forever -- useful to "
                          "test the feed or to run this from your own cron/systemd timer instead "
                          "of leaving it running")
    ipw.add_argument("--cms-only", action="store_true",
                     help="only auto-investigate CVEs that look CMS-related (WordPress/Drupal/"
                          "Joomla) -- by default this watch is generic and processes EVERY CVE "
                          "the channel mentions, developing a hypothesis + PoC for any class; "
                          "CMS-related ones are simply the only ones that can additionally "
                          "reach a dynamically VERIFIED result today (see wpverify.py/"
                          "drupalverify.py/joomlaverify.py). Pass this to skip the rest and save "
                          "time/Docker on CVEs that won't reach that automatic verification")
    ipw.add_argument("--parallel", type=int, default=2,
                     help="how many investigations run at the same time per batch of new CVEs "
                          "(default 2, hard cap 6 -- same caveat as investigate-batch, see its "
                          "help)")
    ipw.add_argument("--budget", type=float, default=300,
                     help="sandbox verification budget in seconds, per CVE (default 300)")
    ipw.add_argument("--burp-mcp-url", help="connect to the official Burp Suite MCP extension "
                                            "once, shared by every investigation this watch "
                                            "launches (same flag as 'investigate', see its help)")
    ipw.add_argument("--out-dir", default="./binoracle_batch_reports",
                     help="directory to write one <CVE-ID>.md report per CVE into (default "
                          "./binoracle_batch_reports, created if missing)")
    ipw.add_argument("--html-dir", help="also export each report as <CVE-ID>.html (with any real "
                                        "screenshots) into this directory")
    ipw.add_argument("--no-cache", action="store_true",
                     help="force a fresh investigation even for a CVE already cached locally "
                          "(same flag as 'investigate', see its help)")
    ipw.set_defaults(func=cmd_investigate_watch)

    return p


def main(argv=None):
    # Si no se da argv explicito, usa la captura temprana (_ARGV, arriba) en vez de releer
    # sys.argv aqui: para cuando esta funcion se ejecuta, los imports de pwntools de este mismo
    # modulo ya han mutado sys.argv (ver la nota junto a _ARGV).
    if argv is None:
        argv = _ARGV
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    try:
        return args.func(args, config)
    except KeyboardInterrupt:
        # Ctrl+C a medio comando: nunca un traceback crudo. Los laboratorios Docker efimeros
        # (wpverify.py/drupalverify.py/joomlaverify.py) ya envuelven TODO su trabajo en
        # try/finally con lab.teardown() -- un KeyboardInterrupt, igual que cualquier otra
        # excepcion, dispara ese finally (Python no distingue BaseException de Exception para
        # efectos de un bloque finally), asi que el laboratorio se limpia solo salvo que el
        # propio proceso muera de golpe (dos Ctrl+C muy rapidos, kill -9...). Si algo quedara
        # suelto de todas formas, 'docker ps -a' lo mostraria -- limpiar a mano con
        # 'docker rm -f <nombre>' y 'docker network rm <nombre>'.
        print("\nabortado por el usuario (Ctrl+C). Si habia un laboratorio Docker efimero en "
             "marcha, se desmonta solo; si 'docker ps -a' muestra algo con el prefijo "
             "'binoracle-' despues de esto, limpialo a mano con 'docker rm -f' / "
             "'docker network rm'.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # p.ej. 'binoracle ... | head': el otro extremo del pipe se cerro, no es un error real.
        return 0
    except Exception as e:
        if args.debug:
            raise
        print(f"\nerror inesperado: {e} (pasa --debug para ver el traceback completo)",
             file=sys.stderr)
        return 1


if __name__ == "__main__":
    main()
