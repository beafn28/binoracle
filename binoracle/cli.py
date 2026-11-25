"""binoracle command line interface."""
from __future__ import annotations

import warnings
warnings.filterwarnings("ignore", message="pkg_resources is deprecated", category=UserWarning)

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
from .report.render import findings_to_json, findings_to_sarif, render_findings
from .workflows.verify import auto_verify, verify_address
from .workflows.enrich import enrich_findings, executive_summary
from .workflows.rop import build_rop_chain
from .workflows.shellcode import gen_shellcode
from .workflows.fuzz import generate_fuzz
from .workflows.autofuzz_afl import autofuzz_afl, render_autofuzz_afl
from .workflows.fmtstring import fmtstring_help
from .workflows.autopoc import autopoc, render_poc
from .workflows.autopwn import autopwn, render_autopwn
from .workflows.audit import run_audit, _is_apk
from .workflows.regress import run_regress, render_regress, autoregress_test, render_regression_tests
from .agent.grounding import GroundingLedger
from .rag import build_kb_hint


def _eprint(*a):
    print(*a, file=sys.stderr)


def _color_ok() -> bool:
    """Return True if stdout supports ANSI colour codes."""
    from .colorlog import _use_color
    return _use_color(sys.stdout)


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


def _docker_sandbox_status() -> tuple:
    """Chequeo real del sandbox dinamico de docker, para `binoracle doctor`.

    Bug real encontrado en vivo: la version anterior solo miraba si el BINARIO docker esta en
    el PATH (shutil.which), nunca si el DAEMON responde -- en un entorno con el cliente
    instalado pero el daemon parado (confirmado en vivo: `docker info` -> "Cannot connect to
    the Docker daemon"), doctor reportaba "docker: disponible" en verde, y solo la linea de la
    imagen fallaba con un mensaje que sugiere "docker build ..." como arreglo -- un build
    tambien falla contra un daemon caido, asi que el usuario solo descubria la causa real (el
    daemon, no la imagen) despues de un intento de build fallido y confuso.
    `_sandbox.run_driver()` SI hace el chequeo correcto (via `docker image inspect`, que exige
    hablar con el daemon) y cae a su runner nativo en consecuencia -- la cadena de exploits en
    si nunca se enganyaba, solo este diagnostico.

    Devuelve (docker_cli_presente, daemon_responde, imagen_binoracle_pwn_construida, mensaje)."""
    import shutil
    docker = shutil.which("docker")
    daemon_ok = False
    img = False
    if docker:
        try:
            import subprocess as _sp
            daemon_ok = _sp.run([docker, "info"], capture_output=True, timeout=10).returncode == 0
            if daemon_ok:
                img = _sp.run([docker, "image", "inspect", "binoracle-pwn"],
                              capture_output=True, timeout=10).returncode == 0
        except Exception:
            daemon_ok = False
    if not docker:
        msg = "no (instala Docker)"
    elif not daemon_ok:
        msg = "binario presente pero el daemon no responde (arranca el servicio docker)"
    else:
        msg = "disponible"
    return bool(docker), daemon_ok, img, msg


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
    docker, daemon_ok, img, docker_msg = _docker_sandbox_status()
    print(f"  {ok(docker and daemon_ok)}docker (sandbox dinamico/exploits): {docker_msg}")
    if docker and daemon_ok:
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
    # Same RAG context `binoracle audit` already builds for itself (curated cheat sheets
    # selected from this binary's real facts, plus prior VERIFIED findings on similar
    # targets) -- found live that `hunt` never consulted the knowledge base at all, despite
    # `binoracle learn` existing specifically to grow it. Reference only: the agent loop's own
    # prompt is explicit that this never overrides a tool result.
    kb_hint = build_kb_hint(reg, store=store)
    res = run_hunt(reg, binary, llm=llm, config=config, store=store, on_step=_step_printer,
                  lang=config.lang, kb_hint=kb_hint)
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
    # See cmd_hunt's comment: same RAG hint `audit` already builds, now also reachable from
    # `ask`, not just `audit`.
    kb_hint = build_kb_hint(reg, store=store)
    loop = AgentLoop(llm, reg, config, store=store, on_step=_step_printer, kb_hint=kb_hint or None)
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
    # See cmd_hunt's comment: same RAG hint `audit` already builds, now also reachable from
    # `chat`, not just `audit`.
    kb_hint = build_kb_hint(reg, store=store)
    loop = AgentLoop(llm, reg, config, store=store, on_step=_step_printer, kb_hint=kb_hint or None)
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
                lang="es", decompiled=None, cfg=None, chains=None, mobile=False):
    html = render_html(binary, triage=triage, findings=findings, ledger=ledger, answer=answer,
                       lang=lang, decompiled=decompiled, cfg=cfg, chains=chains, mobile=mobile)
    Path(path).write_text(html, encoding="utf-8")
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


def cmd_cve_corpus(args, config):
    from binoracle.workflows.libfuzzer_corpus import build_corpus, write_corpus, render_corpus
    from binoracle.workflows.cvelookup import fetch_cve
    _use_col = _color_ok()
    _b = "\033[1m" if _use_col else ""
    _r = "\033[0m" if _use_col else ""
    print(f"\n  {_b}binoracle cve-corpus{_r}  {args.cve_id}\n")
    print("  Fetching NVD description...")
    info = fetch_cve(args.cve_id)
    description = info.description if info.ok else ""
    if not description:
        print(f"  Warning: NVD description not found — {info.note or 'no data'}")
    poc_text = ""
    if getattr(args, "poc_file", "") and Path(args.poc_file).exists():
        try:
            poc_text = Path(args.poc_file).read_text(encoding="utf-8", errors="replace")
            print(f"  PoC loaded from {args.poc_file} ({len(poc_text)} chars)")
        except Exception as e:
            print(f"  Warning: could not read PoC file: {e}")
    corpus = build_corpus(
        cve_id=args.cve_id,
        poc_text=poc_text,
        description=description,
        target_func=args.target_func,
        hint=args.hint,
    )
    wrote_to = None
    try:
        wrote_to = write_corpus(corpus, args.out_dir)
        print(f"  Corpus written to {wrote_to}")
    except Exception as e:
        print(f"  Warning: could not write corpus: {e}")
    print(render_corpus(corpus, wrote_to=wrote_to))


def cmd_finetune(args, config):
    from binoracle.workflows.finetune import build_finetune_dataset, render_finetune
    _use_col = _color_ok()
    _b = "\033[1m" if _use_col else ""
    _r = "\033[0m" if _use_col else ""
    print(f"\n  {_b}binoracle finetune{_r}\n")
    store = None
    try:
        from binoracle.store import load_store
        store = load_store(config)
    except Exception:
        pass
    ds = build_finetune_dataset(
        store=store,
        reports_dir=getattr(args, "reports_dir", "") or "",
        model_id=getattr(args, "model_id", "Qwen/Qwen2.5-Coder-7B-Instruct"),
        out_dir=getattr(args, "out_dir", ".") or ".",
    )
    print(render_finetune(ds))


def cmd_kernel_exploit(args, config):
    from binoracle.workflows.kernel_exploit import build_kernel_exploit, render_kernel_exploit
    from binoracle.workflows.cvelookup import fetch_cve
    _use_col = _color_ok()
    _b = "\033[1m" if _use_col else ""
    _r = "\033[0m" if _use_col else ""
    cve_id = getattr(args, "cve_id", "") or ""
    primitive = getattr(args, "primitive", "") or ""
    print(f"\n  {_b}binoracle kernel-exploit{_r}  {cve_id}\n")
    description = ""
    if cve_id:
        print("  Fetching NVD description...")
        info = fetch_cve(cve_id)
        description = info.description or ""
    chain = build_kernel_exploit(cve_id, description=description, primitive=primitive)
    print(render_kernel_exploit(chain))


def cmd_firmware(args, config):
    from binoracle.workflows.firmware import analyze_firmware, render_firmware
    _use_col = _color_ok()
    _b = "\033[1m" if _use_col else ""
    _r = "\033[0m" if _use_col else ""
    print(f"\n  {_b}binoracle firmware{_r}  {args.image}\n")

    def on_step(msg):
        print(f"  {msg}")

    info = analyze_firmware(args.image, out_dir=args.out_dir or "")
    print(render_firmware(info))


def cmd_cve_chain(args, config):
    from binoracle.workflows.cve_chain import run_chain, render_chain
    _use_col = _color_ok()
    _b = "\033[1m" if _use_col else ""
    _r = "\033[0m" if _use_col else ""
    cves = args.cves
    print(f"\n  {_b}binoracle cve-chain{_r}  {' → '.join(cves)}\n")

    def on_step(msg):
        print(f"  {msg}")

    result = run_chain(
        cve_ids=cves,
        config=config,
        on_step=on_step,
        out_dir=args.out_dir,
    )
    print()
    print(render_chain(result))


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


def cmd_cve_web(args, config):
    from .web_cve import serve as cve_serve
    cve_serve(host=args.host, port=args.port,
              open_browser=not args.no_open, config=config)


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
    if args.extract_libs:
        from .workflows.apkinspect import extract_native_libs
        paths = extract_native_libs(binary, args.extract_libs, abi=args.abi)
        if not paths:
            print(f"\n(no se extrajo ninguna libreria nativa{' para abi='+args.abi if args.abi else ''})")
        else:
            print(f"\n{len(paths)} libreria(s) nativa(s) extraida(s) a {args.extract_libs}/:")
            for p in paths:
                print(f"  {p}")
            print("\nApunta el pipeline de exploiting existente directamente a cualquiera de estas, p.ej.:")
            print(f"  binoracle hunt {paths[0]}")


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
    # La auditoria Android (APK) es grounded/estatica en su nucleo (manifest + Java
    # decompilado): nunca REQUIERE el LLM, asi que no debe bloquearse por falta de modelo
    # local (a diferencia del audit nativo ELF/PE/Mach-O, que si lo necesita para razonar
    # sobre primitivas/ROP). Pero si HAY un modelo local arriba, run_android_audit lo usa
    # igual que el audit nativo (enrich_findings/executive_summary) para narrar los
    # hallazgos grounded -- el LLM nunca sustituye el veredicto fijado por el codigo, solo
    # lo redacta mejor. make_backend() es barato (no abre conexion); solo el .available()
    # posterior hace la llamada de red, por eso es seguro construirlo siempre aqui.
    llm = make_backend(config)
    if not _is_apk(binary) and not llm.available():
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
                    chains=getattr(res, "chains", None),
                    mobile=(getattr(res, "stopped_reason", "") == "android-audit"))
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


def cmd_phpestate(args, config):
    """Inventario/clasificacion de interpretes PHP (EOL/BEHIND/CURRENT), local y opcionalmente
    remoto. No es un verificador de exploit -- ver el docstring de workflows/phpestate.py."""
    from .workflows.phpestate import run_phpestate
    findings = run_phpestate(paths=args.paths or None, url=getattr(args, "url", "") or "",
                             authorized=bool(getattr(args, "authorized", False)), lang=config.lang)
    if getattr(args, "json", None):
        Path(args.json).write_text(findings_to_json(args.url or "local", findings))
        _eprint(f"(JSON -> {args.json})")
    out = render_findings(findings)
    print(out)
    _write_if(getattr(args, "output", None), out)


def _parse_cli_params(raw_arg: str):
    """Parsea --params: nombres sueltos ("action,nonce") o "nombre=valor" (ver cmd_investigate
    para el porque). Extraido a su propia funcion para poder probarlo sin invocar el CLI entero."""
    raw = [p.strip() for p in raw_arg.split(",") if p.strip()]
    if any("=" in p for p in raw):
        parsed: dict = {}
        for p in raw:
            if "=" in p:
                k, _, v = p.partition("=")
                parsed[k.strip()] = v.strip()
            else:
                parsed[p] = "1"   # sin valor dado: marcador neutro, solo declara que existe
        return parsed
    return raw


def _make_cve_step_printer():
    """Rich on_step callback para 'binoracle cve': colores, iconos, fases, paneles de datos."""
    import time as _time
    import re as _re
    import sys as _sys
    from . import colorlog as _cl

    _t0 = _time.time()
    _last_phase = [None]
    _col = _cl._use_color(_sys.stdout)

    # ── Paleta de colores ──────────────────────────────────────────────────────
    R   = "\033[0m"   if _col else ""   # reset
    B   = "\033[1m"   if _col else ""   # bold
    DIM = "\033[2m"   if _col else ""   # dim
    CYN = "\033[36m"  if _col else ""   # cyan  → INFO
    GRN = "\033[32m"  if _col else ""   # verde → OK / VERIFICADO
    YLW = "\033[33m"  if _col else ""   # amarillo → WARN
    RED = "\033[31m"  if _col else ""   # rojo  → ERROR
    BLU = "\033[34m"  if _col else ""   # azul  → fase header
    MAG = "\033[35m"  if _col else ""   # magenta → highlight
    WHT = "\033[97m"  if _col else ""   # blanco → texto prominente
    BGN = "\033[1;32m" if _col else ""  # verde bold → VERIFICADO final

    # Iconos por nivel
    _ICON = {"info": f"{CYN}●{R}", "ok": f"{GRN}✔{R}", "warn": f"{YLW}⚠{R}",
             "error": f"{RED}✖{R}", "verified": f"{BGN}★{R}"}

    _PHASES = [
        (r"nvd|consult|fetch.*cve|recuper", "CONSULTA NVD",        "◉"),
        (r"hipot|llm|modelo|analiz|clasificar|propone|hypothesis",
                                             "HIPÓTESIS LLM",       "◈"),
        (r"grounded|codigo fuente|source|funcion|function|encontr",
                                             "ANÁLISIS DE CÓDIGO",  "◆"),
        (r"endpoi|url|route|ruta|parame",   "ENDPOINT",             "▶"),
        (r"docker|lab|contenedor|container|arran|start|build|construy|scaffold",
                                             "LABORATORIO DOCKER",  "■"),
        (r"baseline|control|mediana|linea base", "BASELINE",        "≡"),
        (r"payload|intento|sleep|sqli|inject|fuzz|verif|probando|confirm|canario|canary",
                                             "VERIFICACIÓN",        "◎"),
        (r"informe|report|html|escrito|resultado final|verified",   "RESULTADO", "◇"),
    ]

    def _phase_for(msg: str):
        ml = msg.lower()
        for pat, name, icon in _PHASES:
            if _re.search(pat, ml):
                return name, icon
        return "", ""

    def _print_phase_header(phase: str, icon: str) -> None:
        pad = 58 - len(phase) - 5
        if _col:
            print(f"\n{BLU}{B}{'─' * 2} {icon}  {phase} {'─' * max(2, pad)}{R}")
        else:
            print(f"\n── {phase} {'─' * max(2, pad + 4)}")

    # ── Extrae datos importantes de mensajes clave ──────────────────────────
    def _highlight(msg: str, level: str) -> str:
        """Resalta fragmentos importantes en el mensaje."""
        if not _col:
            return msg
        # URLs y puertos
        msg = _re.sub(r'(https?://\S+)', f"{MAG}\\1{R}{_cl._COLOR.get(level,'')}", msg)
        # versiones: v1.2.3 o ==1.2.3
        msg = _re.sub(r'(==?[0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                      f"{WHT}\\1{R}{_cl._COLOR.get(level,'')}", msg)
        # CVE IDs
        msg = _re.sub(r'(CVE-\d{4}-\d+)',
                      f"{B}\\1{R}{_cl._COLOR.get(level,'')}", msg)
        # 'VERIFICADO' y 'confirmado'
        msg = _re.sub(r'(?i)(VERIFICADO|confirmad[oa])',
                      f"{BGN}\\1{R}{_cl._COLOR.get(level,'')}", msg)
        return msg

    def _print_data_panel(lines: list[str], color: str = "") -> None:
        """Imprime un panel de datos con borde lateral."""
        c = color if _col else ""
        bar = "│" if _col else "|"
        for ln in lines:
            print(f"  {c}{bar}{R}  {ln}")

    def on_step(msg: str) -> None:
        elapsed = _time.time() - _t0
        ts = f"{elapsed:>7.1f}s"

        phase, icon = _phase_for(msg)
        if phase and phase != _last_phase[0]:
            _print_phase_header(phase, icon)
            _last_phase[0] = phase

        level = _cl.classify(msg)
        ico   = _ICON.get(level, _ICON["info"])
        lc    = _cl._COLOR.get(level, "")
        label = _cl._LABEL.get(level, "INFO")

        # Mensajes de dato importante → panel destacado
        # "objetivo arriba: http://..." → panel verde con URL
        m_up = _re.search(r"objetivo arriba[:\s]+(https?://\S+)[^(]*\(contenedor\s+'([^']+)'",
                           msg)
        if m_up:
            url, ctr = m_up.group(1), m_up.group(2)
            if _col:
                print(f"  {DIM}{ts}{R}  {ico} {lc}{B}[{label}]{R}{lc} {_highlight(msg, level)}{R}")
                print(f"\n  {GRN}{'┌' + '─'*50 + '┐'}{R}")
                print(f"  {GRN}│{R}  {B}URL:{R}        {MAG}{url}{R}")
                print(f"  {GRN}│{R}  {B}Contenedor:{R} {WHT}{ctr}{R}")
                print(f"  {GRN}{'└' + '─'*50 + '┘'}{R}\n")
            else:
                print(f"  {ts}  [{label}] {msg}")
                print(f"  URL: {url}  Contenedor: {ctr}")
            return

        # "hipotesis del LLM: clase=X, disparador=Y" → panel azul con clase
        m_hyp = _re.search(r"hipot[^:]*:[^=]*(clase|class)\s*=\s*(\S+)", msg, _re.I)
        if m_hyp:
            vuln_cls = m_hyp.group(2).rstrip(",")
            if _col:
                print(f"  {DIM}{ts}{R}  {ico} {lc}{B}[{label}]{R}{lc} {_highlight(msg, level)}{R}")
                print(f"\n  {BLU}{'╌'*52}{R}")
                print(f"  {BLU}»{R} {B}Clase:{R}  {MAG}{vuln_cls.upper()}{R}")
                print(f"  {BLU}{'╌'*52}{R}\n")
            else:
                print(f"  {ts}  [{label}] {msg}")
            return

        # "scaffolded minimal X lab at /tmp/..." → resaltar pin
        m_sc = _re.search(r"scaffold[^(]+\(vuln_class=(\S+),\s*pin=(\S+)\)", msg)
        if m_sc:
            if _col:
                vc, pin = m_sc.group(1), m_sc.group(2)
                print(f"  {DIM}{ts}{R}  {ico} {lc}{B}[{label}]{R}{lc} {_highlight(msg, level)}{R}")
                print(f"  {DIM}        pin: {WHT}{pin}{R}{DIM}  ·  clase: {WHT}{vc}{R}")
            else:
                print(f"  {ts}  [{label}] {msg}")
            return

        # "corrigiendo version: '3.9.2' es la version PARCHEADA" → resaltar en amarillo
        if _re.search(r"corrigiendo version|PARCHEADA|ultima vulnerable", msg, _re.I):
            if _col:
                print(f"  {DIM}{ts}{R}  {YLW}{B}[CORR]{R}{YLW} {msg}{R}")
            else:
                print(f"  {ts}  [CORR] {msg}")
            return

        # "VERIFICADO: el secreto plantado" → banner verde brillante
        if _re.search(r"VERIFICADO[:\s]", msg, _re.I):
            if _col:
                print(f"\n  {BGN}{'━'*54}{R}")
                print(f"  {BGN}★  {msg}{R}")
                print(f"  {BGN}{'━'*54}{R}\n")
            else:
                print(f"  *** VERIFICADO: {msg} ***")
            return

        # línea estándar
        if _col:
            print(f"  {DIM}{ts}{R}  {ico} {lc}{B}[{label}]{R}{lc} {_highlight(msg, level)}{R}")
        else:
            print(f"  {ts}  [{label}] {msg}")

    return on_step


def _md_to_plain(text: str) -> str:
    """Convierte markdown a texto plano legible en terminal.

    Reglas aplicadas en orden estricto:
    1. Bloques de codigo (```) → detectados ANTES de cualquier sub; contenido indentado.
    2. Cabeceras #/##/### → texto en mayusculas con subrayado o sin el.
    3. Separadores de tabla |---|  → omitidos.
    4. Filas de tabla → celdas separadas por espacios, backticks en celdas eliminados.
    5. Reglas horizontales (---/===/***/~~~) → linea en blanco.
    6. Blockquote > → indentado.
    7. Negrita/cursiva, backticks inline, enlaces → texto plano.
    8. Backtick suelto residual al inicio/fin de linea → eliminado.
    """
    import re as _re

    _inline_code = _re.compile(r'`+([^`]+)`+')
    _bold_italic = _re.compile(r'\*{1,3}([^*\n]+)\*{1,3}|_{1,3}([^_\n]+)_{1,3}')
    _link        = _re.compile(r'\[([^\]]+)\]\([^)]*\)')
    _hr          = _re.compile(r'^(\s*[-*_~=]{3,}\s*)$')

    def _strip_inline(s: str) -> str:
        s = _inline_code.sub(r'\1', s)
        s = _bold_italic.sub(lambda m: m.group(1) or m.group(2), s)
        s = _link.sub(r'\1', s)
        return s.strip('`')

    out: list[str] = []
    inside_code = False

    for raw in text.splitlines():
        # --- 1. Valla de codigo (``` o ~~~) — ANTES de cualquier transformacion ---
        if _re.match(r'^(`{3,}|~{3,})', raw):
            inside_code = not inside_code
            continue
        if inside_code:
            out.append('  ' + raw)
            continue

        # --- 2. Cabeceras ---
        hm = _re.match(r'^(#{1,6})\s+(.*)', raw)
        if hm:
            level = len(hm.group(1))
            title = _strip_inline(hm.group(2).strip())
            if level <= 2:
                out.append('')
                out.append(title.upper())
                out.append('─' * min(len(title), 60))
            else:
                out.append('')
                out.append(title)
            continue

        # --- 3. Separador de tabla |---|---|  → omitir ---
        if _re.match(r'^\|[\s\-|:]+\|', raw):
            continue

        # --- 4. Fila de tabla | a | b | ---
        if raw.startswith('|') and raw.endswith('|'):
            cells = [_strip_inline(c.strip()) for c in raw[1:-1].split('|')]
            out.append('  ' + '   '.join(cells))
            continue

        # --- 5. Regla horizontal ---/===/***  → linea en blanco ---
        if _hr.match(raw):
            out.append('')
            continue

        # --- 6. Blockquote ---
        line = _re.sub(r'^>\s*', '  ', raw)

        # --- 7. Inline: negrita, cursiva, backticks, enlaces ---
        line = _strip_inline(line)

        out.append(line)

    return '\n'.join(out)


def _print_chain_verdict(cr, cve_id: str, elapsed: float, use_col: bool,
                         bold: str, reset: str, dim: str, colorlog) -> None:
    """Render the terminal verdict box for a ChainResult."""
    if cr.verified:
        vc   = "\033[1;32m" if use_col else ""
        icon = "★  VERIFICADO"
    else:
        vc   = "\033[1;33m" if use_col else ""
        icon = "✖  NO CONFIRMADO"

    bar = "═" * 62
    print(f"\n{vc}╔{bar}╗{reset}")
    print(f"{vc}║{reset}  {vc}{bold}{icon:^60}{reset}{vc}║{reset}")
    print(f"{vc}╚{bar}╝{reset}")

    _wh = "\033[97m" if use_col else ""
    _mc = "\033[35m" if use_col else ""
    _tc = "\033[36m" if use_col else ""

    ev = cr.evidence or {}
    _ep  = ev.get("endpoint") or ev.get("url") or ""
    _pay = ev.get("payload_ganador") or ev.get("payload") or ""
    _ctr = ev.get("contenedor") or ev.get("container") or ""
    if _ep or _pay or _ctr:
        print()
        if _ctr:
            print(f"  {bold}Contenedor{reset}:    {_wh}{_ctr}{reset}")
        if _ep:
            print(f"  {bold}Endpoint{reset}:      {_wh}{_ep}{reset}")
        if _pay:
            print(f"  {bold}Payload{reset}:       {_mc}{_pay}{reset}")

    if cr.cvss_score:
        print(f"  {bold}CVSS{reset}:           {cr.cvss_score} {cr.cvss_severity}")
    if cr.engine_confidence:
        print(f"  {bold}Confianza motor{reset}: {cr.engine_confidence:.0%}")
    if cr.report_path:
        print(f"  {bold}Informe{reset}:        {dim}{cr.report_path}{reset}")

    print(f"\n  {bold}Tiempo total{reset}: {_tc}{elapsed:.1f}s{reset}")
    print(f"  {dim}clase: {cr.cve_class} · {cve_id}{reset}")
    print()


def _export_chain_html(cr, out_path: str, cve_id: str, lang: str) -> None:
    """Export ChainResult.report_md as a minimal HTML file."""
    try:
        from pathlib import Path as _P
        _md = cr.report_md or f"# {cve_id}\n\nSin informe Markdown disponible.\n"
        # Minimal HTML wrapper — no external deps
        _html = (
            f"<!DOCTYPE html><html lang='{lang}'><head>"
            "<meta charset='utf-8'>"
            f"<title>{cve_id} — binoracle</title>"
            "<style>body{font-family:monospace;max-width:900px;margin:2rem auto;"
            "background:#0d1117;color:#c9d1d9;line-height:1.6}"
            "pre,code{background:#161b22;padding:.2em .4em;border-radius:4px}"
            "h1,h2,h3{color:#58a6ff}</style></head><body>"
            "<pre style='white-space:pre-wrap'>"
            + _md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            + "</pre></body></html>"
        )
        _P(out_path).write_text(_html, encoding="utf-8")
    except Exception:
        pass


def cmd_cve(args, config):
    """Shortcut: binoracle cve <CVE-ID> — investigacion completa con logs estructurados."""
    import time as _time
    import sys as _sys
    from .workflows.cve_agent import investigate_cve, render_investigation
    from . import colorlog

    cve_id = args.cve.upper()
    hints: dict = {}
    if getattr(args, "source", None):
        hints["source_url"] = args.source
    if getattr(args, "endpoint", None):
        hints["endpoint"] = args.endpoint
        hints["analyst_endpoint_lock"] = True
    if getattr(args, "method", None):
        hints["http_method"] = args.method
    if getattr(args, "params", None):
        hints["parameters"] = _parse_cli_params(args.params)
    if getattr(args, "vuln_class", None):
        hints["vuln_class"] = args.vuln_class
    if getattr(args, "custom_headers", None):
        import json as _json
        try:
            _ch = _json.loads(args.custom_headers)
            if isinstance(_ch, dict) and _ch:
                hints["custom_headers"] = _ch
        except (ValueError, TypeError):
            pass
    if getattr(args, "companion_plugins", None):
        _slugs = [s.strip() for s in args.companion_plugins.split(",") if s.strip()]
        if _slugs:
            hints["companion_plugins"] = _slugs
    if getattr(args, "target_url", None):
        hints["prebuilt_url"] = args.target_url.rstrip("/")
    if getattr(args, "setup_wp_options", None):
        _parsed_opts = []
        import re as _re
        for _raw in (args.setup_wp_options or []):
            _m = _re.match(r'^([^\[=]+)\[([^\]]+)\]=(.*)$', _raw)
            if _m:
                _parsed_opts.append({"name": _m.group(1), "patch_key": _m.group(2), "value": _m.group(3)})
            else:
                _k, _, _v = _raw.partition("=")
                _parsed_opts.append({"name": _k.strip(), "value": _v or "1"})
        hints["setup_options"] = _parsed_opts

    # Si existe un JSON del analista en binoracle_batch_reports/, cargar campos de
    # configuracion Docker (dockerfile_body / docker_image / extra_files) como hints de
    # base para que se preserven incluso con --no-cache (el LLM fresco no los conoce).
    _batch_json_path = f"binoracle_batch_reports/{cve_id}.json"
    try:
        import json as _j, os as _os2
        if _os2.path.exists(_batch_json_path):
            with open(_batch_json_path, encoding="utf-8") as _bf:
                _stored_notes = _j.load(_bf).get("llm_notes") or {}
            for _field in ("dockerfile_body", "docker_image", "extra_files",
                           "confirm_string", "sqli_param", "poc_cmd", "url_suffix",
                           "custom_headers", "bypass_header", "bypass_value", "bypass_url"):
                if _field not in hints and _stored_notes.get(_field):
                    hints[_field] = _stored_notes[_field]
    except Exception:
        pass

    # ── Banner ────────────────────────────────────────────────────────────────
    _use_col = colorlog._use_color(_sys.stdout)
    _r  = colorlog._RESET if _use_col else ""
    _b  = colorlog._BOLD  if _use_col else ""
    _d  = "\033[2m"    if _use_col else ""
    _ac = "\033[1;96m" if _use_col else ""   # cyan brillante
    _mc = "\033[1;35m" if _use_col else ""   # magenta → CVE ID
    _gc = "\033[1;32m" if _use_col else ""   # verde → OK
    _oc = "\033[1;33m" if _use_col else ""   # ámbar → el "0" de bin0racle y hex values
    _W  = 62   # visible width between ║ borders
    bar = "═" * _W

    def _brow(vis, txt):
        return f"{_ac}║{_r}{txt}{' ' * max(0, _W - vis)}{_ac}║{_r}"

    # Header: "  bin0racle" (11) + 13 spaces + subtitle (36) + 2 spaces = 62
    _hdr = (f"  {_b}bin{_r}{_oc}{_b}0{_r}{_ac}{_b}racle{_r}"
            f"             {_d}oracle de investigación CVE autónoma  {_r}")

    # Crystal ball rows (left 16 visible) + info right column
    _cv  = len(cve_id)
    _rows = [
        (f"   {_ac}╭───────────╮{_r}", 16, "", 0),
        (f"   {_ac}│{_r} 1001 {_oc}0xE9{_r} {_ac}│{_r}", 16,
         f"   {_d}▸ {_r}{_mc}{_b}{cve_id}{_r}", 5 + _cv),
        (f"   {_ac}│{_r} 0110 1011 {_ac}│{_r}", 16,
         f"   {_d}investigación autónoma{_r}", 25),
        (f"   {_ac}│{_r} {_oc}{_b}RCE{_r}  0101 {_ac}│{_r}", 16, "", 0),
        (f"   {_ac}│{_r} 1100 {_oc}0x90{_r} {_ac}│{_r}", 16, "", 0),
        (f"   {_ac}╰─────┬─────╯{_r}", 16, "", 0),
        (f"        {_ac}═╧═{_r}", 11, "", 0),
    ]

    # Footer: "creado por @beafn28" right-aligned (40 pad + 19 text + 3 margin = 62)
    _ft  = f"{_d}creado por {_r}{_oc}{_b}@beafn28{_r}"
    _ftr = " " * (_W - 3 - 19) + _ft + "   "

    print(f"\n{_ac}╔{bar}╗{_r}")
    print(_brow(62, _hdr))
    print(f"{_ac}╠{bar}╣{_r}")
    for la, lv, ra, rv in _rows:
        print(_brow(lv + rv, la + ra))
    print(f"{_ac}╠{bar}╣{_r}")
    print(_brow(62, _ftr))
    print(f"{_ac}╚{bar}╝{_r}\n")

    t_start = _time.time()
    if getattr(args, "quiet", False):
        on_step = lambda _m: None  # silencio total; solo veredicto final
    else:
        on_step = _make_cve_step_printer()

    _lang     = getattr(args, "lang", None) or config.lang
    _budget   = float(getattr(args, "budget", 600) or 600)
    _no_cache = getattr(args, "no_cache", False)
    # run_full_chain is the default; --no-chain falls back to investigate_cve
    _use_chain = not getattr(args, "no_chain", False)

    if _use_chain:
        from .workflows.auto_chain import run_full_chain
        chain_result = run_full_chain(
            cve_id,
            lang=_lang,
            budget_s=_budget,
            on_step=on_step,
            config=config,
            no_cache=_no_cache,
            hints=hints or None,
        )
        elapsed_total = _time.time() - t_start
        _print_chain_verdict(chain_result, cve_id, elapsed_total, _use_col, _b, _r, _d, colorlog)
        if getattr(args, "html", None):
            _export_chain_html(chain_result, args.html, cve_id, _lang)
            colorlog.ok(f"informe HTML escrito en {args.html}")
        if getattr(args, "json_out", None):
            import json as _json
            from pathlib import Path as _Path
            import dataclasses as _dc
            _inv_obj = chain_result.inv
            _jdata = {
                "cve_id": chain_result.cve_id,
                "verified": chain_result.verified,
                "engine_confidence": chain_result.engine_confidence,
                "cve_class": chain_result.cve_class,
                "cvss_score": chain_result.cvss_score,
                "evidence": chain_result.evidence,
                "steps": [_dc.asdict(s) for s in chain_result.steps],
                "report_path": chain_result.report_path,
            }
            _Path(args.json_out).write_text(_json.dumps(_jdata, indent=2,
                                                        ensure_ascii=False, default=str))
            colorlog.ok(f"evidencia JSON escrita en {args.json_out}")
        return

    # ── Fallback: single-stage investigate_cve (--no-chain) ──────────────────
    inv = investigate_cve(
        cve_id,
        config=config,
        on_step=on_step,
        lang=_lang,
        budget_s=_budget,
        hints=hints or None,
        use_cache=not _no_cache,
    )
    elapsed_total = _time.time() - t_start

    # ── Verdict box ───────────────────────────────────────────────────────────
    if inv.verified:
        vc   = "\033[1;32m" if _use_col else ""
        icon = "★  VERIFICADO"
    else:
        vc   = "\033[1;33m" if _use_col else ""
        icon = "✖  NO CONFIRMADO"

    bar2 = "═" * 62
    print(f"\n{vc}╔{bar2}╗{_r}")
    print(f"{vc}║{_r}  {vc}{_b}{icon:^60}{_r}{vc}║{_r}")
    print(f"{vc}╚{bar2}╝{_r}")

    ve = getattr(inv, "verified_evidence", None) or {}
    if isinstance(ve, dict):
        payload  = ve.get("payload_ganador", "")
        t1       = ve.get("tiempo_1_ganador_s", "")
        t2       = ve.get("tiempo_2_ganador_s", "")
        base     = ve.get("tiempo_base_mediana_s", "")
        strategy = ve.get("estrategia", "")
        ctr      = ve.get("contenedor", "")
        endpoint = ve.get("endpoint", "")
        _mc2 = "\033[35m" if _use_col else ""
        _wh  = "\033[97m" if _use_col else ""
        if payload or ctr or endpoint:
            print()
            if ctr:
                print(f"  {_b}Contenedor{_r}:       {_wh}{ctr}{_r}")
            if endpoint:
                print(f"  {_b}Endpoint{_r}:         {_wh}{endpoint}{_r}")
            if payload:
                print(f"  {_b}Payload ganador{_r}:  {_mc2}{payload}{_r}")
            if t1:
                print(f"  {_b}Tiempo 1{_r}: {_wh}{t1}s{_r}  "
                      f"{_b}Tiempo 2{_r}: {_wh}{t2}s{_r}  "
                      f"{_b}Baseline{_r}: {_wh}{base}s{_r}")
            if strategy:
                print(f"  {_b}Estrategia{_r}:       {strategy}")
    detail = getattr(inv, "verified_detail", "") or ""
    if detail:
        print(f"\n  {detail}")

    _tm_c = "\033[36m" if _use_col else ""
    if not inv.verified:
        blockers = getattr(inv, "blockers", []) or []
        if blockers:
            print(f"\n  {_b}Bloqueadores:{_r}")
            for bl in blockers[:3]:
                bl_txt = str(bl)[:800]
                lines  = bl_txt.splitlines()
                print(f"    {vc}▸{_r} {lines[0]}")
                for ln in lines[1:]:
                    print(f"      {ln}")

    print(f"\n  {_b}Tiempo total{_r}: {_tm_c}{elapsed_total:.1f}s{_r}")
    _notes = getattr(inv, "llm_notes", {}) or {}
    _cls   = getattr(inv, "vuln_class", "") or _notes.get("vuln_class", "")
    _cvss  = getattr(inv, "cvss_score", None)
    _sev   = getattr(inv, "cvss_severity", "") or ""
    if _cls or _cvss:
        parts = []
        if _cvss:
            parts.append(f"CVSS {_cvss} {_sev}")
        if _cls:
            parts.append(f"clase: {_cls}")
        poc_k = getattr(inv, "poc_kind", "") or ""
        if poc_k:
            parts.append(f"PoC: {poc_k}")
        print(f"  {_d}{' · '.join(parts)}{_r}")

    _vshots = (getattr(inv, "verified_evidence", {}) or {}).get("screenshots") or []
    _ashots = (getattr(inv, "attempt_evidence", {}) or {}).get("screenshots") or []
    _all_terminal_shots = list(_vshots) + [s for s in _ashots if s not in _vshots]
    if _all_terminal_shots:
        import base64 as _b64mod
        import os as _os
        _term = _os.environ.get("TERM_PROGRAM", "") or _os.environ.get("TERM", "")
        _iterm2 = "iterm" in _term.lower() or _os.environ.get("ITERM_SESSION_ID", "")
        _kitty  = _os.environ.get("KITTY_WINDOW_ID", "") or "kitty" in _term.lower()
        _gc = "\033[32m" if _use_col else ""
        print(f"\n  {_gc}◈ Capturas paso a paso ({len(_all_terminal_shots)} "
              f"imágen{'es' if len(_all_terminal_shots)!=1 else ''}):{_r}")
        for i, _sh in enumerate(_all_terminal_shots):
            _png = _sh.get("png_b64")
            _cap = _sh.get("caption_es" if _lang == "es" else "caption_en") or ""
            _url = _sh.get("url") or ""
            print(f"    {_d}Paso {i+1}:{_r} {_cap[:90]}")
            if _url:
                print(f"      {_d}URL:{_r} {_url[:80]}")
            if _png:
                if _iterm2:
                    _raw = _b64mod.b64decode(_png)
                    _enc = _b64mod.b64encode(_raw).decode("ascii")
                    print(f"\033]1337;File=inline=1;width=80;height=20;preserveAspectRatio=1:{_enc}\a")
                elif _kitty:
                    try:
                        import subprocess as _sp, tempfile as _tf
                        with _tf.NamedTemporaryFile(suffix=".png", delete=False) as _tmp:
                            _tmp.write(_b64mod.b64decode(_png))
                            _tmp_path = _tmp.name
                        _sp.run(["kitty", "+kitten", "icat", "--align=left", _tmp_path],
                                check=False, timeout=5)
                        _os.unlink(_tmp_path)
                    except Exception:
                        pass
                else:
                    _kb = len(_png) * 3 // 4 // 1024
                    print(f"      {_d}[~{_kb} KB — usa -o report.html para ver la imagen]{_r}")
    print()

    if getattr(args, "html", None):
        from .report.html import render_investigation_page
        from pathlib import Path as _Path
        md_full = render_investigation(inv, _lang)
        _Path(args.html).write_text(
            render_investigation_page(md_full, script=inv.developed_script,
                                      cve=cve_id, lang=_lang, poc_kind=inv.poc_kind,
                                      inv=inv),
            encoding="utf-8")
        colorlog.ok(f"informe HTML escrito en {args.html}")

    if getattr(args, "json_out", None):
        from dataclasses import asdict as _asdict
        import json as _json
        from pathlib import Path as _Path
        _Path(args.json_out).write_text(_json.dumps(_asdict(inv), indent=2, ensure_ascii=False))
        colorlog.ok(f"evidencia JSON escrita en {args.json_out}")


def cmd_autodiscover(args, config):
    """binoracle autodiscover — NVD keyword search + autonomous batch investigation."""
    import sys as _sys
    from .workflows.cve_agent import autodiscover_and_investigate, render_autodiscover_result
    from . import colorlog

    scope          = args.scope
    min_cvss       = args.min_cvss
    days_back      = args.days
    max_candidates = args.max_candidates
    parallel       = args.parallel
    budget         = args.budget
    severity       = (args.severity or "").upper()
    keywords       = args.keywords or None
    require_exploit = not args.no_exploit_filter
    lang           = config.lang if hasattr(config, "lang") else "es"
    quiet          = getattr(args, "quiet", False)

    _b  = "\033[1m"  if not quiet else ""
    _r  = "\033[0m"  if not quiet else ""
    _ok = "\033[32m" if not quiet else ""
    _d  = "\033[90m" if not quiet else ""

    if not quiet:
        print(f"\n  {_b}Autonomous CVE discovery{_r}  scope={scope!r}  "
              f"cvss>={min_cvss}  days={days_back}  parallel={parallel}")
        print(f"  {_d}querying NVD → filtering → batch investigation{_r}\n")

    def _on_event(ev: dict):
        if quiet:
            return
        t = ev.get("type", "")
        if t == "discover_done":
            n = ev.get("count", 0)
            ids = ev.get("cve_ids") or []
            print(f"  {_d}[NVD] {n} candidate(s): {', '.join(ids[:8])}"
                  + (f" +{n-8} more" if n > 8 else "") + _r)
        elif t == "start":
            print(f"  {_d}[→] {ev.get('cve_id','?')}{_r}", flush=True)
        elif t == "step":
            msg = (ev.get("message") or "")[:100]
            print(f"       {_d}{msg}{_r}", flush=True)
        elif t == "finish":
            cid  = ev.get("cve_id", "?")
            stat = ev.get("status", "?")
            ela  = ev.get("elapsed_s", 0)
            tag  = (_ok + "VERIFIED" + _r) if stat == "done" else stat
            print(f"  [{tag}] {cid} ({ela:.0f}s)")

    result = autodiscover_and_investigate(
        scope=scope,
        min_cvss=min_cvss,
        days_back=days_back,
        max_candidates=max_candidates,
        parallel=parallel,
        require_exploit=require_exploit,
        severity_filter=severity,
        budget_s=budget,
        config=config,
        lang=lang,
        custom_keywords=keywords,
        on_event=_on_event,
        use_cache=not getattr(args, "no_cache", False),
    )

    summary = render_autodiscover_result(result, lang=lang)
    print("\n" + summary)

    if getattr(args, "json_out", None):
        import json as _json
        from pathlib import Path as _Path
        payload = {
            "scope": result.scope,
            "candidates": result.candidates,
            "investigated": result.investigated,
            "verified": result.verified,
            "not_confirmed": result.not_confirmed,
            "errors": result.errors,
            "elapsed_s": result.elapsed_s,
        }
        _Path(args.json_out).write_text(_json.dumps(payload, indent=2, ensure_ascii=False))
        colorlog.ok(f"resultados JSON escritos en {args.json_out}")

    if result.verified:
        _sys.exit(0)
    elif result.errors and not result.not_confirmed:
        _sys.exit(2)


def cmd_scan(args, config):
    """binoracle scan <source_dir> — static vuln scan + OSV dep audit + CVE test strategies."""
    import json as _json
    from .workflows.engine import UniversalEngine

    source_dir = args.source_dir
    cve_ids    = getattr(args, "cve_ids", None) or []
    base_url   = getattr(args, "base_url", "http://TARGET")
    max_files  = getattr(args, "max_files", 500)
    json_out   = getattr(args, "json_out", None)

    engine = UniversalEngine()
    result = engine.full_analysis(
        source_dir, cve_ids=cve_ids or None,
        base_url=base_url, max_scan_files=max_files,
    )

    print(result.summary)

    # Print test strategies
    for cid, steps in result.test_strategies.items():
        print(f"\n── {cid} ({len(steps)} steps) ──────────────────────────────")
        for s in steps:
            print(f"  [{s.order}] {s.action}")
            if s.curl:
                print(f"       $ {s.curl}")
            if s.expected:
                print(f"       => {s.expected}")

    if json_out:
        import dataclasses
        def _enc(o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            return str(o)
        with open(json_out, "w") as f:
            _json.dump(dataclasses.asdict(result), f, indent=2, default=_enc)
        print(f"\nJSON → {json_out}")

    # Dynamic verification pass: re-runs investigate_cve for each CVE with source set
    if getattr(args, "verify", False):
        from .workflows.cve_agent import investigate_cve, render_investigation
        _verify_cves = list(cve_ids or [])
        # Also pick up CVEs discovered by the OSV scan (if engine added them)
        for _dep in getattr(result, "dependency_vulns", []) or []:
            _cid = _dep.get("cve") or _dep.get("id") or ""
            if _cid and _cid not in _verify_cves:
                _verify_cves.append(_cid)
        if not _verify_cves:
            print("\n[verify] no CVE IDs to verify (pass --cve CVE-XXXX-YYYY)")
        else:
            _vlang  = getattr(args, "lang", None) or config.lang
            _vbdgt  = float(getattr(args, "budget", 300) or 300)
            print(f"\n[verify] running dynamic verification for {len(_verify_cves)} CVE(s) "
                  f"(budget={_vbdgt:.0f}s each)…")
            for _vcve in _verify_cves:
                print(f"\n  ── {_vcve} ──────────────────────────────────")
                _vinv = investigate_cve(
                    _vcve,
                    config=config,
                    on_step=lambda m: print(f"    {m}"),
                    lang=_vlang,
                    budget_s=_vbdgt,
                    hints={"source_url": source_dir},
                    use_cache=False,
                )
                _vstatus = "VERIFIED" if _vinv.verified else "not confirmed"
                print(f"  {_vcve}: {_vstatus}")
                print("  " + render_investigation(_vinv, _vlang, embed_images=False)[:1200])


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
        hints["analyst_endpoint_lock"] = True
    if getattr(args, "method", None):
        hints["http_method"] = args.method
    if getattr(args, "params", None):
        # Bug real encontrado en vivo investigando CVE-2025-57633 (FTP-Flask-python) sin LLM:
        # --params solo aceptaba nombres sueltos ("action,nonce,directory_id"), nunca un VALOR
        # concreto -- pero muchas apps reales gatean que rama de codigo se ejecuta detras de un
        # parametro acompanante con un valor LITERAL fijo (aqui, request.form['submit'] ==
        # 'Upload File'; en otras, action=X/type=Y/mode=Z). Sin forma de fijarlo a mano, el
        # analista sin LLM manda ese parametro vacio o ausente, la app nunca llega al codigo
        # vulnerable, y el verificador reporta "no confirmado" por una razon de infraestructura,
        # no porque la vulnerabilidad no exista -- confirmado en vivo: el mismo payload/endpoint
        # fallo 13/13 sin 'submit=Upload File' y confirmo la inyeccion real a la primera con el.
        # Acepta ahora "nombre=valor" ademas de "nombre" suelto (ver _parse_cli_params).
        hints["parameters"] = _parse_cli_params(args.params)
    if getattr(args, "sqli_param", None):
        hints["sqli_param"] = args.sqli_param
    if getattr(args, "cli_setup_cmd", None):
        hints["cli_setup_cmd"] = args.cli_setup_cmd
    if getattr(args, "cli_run_cmd", None):
        hints["cli_run_cmd"] = args.cli_run_cmd
    if getattr(args, "cli_argv_image", None):
        hints["cli_argv_image"] = args.cli_argv_image
    if getattr(args, "cli_argv_setup", None):
        hints["cli_argv_setup"] = args.cli_argv_setup
    if getattr(args, "cli_argv", None):
        import json as _json
        hints["cli_argv"] = _json.loads(args.cli_argv)
    if getattr(args, "cli_payload_index", None) is not None:
        hints["cli_payload_index"] = args.cli_payload_index
    if getattr(args, "unauthenticated_login_bypass", False):
        hints["unauthenticated_login_bypass"] = True
    if getattr(args, "victim_role", None):
        hints["victim_role"] = args.victim_role
    if getattr(args, "bypass_header", None):
        hints["bypass_header"] = args.bypass_header
    if getattr(args, "bypass_value", None):
        hints["bypass_value"] = args.bypass_value
    if getattr(args, "confirm_string", None):
        hints["confirm_string"] = args.confirm_string
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
    _inv_lang   = getattr(args, "lang", None) or config.lang
    _inv_budget = float(getattr(args, "budget", 300) or 300)
    _inv_cve    = args.cve.upper() if hasattr(args, "cve") else args.cve
    _inv_binary = getattr(args, "binary", "") or ""
    _use_col    = _color_ok()
    _b2 = "\033[1m" if _use_col else ""
    _r2 = "\033[0m" if _use_col else ""
    _d2 = "\033[2m" if _use_col else ""
    if not getattr(args, "no_chain", False):
        from .workflows.auto_chain import run_full_chain
        _cr = run_full_chain(
            _inv_cve,
            binary=_inv_binary,
            lang=_inv_lang,
            budget_s=_inv_budget,
            on_step=lambda m: colorlog.line(m),
            config=config,
            no_cache=getattr(args, "no_cache", False),
            hints=hints or None,
        )
        _print_chain_verdict(_cr, _inv_cve, _cr.elapsed_s, _use_col, _b2, _r2, _d2, colorlog)
        if getattr(args, "json", None):
            import json as _json2
            from pathlib import Path as _P2
            import dataclasses as _dc2
            _P2(args.json).write_text(_json2.dumps({
                "cve_id": _cr.cve_id, "verified": _cr.verified,
                "engine_confidence": _cr.engine_confidence,
                "evidence": _cr.evidence, "report_path": _cr.report_path,
                "steps": [_dc2.asdict(s) for s in _cr.steps],
            }, indent=2, ensure_ascii=False, default=str))
            colorlog.ok(f"JSON → {args.json}")
        return
    inv = investigate_cve(_inv_cve, binary=_inv_binary,
                          config=config, on_step=lambda m: colorlog.line(m), lang=_inv_lang,
                          budget_s=_inv_budget, hints=hints or None,
                          use_cache=not getattr(args, "no_cache", False))
    # el terminal no puede pintar imagenes: embed_images=False cambia cada captura por un aviso
    # corto en vez de volcar decenas de KB de base64 como texto ilegible. El export HTML (abajo)
    # SI usa embed_images=True (el default), esas son las que de verdad se pintan como <img>.
    # Capturas inline en iTerm2/Kitty si las hay
    _vshots2 = (getattr(inv, "verified_evidence", {}) or {}).get("screenshots") or []
    _ashots2 = (getattr(inv, "attempt_evidence", {}) or {}).get("screenshots") or []
    _term_shots2 = list(_vshots2) + [s for s in _ashots2 if s not in _vshots2]
    if _term_shots2:
        import base64 as _b64m2, os as _os2
        _tp2 = _os2.environ.get("TERM_PROGRAM", "") or _os2.environ.get("TERM", "")
        _iterm22 = "iterm" in _tp2.lower() or _os2.environ.get("ITERM_SESSION_ID", "")
        _kitty2 = _os2.environ.get("KITTY_WINDOW_ID", "") or "kitty" in _tp2.lower()
        print(f"\n  Capturas paso a paso ({len(_term_shots2)}):")
        for i2, _sh2 in enumerate(_term_shots2):
            _png2 = _sh2.get("png_b64")
            _cap2 = _sh2.get("caption_es" if config.lang == "es" else "caption_en") or ""
            print(f"    Paso {i2+1}: {_cap2[:90]}")
            if _sh2.get("url"):
                print(f"      URL: {_sh2['url'][:80]}")
            if _png2:
                if _iterm22:
                    _raw2 = _b64m2.b64decode(_png2)
                    _enc2 = _b64m2.b64encode(_raw2).decode("ascii")
                    print(f"\033]1337;File=inline=1;width=80;height=20;preserveAspectRatio=1:{_enc2}\a")
                elif _kitty2:
                    try:
                        import subprocess as _sp2, tempfile as _tf2
                        with _tf2.NamedTemporaryFile(suffix=".png", delete=False) as _tmp2:
                            _tmp2.write(_b64m2.b64decode(_png2))
                            _tp2n = _tmp2.name
                        _sp2.run(["kitty", "+kitten", "icat", "--align=left", _tp2n],
                                 check=False, timeout=5)
                        _os2.unlink(_tp2n)
                    except Exception:
                        pass
                else:
                    _kb2 = len(_png2) * 3 // 4 // 1024
                    print(f"      [~{_kb2} KB — usa -o report.html para ver la imagen]")
    # Siempre imprime el resumen en terminal (sin imágenes base64)
    print("\n" + render_investigation(inv, config.lang, embed_images=False))
    if getattr(args, "html", None):
        from .report.html import render_investigation_page
        md_full = render_investigation(inv, config.lang)
        Path(args.html).write_text(
            render_investigation_page(md_full, script=inv.developed_script, cve=args.cve,
                                      lang=config.lang, poc_kind=inv.poc_kind, inv=inv),
            encoding="utf-8")
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
                                      out_dir: Path, html_dir, use_cache: bool,
                                      use_chain: bool = False):
    """Nucleo compartido de investigate-batch e investigate-watch: lanza investigate_cves_batch
    sobre `cve_ids`, escribe un informe por CVE en `out_dir` (y en `html_dir` si se da), imprime
    el progreso en vivo y la tabla resumen al final. Devuelve los BatchItem resultantes.

    Si use_chain=True, usa run_full_chain (8 etapas) en vez de investigate_cves_batch;
    la concurrencia se hace con ThreadPoolExecutor igual que el batch normal."""

    if use_chain:
        from .workflows.auto_chain import run_full_chain
        from concurrent.futures import ThreadPoolExecutor, as_completed
        colorlog.info(f"lanzando {len(cve_ids)} cadenas completas (chain mode) "
                      f"con paralelismo {min(parallel, 2)}...")
        _chain_par = min(parallel, 2)  # chain es más pesada, cap más conservador

        def _run_one(cve_id):
            colorlog.info(f"[{cve_id}] iniciando cadena completa...")
            cr = run_full_chain(cve_id, lang=config.lang, budget_s=budget_s,
                                on_step=lambda m: colorlog.line(f"[{cve_id}] {m}"),
                                config=config, no_cache=not use_cache)
            colorlog.ok(f"[{cve_id}] cadena terminada — verified={cr.verified} "
                        f"conf={cr.engine_confidence:.0%}")
            # Write report
            if cr.report_md:
                (out_dir / f"{cve_id}.md").write_text(cr.report_md)
            import json as _j
            (out_dir / f"{cve_id}.json").write_text(_j.dumps({
                "cve_id": cr.cve_id, "verified": cr.verified,
                "engine_confidence": cr.engine_confidence,
                "cve_class": cr.cve_class, "cvss_score": cr.cvss_score,
                "evidence": cr.evidence, "report_path": cr.report_path,
            }, indent=2, ensure_ascii=False, default=str))
            if html_dir:
                _export_chain_html(cr, str(html_dir / f"{cve_id}.html"), cve_id, config.lang)
            return cr

        chain_results = []
        with ThreadPoolExecutor(max_workers=_chain_par) as _ex:
            futures = {_ex.submit(_run_one, cid): cid for cid in cve_ids}
            for fut in as_completed(futures):
                try:
                    chain_results.append(fut.result())
                except Exception as e:
                    colorlog.error(f"[{futures[fut]}] error en chain: {e}")

        verified = sum(1 for r in chain_results if r.verified)
        print("\n── Resumen del lote (chain) ──────────────────────────────────")
        for cr in chain_results:
            icon = "✓" if cr.verified else "✗"
            print(f"  {icon} {cr.cve_id:<25} conf={cr.engine_confidence:.0%}  "
                  f"clase={cr.cve_class or '?'}")
        print(f"  Verificados: {verified}/{len(chain_results)}")
        colorlog.info(f"informes en {out_dir}/" + (f" y HTML en {html_dir}/" if html_dir else ""))
        return chain_results

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
                                          poc_kind=it.investigation.poc_kind),
                encoding="utf-8")

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
        html_dir, not getattr(args, "no_cache", False),
        use_chain=bool(getattr(args, "chain", False)))


def cmd_investigate_never_attempted(args, config):
    """Verifica CVEs que tienen hipótesis LLM pero nunca pasaron por el verificador dinámico."""
    from .workflows.auto_chain import process_never_attempted_cves
    max_cves  = int(getattr(args, "max_cves", 10) or 10)
    min_cvss  = float(getattr(args, "min_cvss", 7.0) or 7.0)
    budget_s  = float(getattr(args, "budget", 300) or 300)
    lang      = getattr(args, "lang", "es") or "es"
    reports   = getattr(args, "reports_dir", "binoracle_batch_reports") or "binoracle_batch_reports"
    results   = process_never_attempted_cves(
        max_cves=max_cves, min_cvss=min_cvss, lang=lang,
        budget_s=budget_s, reports_dir=reports, on_step=print)
    verified = sum(1 for r in results if r.verified)
    print(f"\nTotal: {len(results)} CVEs procesados, {verified} verificados")


def cmd_reanalyze_failed(args, config):
    """Re-analyze CVEs that were attempted but failed — feeds real HTTP evidence to the LLM."""
    from .workflows.auto_chain import reanalyze_failed_cves
    max_cves  = int(getattr(args, "max_cves", 5) or 5)
    min_cvss  = float(getattr(args, "min_cvss", 7.0) or 7.0)
    budget_s  = float(getattr(args, "budget", 400) or 400)
    lang      = getattr(args, "lang", "es") or "es"
    reports   = getattr(args, "reports_dir", "binoracle_batch_reports") or "binoracle_batch_reports"
    results   = reanalyze_failed_cves(
        max_cves=max_cves, min_cvss=min_cvss, lang=lang,
        budget_s=budget_s, reports_dir=reports, on_step=print)
    verified = sum(1 for r in results if r.verified)
    print(f"\nTotal: {len(results)} CVEs reanalizado, {verified} verificados")


def cmd_nvd_watch(args, config):
    """Fully autonomous mode: polls NVD API for new high-severity CVEs and investigates each."""
    import time as _time
    from .workflows.auto_chain import auto_queue_nvd, retry_failed_cves, process_never_attempted_cves

    days_back  = int(getattr(args, "days_back", 2) or 2)
    min_cvss   = float(getattr(args, "min_cvss", 7.0) or 7.0)
    max_cves   = int(getattr(args, "max_cves", 10) or 10)
    interval   = float(getattr(args, "interval", 3600) or 3600)
    once       = bool(getattr(args, "once", False))
    web_only   = not bool(getattr(args, "all_stacks", False))
    priority   = getattr(args, "priority", "cvss") or "cvss"
    budget_s   = float(getattr(args, "budget", 300) or 300)
    lang       = getattr(args, "lang", "es") or "es"
    do_retry           = bool(getattr(args, "retry", False))
    do_never_attempted = bool(getattr(args, "never_attempted", False))

    def _step(msg):
        print(msg, flush=True)

    _step(f"binoracle nvd-watch: CVSS≥{min_cvss}, últimos {days_back}d, "
          f"cada {interval/60:.0f}min, prioridad={priority}")

    while True:
        _step(f"\n{'='*60}")
        _step("nvd-watch: consultando NVD...")
        results = auto_queue_nvd(
            days_back=days_back, min_cvss=min_cvss, max_cves=max_cves,
            web_only=web_only, lang=lang, budget_s=budget_s,
            priority_mode=priority, on_step=_step)
        verified = sum(1 for r in results if r.verified)
        _step(f"nvd-watch: {len(results)} CVEs procesados, {verified} verificados")
        # Summary table of this cycle's results
        if results:
            _step("\n┌──────────────────────────────────────────────────────────────")
            _step(f"│ RESUMEN DEL CICLO ({len(results)} CVEs):")
            _step("├──────────────────────────────────────────────────────────────")
            _step("│  CVE-ID               Resultado      Conf  Clase")
            _step("├──────────────────────────────────────────────────────────────")
            for _r in results:
                _st = "✓ VERIF." if _r.verified else "✗ no conf"
                _conf = f"{int(_r.engine_confidence * 100)}%"
                _cls = (_r.cve_class or "?")[:18]
                _cid = _r.cve_id[:22]
                _step(f"│  {_cid:<22} {_st:<14} {_conf:<5} {_cls}")
            _step("└──────────────────────────────────────────────────────────────")

        if do_retry:
            _step("nvd-watch: reintentando cola de fallos transitorios...")
            retry_results = retry_failed_cves(max_cves=5, lang=lang,
                                              budget_s=budget_s, on_step=_step)
            _step(f"nvd-watch: {len(retry_results)} CVEs reintentados")

        if do_never_attempted:
            _step("nvd-watch: procesando CVEs nunca intentados del historial...")
            _na_results = process_never_attempted_cves(
                max_cves=5, min_cvss=min_cvss, lang=lang,
                budget_s=budget_s, on_step=_step)
            _step(f"nvd-watch: {len(_na_results)} CVEs nunca intentados procesados")

        # Send Telegram cycle summary if BINORACLE_TELEGRAM_TOKEN + CHAT_ID are set
        import os as _os_tg, json as _json_tg
        try:
            import urllib.request as _ureq
        except Exception:
            _ureq = None  # type: ignore
        _tg_token = (_os_tg.environ.get("BINORACLE_TELEGRAM_TOKEN") or
                     (config or {}).get("telegram_token", ""))
        _tg_chat  = (_os_tg.environ.get("BINORACLE_TELEGRAM_CHAT_ID") or
                     (config or {}).get("telegram_chat_id", ""))
        if _tg_token and _tg_chat and results and _ureq:
            try:
                _verif_cves = [r for r in results if r.verified]
                _cycle_msg = (
                    f"binoracle nvd-watch — ciclo completado\n"
                    f"CVEs: {len(results)} | Verificados: {len(_verif_cves)}\n"
                )
                if _verif_cves:
                    _cycle_msg += "\nVERIFICADOS:\n"
                    for _vr in _verif_cves[:5]:
                        _cycle_msg += (f"  OK {_vr.cve_id} CVSS={_vr.cvss_score} "
                                       f"conf={int(_vr.engine_confidence*100)}%\n")
                _high_conf = [r for r in results
                              if not r.verified and r.engine_confidence >= 0.60]
                if _high_conf:
                    _cycle_msg += "\nAlta confianza (no verif.):\n"
                    for _hr in _high_conf[:3]:
                        _cycle_msg += (f"  ? {_hr.cve_id} "
                                       f"conf={int(_hr.engine_confidence*100)}%\n")
                _tg_url = f"https://api.telegram.org/bot{_tg_token}/sendMessage"
                _tg_body = _json_tg.dumps({"chat_id": _tg_chat, "text": _cycle_msg}).encode()
                _tg_req = _ureq.Request(
                    _tg_url, data=_tg_body,
                    headers={"Content-Type": "application/json"}, method="POST")
                with _ureq.urlopen(_tg_req, timeout=8):
                    pass
                _step("nvd-watch: resumen del ciclo enviado por Telegram")
            except Exception as _tg_e:
                _step(f"nvd-watch: Telegram: {_tg_e}")

        if once:
            break
        _step(f"nvd-watch: próximo ciclo en {interval/60:.0f} min...")
        _time.sleep(interval)


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
                use_cache, use_chain=bool(getattr(args, "chain", False)))
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

    cv = sub.add_parser("cve-corpus",
                        help="seed a libFuzzer corpus from a CVE investigation (PoC + NVD description)")
    cv.add_argument("cve_id", help="CVE identifier (e.g. CVE-2025-27516)")
    cv.add_argument("--func", default="target_function", dest="target_func",
                    help="name of the C function to fuzz (skeleton target)")
    cv.add_argument("--hint", default="", help="short hint about the input format")
    cv.add_argument("--out", default=".", dest="out_dir",
                    help="output directory for the corpus (default: .)")
    cv.add_argument("--poc", default="", dest="poc_file",
                    help="path to a file containing the PoC text (optional)")
    cv.set_defaults(func=cmd_cve_corpus)

    ft = sub.add_parser("finetune",
                        help="export CVE investigations as a LoRA fine-tuning dataset for exploit hypothesis generation")
    ft.add_argument("--reports-dir", default="", dest="reports_dir",
                    help="directory of binoracle JSON report files to include")
    ft.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct", dest="model_id",
                    help="HuggingFace model ID for the LoRA script")
    ft.add_argument("--out", default=".", dest="out_dir",
                    help="output directory for train.jsonl, val.jsonl, run_lora.py")
    ft.set_defaults(func=cmd_finetune)

    ke = sub.add_parser("kernel-exploit",
                        help="generate a kernel exploit chain skeleton (ret2usr, UAF, ROP, dirty-pipe, ...)")
    ke.add_argument("cve_id", nargs="?", default="",
                    help="CVE identifier — NVD description auto-selects the primitive")
    ke.add_argument("--primitive", default="",
                    choices=["ret2usr", "uaf_driver", "heap_spray", "rop_chain",
                             "modprobe_path", "msg_msg", "seq_operations",
                             "dirty_pipe", "io_uring", ""],
                    help="force a specific exploit primitive (default: auto-detect from NVD description)")
    ke.set_defaults(func=cmd_kernel_exploit)

    fw = sub.add_parser("firmware",
                        help="analyze firmware images: UEFI (.fd/.efi), SquashFS, JFFS2, uImage, raw flash")
    fw.add_argument("image", help="path to the firmware file")
    fw.add_argument("--out", default="", dest="out_dir",
                    help="directory for extracted contents (default: auto temp dir)")
    fw.set_defaults(func=cmd_firmware)

    ch = sub.add_parser("cve-chain",
                        help="run a multi-CVE exploit chain (web RCE → local privesc → ...)")
    ch.add_argument("cves", nargs="+",
                    help="ordered CVE IDs forming the chain (e.g. CVE-2021-44228 CVE-2021-4034)")
    ch.add_argument("--out", default=".", dest="out_dir",
                    help="output directory for per-CVE HTML reports (default: .)")
    ch.set_defaults(func=cmd_cve_chain)

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

    wv = sub.add_parser("web", help="launch the CVE verification web UI with live log streaming and PDF export")
    wv.add_argument("--host", default="127.0.0.1")
    wv.add_argument("--port", type=int, default=8000)
    wv.add_argument("--no-open", action="store_true", help="do not auto-open the browser")
    wv.set_defaults(func=cmd_cve_web)

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
    ak.add_argument("--extract-libs", metavar="DIR",
                    help="extract the APK's native .so libraries (real ELF binaries, same "
                         "memory-corruption surface as any other binary) into DIR/<abi>/, "
                         "ready to point `binoracle hunt`/`cveplan`/`autopwn` at directly")
    ak.add_argument("--abi", default="", help="with --extract-libs, only this ABI (e.g. arm64-v8a); default: all")
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

    pep = sub.add_parser("phpestate", help="PHP exposure/triage: inventory local PHP interpreters "
                                           "(and, opt-in, a remote host's headers) and classify "
                                           "EOL/BEHIND/CURRENT against php.net's own release data "
                                           "-- inventory only, never an exploit")
    pep.add_argument("paths", nargs="*", help="root path(s) or direct php binary path(s) to scan; "
                                              "default: PATH + common install layouts")
    pep.add_argument("--url", help="remote HTTP(S) URL to passively fingerprint (headers/cookies "
                                   "only, one GET, requires --authorized)")
    pep.add_argument("--authorized", action="store_true",
                     help="REQUIRED alongside --url: confirms you are authorized to test that "
                          "host. Without it, --url is accepted but no request is ever sent.")
    pep.add_argument("--json", help="also write machine-readable findings to this path")
    pep.add_argument("--output", help="also write the rendered findings to this path")
    pep.set_defaults(func=cmd_phpestate)

    cv = sub.add_parser("cve", help="SHORTCUT: binoracle cve <CVE-ID> — full autonomous investigation "
                                   "with structured real-time logs (timestamps, phase headers, verdict box)")
    cv.add_argument("cve", help="CVE id (e.g. CVE-2025-59681)")
    cv.add_argument("--source", help="source dir / plugin slug / git URL for the vulnerable code")
    cv.add_argument("--endpoint", help="vulnerable HTTP endpoint")
    cv.add_argument("--method", help="HTTP method override (omit to let binoracle detect it)")
    cv.add_argument("--params", help="comma-separated request parameters (name or name=value)")
    cv.add_argument("--vuln-class", help="known vuln class (sqli, rce, xxe, missing-authorization...)")
    cv.add_argument("--custom-headers", dest="custom_headers",
                    help="JSON dict of custom HTTP headers the attack needs "
                         '(e.g. \'{"X-Wcpay-Platform-Checkout-User":"1"}\' for CVE-2023-28121)')
    cv.add_argument("--companion-plugins", dest="companion_plugins",
                    help="Comma-separated WordPress.org plugin slugs to install BEFORE the main "
                         "plugin in the lab (e.g. 'woocommerce' for WooCommerce extensions). "
                         "Auto-detected from source, but needed when the dependency uses "
                         "function_exists() instead of is_plugin_active().")
    cv.add_argument("--setup-wp-option", action="append", dest="setup_wp_options",
                    metavar="OPTION=VALUE or OPTION[KEY]=VALUE",
                    help="set a WordPress option before the SQLi test (repeatable). "
                         "Use OPTION=VALUE for top-level options or OPTION[KEY]=VALUE for "
                         "nested options in a serialised array -- e.g. "
                         "\"learnpress[get_courses_of_subcategory]=yes\"")
    cv.add_argument("--budget", type=float, default=600,
                    help="verification budget in seconds (default 600)")
    cv.add_argument("--target-url", dest="target_url",
                    help="URL base de un objetivo ya corriendo (salta el lab Docker efimero). "
                         "Usar cuando el objetivo esta levantado manualmente, ej. "
                         "'http://localhost:1337'. El motor hace las peticiones directamente "
                         "contra esa URL sin construir ni arrancar ningun contenedor.")
    cv.add_argument("--no-cache", action="store_true", help="force fresh investigation (no cache)")
    cv.add_argument("--no-chain", action="store_true",
                    help="skip the full 8-stage chain and use the faster single-stage "
                         "investigate_cve instead (useful for quick checks or when Docker is "
                         "not available)")
    cv.add_argument("--lang", default=None, choices=["es", "en"],
                    help="report language (default: from config, usually 'es')")
    cv.add_argument("-o", "--html", help="export full HTML report (with screenshots) to this path")
    cv.add_argument("--json", dest="json_out", help="dump full evidence JSON to this path")
    cv.add_argument("-q", "--quiet", action="store_true",
                    help="no imprime pasos en vivo; solo muestra el veredicto final")
    cv.set_defaults(func=cmd_cve)

    ad = sub.add_parser("autodiscover",
                        help="Autonomous CVE discovery: NVD keyword search + batch investigation "
                             "without specifying individual CVE IDs")
    ad.add_argument("scope",
                    help="Technology scope: wordpress-plugin, python-flask, python-django, nodejs, "
                         "php, java-spring, ruby-rails, apache, nginx, docker, kubernetes, "
                         "linux-kernel — or any free-form keyword")
    ad.add_argument("--min-cvss",  type=float, default=8.5, dest="min_cvss",
                    help="Minimum CVSS base score (default 8.5)")
    ad.add_argument("--days",      type=int,   default=90,
                    help="Search window in days back from today (default 90)")
    ad.add_argument("--max-candidates", type=int, default=20, dest="max_candidates",
                    help="Max CVEs to investigate (default 20)")
    ad.add_argument("--parallel",  type=int,   default=2,
                    help="Parallel investigation workers (default 2)")
    ad.add_argument("--severity",  default="CRITICAL",
                    help="NVD severity filter: CRITICAL|HIGH|MEDIUM|LOW (default CRITICAL)")
    ad.add_argument("--budget",    type=float, default=600,
                    help="Verification budget per CVE in seconds (default 600)")
    ad.add_argument("--no-exploit-filter", action="store_true",
                    help="Include CVEs without a confirmed public PoC")
    ad.add_argument("--keywords",  nargs="+",
                    help="Override scope preset with custom NVD keyword(s)")
    ad.add_argument("--no-cache",  action="store_true",
                    help="Force fresh investigation (skip cache)")
    ad.add_argument("--json", dest="json_out",
                    help="Dump results JSON to this path")
    ad.add_argument("-q", "--quiet", action="store_true",
                    help="Only print the final summary")
    ad.set_defaults(func=cmd_autodiscover)

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
    ip.add_argument("--params", help="comma-separated request parameters: bare names "
                                     "(id,email) or name=value when a companion parameter needs "
                                     "a specific literal to even reach the vulnerable code path "
                                     "(e.g. submit=Upload File,ftp_file) -- mixing both is fine")
    ip.add_argument("--sqli-param", help="for --vuln-class sqli: the exact parameter name to "
                                         "inject into, overriding the automatic guess -- needed "
                                         "when --params also carries OTHER required parameters "
                                         "(e.g. a real directory/resource id the endpoint "
                                         "validates before reaching the vulnerable sink) whose "
                                         "name would otherwise be picked over the real "
                                         "injectable one by the generic id/search/sort heuristic")
    ip.add_argument("--setup-wp-option", action="append", dest="setup_wp_options",
                    metavar="OPTION=VALUE or OPTION[KEY]=VALUE",
                    help="set a WordPress option before the SQLi test (repeatable). "
                         "Use OPTION=VALUE for top-level options (wp option update) or "
                         "OPTION[KEY]=VALUE for nested options in a serialised array "
                         "(wp option patch insert) -- e.g. "
                         "\"learnpress[get_courses_of_subcategory]=yes\"")
    ip.add_argument("--cli-setup-cmd", help="for a command-injection CVE in a LOCAL CLI tool "
                                            "(no HTTP endpoint at all, e.g. a CVE in an npm/pip "
                                            "package's own CLI): shell command that prepares a "
                                            "disposable work dir with the exact version to check, "
                                            "e.g. 'npm install glob@11.0.0' -- run once, before "
                                            "anything else. Requires --cli-run-cmd too")
    ip.add_argument("--cli-run-cmd", help="paired with --cli-setup-cmd: shell command that "
                                          "invokes the tool exactly as an analyst would, e.g. "
                                          "'node node_modules/.bin/glob -c echo \"**/*\"' -- run "
                                          "after planting a file whose NAME is the payload; "
                                          "verified if a canary file appears in the work dir "
                                          "(see cliverify.py)")
    ip.add_argument("--cli-argv-image", help="for a CVE where the payload is the VALUE of a CLI "
                                            "argument (not a filename): the Docker image to run "
                                            "the tool in, e.g. 'node:20-slim' (see "
                                            "cliverify.verify_cli_argv_command_injection)")
    ip.add_argument("--cli-argv-setup", help="paired with --cli-argv-image: shell command run "
                                            "once (with network) to install the exact version "
                                            "to check, e.g. 'npm install "
                                            "@cyclonedx/cyclonedx-npm@4.0.0'")
    ip.add_argument("--cli-argv", help="paired with --cli-argv-image/--cli-payload-index: the "
                                      "full argv to run the tool with, as a JSON array, e.g. "
                                      "'[\"node\", \"node_modules/.bin/cyclonedx-npm\", "
                                      "\"--workspace\", \"PLACEHOLDER\"]' -- the element at "
                                      "--cli-payload-index is replaced with the real payload")
    ip.add_argument("--cli-payload-index", type=int,
                    help="index into --cli-argv whose value is the injectable argument")
    ip.add_argument("--unauthenticated-login-bypass", action="store_true",
                    help="WordPress missing-authorization/idor only: the endpoint needs NO "
                         "prior session at all (fully public/unauthenticated) and lets an "
                         "attacker log in as an existing user by supplying only a non-secret "
                         "identifier (typically their email) via --params, with no real "
                         "credential/token validated -- a THIRD pattern distinct from both "
                         "the credential-change and the by-ID login-as account-takeover (set "
                         "this explicitly; it is never guessed from --params alone, since an "
                         "email+password pair there could just as easily mean 'change this "
                         "admin's credential', the existing account-takeover pattern)")
    ip.add_argument("--victim-role", default="",
                    help="with --unauthenticated-login-bypass: the exact WordPress role the "
                         "victim account needs for the plugin's own endpoint to accept it "
                         "(default: subscriber) -- some plugins gate the endpoint's success "
                         "path on a role THEY define (e.g. a 'patient' role), not any "
                         "logged-in user")
    ip.add_argument("--bypass-header", default="",
                    help="nombre de la cabecera HTTP maliciosa para un bypass de autorizacion "
                         "via cabecera (p.ej. 'x-middleware-subrequest' para CVE-2025-29927). "
                         "Requiere --bypass-value. Activa verify_generic_header_bypass en "
                         "cve_agent al combinar con --source de un directorio/repo con Dockerfile.")
    ip.add_argument("--bypass-value", default="",
                    help="valor exacto de --bypass-header (p.ej. "
                         "'middleware:middleware:middleware:middleware:middleware')")
    ip.add_argument("--confirm-string", default="",
                    help="cadena que debe aparecer en la respuesta con bypass para "
                         "confirmar acceso real (vacia = solo se comprueba que el "
                         "status sea 2xx). Combinada con --bypass-header.")
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
    ip.add_argument("--lang", default=None, choices=["es", "en"],
                    help="report language override (default: from config)")
    ip.add_argument("--no-chain", action="store_true",
                    help="use the faster single-stage investigate_cve instead of the full "
                         "8-stage chain (default is chain mode)")
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
    ipb.add_argument("--chain", action="store_true",
                     help="use run_full_chain (8-stage autonomous pipeline) for each CVE "
                          "instead of investigate_cve; slower but produces richer reports "
                          "and feeds ~/.binoracle/history/")
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
    ipw.add_argument("--chain", action="store_true",
                     help="use run_full_chain (8-stage) for each CVE the watch discovers "
                          "instead of investigate_cve; produces full reports + feeds history/")
    ipw.set_defaults(func=cmd_investigate_watch)

    ina = sub.add_parser("investigate-never-attempted",
                          help="re-run full chain on CVEs that were investigated but never verified — "
                               "picks up batch-report JSONs with no attempt_evidence and re-tests them")
    ina.add_argument("--max-cves", type=int, default=10,
                     help="maximum CVEs to process in one run (default 10)")
    ina.add_argument("--min-cvss", type=float, default=7.0,
                     help="minimum CVSS score (default 7.0)")
    ina.add_argument("--budget", type=float, default=300,
                     help="verification budget in seconds per CVE (default 300)")
    ina.add_argument("--lang", choices=["es", "en"], default="es")
    ina.add_argument("--reports-dir", default="binoracle_batch_reports",
                     help="directory containing the batch JSON reports (default binoracle_batch_reports)")
    ina.set_defaults(func=cmd_investigate_never_attempted)

    raf = sub.add_parser("re-analyze-failed",
                         help="re-analyze CVEs that were attempted but failed — "
                              "feeds real HTTP evidence to the LLM to repair the hypothesis "
                              "and re-runs the verifier with the corrected parameters")
    raf.add_argument("--max-cves", type=int, default=5,
                     help="maximum CVEs to process in one run (default 5)")
    raf.add_argument("--min-cvss", type=float, default=7.0,
                     help="minimum CVSS score to consider (default 7.0)")
    raf.add_argument("--budget", type=float, default=400,
                     help="verification budget in seconds per CVE (default 400)")
    raf.add_argument("--lang", choices=["es", "en"], default="es")
    raf.add_argument("--reports-dir", default="binoracle_batch_reports",
                     help="directory containing the batch JSON reports (default binoracle_batch_reports)")
    raf.set_defaults(func=cmd_reanalyze_failed)

    nvdw = sub.add_parser("nvd-watch", help="poll NVD API for new high-severity web CVEs and "
                                            "auto-investigate each — fully autonomous mode: "
                                            "no manual CVE input needed, runs forever")
    nvdw.add_argument("--days-back", type=int, default=2,
                      help="look back this many days for new CVEs (default 2)")
    nvdw.add_argument("--min-cvss", type=float, default=7.0,
                      help="minimum CVSS score to process (default 7.0)")
    nvdw.add_argument("--max-cves", type=int, default=10,
                      help="max CVEs to process per poll cycle (default 10)")
    nvdw.add_argument("--interval", type=float, default=3600,
                      help="seconds between NVD polls (default 3600 = 1h, NVD allows ~100 "
                           "req/day without API key)")
    nvdw.add_argument("--once", action="store_true",
                      help="poll once and exit instead of looping")
    nvdw.add_argument("--all-stacks", action="store_true",
                      help="process all CVEs, not just web-related ones")
    nvdw.add_argument("--priority", default="cvss",
                      choices=["cvss", "new", "cms", "epss+kev", "exploitation"],
                      help=("sort order: cvss (default), new (newest first), cms (CMS first), "
                            "epss+kev / exploitation (CISA KEV + EPSS score — highest "
                            "real-world exploitation probability first)"))
    nvdw.add_argument("--budget", type=float, default=300,
                      help="investigation budget per CVE in seconds (default 300)")
    nvdw.add_argument("--lang", default="es", choices=["es", "en"],
                      help="report language (default es)")
    nvdw.add_argument("--retry", action="store_true",
                      help="also retry previously failed CVEs from the retry queue")
    nvdw.add_argument("--never-attempted", dest="never_attempted", action="store_true",
                      help="also process CVEs in batch reports that were investigated but never verified")
    nvdw.set_defaults(func=cmd_nvd_watch)

    sc2 = sub.add_parser("scan", help="static security scan + dependency audit + CVE test strategies "
                                      "for a source directory (wraps the Universal Engine full_analysis)")
    sc2.add_argument("source_dir", help="path to the source directory to audit")
    sc2.add_argument("--cve", action="append", dest="cve_ids", metavar="CVE-ID",
                     help="CVE ID to include in test strategies (can be repeated)")
    sc2.add_argument("--base-url", default="http://TARGET",
                     help="base URL for curl commands in test strategies (default: http://TARGET)")
    sc2.add_argument("--max-files", type=int, default=500,
                     help="max files to scan for static findings (default 500)")
    sc2.add_argument("--json", dest="json_out", help="dump full result as JSON to this path")
    sc2.add_argument("--verify", action="store_true",
                     help="after static scan, automatically run investigate_cve on each CVE found "
                          "in --cve or discovered via OSV, using the scanned source as --source; "
                          "requires Docker for dynamic lab verification")
    sc2.add_argument("--budget", type=float, default=300,
                     help="verification budget per CVE when --verify is used (default 300s)")
    sc2.add_argument("--lang", default=None, choices=["es", "en"],
                     help="report language when --verify is used (default: from config)")
    sc2.set_defaults(func=cmd_scan)

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
    # `main()` returns an int exit code throughout (130/0/1 here, plus every subcommand's own
    # sys.exit(N)) -- but a bare SystemExit from one of those already bypasses this module-level
    # call either way, so the int path only mattered for the generic `except Exception` below.
    # Without sys.exit(), `python3 -m binoracle.cli ...` always exited 0 regardless of what
    # main() returned: an unexpected error printed "error inesperado: ..." to stderr but the
    # process still reported success, silently breaking any script checking $? (confirmed live
    # running batches of `ask`/`hunt` over real CTF targets -- a crashed run looked identical to
    # a clean one to the calling shell). The installed `binoracle` console-script entry point
    # was never affected: setuptools' generated wrapper already does sys.exit(main()) itself.
    sys.exit(main())
