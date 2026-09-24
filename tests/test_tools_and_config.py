"""Toolchain detection, RAG runtime config, and web command surface."""

from binoracle.toolcheck import check_tools, render, ToolStatus
from binoracle.rag import get_kb, configure


def test_toolcheck_runs():
    st = check_tools()
    assert isinstance(st, list) and len(st) >= 12
    assert all(isinstance(x, ToolStatus) for x in st)
    # core oracles are always in the catalog (present or not)
    names = {x.name for x in st}
    assert any("radare2" in n for n in names)
    assert any("pwntools" in n for n in names)


def test_toolcheck_render():
    out = render(check_tools())
    assert "toolchain de pentest" in out
    assert "Estatico" in out or "static" in out.lower()


def test_rag_configure_toggles():
    kb = get_kb()
    # expand/rerank flip without needing a model (embed left untouched)
    configure(expand=True, rerank=True)
    assert kb._use_expand_llm is True and kb._use_rerank is True
    configure(expand=False, rerank=False)
    assert kb._use_expand_llm is False and kb._use_rerank is False


def test_rag_status_string():
    s = get_kb().status()
    assert "TF-IDF" in s and "chunks" in s


def test_secrets_scanner():
    # El scanner de credenciales detecta patrones reales y no dispara con placeholders.
    from binoracle.workflows.secrets import scan_secrets
    from binoracle.oracles.base import ToolResult

    class _Tool:
        def run(self):
            return ToolResult(True, "radare2: izz",
                              "AKIAIOSFODNN7EXAMPLE\npassword=SuperSecret123\n"
                              "password=changeme\napi_key=your_key_here")

    class _Reg:
        def get(self, name):
            return _Tool() if name == "r2_strings" else None

    fs = scan_secrets(_Reg(), "x")
    titles = " ".join(f.title.lower() for f in fs)
    assert any("aws" in t.lower() for t in [f.title for f in fs]), "no detecto la AWS key"
    assert any("credencial" in f.title.lower() for f in fs), "no detecto la password real"
    # placeholders (changeme / your_key_here) NO deben generar hallazgo
    joined = " ".join(f.evidence for f in fs)
    assert "changeme" not in joined and "your_key_here" not in joined


def test_ingest_classify():
    # El clasificador de aprendizaje automatico: binario-RE se queda, web/routers fuera,
    # chino a traducir.
    from binoracle.ingest import classify
    arm = ("# AArch64 reversing\n## Workflow\nDisassemble the ELF with objdump, load it in "
           "Ghidra, trace the ROP gadget and the syscall boundary. Recover the struct layout "
           "and rename functions. Use frida to hook the native library at runtime.\n" * 3)
    assert classify("arm64-reversing/SKILL.md", arm)[0] == "keep"
    assert classify("vendor-cloudflare-turnstile/SKILL.md", "captcha bypass")[0] == "drop"
    assert classify("sqli-playbook.md",
                    "SQL injection via GraphQL and SSRF and JWT and XSS")[0] == "drop"
    assert classify("ida-reverse/SKILL.md",
                    "## ACTION REQUIRED\nNOW: run start.ps1\nhands off to orchestrator")[0] == "drop"
    assert classify("kctf/writeup.md", "这是一个逆向工程的题解 " * 20)[0] == "translate"
    assert classify("skills/README.md", "index of modules")[0] == "drop"


def test_rag_wires_in_tool_knowledge():
    # "Todo hilado": el catalogo de herramientas (toolcheck) esta en el RAG, no solo los
    # cheat sheets. Una consulta por una herramienta la recupera.
    from binoracle.toolcheck import tool_catalog
    kb = get_kb()
    tool_chunks = [c for c in kb.chunks if c.doc.startswith("tools/")]
    assert len(tool_chunks) == len(tool_catalog()), "faltan herramientas en el RAG"
    top = kb.retrieve("libc-database identify libc offsets from a leak", k=3)
    assert any(c.doc == "tools/libc-database" for c, _ in top), \
        "el saber-herramientas no se recupera"


def test_rag_excludes_readme_manifests():
    # Los README son indices de navegacion del corpus, no cheat sheets:
    # no deben indexarse ni aparecer en el desglose de fuentes.
    kb = get_kb()
    bad = {"readme", "skill", "index", "_index", "_template"}
    offenders = [c.doc for c in kb.chunks if c.doc.rsplit("/", 1)[-1].lower() in bad]
    assert not offenders, f"manifiestos/routers indexados como conocimiento: {offenders[:5]}"
    assert "README" not in kb.sources_summary()


def test_rag_index_has_no_duplicate_chunks():
    # El mismo tema aparece en varios corpus importados; el dedup exacto en _add debe evitar
    # que un chunk identico gaste un slot del top-k con contenido repetido.
    import collections
    kb = get_kb()
    seen = collections.Counter((c.title.strip(), c.text.strip()) for c in kb.chunks)
    dups = [t for (t, _), n in seen.items() if n > 1]
    assert not dups, f"chunks duplicados exactos en el indice: {dups[:5]}"


def test_rag_index_has_no_cjk_noise():
    # binoracle trabaja en ES/EN: ningun chunk debe quedar dominado por CJK (traducciones
    # parciales que dejaron titulos/terminos en chino).
    import re
    cjk = re.compile(r"[一-鿿]")
    kb = get_kb()
    noisy = [c.doc for c in kb.chunks
             if len(cjk.findall(c.title + c.text)) / max(len(c.title + c.text), 1) > 0.02]
    assert not noisy, f"chunks con CJK residual >2%: {noisy[:5]}"


def test_web_rag_command():
    from binoracle.web import run_command
    r = run_command({"command": "rag", "options": {"expand": 1}})
    assert r["ok"] and "rag" in r
    assert r["rag"]["expand"] is True
    run_command({"command": "rag", "options": {"expand": 0}})


def test_web_kb_library():
    from binoracle.web import run_command
    r = run_command({"command": "kb", "options": {}})
    assert r["ok"] and r.get("kind") == "library"
    html = r["html"]
    assert "Biblioteca" in html and "const DOCS=" in html
    # imported skills (subdirs) must NOT appear as browsable library ENTRIES (its id has no
    # "/"). El texto de un cheat sheet curado si puede mencionar "skills/" en su atribucion.
    assert '"id": "skills/' not in html


def test_web_tools_command():
    from binoracle.web import run_command
    r = run_command({"command": "tools", "options": {}})
    assert r["ok"] and "toolchain" in r["text"]
