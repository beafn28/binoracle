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


def _mock_reg(imports="", strings=""):
    from binoracle.oracles.base import ToolResult

    class _T:
        def __init__(self, d): self.d = d
        def run(self): return ToolResult(True, "r2", self.d)

    class _R:
        def get(self, name):
            if name == "r2_imports": return _T(imports)
            if name == "r2_strings": return _T(strings)
            return None
    return _R()


def test_fileperms_scanner():
    from binoracle.workflows.fileperms import scan_file_perms
    reg = _mock_reg(imports="sym.imp.tmpnam\nsym.imp.fopen\nsym.imp.chmod",
                    strings="/tmp/app_cache.dat")
    fs = scan_file_perms(reg, "x")
    titles = " ".join(f.title.lower() for f in fs)
    assert "tmpnam" in titles and "temporal" in titles  # temp inseguro + despliegue en /tmp


def test_commsec_scanner():
    from binoracle.workflows.commsec import scan_comms
    reg = _mock_reg(imports="sym.imp.MD5_Init",
                    strings="http://updates.local/x\nCURLOPT_SSL_VERIFYPEER=0\nRC4")
    fs = scan_comms(reg, "x")
    titles = " ".join(f.title.lower() for f in fs)
    assert "sin cifrar" in titles         # cleartext http
    assert "certificado" in titles        # verify disabled
    assert "criptografia" in titles       # weak crypto


def test_backdoors_scanner():
    from binoracle.workflows.backdoors import scan_backdoors
    # bind shell: socket + bind + listen + dup2/execve + /bin/sh
    reg = _mock_reg(imports="sym.imp.socket\nsym.imp.bind\nsym.imp.listen\nsym.imp.dup2\nsym.imp.execve",
                    strings="/bin/sh")
    fs = scan_backdoors(reg, "x")
    titles = " ".join(f.title.lower() for f in fs)
    assert "bind shell" in titles, "no detecto la bind shell"
    # reverse shell: socket + connect + execve
    reg2 = _mock_reg(imports="sym.imp.socket\nsym.imp.connect\nsym.imp.execl", strings="")
    ts2 = " ".join(f.title.lower() for f in scan_backdoors(reg2, "x"))
    assert "reverse shell" in ts2, "no detecto la reverse shell"
    # inyeccion por concatenacion: system + sprintf
    reg3 = _mock_reg(imports="sym.imp.system\nsym.imp.sprintf", strings="")
    ts3 = " ".join(f.title.lower() for f in scan_backdoors(reg3, "x"))
    assert "concatenacion" in ts3, "no detecto la inyeccion por concatenacion"
    # sin red y sin builders: sin falsos positivos
    assert scan_backdoors(_mock_reg(imports="sym.imp.printf", strings=""), "x") == []


def test_dynamic_parse_and_findings():
    # Parser del shim LD_PRELOAD + generacion de hallazgos (sin docker: se prueba _parse directo).
    from binoracle.workflows.dynamic import _parse, dynamic_findings
    # formato del shim: el valor con espacios (cmd/path) va SIEMPRE al final de linea
    log = (
        "__BO__ connect ip=10.13.37.7 port=4444\n"
        "__BO__ bind ip=0.0.0.0 port=1337\n"
        "__BO__ open path=/etc/passwd\n"
        "__BO__ chmod mode=777 path=/tmp/x\n"
        "__BO__ execve arg=sh path=/bin/sh\n"
        "__BO__ system cmd=cat /etc/passwd /tmp/notes.txt\n"
        "algo de ruido que no es evento\n"
    )
    t = _parse(log)
    assert t.connects and t.connects[0]["ip"] == "10.13.37.7" and t.connects[0]["port"] == "4444"
    assert t.binds and t.binds[0]["port"] == "1337"
    assert "/etc/passwd" in t.files
    assert t.chmods and t.chmods[0]["mode"] == "777" and t.chmods[0]["path"] == "/tmp/x"
    assert any("/bin/sh" in e for e in t.execs)
    # comando con espacios NO se trunca (regresion del bug de _kv)
    assert any("cat /etc/passwd /tmp/notes.txt" in e for e in t.execs)
    titles = " ".join(f.title.lower() for f in dynamic_findings(t, "es"))
    assert "conexion saliente" in titles     # callback
    assert "shell" in titles                  # exec de shell
    assert "sensibles" in titles              # /etc/passwd
    assert all(f.verdict == "verified" for f in dynamic_findings(t, "es"))  # ejecucion real


def test_attack_chain_runtime():
    # La cadena de explotacion incluye el callback en runtime cuando hay conexion saliente.
    from binoracle.report.html import _attack_chain
    from binoracle.store.session import Finding
    fs = [Finding(title="Conexion saliente en runtime a 10.13.37.7:4444", severity="high",
                  verdict="verified", location="runtime / red", evidence="[dynamic] connect")]
    h = _attack_chain(fs, {"Canary": None, "PIE": None}, "es")
    assert "C2" in h or "exfiltracion" in h
    assert "chain-step" in h


def test_chainanalyzer_classify_and_score():
    from binoracle.workflows.chainanalyzer import (_classify, _best_for, _score, ExploitChain, Gadget)
    # gadget limpio: pop rdi; ret
    g = _classify({"retaddr": 0x401234, "opcodes": [
        {"addr": 0x401234, "opcode": "pop rdi", "type": "pop"},
        {"addr": 0x401235, "opcode": "ret", "type": "ret"}]})
    assert g and g.sets == ["rdi"] and g.stack_delta == 16 and g.kind == "pop"
    # gadget sucio: contiene un salto condicional -> no utilizable
    assert _classify({"retaddr": 0x1, "opcodes": [
        {"opcode": "jrcxz 0x1", "type": "cjmp"}, {"opcode": "pop rdi", "type": "pop"},
        {"opcode": "ret", "type": "ret"}]}) is None
    # syscall
    gs = _classify({"retaddr": 0x2, "opcodes": [{"opcode": "syscall", "type": "syscall"}]})
    assert gs and gs.kind == "syscall"
    # _best_for elige el pop del registro pedido
    assert _best_for([g, gs], "rdi") is g and _best_for([gs], "rdi") is None
    # scoring: cadena con requisito faltante no es factible y puntua menos
    c = ExploitChain(name="t", requirements=["[OK] a", "[X] b"], gadgets_used=[1])
    _score(c)
    assert c.feasible is False and c.score < 100
    c2 = ExploitChain(name="ok", requirements=["[OK] a"], gadgets_used=[])
    _score(c2)
    assert c2.feasible is True and c2.score == 100


def test_dotnet_detect_and_secrets(tmp_path):
    from binoracle.workflows.dotnet import is_dotnet, _scan_code_secrets, decompile_dotnet
    # deteccion por firma: MZ + 'BSJB' -> .NET; MZ sin BSJB -> no
    net = tmp_path / "a.exe"; net.write_bytes(b"MZ" + b"\x00" * 200 + b"BSJB" + b"\x00" * 50)
    native = tmp_path / "b"; native.write_bytes(b"\x7fELF" + b"\x00" * 100)
    plainpe = tmp_path / "c.exe"; plainpe.write_bytes(b"MZ" + b"\x00" * 300)
    assert is_dotnet(str(net)) is True
    assert is_dotnet(str(native)) is False
    assert is_dotnet(str(plainpe)) is False
    # decompile degrada bien si no es .NET
    assert decompile_dotnet(str(native)).is_dotnet is False
    # escaneo de secretos en codigo decompilado
    code = ('class X { const string Password = "hunter2_backdoor";\n'
            ' const string Greeting = "hello world";\n'
            ' string conn = "Server=db;User Id=sa;Password=Str0ng!";\n'
            ' const string ApiKey = "changeme"; }')
    hits = {h["value"] for h in _scan_code_secrets(code)}
    assert "hunter2_backdoor" in hits           # const con nombre sospechoso
    assert any("User Id=sa" in v for v in hits)  # cadena de conexion
    assert "hello world" not in hits             # const generica: ignorada
    assert "changeme" not in hits                # placeholder: ignorado


def test_cvss_mapping():
    from binoracle.report.cvss import cvss_for, classify
    from binoracle.store.session import Finding
    def F(t, v): return Finding(title=t, severity="high", verdict=v, location="", evidence="")
    # clasificacion por clase
    assert classify(F("Exploit ret2win verificado", "verified")) == "mem_rce"
    assert classify(F("Posible reverse shell", "grounded")) == "net_rce"
    assert classify(F("Secreto hardcodeado: apikey", "grounded")) == "secret"
    assert classify(F("Algo que no encaja en nada", "grounded")) is None
    # verificado -> E:A ; grounded -> E:P ; el vector siempre presente
    rv = cvss_for(F("Exploit ret2win verificado", "verified"))
    rg = cvss_for(F("Desbordamiento de buffer overflow", "grounded"))
    assert rv.exploit_maturity == "A" and "/E:A" in rv.vector
    assert rg.exploit_maturity == "P" and "/E:P" in rg.vector
    assert cvss_for(F("nada", "grounded")) is None    # no se inventa CVSS
    # si la libreria cvss esta instalada, el score es el oficial (verificado >= grounded misma clase)
    try:
        import cvss  # noqa: F401
        assert rv.base is not None and rg.base is not None and rv.base >= rg.base
        assert rv.severity in ("Critical", "High", "Medium", "Low", "None")
    except ImportError:
        assert rv.base is None   # degrada sin romper


def test_ghidra_client_extract_and_fallback():
    from binoracle.oracles import ghidra as g
    # extraccion de codigo desde respuesta JSON envuelta (formato del plugin GhidraMCP)
    j = ('{"success":true,"name":"main","address":"0x401136",'
         '"decompilation":"undefined8 main(void){ char buf[64]; read(0, buf, 256); return 0; }"}')
    code = g._extract_code(j)
    assert code and "read(0, buf, 256)" in code
    # ruido no-C -> None (no se inventa decompilacion)
    assert g._extract_code("ok connected") is None
    assert g._extract_code("") is None
    # sin servidor arriba: indisponible y None, sin excepcion (fallback a r2)
    import os
    os.environ["BINORACLE_GHIDRA_URL"] = "http://127.0.0.1:1"   # puerto imposible
    assert g.available(timeout=1.0) is False
    assert g.decompile_function("main", timeout=1.0) is None
    os.environ.pop("BINORACLE_GHIDRA_URL", None)


def test_ghidra_server_config_logic(monkeypatch):
    from binoracle.oracles import ghidra_server as gs
    # autostart: env manda sobre config
    monkeypatch.setenv("BINORACLE_GHIDRA_AUTOSTART", "0")
    assert gs.autostart_enabled({"autostart": True}) is False
    monkeypatch.setenv("BINORACLE_GHIDRA_AUTOSTART", "1")
    assert gs.autostart_enabled({"autostart": False}) is True
    monkeypatch.delenv("BINORACLE_GHIDRA_AUTOSTART", raising=False)
    assert gs.autostart_enabled({"autostart": True}) is True
    assert gs.autostart_enabled({}) is True          # default ON
    # port: env > cfg > default
    monkeypatch.setenv("BINORACLE_GHIDRA_PORT", "9999")
    assert gs._port({"port": 8089}) == 9999
    monkeypatch.delenv("BINORACLE_GHIDRA_PORT", raising=False)
    assert gs._port({"port": 8100}) == 8100
    assert gs._port({}) == 8089
    # stop(None) no rompe
    gs.stop(None)


def test_decai_parse_and_enable(monkeypatch):
    from binoracle.oracles import decai as dc
    # _clean: extrae el bloque de codigo de la salida con fences markdown
    out = "bla bla\n```c\nint f(int a){ return a+1; }\n```\nmas texto"
    code = dc._clean(out)
    assert code and "return a+1" in code and "bla bla" not in code
    # sin codigo -> None (no se inventa)
    assert dc._clean("solo texto sin codigo") is None
    assert dc._clean("") is None
    # enabled: env manda (si esta instalado)
    monkeypatch.setattr(dc, "installed", lambda: True)
    monkeypatch.setenv("BINORACLE_DECAI", "0")
    assert dc.enabled() is False
    monkeypatch.setenv("BINORACLE_DECAI", "1")
    assert dc.enabled() is True
    # si no esta instalado, siempre False
    monkeypatch.setattr(dc, "installed", lambda: False)
    assert dc.enabled() is False


def test_decompile_crosscheck():
    from binoracle.workflows.decompile import _crosscheck
    v = [("ghidra", "void vuln(){ char buf[64]; read(0,buf,256); }"),
         ("decai", "int vuln(int fd,char*buf){ return read(fd,buf,256); }"),
         ("pdg", "void vuln(){ char b[64]; gets(b); }")]
    note = _crosscheck(v, "es")
    assert "gets" in note and "read" in note        # discrepancia de sinks detectada
    assert "tamano" in note.lower() or "confirm" in note.lower()
    assert _crosscheck(v[:1], "es") == ""            # <2 motores -> sin contraste
    # coincidencia total de sinks
    agree = [("ghidra", "read(0,b,256);"), ("decai", "read(fd,b,256);")]
    assert "coinciden" in _crosscheck(agree, "es").lower()


def test_sarif_export():
    import json
    from binoracle.report.render import findings_to_sarif
    from binoracle.store.session import Finding
    fs = [
        Finding(title="Exploit ret2win verificado", severity="critical", verdict="verified",
                location="win=0x401156", evidence="offset=72", rationale="ret2win alcanzado",
                recommendation="canary+PIE"),
        Finding(title="Comunicacion sin cifrar (cleartext)", severity="medium", verdict="grounded",
                location=".text", evidence="http://x", rationale="trafico en claro", recommendation="TLS"),
    ]
    doc = json.loads(findings_to_sarif("/tmp/vuln", fs))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "binoracle"
    assert len(run["results"]) == 2
    r0 = run["results"][0]
    assert r0["level"] == "error"                 # critical -> error
    assert run["results"][1]["level"] == "warning"  # medium -> warning
    assert r0["properties"]["verdict"] == "verified"
    # si cvss esta, el vector 4.0 y security-severity aparecen
    try:
        import cvss  # noqa: F401
        assert r0["properties"]["cvss_v4_vector"].startswith("CVSS:4.0/")
        assert "security-severity" in r0["properties"]
    except ImportError:
        pass
    # cada result referencia una rule declarada
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in rule_ids for res in run["results"])


def test_chain_verify_proof_plumbing():
    from binoracle.workflows.chainanalyzer import _proof_from_pie, ExploitChain
    # parseo de la linea de autopie
    p = _proof_from_pie("VERIFIED off=72 base=0x555555554000 strategy=rop-pie")
    assert p["offset"] == 72 and p["base"] == "0x555555554000" and p["strategy"] == "rop-pie"
    assert _proof_from_pie("NOT_VERIFIED") == {}
    # el dataclass lleva los campos de prueba, por defecto sin verificar
    c = ExploitChain(name="x")
    assert c.verified is False and c.proof == {}


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
