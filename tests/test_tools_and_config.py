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


def test_rag_embed_requested_reflects_config_not_readiness():
    # Regresion: el panel web leia "embed": kb.embeds is not None para marcar la casilla
    # 'Semantico (embeddings)' -- eso es True SOLO cuando el hilo de fondo YA TERMINO de
    # construir los embeddings, asi que mientras embed_mode == 'construyendo...' (varios
    # segundos tras arrancar, con __init__ o tras un toggle) la casilla salia DESMARCADA,
    # pareciendo apagada cuando en realidad esta activa y terminando. _embed_requested separa
    # 'configurado/activo' de 'ya listo'.
    from unittest.mock import patch
    kb = get_kb()
    configure(embed=False)
    assert kb._embed_requested is False and kb.embeds is None
    # activar: _embed_requested pasa a True de inmediato aunque la construccion real (lenta,
    # sincrona en configure()) todavia no haya terminado -- se mockea _init_embeddings (no-op)
    # para no disparar el calculo real de embeddings sobre todo el KB en el test.
    with patch.object(kb, "_init_embeddings", lambda: None):
        configure(embed=True)
    assert kb._embed_requested is True
    configure(embed=False)          # deja el estado como estaba para no afectar otros tests


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


def test_secrets_extended_providers():
    # casuistica ampliada de credenciales (proveedores concretos + clave crypto)
    from binoracle.workflows.secrets import scan_secrets
    from binoracle.oracles.base import ToolResult

    class _T:
        def run(self):
            return ToolResult(True, "izz",
                              "sk_live_abcdefghij0123456789ABCD\n"
                              "glpat-xxxxYYYYzzzz11112222\n"
                              "\"type\": \"service_account\"\n"
                              "aes_key = 00112233445566778899aabbccddeeff\n"
                              "password=changeme\n")

    class _R:
        def get(self, n):
            return _T() if n == "r2_strings" else None

    titles = " ".join(f.title.lower() for f in scan_secrets(_R(), "x"))
    assert "stripe" in titles and "gitlab" in titles
    assert "service account" in titles or "gcp" in titles
    assert "criptografica" in titles
    # el placeholder changeme sigue filtrado
    assert "changeme" not in " ".join(f.evidence for f in scan_secrets(_R(), "x"))


def _mock_reg(imports="", strings="", same_func=True, callers=None):
    from binoracle.oracles.base import ToolResult

    class _T:
        def __init__(self, d): self.d = d
        def run(self): return ToolResult(True, "r2", self.d)

    # envuelve cada linea de `strings` como una fila real de la tabla `izz` (offset/seccion/tipo +
    # contenido), para que string_values() (que exige ese formato) las parsee igual que los
    # escaneres que aun miran el blob crudo (el contenido sigue presente, solo con prefijo).
    _wrapped_strings = "\n".join(
        f"0  0x0  0x0  {len(ln)}  {len(ln)}  .rdata  ascii  {ln}" for ln in strings.splitlines()
    ) if strings else strings

    class _Xrefs:
        # simula r2_xrefs (axt): con same_func=True (por defecto), toda funcion importada se dice
        # llamada desde 'main' -- suficiente para que shares_caller() vea coocurrencia en los tests
        # que no versan sobre esa logica. same_func=False simula funciones SIN llamador resuelto
        # (como haria un binario real donde los sinks estan en funciones distintas), para probar el
        # camino negativo de shares_caller. `callers` (opcional): {nombre: funcion} para asignar un
        # llamador DISTINTO por simbolo (simula p.ej. exec en una funcion y drop en otra).
        def run(self, target=""):
            name = target.rsplit(".", 1)[-1] if target else ""
            if callers is not None:
                fn = callers.get(name)
                return ToolResult(True, "r2", f"{fn} 0x1000 [CALL:--x] call sym.imp.{name}" if fn else "")
            if same_func and name and (name in imports.lower()):
                return ToolResult(True, "r2", f"main 0x1000 [CALL:--x] call sym.imp.{name}")
            return ToolResult(True, "r2", "")

    class _R:
        def get(self, name):
            if name == "r2_imports": return _T(imports)
            if name == "r2_strings": return _T(_wrapped_strings)
            if name == "r2_xrefs": return _Xrefs()
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
    # casuistica ampliada DA4/DA7: Blowfish, MD2, protocolo obsoleto, ws:// en claro
    reg2 = _mock_reg(imports="sym.imp.BF_set_key",
                     strings="ws://live/feed\nSSLv3_method\nMD2_Init")
    t2 = " ".join(f.title.lower() for f in scan_comms(reg2, "x"))
    assert "obsoleto" in t2               # SSLv3
    assert "sin cifrar" in t2             # ws://
    assert "criptografia" in t2           # blowfish / md2


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


def test_chain_badchars():
    from binoracle.workflows.chainanalyzer import (_sig_bytes, _bad_in, _apply_badchars,
                                                   _SINK_BADCHARS, ExploitChain)
    # bytes significativos (sin ceros altos) y deteccion del byte prohibido
    assert _sig_bytes(0x40010a) == [0x0a, 0x01, 0x40]
    assert _bad_in(0x40010a, _SINK_BADCHARS["gets"]) == [0x0a]     # newline en la direccion
    assert _bad_in(0x401156, _SINK_BADCHARS["gets"]) == []          # limpia
    assert _bad_in(0x401156, _SINK_BADCHARS["read"]) == []          # read es binario-safe
    # scanf corta en espacio (0x20): 0x402041 lo contiene
    assert 0x20 in _bad_in(0x402041, _SINK_BADCHARS["scanf"])
    # _apply_badchars anade un break-point por cada direccion con byte prohibido
    c = ExploitChain(name="t")
    _apply_badchars(c, [0x40010a, 0x401156], _SINK_BADCHARS["gets"], "gets", "es")
    assert len(c.break_points) == 1 and "0xa" in c.break_points[0]
    # sin badset (read) no marca nada
    c2 = ExploitChain(name="t2")
    _apply_badchars(c2, [0x40010a], set(), "read", "es")
    assert c2.break_points == []


def test_rag_health():
    # El conocimiento debe estar LIMPIO: sin duplicados exactos ni chino sin traducir (>2% CJK),
    # para no alimentar 'cosas falsas'. El RAG es referencia; los hallazgos salen de oraculos.
    from binoracle.rag import get_kb
    h = get_kb().health()
    assert h["chunks"] > 0 and h["docs"] > 0 and h["sources"] > 0
    assert h["duplicates"] == 0, f"hay {h['duplicates']} chunks duplicados en el RAG"
    assert h["cjk_chunks"] == 0, f"chino sin traducir en: {h['cjk_docs']}"
    assert h["clean"] is True


def test_owasp_scanners_da2_da9_da10():
    # Las 3 categorias que faltaban ahora tienen scanner real (DA2 auth, DA9 versiones, DA10 logging)
    from binoracle.workflows.versions import scan_versions
    from binoracle.workflows.authcheck import scan_auth
    from binoracle.workflows.logging_check import scan_logging
    reg = _mock_reg(imports="sym.imp.strcmp\nsym.imp.socket\nsym.imp.recv",
                    strings="GNU C Library (Ubuntu) stable release version 2.23\n"
                            "enter password:\nadmin_token=abcd1234")
    # DA9: glibc 2.23 es antigua
    assert any("glibc 2.23" in f.title.lower() or "componente antiguo" in f.title.lower()
               for f in scan_versions(reg, "x"))
    # DA2: comparacion con credencial hardcodeada
    assert any("comparacion" in f.title.lower() or "comparison" in f.title.lower()
               for f in scan_auth(reg, "x"))
    # DA10: binario de red (recv) sin syslog -> logging insuficiente
    assert any("logging" in f.title.lower() or "registro" in f.title.lower()
               for f in scan_logging(reg, "x"))
    # DA10 conservador: binario no sensible no dispara
    assert scan_logging(_mock_reg(imports="sym.imp.printf"), "x") == []


def test_hardening_scanner():
    from binoracle.workflows.hardening import scan_hardening
    from binoracle.oracles.base import ToolResult

    class _T:
        def __init__(self, d, meta=None): self.d = d; self.meta = meta or {}
        def run(self): return ToolResult(True, "r", self.d, meta=self.meta)

    class _R:
        def __init__(self, cs, imp, st): self.cs = cs; self.imp = imp; self.st = st
        def get(self, n):
            if n == "r2_checksec": return _T("", self.cs)
            if n == "r2_imports": return _T(self.imp)
            if n == "r2_strings": return _T(self.st)
            return None

    # las strings van en formato de fila real de `izz` (offset/seccion/tipo + valor): string_values()
    # exige ese formato -- ver _mock_reg mas arriba, que hace lo mismo para los demas escaneres.
    st = ("0  0x0  0x0  10  10  .rodata  ascii  LD_PRELOAD\n"
          "1  0x0  0x0  2   2   .rodata  ascii  sh\n"
          "2  0x0  0x0  5   5   .rodata  ascii  ls -la")
    reg = _R({"nx": "false", "pic": "false", "canary": "false", "relro": "partial"},
             "sym.imp.setenv\nsym.imp.system", st)
    titles = " ".join(f.title.lower() for f in scan_hardening(reg, "x"))
    assert "endurecimiento" in titles          # build hardening insuficiente
    assert "ld_" in titles or "entorno" in titles   # LD_* env
    assert "path" in titles                    # ejecucion por PATH relativa
    # binario endurecido (todo ON) no dispara el de hardening
    reg2 = _R({"nx": "true", "pic": "true", "canary": "true", "relro": "full"}, "sym.imp.printf", "")
    assert not any("endurecimiento" in f.title.lower() for f in scan_hardening(reg2, "x"))


def test_injection_scanner():
    from binoracle.workflows.injection import scan_injection
    reg = _mock_reg(imports="sym.imp.sqlite3_exec\nsym.imp.sprintf\nsym.imp.recv\nsym.imp.system",
                    strings="SELECT * FROM users WHERE name='%s'")
    titles = " ".join(f.title.lower() for f in scan_injection(reg, "x"))
    assert "sql" in titles                     # SQLi por concatenacion
    assert "superficie de inyeccion" in titles  # entrada -> exec
    # parametrizado sin builders: no marca SQLi
    reg2 = _mock_reg(imports="sym.imp.sqlite3_prepare\nsym.imp.sqlite3_bind", strings="SELECT 1")
    assert not any("sql" in f.title.lower() for f in scan_injection(reg2, "x"))


def test_authz_scanner(tmp_path):
    import os
    from binoracle.workflows.authz import scan_authz
    p = tmp_path / "suidbin"
    p.write_bytes(b"\x7fELF")
    os.chmod(p, 0o4755)                         # SUID
    # SUID + exec sin drop -> privesc
    reg = _mock_reg(imports="sym.imp.system\nsym.imp.execl")
    assert any("sin soltar privilegios" in f.title.lower() for f in scan_authz(reg, str(p)))
    # SUID + exec + drop -> no marca el fuerte
    reg2 = _mock_reg(imports="sym.imp.system\nsym.imp.setresuid")
    assert not any("ejecuta comandos" in f.title.lower() for f in scan_authz(reg2, str(p)))
    # binario NO privilegiado -> no aplica
    q = tmp_path / "plain"; q.write_bytes(b"\x7fELF"); os.chmod(q, 0o755)
    assert scan_authz(_mock_reg(imports="sym.imp.system"), str(q)) == []


def test_cfg_block_state():
    from binoracle.workflows.cfg import _block_state, _state_note, _norm_reg
    # normalizacion de sub-registros a 64 bits
    assert _norm_reg("eax") == "rax" and _norm_reg("dil") == "rdi" and _norm_reg("r8d") == "r8"
    blk = [{"txt": "push rbp", "addr": "0x0"},
           {"txt": "mov rbp, rsp", "addr": "0x1"},
           {"txt": "sub rsp, 0x40", "addr": "0x2"},
           {"txt": "lea rax, [rbp-0x40]", "addr": "0x3"},
           {"txt": "mov edi, eax", "addr": "0x4"},
           {"txt": "call sym.imp.read", "addr": "0x5"}]
    st = _block_state(blk)
    assert st["delta"] == -8 - 0x40                 # push (-8) + sub rsp 0x40
    assert "rax" in st["w"] and "rdi" in st["w"]    # lea->rax, mov edi (rdi)
    assert "rbp" in st["r"]
    assert any("rbp-0x40" in s for s in st["slots"])
    assert "sym.imp.read" in st["calls"]
    note = _state_note(st, "es")
    assert "escribe" in note and "RSP" in note and "llama" in note


def test_trail_kind_classifier():
    from binoracle.report.html import _trail_kind
    assert _trail_kind("try_ret2win", "autopoc: sandbox", "uid=0(root)", "es")[0].startswith("ejecucion")
    assert "angr" in _trail_kind("x", "angr", "reachable", "es")[0]
    assert _trail_kind("dynamic_trace", "LD_PRELOAD", "connect", "es")[0] == "dinamica"
    assert _trail_kind("r2_sinks", "radare2: axt", "read", "es")[0] == "estatica"
    # cada tecnica tiene su color
    cols = {_trail_kind(*a, "es")[1] for a in [("t", "sandbox", "shell"), ("t", "angr", ""),
                                               ("t", "gdb", "stop reason"), ("t", "r2", "pdf")]}
    assert len(cols) == 4


def test_payload_layout():
    from binoracle.report.html import _le_bytes, _payload_layout_html
    assert _le_bytes("0x401156") == ["56", "11", "40", "00", "00", "00", "00", "00"]
    h = _payload_layout_html(72, "0x401156", "es")
    assert "paylay" in h and "p64(0x401156)" in h
    assert "0x48" in h                         # offset 72 en hex
    assert "56 11 40" in h                     # direccion en little-endian
    assert _payload_layout_html("N", "0x0", "es") == ""   # sin offset numerico -> vacio


def test_cve_exploit_plan():
    from binoracle.workflows.cveplan import classify_cve, plan, render_plan
    assert classify_cve("a stack-based buffer overflow allows RCE") == "stack-overflow"
    assert classify_cve("use-after-free in the handler") == "uaf"
    assert classify_cve("uncontrolled format string (%n)") == "format-string"
    assert classify_cve("nothing recognizable here") is None
    # plan de stack overflow con NX+PIE+canary -> fases de leak + control + ROP
    pl = plan("stack buffer overflow via strcpy", {"nx": True, "pie": True, "canary": True, "relro": "full"},
              cve="CVE-2024-1", lang="es")
    assert pl.vuln_class == "stack-overflow" and pl.cve == "CVE-2024-1"
    names = " ".join(ph.name.lower() for ph in pl.phases)
    assert "canary" in names and "pie" in names and "rop" in names and "objetivo" in names
    assert any("Full RELRO" in m for m in pl.mitigations)
    assert "ret2win" in pl.kb_refs
    md = render_plan(pl, "es")
    assert "Esquema de explotacion" in md and "Primitiva" in md
    # sin clase reconocida -> plan vacio con nota
    assert plan("blah blah", {}, lang="es").ok is False


def test_cveplan_script_from_proof():
    from binoracle.workflows.cveplan import _pwn_script_from_proof
    s = _pwn_script_from_proof({"strategy": "ret2win", "offset": 72, "win": "0x401156"}, "vuln")
    assert "OFFSET = 72" in s and "0x401156" in s and "from pwn import" in s and "./vuln" in s
    s2 = _pwn_script_from_proof({"strategy": "ret2libc+leak (2 etapas)", "offset": 88}, "b")
    assert "rop.puts(elf.got['puts'])" in s2 and "libc" in s2
    assert _pwn_script_from_proof({"strategy": "ret2win"}, "x").endswith("offset no resuelto")


def test_owasp_all_categories_covered():
    # Tras anadir DA2/DA9/DA10, las 10 categorias OWASP se examinan de verdad (covered=True)
    from binoracle.report.render import _OWASP_DESKTOP
    not_covered = [cid for cid, name, covered, kws in _OWASP_DESKTOP if not covered]
    assert not_covered == [], f"categorias sin scanner: {not_covered}"


def test_reachability_helpers():
    from binoracle.workflows.reachability import ReachResult, _EXEC_SINKS, _OVF_SINKS
    r = ReachResult(ok=True, target=0x401156, stdin=b"s3cr3t\n\x00\x00")
    assert r.stdin_hex.startswith("73336372")           # 's3cr'
    assert r.stdin_printable.startswith("s3cr3t")        # legible; nulos -> '.'
    assert "." in r.stdin_printable                       # bytes no imprimibles -> '.'
    # sinks de ejecucion priorizados y sin solaparse con los de overflow
    assert "system" in _EXEC_SINKS and "execve" in _EXEC_SINKS
    assert "gets" in _OVF_SINKS and "read" in _OVF_SINKS
    assert not (set(_EXEC_SINKS) & set(_OVF_SINKS))


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


def test_cveplan_html_schema_and_verified_exploit():
    # El informe muestra el ESQUEMA de explotacion (clase -> primitiva -> concrecion -> fases ->
    # mitigaciones) y, si hay cadena verificada, la PRUEBA y el script pwntools desarrollado.
    from binoracle.workflows.cveplan import plan_from_analysis
    from binoracle.report.html import _cveplan_html

    class FakeChain:
        name = "ret2win"; verified = True; target = "win"
        proof = {"strategy": "ret2win", "offset": 72, "win": "0x401156", "output": "uid=0(root)"}

    class FakeAn:
        ok = True; target = "win"
        control = {"RIP": True, "rip_offset": 72,
                   "reg_gadgets": {"rdi": {"addr": "0x401234"}}, "pivot_gadget": None}
        gadgets = list(range(120)); chains = [FakeChain()]

    pl = plan_from_analysis(FakeAn(), {"nx": True, "pie": False, "canary": False, "relro": "partial"},
                            binary_name="vuln", lang="es")
    assert pl.ok and pl.vuln_class == "stack-overflow"
    assert pl.verified and pl.concrete.get("offset") == 72 and pl.script
    for lang in ("es", "en"):
        html = _cveplan_html(pl, lang)
        assert 'id="sec-exploitplan"' in html
        assert "0x401234" in html and "uid=0(root)" in html
        assert "pwntools" in html.lower()
        assert "—" not in html  # sin guiones largos
    # sin analisis reconocible -> sin seccion
    from binoracle.workflows.cveplan import ExploitPlan
    assert _cveplan_html(ExploitPlan(), "es") == ""


def test_report_embeds_exploit_plan_toc():
    # render_html enlaza la seccion en el indice solo cuando hay plan concreto (no crashea sin chains).
    from binoracle.report.html import render_html
    out = render_html("target.bin", findings=[], lang="es", chains=None)
    assert "sec-exploitplan" not in out  # sin chains, sin seccion


def test_history_delete_removes_scan():
    # Se puede borrar un binario del historial junto con sus hallazgos/facts/notas.
    import os, tempfile
    from binoracle.store.session import SessionStore, delete_binary, list_all_binaries, Finding
    d = tempfile.mkdtemp()
    b = os.path.join(d, "target.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + os.urandom(200))
    db = os.path.join(d, "sess.db")
    s = SessionStore(db, b)
    s.add_finding(Finding(title="stack overflow", severity="high", verdict="verified",
                          evidence="[sandbox] uid=0", location="main"))
    s.add_fact("r2", "r2", "aaa ok")
    bid = s.bin_id
    s.close()
    assert len(list_all_binaries(db)) == 1
    res = delete_binary(db, bid)
    assert res["ok"] and res["deleted"]["binaries"] == 1 and res["deleted"]["findings"] == 1
    assert list_all_binaries(db) == []
    assert delete_binary(db, "deadbeef")["ok"] is False


def test_session_store_save_and_load_report_roundtrip():
    # save_report()/load_report(): el informe COMPLETO (no solo los findings sueltos) que
    # renderDash() consume, guardado tal cual para poder reabrirlo desde el historial sin
    # re-analizar. Un informe nuevo del mismo 'kind' REEMPLAZA al anterior (no se acumulan).
    import os, tempfile
    from binoracle.store.session import SessionStore
    d = tempfile.mkdtemp()
    b = os.path.join(d, "target.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + os.urandom(200))
    db = os.path.join(d, "sess.db")
    s = SessionStore(db, b)
    assert s.load_report("dashboard") is None
    data1 = {"arch": "x86", "bits": "64", "findings": {"total": 1, "verified": 0, "by_sev": {}},
             "items": [{"title": "primero"}]}
    s.save_report("dashboard", data1)
    assert s.load_report("dashboard") == data1
    data2 = {"arch": "x86", "bits": "64", "findings": {"total": 2, "verified": 1, "by_sev": {}},
             "items": [{"title": "segundo"}]}
    s.save_report("dashboard", data2)
    loaded = s.load_report("dashboard")
    assert loaded == data2  # reemplaza, no acumula
    s.close()


def test_delete_binary_also_removes_stored_report():
    import os, tempfile
    from binoracle.store.session import SessionStore, delete_binary
    d = tempfile.mkdtemp()
    b = os.path.join(d, "target.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + os.urandom(200))
    db = os.path.join(d, "sess.db")
    s = SessionStore(db, b)
    s.save_report("dashboard", {"findings": {"total": 0, "verified": 0, "by_sev": {}}, "items": []})
    bid = s.bin_id
    s.close()
    res = delete_binary(db, bid)
    assert res["ok"] and res["deleted"].get("reports") == 1
    s2 = SessionStore(db, b)
    assert s2.load_report("dashboard") is None
    s2.close()


def test_history_click_loads_stored_report_without_rescanning(monkeypatch, tmp_path):
    # El bug reportado: al hacer click en un binario del historial, la web volvia a
    # RE-ESCANEARLO (dash() -> stream('dashboard'), pipeline completo: triage+hunt+verify+
    # dynamic_trace) en vez de llevar al informe YA analizado. Ahora el frontend llama a
    # 'dashboard_stored', que debe: (a) si hay un informe guardado, emitirlo TAL CUAL con un
    # unico paso informativo y SIN disparar ninguna herramienta pesada; (b) si nunca se genero
    # ninguno, caer al analisis en vivo (unico caso donde SI se re-escanea).
    import os
    import binoracle.web as web
    from binoracle.store.session import SessionStore

    class _FakeConfig:
        def db_path(self):
            return str(tmp_path / "sess.db")
        lang = "es"

    monkeypatch.setattr(web, "load_config", lambda: _FakeConfig())

    b = str(tmp_path / "target.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + os.urandom(200))

    stored = {"arch": "x86", "bits": "64", "format": "elf",
              "mitigations": {"NX": True}, "findings": {"total": 3, "verified": 1, "by_sev": {}},
              "items": [{"title": "cacheado"}], "sinks": [], "functions": 0, "sink_detail": ""}
    s = SessionStore(_FakeConfig().db_path(), b)
    s.save_report("dashboard", stored)
    s.close()

    events = []
    web.run_streaming("dashboard_stored", b, False, lambda kind, data: events.append((kind, data)))
    kinds = [k for k, _ in events]
    assert kinds == ["step", "dashboard", "done"]
    assert events[1][1] == stored
    # nada de pasos de la tuberia pesada (serian visibles como mensajes de "step" adicionales)
    steps = [d for k, d in events if k == "step"]
    assert not any("hunt" in s.lower() or "sinks y vulnerabilidades" in s.lower() for s in steps)


def test_web_history_delete_command():
    from binoracle.web import run_command
    r = run_command({"command": "history_delete", "options": {"bin_id": ""}})
    assert r["ok"] is False  # bin_id vacio -> no borra
    assert "history" in r  # aun asi devuelve el historial actualizado


def test_web_history_multiselect_delete(tmp_path, monkeypatch):
    # Papelera: seleccion multiple -> borra varios binarios del historial de una vez.
    import binoracle.web as web
    from binoracle.store.session import SessionStore, Finding
    db = str(tmp_path / "s.db")
    ids = []
    for nm in ("a.bin", "b.bin", "c.bin"):
        p = str(tmp_path / nm)
        with open(p, "wb") as fh:
            fh.write(b"\x7fELF" + (nm.encode() * 20))
        s = SessionStore(db, p)
        s.add_finding(Finding(title="t", severity="low", verdict="grounded",
                              evidence="e", location=nm))
        ids.append(s.bin_id)
        s.close()

    class Cfg:
        lang = "es"
        def db_path(self):
            return db
    monkeypatch.setattr(web, "load_config", lambda: Cfg())
    assert len(web.run_command({"command": "history", "options": {}})["history"]) == 3
    r = web.run_command({"command": "history_delete", "options": {"bin_ids": ids[:2]}})
    assert r["ok"] and r["deleted_count"] == 2 and len(r["history"]) == 1
    # seleccion vacia no borra nada
    assert web.run_command({"command": "history_delete", "options": {"bin_ids": []}})["ok"] is False


def test_cveplan_exports_developed_exploit(tmp_path, capsys):
    # binoracle DESARROLLA el exploit: --out escribe un script pwntools ejecutable, anclado a la
    # cadena verificada. Aqui forzamos un plan con script y comprobamos la exportacion.
    import os, types
    from binoracle import cli
    from binoracle.workflows import cveplan as CV
    pl = CV.ExploitPlan(vuln_class="stack-overflow", primitive="RIP", verified=True)
    pl.proof = {"strategy": "ret2win", "offset": 72, "win": "0x401156"}
    pl.script = CV._pwn_script_from_proof(pl.proof, "vuln")
    orig = CV.plan_for_binary
    CV.plan_for_binary = lambda *a, **k: pl
    try:
        out = str(tmp_path / "exploit.py")
        cfg = types.SimpleNamespace(lang="es")
        args = types.SimpleNamespace(binary="./vuln", text="stack overflow", cve="",
                                     no_verify=False, out=out)
        cli.cmd_cveplan(args, cfg)
    finally:
        CV.plan_for_binary = orig
    assert os.path.exists(out)
    assert os.stat(out).st_mode & 0o111  # ejecutable
    body = open(out).read()
    assert "from pwn import *" in body and "OFFSET = 72" in body


def test_render_exploit_page_functional_section():
    # Apartado CVE -> exploit funcional: pagina autocontenida con esquema, estado verificado y el
    # exploit desarrollado descargable (data URI del script pwntools).
    from binoracle.report.html import render_exploit_page
    from binoracle.workflows.cveplan import ExploitPlan, _pwn_script_from_proof
    pl = ExploitPlan(vuln_class="stack-overflow", primitive="control de RIP", verified=True,
                     kb_refs=["ret2win", "rop"])
    pl.concrete = {"offset": 72, "reg_gadgets": {"rdi": "0x401234"}, "target": "win",
                   "gadgets_total": 150, "chain": "ret2win"}
    pl.proof = {"strategy": "ret2win", "offset": 72, "win": "0x401156", "output": "uid=0(root)"}
    pl.script = _pwn_script_from_proof(pl.proof, "vuln")
    for lang in ("es", "en"):
        pg = render_exploit_page(pl, "/tmp/vuln", lang)
        assert "<!doctype html>" in pg
        assert 'class="dlbtn"' in pg and "data:text/x-python;base64," in pg
        assert "sec-exploitplan" in pg and "uid=0(root)" in pg
        assert "—" not in pg  # sin em-dash
    # plan no reconocido -> pagina de guia, sin el boton de descarga (el anchor, no la clase CSS)
    bad = render_exploit_page(ExploitPlan(note="clase no reconocida"), "/tmp/vuln", "es")
    assert "No se pudo derivar" in bad and 'class="dlbtn"' not in bad


def test_develop_exploit_all_classes_compile():
    # El desarrollador de exploits produce un script pwntools que COMPILA para cada clase.
    from binoracle.workflows.cveplan import plan
    import ast
    classes = {"stack buffer overflow": "stack-overflow", "format string": "format-string",
               "heap overflow": "heap-overflow", "use-after-free": "uaf", "double free": "double-free",
               "out-of-bounds write": "oob-write", "integer overflow": "integer-overflow",
               "type confusion": "type-confusion"}
    for text, expect in classes.items():
        pl = plan(text, {"nx": True, "pie": False, "canary": False})
        assert pl.vuln_class == expect
        assert pl.script and "from pwn import *" in pl.script
        compile(pl.script, "<exploit>", "exec")  # sintaxis valida
    # NX desactivado -> ret2shellcode
    assert "shellcraft" in plan("stack buffer overflow", {"nx": False}).script
    # SROP disponible como estrategia (D) para stack-overflow estatico/minimo
    so = plan("stack buffer overflow", {"nx": True, "pie": False}).script
    assert "SigreturnFrame" in so and "SYS_execve" in so
    # one-gadget ofrecido en la ruta de heap (tras resolver la base de libc)
    assert "one_gadget" in plan("heap overflow", {"nx": True}).script


def test_default_corpus_is_elf_only():
    # El corpus de entrenamiento son ELF ejecutables/PIE reales: sin PE (.exe) ni core dumps.
    from binoracle.workflows.exploit_trainer import default_corpus, _is_elf
    corpus = default_corpus()
    assert corpus, "el corpus de ejemplo no deberia estar vacio"
    assert all(_is_elf(p) for p in corpus)
    names = [p.rsplit("/", 1)[-1] for p in corpus]
    assert "srop" in names            # objetivo SROP
    assert not any(n.endswith(".exe") or n == "core" for n in names)
    # el corpus ampliado cubre clases variadas (heap, format-string, oob, integer, uaf, canary)
    for expected in ("canary", "fmt_got", "uaf", "intoverflow", "oobwrite", "notes_heap", "staticrop"):
        assert expected in names, f"falta {expected} en el corpus"
    assert len(corpus) >= 18


def test_exploit_skill_accumulates(tmp_path):
    # La tabla de habilidad acumula intentos/exitos entre ejecuciones (progreso medible).
    from binoracle.store.session import SessionStore, read_exploit_skill
    db = str(tmp_path / "s.db")
    b = str(tmp_path / "t.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + b"Z" * 200)
    s = SessionStore(db, b)
    s.record_exploit_attempt("x86", "stack-overflow", "ret2win", True, 72)
    s.record_exploit_attempt("x86", "stack-overflow", "ret2win", False, None)
    s.record_exploit_attempt("x86", "stack-overflow", "template", False, 552)
    s.close()
    sk = {(r["arch"], r["cls"], r["strategy"]): r for r in read_exploit_skill(db)}
    assert sk[("x86", "stack-overflow", "ret2win")]["attempts"] == 2
    assert sk[("x86", "stack-overflow", "ret2win")]["successes"] == 1
    assert abs(sk[("x86", "stack-overflow", "ret2win")]["rate"] - 0.5) < 1e-9
    assert sk[("x86", "stack-overflow", "template")]["successes"] == 0


def test_trainer_report_renders():
    from binoracle.workflows.exploit_trainer import TrainingReport, TrainCase, render_training
    rep = TrainingReport(attempted=2, verified=1, learned=1, seconds=1.0,
                         per_class={"stack-overflow": {"attempted": 2, "verified": 1}},
                         cases=[TrainCase(binary="a", name="ret2win", vuln_class="stack-overflow",
                                          strategy="ret2win", verified=True, offset=72)])
    md = render_training(rep, "es")
    assert "Entrenamiento" in md and "ret2win" in md and "50%" in md
    assert "—" not in md


def test_cve_id_detection_and_classifier_cooccurrence():
    from binoracle.workflows.cvelookup import is_cve_id
    from binoracle.workflows.cveplan import classify_cve
    assert is_cve_id("mira CVE-2021-3156 sudo") == "CVE-2021-3156"
    assert is_cve_id("stack overflow") is None
    # la clasificacion cae al respaldo por co-ocurrencia con la redaccion real de la NVD
    assert classify_cve("an off-by-one leading to a heap-based buffer overflow") == "heap-overflow"
    assert classify_cve("stack-based buffer overflow in parser") == "stack-overflow"
    assert classify_cve("a use after free in the handler") == "uaf"


def test_render_cve_info_gap_vs_public():
    from binoracle.workflows.cvelookup import CVEInfo, ExploitRef, render_cve_info
    gap = CVEInfo(cve_id="CVE-2099-0001", ok=True, description="heap overflow in x",
                  cvss_score=9.8, cvss_severity="CRITICAL")
    md = render_cve_info(gap, "es")
    assert "NO consta" in md and "CVE-2099-0001" in md
    pub = CVEInfo(cve_id="CVE-2099-0002", ok=True, description="stack overflow", has_public_exploit=True,
                  exploit_refs=[ExploitRef(url="https://www.exploit-db.com/exploits/12345",
                                           source="exploit-db", edb_id="12345")])
    md2 = render_cve_info(pub, "es")
    assert "SI consta" in md2 and "EDB-12345" in md2


def test_sft_sample_chat_format():
    from binoracle.workflows.exploit_dataset import Sample
    s = Sample(cls="stack-overflow", arch="x86", facts={"nx": "true", "pie": False, "bits": "64"},
               script="from pwn import *\nio=process('./t')", verified=True, binary="/x/ret2win")
    chat = s.to_chat()
    roles = [m["role"] for m in chat["messages"]]
    assert roles == ["system", "user", "assistant"]
    assert "NX=on" in chat["messages"][1]["content"] and "PIE=off" in chat["messages"][1]["content"]
    assert chat["messages"][2]["content"].startswith("from pwn import *")
    assert chat["meta"]["verified"] is True and chat["meta"]["binary"] == "ret2win"


def test_classify_binary_by_indicators():
    # Clasificacion por el binario: format-string (printf con formato variable) vs heap (UAF) vs
    # stack (gets/strcpy). Los que no dan senal concluyente quedan None (decide el control de RIP).
    from binoracle.workflows.cveplan import classify_binary
    import os
    cases = {"fmt_got": "format-string", "fmtstring": "format-string",
             "uaf": "uaf", "notes_heap": "uaf", "heapbug": ("heap-overflow", "uaf"),
             "ret2win": "stack-overflow", "ret2libc": None, "oobwrite": None,
             "srop": None, "canary": None}
    for name, expect in cases.items():
        p = f"samples/bin/{name}"
        if not os.path.exists(p):
            continue          # corpus se construye con samples/build.sh; no falla si no esta
        got = classify_binary(p)
        if isinstance(expect, tuple):
            assert got in expect, f"{name}: got {got}, expected one of {expect}"
        else:
            assert got == expect, f"{name}: got {got}, expected {expect}"


def test_classify_cve_accepts_canonical_ids():
    # classify_binary produce ids canonicos; classify_cve debe aceptarlos tal cual.
    from binoracle.workflows.cveplan import classify_cve
    for cid in ("stack-overflow", "heap-overflow", "uaf", "format-string", "oob-write"):
        assert classify_cve(cid) == cid


def test_exploitdb_github_crawl_graceful_and_render():
    # Las fuentes extra (GitHub PoC + searchsploit) no lanzan y devuelven [] con entrada invalida
    # (sin red). El render agrupa por fuente con conteo.
    from binoracle.workflows.cvelookup import (search_github_poc, search_searchsploit,
                                               render_cve_info, CVEInfo, ExploitRef)
    assert search_github_poc("no-es-cve") == []
    assert search_searchsploit("no-es-cve") == []
    pub = CVEInfo(cve_id="CVE-2099-0003", ok=True, description="stack overflow",
                  has_public_exploit=True,
                  exploit_refs=[ExploitRef(url="https://github.com/a/b", source="github"),
                                ExploitRef(url="https://github.com/c/d", source="github"),
                                ExploitRef(url="https://www.exploit-db.com/exploits/9", source="exploit-db", edb_id="9")])
    md = render_cve_info(pub, "es")
    assert "SI consta" in md and "github: 2" in md and "exploit-db: 1" in md
    gap = CVEInfo(cve_id="CVE-2099-0004", ok=True, description="heap overflow")
    assert "posible hueco" in render_cve_info(gap, "es")


def test_cve_agent_deterministic_render():
    # El agente de investigacion funciona sin LLM (via determinista): render con clase, bloqueos y
    # el exploit desarrollado. Maneja steps como dicts del modelo y el estado de lookup.
    from binoracle.workflows.cve_agent import Investigation, render_investigation
    inv = Investigation(cve_id="CVE-2024-33599", description="nscd stack-based buffer overflow",
                        lookup_ok=True, is_gap=True, vuln_class="stack-overflow",
                        llm_notes={"target_binary": "nscd", "trigger": "netgroup request",
                                   "steps": [{"step": "exhaust cache"}, "overflow"]},
                        developed_script="from pwn import *\nio=process('./t')",
                        blockers=["falta nscd", "falta disparador"])
    md = render_investigation(inv, "es")
    assert "CVE-2024-33599" in md and "HUECO" in md and "stack-overflow" in md
    assert "nscd" in md and "exhaust cache" in md            # step dict aplanado
    assert "Bloqueos" in md and "from pwn import *" in md
    # exploit verificado se muestra como tal
    inv2 = Investigation(cve_id="CVE-1-1", lookup_ok=True, verified=True, verified_detail="offset=88")
    assert "VERIFICADO" in render_investigation(inv2, "es")


def test_dockerfetch_render_and_guard():
    # render + validacion de entrada sin tocar Docker/red.
    from binoracle.workflows.dockerfetch import fetch_from_image, render_fetch, FetchResult
    r = fetch_from_image("", "", on_step=lambda m: None)   # sin imagen/ruta -> falla limpio
    assert r.ok is False and r.note
    ok = FetchResult(ok=True, image="debian:12", src_path="/usr/bin/whoami",
                     local_path="/tmp/fetched/whoami")
    md = render_fetch(ok, "es")
    assert "Binario extraido" in md and "debian:12" in md and "investigate" in md
    bad = render_fetch(FetchResult(ok=False, note="no se hallo", candidates=["/a", "/b"]), "es")
    assert "fallida" in bad.lower() and "/a" in bad


def test_autofuzz_render_and_result():
    # render del descubridor de disparador + propiedad crashed sin tocar docker.
    from binoracle.workflows.autofuzz import FuzzResult, Trigger, render_fuzz
    r = FuzzResult(ok=True, binary="/x/ret2win",
                   triggers=[Trigger("stdin", "stack-overflow", min_size=128, exit_code=139,
                                     evidence="crash con 128 bytes")])
    assert r.crashed
    md = render_fuzz(r, "es")
    assert "stdin" in md and "stack-overflow" in md and "128" in md
    empty = FuzzResult(ok=False, note="sin crash")
    assert "sin crash" in render_fuzz(empty, "es") and empty.crashed is False
    # cyclic fallback no lanza sin pwntools
    from binoracle.workflows.autofuzz import _cyclic
    assert len(_cyclic(100)) == 100


def test_autofuzz_expand_tokens():
    # Regresion: _expand usa `re` (PAD/CYCLIC) - un import faltante rompia TODO caso dirigido
    # silenciosamente (capturado por el except generico de directed_fuzz). Debe expandir de verdad.
    from binoracle.workflows.autofuzz import _expand
    assert _expand("-s {PAD:5}\\") == b"-s AAAAA\\"
    assert _expand("x{CYCLIC:8}y") == b"xaaaabaaay"
    assert _expand(None) == b""
    assert _expand(b"raw") == b"raw"
    assert _expand("plain") == b"plain"


def test_directed_fuzz_without_llm():
    # Sin LLM disponible, directed_fuzz no lanza y deja nota clara (no falso "ok").
    from binoracle.workflows.autofuzz import directed_fuzz

    class _Unavailable:
        def available(self):
            return False

    res = directed_fuzz("/nonexistent-binary-xyz", "hint", _Unavailable())
    assert res.ok is False and "no encontrado" in res.note

    class _NoLLM:
        pass
    res2 = directed_fuzz(__file__, "hint", None)
    assert res2.ok is False and "sin LLM" in res2.note


def test_shares_caller_same_vs_different_function():
    # shares_caller exige que dos simbolos esten llamados desde la MISMA funcion (via r2_xrefs), no
    # solo que ambos existan en el binario -- distingue flujo de datos real (mismo camino de codigo)
    # de mera co-presencia (que fue el origen de FPs en injection.py/backdoors.py: p.ej. un system()
    # de cadena FIJA en un 'win()' de CTF, sin relacion con un gets() en main()).
    from binoracle.workflows._binfacts import shares_caller, callers_of
    same = _mock_reg(imports="sym.imp.sprintf\nsym.imp.system", same_func=True)
    assert shares_caller(same, ["sprintf"], ["system"]) is True
    assert callers_of(same, "sprintf") == {"main"}
    diff = _mock_reg(imports="sym.imp.gets\nsym.imp.system", same_func=False)
    assert shares_caller(diff, ["gets"], ["system"]) is False


def test_backdoors_requires_same_function_not_just_presence():
    # Regresion: el patron 'socket+bind+listen+exec en el binario' ya NO basta si estan en funciones
    # SIN relacion (p.ej. un servidor legitimo + un helper de backup que hace exec en otro sitio).
    same = _mock_reg(imports="sym.imp.socket\nsym.imp.bind\nsym.imp.listen\nsym.imp.execve",
                     strings="/bin/sh", same_func=True)
    from binoracle.workflows.backdoors import scan_backdoors
    titles_same = " ".join(f.title.lower() for f in scan_backdoors(same, "x"))
    assert "bind shell" in titles_same
    diff = _mock_reg(imports="sym.imp.socket\nsym.imp.bind\nsym.imp.listen\nsym.imp.execve",
                     strings="/bin/sh", same_func=False)
    assert scan_backdoors(diff, "x") == []          # sin coocurrencia real -> sin hallazgo


def test_authcheck_cred_regex_boundaries():
    # Regresion: sin limite alguno, "pin" hacia match dentro de "GetStartupInfoA" (API de Windows,
    # nada que ver con credenciales) -- confirmado en win_chall.exe. Con \b clasico se habria roto
    # el caso real "MASTER_PASSWORD_2024" (guion bajo cuenta como \w, no separa). El limite correcto
    # es 'sin letra adyacente' (digitos/guion bajo/inicio/fin si cuentan como frontera de palabra).
    from binoracle.workflows.authcheck import _CRED, _PROMPT_ONLY
    assert not _CRED.search("GetStartupInfoA")
    assert not _CRED.search("LPSTARTUPINFOA")
    assert _CRED.search("MASTER_PASSWORD_2024xk")
    assert _CRED.search("AUTH_TOKEN_XYZ123")
    # prompts de UI (solo la etiqueta, sin valor real) se filtran aparte
    assert _PROMPT_ONLY.match("pass?")
    assert _PROMPT_ONLY.match("login:")
    assert not _PROMPT_ONLY.match("MASTER_PASSWORD_2024xk")


def test_authcheck_no_false_positive_on_windows_binary():
    # Regresion sobre binario real: win_chall.exe (PE) tiene STARTUPINFOA/LPSTARTUPINFOA en sus
    # strings (metadatos de arranque de Windows) que antes disparaban 'credencial hardcodeada' por
    # contener "pin" como substring sin limites, y "pass?" (un prompt de UI, no una credencial).
    # Ninguna de las dos debe producir un hallazgo.
    import os
    from binoracle.oracles import build_registry
    from binoracle.workflows.authcheck import scan_auth
    b = "samples/bin/win_chall.exe"
    if not os.path.exists(b):
        return
    reg = build_registry(b)
    fs = scan_auth(reg, b, "es")
    assert fs == [], [f.title for f in fs]


def test_web_md_to_html_renders_bold_tables_ordered_lists():
    # Regresion: la Biblioteca de Conocimiento (Conocimiento/kb) mostraba **negrita** literal y
    # tablas markdown como un parrafo ilegible de '|' sueltos -- confirmado en owasp-desktop.md
    # (tabla de 10 filas) y en 9/47 cheat sheets con **negrita**.
    from binoracle.web import _md_to_html
    html = _md_to_html("**bold** and *italic*\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n"
                       "1. paso uno\n2. paso dos\n")
    assert "<strong>bold</strong>" in html and "<em>italic</em>" in html
    assert "**" not in html
    assert "<table>" in html and "<th>A</th>" in html and "<td>1</td>" in html
    assert "|" not in html.replace("<td>", "").replace("</td>", "")  # sin pipes sueltos en prosa
    assert "<ol>" in html and "<li>paso uno</li>" in html


def test_report_md_rich_renders_lists_and_tables():
    # Regresion: _md_rich (usado por Investigar/Entrenar/Dataset) mostraba cada '- item' como un
    # <p> con guion literal, sin <ul>/<ol> real -- confirmado en el informe de 'Investigar (LLM)'.
    from binoracle.report.html import _md_rich
    html = _md_rich("## Titulo\n- **clave**: valor\n- otro item\n\n1. paso uno\n2. paso dos\n\n"
                    "| ID | Nombre |\n|----|--------|\n| 1 | x |\n")
    assert "<ul><li><strong>clave</strong>: valor</li>" in html
    assert "<ol><li>paso uno</li>" in html
    assert "<table>" in html and "<th>ID</th>" in html
    assert "**" not in html
    assert not __import__("re").search(r"<p>\s*-\s", html)   # sin guiones literales en <p>


def test_chainanalyzer_facts_word_boundaries():
    # Regresion (hallada por un subagente de auditoria): _facts() marcaba "win" dentro de
    # "_unwind_resume" (el runtime de excepciones de C++/libgcc_s, presente en CUALQUIER binario
    # con try/catch) como si fuera la funcion win()/gift del reto -- fabricando un objetivo de
    # ret2win inexistente. Tambien: "puts" in texto matcheaba "fputs" (substring), marcando puts()
    # como disponible para la fuga cuando solo hay fputs(); y el chequeo de reentrada usaba
    # substring sobre un grep en vez de igualdad exacta de nombre de funcion.
    import json
    from unittest.mock import patch
    from binoracle.workflows.chainanalyzer import _facts, _overflow_sink

    class _FakeR2:
        def __init__(self, cmds): self.cmds = cmds
        def cmd(self, c):
            for prefix, out in self.cmds.items():
                if c.startswith(prefix):
                    return out
            return ""

    # 'win' NO debe matchear dentro de _Unwind_Resume (solo funciones de C++/libgcc_s presentes)
    fns = json.dumps([{"name": "main", "offset": 4096},
                      {"name": "sym.imp._Unwind_Resume", "offset": 8192}])
    r2 = _FakeR2({"ij": json.dumps({"bin": {}}), "aflj": fns, "iij": "[]", "izzj": "{}"})
    with patch("binoracle.oracles.r2session.get", return_value=r2):
        f = _facts("/nonexistent")
    assert f["win"] is None, "'win' hizo match dentro de _Unwind_Resume"

    # 'puts' NO debe marcarse presente si solo hay 'fputs' (substring de 'puts')
    imps = json.dumps([{"name": "sym.imp.fputs"}])
    r2b = _FakeR2({"ij": json.dumps({"bin": {}}), "aflj": "[]", "iij": imps, "izzj": "{}"})
    with patch("binoracle.oracles.r2session.get", return_value=r2b):
        fb = _facts("/nonexistent")
    assert fb["puts"] is False and fb["leak_fn"] is None

    # 'gets' NO debe matchear dentro de la disassembly de una funcion que solo llama a getsockopt
    fns2 = json.dumps([{"name": "sym.check_sock", "offset": 4096}])
    r2c = _FakeR2({"aflj": fns2, "pdf @ sym.check_sock": "call sym.imp.getsockopt"})
    with patch("binoracle.oracles.r2session.get", return_value=r2c):
        sink = _overflow_sink("/nonexistent")
    assert sink is None, "'gets' hizo match dentro de getsockopt"


def test_analyze_chains_not_applicable_for_non_elf_binaries():
    # BUG real encontrado revisando un informe generado contra un .exe de Windows real
    # (Ingrid.exe, PE32 x86 32-bit): analyze_chains() generaba (y con verify=True, intentaba
    # VERIFICAR EN SANDBOX) cadenas puramente ELF/glibc -- "tcache dup -> free@GOT=system()",
    # "execve syscall", strings '/bin/sh' -- para un binario donde nada de eso existe (PE no
    # tiene GOT/PLT ni tcache; Windows no tiene glibc). Ademas de enganoso en el informe, cada
    # intento de verificacion es una tanda de docker que nunca puede tener exito: tiempo tirado.
    # Fix: _facts() ahora lee `bintype` (via 'ij'), y analyze_chains() corta ANTES de enumerar
    # gadgets o construir ninguna cadena si el binario no es ELF.
    from unittest.mock import patch
    from binoracle.workflows import chainanalyzer

    fake_facts = {"bintype": "pe", "arch": "x86_32", "canary": True, "pie": False, "nx": True,
                  "win": None, "system": None, "binsh": None, "rip_offset": 100}
    with patch.object(chainanalyzer, "_facts", return_value=fake_facts):
        an = chainanalyzer.analyze_chains("samples/bin/ret2win", None, verify=True, lang="es")
    assert an.applicable is False
    assert an.chains == []
    assert an.gadgets == []          # ni siquiera se enumeraron gadgets: corte antes de eso
    assert "pe" in an.note.lower()

    # un ELF real (bintype=elf, o no detectado -- None se trata como aplicable) SI debe seguir
    # construyendo cadenas con normalidad: no se ha cambiado el comportamiento para el caso normal.
    an_elf = chainanalyzer.analyze_chains("samples/bin/ret2win", None, verify=False, lang="es")
    assert an_elf.applicable is True
    assert an_elf.chains, "un ELF real no deberia perder sus cadenas por este cambio"


def test_pe_capability_map_classifies_imports_by_category():
    # Fase 2 de una auditoria PE (pedida explicitamente): clasificar el binario por lo que PUEDE
    # hacer (red/proceso/privilegios/cripto/registro/ficheros) a partir de sus imports, antes de
    # leer ninguna funcion.
    from binoracle.report.html import _pe_capability_map, _capability_html

    class _FakeTriage:
        sections = [("Imports", "radare2: ii",
                     "nth vaddr      bind type lib            name\n"
                     "----------------------------------------------\n"
                     "1   0x00abe1f4 NONE FUNC KERNEL32.dll   CreateProcessA\n"
                     "2   0x00abe1f8 NONE FUNC WININET.dll    InternetOpenA\n"
                     "3   0x00abe1fc NONE FUNC ADVAPI32.dll   RegCreateKeyExA\n"
                     "4   0x00abe200 NONE FUNC ADVAPI32.dll   AdjustTokenPrivileges\n"
                     "5   0x00abe204 NONE FUNC ADVAPI32.dll   CryptAcquireContextA\n")]

    cm = _pe_capability_map(_FakeTriage())
    assert cm["red"] == ["InternetOpenA"]
    assert "CreateProcessA" in cm["proceso"]
    assert cm["privilegios"] == ["AdjustTokenPrivileges"]
    assert cm["registro"] == ["RegCreateKeyExA"]
    assert cm["cripto"] == ["CryptAcquireContextA"]
    html = _capability_html(cm, "es")
    assert "InternetOpenA" in html and "AdjustTokenPrivileges" in html

    # sin imports reconocidos (o sin seccion de Imports): no debe reventar, solo no clasificar nada
    class _EmptyTriage:
        sections = [("Imports", "radare2: ii", "(no imports)")]
    assert _pe_capability_map(_EmptyTriage()) == {}
    assert _capability_html({}, "es") == ""


def test_pe_capability_map_exact_match_for_short_socket_names():
    # BUG real encontrado con un PE real (Ingrid.exe): 'SendMessageA' (mensajeria de ventanas,
    # user32, nada que ver con red) caia en la categoria "Red" solo por empezar por "send" (los
    # nombres BSD-socket clasicos -- send/recv/connect/bind/listen/accept/socket -- son
    # demasiado cortos para prefix-match sin choques). Deben exigir coincidencia EXACTA; los
    # nombres largos y especificos (InternetOpen, WinHttpConnect...) siguen siendo prefix-match.
    from binoracle.report.html import _pe_capability_map

    class _FakeTriage:
        sections = [("Imports", "radare2: ii",
                     "1 0x1 NONE FUNC USER32.dll  SendMessageA\n"
                     "2 0x2 NONE FUNC WS2_32.dll   send\n"
                     "3 0x3 NONE FUNC WS2_32.dll   connect\n"
                     "4 0x4 NONE FUNC WS2_32.dll   ConnectNamedPipe\n")]

    cm = _pe_capability_map(_FakeTriage())
    assert "SendMessageA" not in cm.get("red", [])
    assert "ConnectNamedPipe" not in cm.get("red", [])
    assert cm["red"] == ["connect", "send"]


def test_pe_dll_characteristics_decodes_mitigation_bits():
    # ASLR/DEP/CFG de Windows viven en IMAGE_OPTIONAL_HEADER.DllCharacteristics, no en ningun
    # campo de checksec -- hay que decodificar los bits IMAGE_DLLCHARACTERISTICS_* a mano.
    from unittest.mock import patch
    from binoracle.report.html import _pe_dll_characteristics

    class _FakeR2:
        def __init__(self, header_text):
            self.header_text = header_text
        def cmd(self, c):
            if c == "iHj":
                import json
                return json.dumps({"header": self.header_text})
            return ""

    # DYNAMIC_BASE (0x40) + NX_COMPAT (0x100) + GUARD_CF (0x4000) = 0x4140: los 3 activos
    r2 = _FakeR2("IMAGE_OPTIONAL_HEADERS\n  DllCharacteristics : 0x4140\n")
    with patch("binoracle.oracles.r2session.get", return_value=r2):
        pe = _pe_dll_characteristics("/nonexistent")
    assert pe == {"ASLR": True, "DEP": True, "CFG": True}

    # solo TERMINAL_SERVER_AWARE (0x8000): ninguna de las 3 mitigaciones activa
    r2b = _FakeR2("IMAGE_OPTIONAL_HEADERS\n  DllCharacteristics : 0x8000\n")
    with patch("binoracle.oracles.r2session.get", return_value=r2b):
        pe_off = _pe_dll_characteristics("/nonexistent")
    assert pe_off == {"ASLR": False, "DEP": False, "CFG": False}


def test_pe_packing_check_flags_high_entropy_and_known_packer_sections():
    # Fase 0: si el binario esta empaquetado, el resto del analisis estatico ve el stub del
    # packer, no el programa real -- hay que avisar ANTES que de cualquier otra cosa. Umbral
    # empirico de entropia ~7.0 (comprimido/cifrado), mas nombres de seccion de packers conocidos.
    from unittest.mock import patch
    from binoracle.report.html import _pe_packing_check, _packing_warning_html
    import json

    class _FakeR2:
        def __init__(self, secs): self.secs = secs
        def cmd(self, c):
            return json.dumps(self.secs) if c == "iSj entropy" else ""

    # seccion .text con entropia normal (codigo) + UPX0 vacia (tipico de UPX) -> ambos indicios
    secs = [{"name": ".text", "entropy": "4.06"}, {"name": "UPX0", "entropy": "0.01"},
            {"name": "UPX1", "entropy": "7.85"}]
    with patch("binoracle.oracles.r2session.get", return_value=_FakeR2(secs)):
        pk = _pe_packing_check("/nonexistent")
    assert ("UPX0", "UPX") in pk["packer_sections"]
    assert ("UPX1", "UPX") in pk["packer_sections"]
    assert any(name == "UPX1" for name, _ent in pk["high_entropy"])
    html = _packing_warning_html(pk, "es")
    assert "UPX" in html

    # binario normal, sin packer ni entropia alta: no debe generar ningun aviso
    secs_clean = [{"name": ".text", "entropy": "4.06"}, {"name": ".rsrc", "entropy": "2.30"}]
    with patch("binoracle.oracles.r2session.get", return_value=_FakeR2(secs_clean)):
        pk_clean = _pe_packing_check("/nonexistent")
    assert pk_clean == {}
    assert _packing_warning_html(pk_clean, "es") == ""


def test_pe_packing_check_flags_low_function_count():
    # Fase 0 (metodologia PE pegada por el usuario): "contar las funciones detectadas (afl~?)"
    # como senal ADICIONAL de empaquetado -- un binario grande con muy pocas funciones es tipico
    # del stub de un packer (el programa real esta comprimido/cifrado, r2 no ve codigo ahi).
    from unittest.mock import patch
    from binoracle.report.html import _pe_packing_check, _packing_warning_html
    import json

    class _FakeR2:
        def __init__(self, secs, nfcn): self.secs = secs; self.nfcn = nfcn
        def cmd(self, c):
            if c == "iSj entropy":
                return json.dumps(self.secs)
            if c == "aflc":
                return str(self.nfcn)
            return ""

    secs_clean = [{"name": ".text", "entropy": "4.06"}]
    # binario grande (por encima del umbral) con solo 5 funciones detectadas -> sospechoso
    with patch("binoracle.oracles.r2session.get", return_value=_FakeR2(secs_clean, 5)), \
         patch("os.path.getsize", return_value=1_000_000):
        pk = _pe_packing_check("/nonexistent")
    assert pk.get("low_fncount") == (5, 1_000_000)
    html = _packing_warning_html(pk, "es")
    assert "5" in html and "funciones" in html

    # mismo recuento bajo pero binario PEQUENO (por debajo del umbral de tamano): no es senal,
    # cualquier programa pequeno tiene pocas funciones de forma legitima
    with patch("binoracle.oracles.r2session.get", return_value=_FakeR2(secs_clean, 5)), \
         patch("os.path.getsize", return_value=5_000):
        pk_small = _pe_packing_check("/nonexistent")
    assert pk_small == {}

    # binario grande con muchas funciones (normal): tampoco es senal
    with patch("binoracle.oracles.r2session.get", return_value=_FakeR2(secs_clean, 800)), \
         patch("os.path.getsize", return_value=1_000_000):
        pk_normal = _pe_packing_check("/nonexistent")
    assert pk_normal == {}


def test_pe_capability_map_has_database_category():
    # Fase 2 de la metodologia pegada por el usuario pide explicitamente "¿Tiene acceso a bases de
    # datos?" como una categoria del mapa de capacidades, junto a red/proceso/privilegios/cripto/
    # registro -- faltaba.
    from binoracle.report.html import _pe_capability_map

    class _FakeTriage:
        sections = [("Imports", "radare2: ii",
                     "1 0x1 NONE FUNC ODBC32.dll   SQLDriverConnect\n"
                     "2 0x2 NONE FUNC ODBC32.dll   SQLExecDirect\n"
                     "3 0x3 NONE FUNC KERNEL32.dll GetLastError\n")]

    cm = _pe_capability_map(_FakeTriage())
    assert cm.get("bd") == ["SQLDriverConnect", "SQLExecDirect"]


def test_pe_capability_map_falls_back_to_pefile_when_r2_imports_empty():
    # Fase 0 de la metodologia: "si ii/iij de r2 falla, no asumir que el binario no tiene tabla de
    # importaciones -- probar readpe/pefile antes de concluir nada". Si el texto de imports de r2
    # viene vacio (parser atragantado, PE raro), el mapa de capacidades debe caer a pefile en vez
    # de devolver {} silenciosamente.
    from unittest.mock import patch, MagicMock
    from binoracle.report.html import _pe_capability_map

    class _FakeTriageEmpty:
        sections = [("Imports", "radare2: ii", "")]

    fake_import = MagicMock()
    fake_import.name = b"InternetOpenA"
    fake_entry = MagicMock()
    fake_entry.imports = [fake_import]
    fake_pe = MagicMock()
    fake_pe.DIRECTORY_ENTRY_IMPORT = [fake_entry]

    with patch("pefile.PE", return_value=fake_pe):
        cm = _pe_capability_map(_FakeTriageEmpty(), binary="/nonexistent.exe")
    assert cm.get("red") == ["InternetOpenA"]

    # sin binario para el fallback: sigue devolviendo {} (no puede hacer nada mas)
    assert _pe_capability_map(_FakeTriageEmpty()) == {}


def test_pe_dll_hijack_check_flags_known_hijackable_dll_unless_hardened():
    # Checklist base pegada por el usuario: "DLL hijacking - se utilizan rutas relativas?". Senal
    # practica: importa una DLL de las que Windows carga por busqueda de nombre (conocida en
    # investigaciones publicas de sideloading) SIN usar SetDllDirectory/SetDefaultDllDirectories
    # para fijar su propia ruta de busqueda.
    from binoracle.report.html import _pe_dll_hijack_check, _dll_hijack_html

    class _FakeTriageVulnerable:
        sections = [("Imports", "radare2: ii",
                     "1 0x1 NONE FUNC VERSION.dll  GetFileVersionInfoA\n"
                     "2 0x2 NONE FUNC UXTHEME.dll  SetWindowTheme\n"
                     "3 0x3 NONE FUNC KERNEL32.dll LoadLibraryA\n")]

    res = _pe_dll_hijack_check(_FakeTriageVulnerable())
    assert res["dlls"] == ["uxtheme.dll", "version.dll"]
    html = _dll_hijack_html(res, "es")
    assert "version.dll" in html and "uxtheme.dll" in html

    # mismas DLLs pero el binario SI fija su propia ruta de busqueda -> se considera endurecido
    class _FakeTriageHardened:
        sections = [("Imports", "radare2: ii",
                     "1 0x1 NONE FUNC VERSION.dll   GetFileVersionInfoA\n"
                     "2 0x2 NONE FUNC KERNEL32.dll  SetDllDirectoryW\n")]

    assert _pe_dll_hijack_check(_FakeTriageHardened()) == {}

    # sin ninguna DLL de la lista conocida: nada que avisar
    class _FakeTriageClean:
        sections = [("Imports", "radare2: ii", "1 0x1 NONE FUNC KERNEL32.dll GetLastError\n")]

    assert _pe_dll_hijack_check(_FakeTriageClean()) == {}
    assert _dll_hijack_html({}, "es") == ""


def test_pe_pdb_leak_extracts_debug_directory_path():
    # Checklist base pegada por el usuario: "filtracion de informacion sensible en strings...
    # rutas de compilacion". El PE Debug Directory (CodeView/RSDS) suele embeber la ruta absoluta
    # al .pdb tal cual quedo en la maquina de build. r2 no expone este directorio, por eso pefile.
    from unittest.mock import patch, MagicMock
    from binoracle.report.html import _pe_pdb_leak, _pdb_leak_html

    fake_cv_entry = MagicMock()
    fake_cv_entry.PdbFileName = b"C:\\build\\agent1\\src\\Release\\Ingrid.pdb\x00\x00"
    fake_debug_entry = MagicMock()
    fake_debug_entry.entry = fake_cv_entry
    fake_pe = MagicMock()
    fake_pe.DIRECTORY_ENTRY_DEBUG = [fake_debug_entry]

    with patch("pefile.PE", return_value=fake_pe):
        res = _pe_pdb_leak("/nonexistent.exe")
    assert res["pdb_path"] == "C:\\build\\agent1\\src\\Release\\Ingrid.pdb"
    html = _pdb_leak_html(res, "es")
    assert "Ingrid.pdb" in html

    # sin debug directory (release limpio, caso comun): no hay nada que avisar
    fake_pe_clean = MagicMock()
    fake_pe_clean.DIRECTORY_ENTRY_DEBUG = []
    with patch("pefile.PE", return_value=fake_pe_clean):
        assert _pe_pdb_leak("/nonexistent.exe") == {}
    assert _pdb_leak_html({}, "es") == ""


def test_win32_constant_annotations_resolves_known_apis_only():
    # Fase 4 de la metodologia pegada por el usuario: "cualquier numero magico que aparezca en
    # una llamada a una API de Windows se debe verificar contra la documentacion oficial antes de
    # interpretarse". Implementado DETERMINISTA (tabla curada, no el LLM adivinando), por familia
    # de API para no confundir valores que colisionan entre APIs (0x80000000 es GENERIC_READ en
    # CreateFile pero HKEY_CLASSES_ROOT en el registro).
    from binoracle.report.html import _win32_constant_annotations, _win32_constants_html

    code = (
        'HANDLE h = CreateFileA(path, 0x80000000, 0, 0, 3, 0, 0);\n'
        'LPVOID p = VirtualAlloc(0, 0x1000, 0x3000, 0x40);\n'
        'RegOpenKeyExA(0x80000002, sub, 0, 0, &hk);\n'
        'int x = 42;  // literal suelto, sin API conocida en la linea: no debe anotarse\n'
    )
    hits = _win32_constant_annotations(code)
    assert ("createfile", "0x80000000", "GENERIC_READ") in hits
    assert ("createfile", "3", "OPEN_EXISTING") in hits
    assert ("virtualalloc", "0x1000", "MEM_COMMIT") in hits
    assert ("virtualalloc", "0x3000", "MEM_COMMIT|MEM_RESERVE") in hits
    assert ("virtualalloc", "0x40", "PAGE_EXECUTE_READWRITE") in hits
    assert ("regopenkey", "0x80000002", "HKEY_LOCAL_MACHINE") in hits
    assert not any(h[1] == "42" for h in hits)

    html = _win32_constants_html(hits, "es")
    assert "GENERIC_READ" in html and "HKEY_LOCAL_MACHINE" in html

    # mismo valor 0x80000000, API distinta (registro, no CreateFile) -> simbolo distinto, sin
    # colision entre tablas
    reg_only = _win32_constant_annotations("RegCreateKeyExA(0x80000000, name, 0, 0, 0, 0, 0, &hk, 0);")
    assert reg_only == [("regcreatekey", "0x80000000", "HKEY_CLASSES_ROOT")]

    # sin ninguna API Win32 conocida en el texto: nada que anotar
    assert _win32_constant_annotations("int add(int a, int b) { return a + b; }") == []
    assert _win32_constants_html([], "es") == ""


def test_methodology_html_documents_every_phase_honestly():
    # Peticion explicita del usuario: que la metodologia (Fases 0-9 + checklist) quede "toda
    # representada y bien documentada" en el informe, no solo aplicada en silencio. Debe ser
    # honesta: nunca afirmar cobertura de una fase que no existe en el binario concreto (p.ej. no
    # decir "cadena completa" si no hay seccion de cadena de ataque para ESTE informe).
    from binoracle.report.html import _methodology_html

    # PE con todas las secciones presentes: fases 0/2 (especificas de PE) + 3/4/5/6/7/8/9
    has_full = {"dec": True, "chain": True, "owasp": True}
    html = _methodology_html(True, has_full, "es")
    for phase in ("Fase 0", "Fase 2", "Fase 3", "Fase 4", "Fase 5", "Fase 6", "Fase 7", "Fase 9"):
        assert phase in html
    assert "sandbox de verificacion dinamica" in html and "Linux/ELF-only" in html  # Fase 8 honesta en PE
    assert "MSI" in html and "fuera de alcance" not in html.lower() or "Fuera de alcance" in html

    # ELF: no debe reclamar Fase 0/2 (especificas de PE: Rich Header, capacidades Win32...)
    html_elf = _methodology_html(False, has_full, "es")
    assert "Fase 0" not in html_elf and "Fase 2" not in html_elf
    assert "sandbox aislado interceptando" in html_elf  # Fase 8 distinta para ELF (si se ejecuta)

    # sin decompilacion ni cadena ni OWASP en este binario concreto: el texto debe decirlo, no
    # fingir que si se cubrio
    has_empty = {"dec": False, "chain": False, "owasp": False}
    html_empty = _methodology_html(True, has_empty, "es")
    assert "no se pudo decompilar" in html_empty
    assert "no hay suficientes hallazgos" in html_empty
    assert "sin hallazgos que mapear" in html_empty


def test_pe_rich_header_reports_presence_and_entry_count():
    # Gap menor de la Fase 0 ("buscar... el Rich Header... esto determina si vamos a
    # encontrarnos con convenciones MSVC, GCC, Delphi, .NET"): el Rich Header solo lo escribe el
    # linker de Microsoft, asi que su presencia confirma toolchain MSVC. No se decodifica la
    # tabla de product-id -> version de VS (no oficial, propensa a error); solo presencia+conteo.
    from unittest.mock import patch, MagicMock
    from binoracle.report.html import _pe_rich_header, _rich_header_html

    fake_pe = MagicMock()
    # 3 pares (compid, count) = 3 entradas
    fake_pe.parse_rich_header.return_value = {
        "values": [9981587, 2, 10394907, 60, 0, 2],
        "key": b"1234",
    }
    with patch("pefile.PE", return_value=fake_pe):
        res = _pe_rich_header("/nonexistent.exe")
    assert res == {"present": True, "entries": 3}
    html = _rich_header_html(res, "es")
    assert "MSVC" in html and "3" in html

    # sin Rich Header (MinGW/GCC/Delphi/.NET, o eliminado por el linker): nada que informar
    fake_pe_none = MagicMock()
    fake_pe_none.parse_rich_header.return_value = None
    with patch("pefile.PE", return_value=fake_pe_none):
        assert _pe_rich_header("/nonexistent.exe") == {}
    assert _rich_header_html({}, "es") == ""


def test_pe_sibling_dll_signing_flags_dlls_without_authenticode(tmp_path):
    # Checklist base ("¿Y sus DLLs?" -- la firma no solo se comprueba en el EXE principal): DLLs
    # en el mismo directorio que el ejecutable sin tabla de certificados Authenticode.
    from unittest.mock import patch, MagicMock
    import os
    import pefile
    from binoracle.report.html import _pe_sibling_dll_signing, _sibling_dll_signing_html

    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    (tmp_path / "signed.dll").write_bytes(b"MZ")
    (tmp_path / "unsigned.dll").write_bytes(b"MZ")

    sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]

    def _fake_pe(path, fast_load=True):
        pe = MagicMock()
        dd = [MagicMock() for _ in range(20)]
        for d in dd:
            d.VirtualAddress = 0
            d.Size = 0
        # ojo: "unsigned.dll" contiene "signed.dll" como substring -> comparar el basename exacto
        if os.path.basename(str(path)) == "signed.dll":
            dd[sec_idx].VirtualAddress = 0x1000
            dd[sec_idx].Size = 0x200
        pe.OPTIONAL_HEADER.DATA_DIRECTORY = dd
        return pe

    with patch("pefile.PE", side_effect=_fake_pe):
        res = _pe_sibling_dll_signing(str(exe))
    assert res == {"unsigned_dlls": ["unsigned.dll"], "total": 2}
    html = _sibling_dll_signing_html(res, "es")
    assert "unsigned.dll" in html and "signed.dll" not in html.split("Authenticode")[1].split("<p")[0]

    # sin DLLs junto al ejecutable: nada que informar
    only_exe = tmp_path / "solo"
    only_exe.mkdir()
    (only_exe / "app.exe").write_bytes(b"MZ")
    assert _pe_sibling_dll_signing(str(only_exe / "app.exe")) == {}
    assert _sibling_dll_signing_html({}, "es") == ""


def test_pe_sandbox_flag_check_detects_no_sandbox_string():
    # Checklist base ("ejecucion sin sandboxing en componentes de terceros... se identifica al
    # detectar '--no-sandbox' en el comando ejecutado"): busca el literal en las strings (izz).
    from unittest.mock import patch
    from binoracle.report.html import _pe_sandbox_flag_check, _sandbox_flag_html

    class _FakeR2:
        def __init__(self, txt): self.txt = txt
        def cmd(self, c):
            return self.txt if c == "izz" else ""

    r2_electron = _FakeR2("0x1000 20 20 --no-sandbox\n0x1010 12 12 libcef.dll\n")
    with patch("binoracle.oracles.r2session.get", return_value=r2_electron):
        res = _pe_sandbox_flag_check("/nonexistent")
    assert res == {"found": True, "electron": True}
    html = _sandbox_flag_html(res, "es")
    assert "no-sandbox" in html and "Electron" in html

    r2_no_flag = _FakeR2("0x1000 10 10 hello world\n")
    with patch("binoracle.oracles.r2session.get", return_value=r2_no_flag):
        assert _pe_sandbox_flag_check("/nonexistent") == {}
    assert _sandbox_flag_html({}, "es") == ""


def test_rop_binsh_search_uses_real_null_byte():
    # Regresion: build_rop_chain buscaba b"/bin/sh\\x00" (doble barra invertida en el fuente ->
    # los 4 caracteres LITERALES '\','x','0','0', NO un byte nulo) en la libc proporcionada para
    # la estrategia 3 (ret2libc con --libc). Como ninguna libc real contiene ese texto literal, la
    # busqueda SIEMPRE fallaba y el offset de /bin/sh salia como '??' aunque la libc si tuviera el
    # string real. Se verifica con un mock que captura los bytes EXACTOS pasados a libc.search().
    import sys
    import types
    from unittest.mock import MagicMock, patch

    captured = {}

    class _FakeLibc:
        def __init__(self, *a, **k): pass
        def search(self, pattern):
            captured["pattern"] = pattern
            return iter([])                # simula que no se encuentra (no afecta la asercion)
        symbols = {"system": 0x1234}

    class _FakeElf:
        def __init__(self, *a, **k):
            self.pie = True; self.nx = True; self.plt = {}; self.symbols = {}
        def search(self, pattern):
            return iter([])                 # el binario no tiene '/bin/sh' -> fuerza estrategia 3

    fake_pwn = types.SimpleNamespace(
        context=MagicMock(arch="amd64", binary=None),
        ELF=lambda path, **k: _FakeLibc() if "libc" in str(path) else _FakeElf(),
        ROP=lambda elf: MagicMock())
    with patch.dict(sys.modules, {"pwn": fake_pwn}):
        import importlib
        from binoracle.workflows import rop as rop_mod
        importlib.reload(rop_mod)
        try:
            rop_mod.build_rop_chain("/fake/binary", goal="auto", libc_path="/fake/libc.so.6")
        finally:
            importlib.reload(rop_mod)   # restaura el modulo real (pwntools de verdad) para el resto
    assert captured.get("pattern") == b"/bin/sh\x00", (
        f"se busco {captured.get('pattern')!r} en vez del string real con byte nulo")


def test_chainanalyzer_facts_finds_binsh_in_izzj_list_format():
    # Regresion CRITICA (encontrada investigando ropme_pie por peticion del usuario): _facts()
    # parseaba `izzj` como json.loads(...).get("strings", []) -- pero izzj devuelve una lista JSON
    # DIRECTA ([{...}, ...]), no {"strings": [...]}. Llamar .get() sobre una lista lanza
    # AttributeError, capturado por el `except Exception: pass` que envuelve TODO el bloque, asi
    # que f["binsh"] JAMAS se establecia para NINGUN binario, sistematicamente -- no solo
    # ropme_pie. Confirmado con un binario real (ropme_pie) que SI tiene "/bin/sh" en .data
    # (viene de `char binsh[] = "/bin/sh";` en el fuente, para el reto ret2syscall), pero
    # _facts() nunca lo veia, asi que la cadena execve syscall salia con el requisito
    # "cadena '/bin/sh'" marcado [X] incluso estando presente.
    import os
    b = "samples/bin/ropme_pie"
    if not os.path.exists(b):
        return
    from binoracle.workflows.chainanalyzer import _facts
    f = _facts(b)
    assert f.get("binsh") is not None, "binsh no detectado pese a estar presente en .data"


def test_chainanalyzer_attempts_verify_on_pie_despite_pie_breakpoint():
    # Regresion CRITICA (misma familia que el hallazgo del heap): autopie.py's autopie_ret2win()
    # already WORKED standalone against a real PIE binary (resolves the ASLR-off sandbox base, no
    # leak needed), but analyze_chains() gated verification attempts on c.feasible, which requires
    # ZERO break_points -- and _mitig_breakpoints() always adds a PIE break_point ('addresses are
    # random, the chain breaks without a leak') to any PIE binary's ret2win/ret2libc/execve chain,
    # even though the PIE-aware verifier specifically does not need a leak. So _verify_chain() was
    # NEVER invoked for ANY PIE binary, regardless of budget, even though the working verifier was
    # one function call away. Fixed with _should_attempt_verify(): gate on unmet requirements only
    # (canary still blocks the attempt -- no driver bypasses it by brute force).
    import os
    import shutil
    b = "samples/bin/ret2win_pie"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    ret2win = next(c for c in an.chains if c.name == "ret2win")
    assert ret2win.unmet_requirements == 0
    assert ret2win.verified, ret2win.sim_result
    assert ret2win.proof.get("strategy") == "ret2win-pie"
    # el canary SI debe seguir bloqueando el intento (no hay bypass de canary en los drivers)
    b2 = "samples/bin/canary"
    if os.path.exists(b2):
        an2 = analyze_chains(b2, None, verify=True, lang="es")
        c2 = next(c for c in an2.chains if c.name == "ret2win")
        assert c2.sim_result in ("no simulada", "not simulated"), c2.sim_result


def test_find_win_resolves_gift_function_in_stripped_binary():
    # Nueva capacidad (user-requested: ret2win.stripped): find_win() solo buscaba el simbolo
    # 'win' por NOMBRE (_GIFT_RE sobre afl), asi que en un binario stripped (sin nombres de
    # funcion locales) nunca lo encontraba, aunque la funcion gift siga presente en el codigo.
    # Fix: system/execve/execl NUNCA se stripean (son imports dinamicos, necesarios para el
    # enlazado) -- se busca la funcion que LOS LLAMA (via xref) con un string de shell cerca
    # ('/bin/sh' etc), y se resuelve su direccion de INICIO real (afo), sea o no un simbolo
    # con nombre. Verificado con un binario real: ret2win.stripped ahora resuelve win() en la
    # MISMA direccion (0x401176) que su variante no-stripped, y analyze_chains() VERIFICA el
    # ret2win completo (shell real, uid=0) donde antes se quedaba en 'no se encontro una
    # funcion gift'.
    import os
    b = "samples/bin/ret2win.stripped"
    if not os.path.exists(b):
        return
    from binoracle.workflows.autopoc import find_win
    w = find_win(b)
    assert w == 0x401176, f"win esperado en 0x401176, obtenido {hex(w) if w else None}"


def test_ret2win_stripped_verifies_end_to_end():
    import os
    import shutil
    b = "samples/bin/ret2win.stripped"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    ret2win = next(c for c in an.chains if c.name == "ret2win")
    assert ret2win.unmet_requirements == 0
    assert ret2win.verified, ret2win.sim_result
    assert ret2win.proof.get("win") == "0x401176"


def test_ret2win32_verifies_end_to_end():
    # ret2win32 (32 bits, sin PIE) se quedaba SIEMPRE sin verificar por DOS bugs independientes,
    # ninguno de los dos especifico de Docker/qemu:
    #   1) autopoc.py empaquetaba la direccion de retorno con 8 bytes fijos (p64) sin importar
    #      la arquitectura del binario; en un ELF de 32 bits el valor de retorno en pila son 4
    #      bytes, asi que los 4 de mas escriben sobre lo que sigue en la pila y el proceso
    #      termina con SIGSEGV en vez de saltar a win(). Fix: _word_size(binary) via r2 'ij'.
    #   2) el offset devuelto por angr/el metodo estatico (_static_offset, que ademas sumaba +8
    #      fijos en vez de word_size) no coincidia exactamente con el offset real (80 vs 72):
    #      el padding de alineacion del compilador puede desplazarlo por exactamente un word.
    #      Fix: _offset_candidates ahora tambien prueba los vecinos +/- word_size de cada
    #      candidato.
    # Por separado (no cubierto por este test, requiere docker): _docker_run/_docker_run_raw
    # tambien se cambiaron de la imagen gcc:13 (sin libc6:i386) a binoracle-pwn (con soporte
    # i386 anadido a .docker/Dockerfile.pwn), o el proceso de 32 bits ni siquiera arrancaba
    # (qemu-i386: Could not open '/lib/ld-linux.so.2').
    import os
    import shutil
    b = "samples/bin/ret2win32"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    ret2win = next(c for c in an.chains if c.name == "ret2win")
    assert ret2win.unmet_requirements == 0
    assert ret2win.verified, ret2win.sim_result
    assert ret2win.proof.get("win") == "0x80491a6"


def test_autopoc_word_size_detects_32_vs_64_bit():
    import os
    from binoracle.workflows.autopoc import _word_size
    b32 = "samples/bin/ret2win32"
    b64 = "samples/bin/ret2win"
    if os.path.exists(b32):
        assert _word_size(b32) == 4
    if os.path.exists(b64):
        assert _word_size(b64) == 8


def test_chainanalyzer_wires_up_write_what_where_driver():
    # Nueva capacidad (user-requested: ampliar la cobertura de clases de vulnerabilidad
    # detectadas/verificadas): oobwrite.c tiene un write-what-where real ('table[idx] = val' sin
    # comprobar idx) que ningun chain type previo cubria (no es overflow lineal de pila, no es
    # heap-UAF). Construido y verificado con shell real en el sandbox: sin PIE, el offset entre
    # el array global y una entrada GOT (puts) es ESTATICO, asi que 'idx' se calcula sin ninguna
    # fuga y sobrescribe esa entrada con win(); el propio binario llama a esa funcion justo
    # despues (puts("ok")), disparando el exploit.
    import os
    import shutil
    b = "samples/bin/oobwrite"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    wow = next((c for c in an.chains if c.name == "write-what-where"), None)
    assert wow is not None, "no se construyo la cadena write-what-where (wow_ok debia ser True)"
    assert wow.verified, wow.sim_result
    assert wow.proof.get("offset") == -12


def test_facts_corrects_canary_false_positive_on_static_binaries():
    # BUG real (no un limite fundamental): `canary` de `ij` es un flag DEL BINARIO ENTERO. En un
    # binario estaticamente enlazado, __stack_chk_fail viaja siempre dentro de la libc completa
    # aunque NINGUNA funcion propia lo use, asi que r2 marcaba canary=True incluso cuando vuln()
    # no comprueba nada -- confirmado leyendo el desensamblado real de vuln() en los 4 binarios de
    # abajo (sus fuentes dicen explicitamente "no canary" y no hay ningun `fs:0x28`/stack_chk ahi).
    # Esto bloqueaba SIEMPRE su verificacion via _should_attempt_verify() (que rechaza canary=True
    # sin condiciones), pese a que un simple ret2win/ROP era perfectamente viable. `canary` y
    # `ret2win_hardened` (canary real, confirmado con `mov rax, qword fs:[0x28]` en su vuln())
    # deben seguir dando True: la correccion solo debe activarse para el falso positivo.
    import os
    from binoracle.workflows.chainanalyzer import _facts
    real_canary = {"samples/bin/canary": True, "samples/bin/ret2win_hardened": True}
    false_positive = {"samples/bin/ropme": False, "samples/bin/ropme_pie": False,
                       "samples/bin/srop": False, "samples/bin/staticrop": False}
    for b, expected in {**real_canary, **false_positive}.items():
        if not os.path.exists(b):
            continue
        f = _facts(b)
        assert f.get("canary") is expected, f"{b}: canary esperado {expected}, obtenido {f.get('canary')}"


def test_ropme_and_srop_verify_end_to_end_after_canary_fix():
    # Consecuencia directa del fix de arriba: antes de esto, ropme y srop NUNCA intentaban
    # verificarse (canary=True los bloqueaba en la puerta), pese a no tener canary real y tener
    # todos los gadgets necesarios para una cadena execve('/bin/sh') por syscall.
    import os
    import shutil
    from binoracle.workflows.chainanalyzer import analyze_chains
    for b in ("samples/bin/ropme", "samples/bin/srop"):
        if not os.path.exists(b) or not shutil.which("docker"):
            continue
        an = analyze_chains(b, None, verify=True, lang="es")
        execve = next((c for c in an.chains if c.name == "execve syscall"), None)
        assert execve is not None
        assert execve.verified, f"{b}: {execve.sim_result}"


def test_ropme_pie_verifies_with_retries_under_flaky_base_resolution():
    # ropme_pie es static-PIE. En este sandbox (Docker Desktop en Apple Silicon), un binario
    # static-PIE se traduce via Rosetta en vez de qemu-user, y resolve_base() (io.libs() /
    # /proc/pid/maps) solo atrapa la direccion real de carga en una VENTANA DE TIEMPO
    # intermitente -- confirmado probando la MISMA logica de resolucion muchas veces seguidas:
    # a veces encuentra la base real (y el exploit funciona con shell real, uid=0), a veces solo
    # ve el propio wrapper de Rosetta y usa el fallback fijo (que no es la base real, y el
    # syscall chain revienta el proceso de inmediato). El offset correcto (72, confirmado via
    # r2) YA estaba primero en la lista de offsets probados -- el problema nunca fue el offset,
    # sino que cada offset solo se intentaba con UNA resolucion de base. El fix (RETRIES por
    # offset en _DRIVER_ROP/_DRIVER en autopie.py) sube las probabilidades de atrapar la ventana
    # buena sin cambiar la logica de resolucion en si.
    import os
    import shutil
    from binoracle.workflows.chainanalyzer import analyze_chains
    b = "samples/bin/ropme_pie"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    an = analyze_chains(b, None, verify=True, lang="es")
    execve = next((c for c in an.chains if c.name == "execve syscall"), None)
    assert execve is not None
    assert execve.verified, execve.sim_result
    assert execve.proof.get("offset") == 72


def test_chainanalyzer_wires_up_tcache_dup_driver():
    # Nueva capacidad: notes_heap.c corre bajo glibc >= 2.34 (sin __free_hook/__malloc_hook) y
    # no tiene win()/system() en el binario -- ninguna de las tecnicas de heap previas (tcache
    # tcache-poison via autoheap.py, uaf funcptr-hijack via autouaf.py) aplica, ambas requieren
    # win(). La UNICA defensa activa contra el double-free es el campo `key` aleatorizado de
    # tcache; con una escritura UAF (edit sobre indice ya liberado) basta con corromperlo con
    # CUALQUIER valor para saltarsela -- no hace falta conocer su valor real. El envenenamiento
    # del puntero 'next' (safe-linking, XOR contra la propia direccion del campo) se calcula sin
    # ninguna fuga porque el sandbox corre con ASLR desactivado. La UNICA comprobacion real que
    # glibc sigue haciendo sobre la direccion envenenada es que este alineada a 16 bytes
    # ("malloc(): unaligned tcache chunk detected" si no) -- NO que el contenido en direccion-8
    # parezca un tamano de chunk valido (confirmado empiricamente: apuntar a atoi@GOT, que NO
    # esta alineado, aborta con ese mensaje exacto; apuntar a free@GOT, que SI esta alineado,
    # funciona sin comprobacion de tamano). Con free@GOT retargeteada a system() (resuelto desde
    # la libc local del sandbox), la propia operacion free() del binario sobre una nota cuyo
    # CONTENIDO es '/bin/sh' se convierte en system('/bin/sh') = shell real.
    import os
    import shutil
    b = "samples/bin/notes_heap"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    tcd = next((c for c in an.chains if c.name == "tcache dup"), None)
    assert tcd is not None, "no se construyo la cadena tcache dup (tcache_dup_ok debia ser True)"
    assert tcd.verified, tcd.sim_result
    assert tcd.proof.get("got_symbol") == "free"
    assert tcd.proof.get("got") == "0x404000"


def test_autotcachedup_excludes_binaries_with_win():
    # heapexp/uaf ya tienen win() y su propia tecnica mas directa (tcache-poison / funcptr
    # hijack); la cadena tcache_dup NO debe intentarse ahi (evita atacar un binario con una
    # tecnica pensada para el caso "sin gift function" cuando ya hay una mas simple disponible).
    import os
    from binoracle.workflows.autotcachedup import _tcache_dup_applicable
    for b in ("samples/bin/heapexp", "samples/bin/uaf"):
        if os.path.exists(b):
            assert _tcache_dup_applicable(b) is False


def test_chainanalyzer_wires_up_uaf_funcptr_hijack_driver():
    # Nueva capacidad: uaf.c tiene un UAF real (free() no anula el puntero) donde un malloc
    # posterior del MISMO tamano recicla el chunk liberado (tcache LIFO, sin doble-free ni fake
    # chunk) y la struct reciclada empieza con un puntero a funcion. Tecnica DISTINTA de la ya
    # cubierta por uaf_tcache/autoheap.py (esa necesita fabricar un chunk falso en free@GOT). El
    # menu (numeros de opcion) se reconoce dinamicamente por las cadenas del binario, no esta
    # cableado al protocolo concreto de este sample (1)new 2)free 3)run 4)note).
    import os
    import shutil
    b = "samples/bin/uaf"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    uaf = next((c for c in an.chains if c.name == "uaf funcptr-hijack"), None)
    assert uaf is not None, "no se construyo la cadena uaf funcptr-hijack (uaf_fnptr_ok debia ser True)"
    assert uaf.verified, uaf.sim_result
    assert uaf.proof.get("win") == "0x4011d7"


def test_chainanalyzer_wires_up_format_string_driver():
    # Nueva capacidad (misma linea de trabajo que write-what-where: ampliar clases de
    # vulnerabilidad cubiertas). autofmt.py YA EXISTIA completo (offset via %N$p, resolucion de
    # system() desde la libc local del sandbox, fmtstr_payload sobre printf@GOT) y funcionaba
    # standalone (autofmt('samples/bin/fmtstring') -> verified=True) pero no tenia NINGUNA
    # referencia en chainanalyzer.py: no habia hecho ('printf' en _facts), ni cadena, ni rama en
    # _verify_chain. fmtstring.c no llama a system() ni tiene win(): el exploit retarget-ea
    # printf@GOT a system usando la libc local (misma logica que ret2libc con leak, pero sin
    # necesitar ninguna fuga real porque estamos verificando en sandbox controlado) y la propia
    # siguiente llamada a printf(buf) del programa se convierte en system(buf).
    import os
    import shutil
    b = "samples/bin/fmtstring"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    fmt = next((c for c in an.chains if c.name == "format-string"), None)
    assert fmt is not None, "no se construyo la cadena format-string (printf debia estar importado)"
    assert fmt.verified, fmt.sim_result
    assert fmt.proof.get("offset") == 6


def test_chainanalyzer_format_string_driver_handles_pie():
    # Misma cadena que arriba pero sobre la variante PIE: confirma que autofmt.py resuelve
    # correctamente la base de printf@GOT y de system() via io.libs() cuando el binario esta
    # cargado a una direccion aleatorizada, sin depender de ninguna direccion fija.
    import os
    import shutil
    b = "samples/bin/fmtstring_pie"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    fmt = next((c for c in an.chains if c.name == "format-string"), None)
    assert fmt is not None, "no se construyo la cadena format-string (printf debia estar importado)"
    assert fmt.verified, fmt.sim_result


def test_chainanalyzer_wires_up_working_heap_driver():
    # Regresion CRITICA: autoheap.py's autoheap_shell() (tcache-poison -> free@GOT=win, full
    # sandbox exploit) already existed and WORKED standalone -- verified directly against
    # samples/bin/heapexp returns verified=True -- but analyze_chains() (the function
    # plan_for_binary()/the trainer actually calls) never invoked it at all: classify_binary()
    # correctly tagged these binaries 'uaf', but no chain ever attempted the working driver, so
    # they stayed 'template, not verified' forever regardless of budget (confirmed across 3
    # training runs in this session, all reporting 0/N heap binaries verified).
    import os
    import shutil
    b = "samples/bin/heapexp"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains(b, None, verify=True, lang="es")
    heap_chains = [c for c in an.chains if c.name == "uaf tcache-poison"]
    assert heap_chains, "no se construyo la cadena de heap (heap_shell_ok debia ser True)"
    assert heap_chains[0].verified, heap_chains[0].sim_result
    assert "VERIFIED" in (heap_chains[0].proof.get("output") or "")
    assert heap_chains[0].proof.get("free_got") == "0x404000"


def test_cveplan_classify_no_substring_false_positives():
    # Regresion CRITICA: classify_binary() (el clasificador central de clase de vulnerabilidad que
    # decide que tipo de exploit desarrollar) usaba substring sobre el texto crudo de imports:
    # "free" in texto hacia match dentro de "freeaddrinfo" (getaddrinfo/red, nada que ver con
    # free() de memoria), clasificando como 'uaf' un binario que malloc()+usa red pero NUNCA llama
    # a free(). Confirmado con un binario real. Mismo motivo para 'gets' en 'getsockopt' etc.
    from binoracle.workflows.cveplan import classify_binary
    reg = _mock_reg(imports="sym.imp.malloc\nsym.imp.freeaddrinfo\nsym.imp.getaddrinfo")
    assert classify_binary("x", reg=reg) is None, "malloc+freeaddrinfo NO deberia ser 'uaf'"
    reg2 = _mock_reg(imports="sym.imp.getsockopt")
    assert classify_binary("x", reg=reg2) is None, "getsockopt NO deberia ser 'stack-overflow'"
    # true positive: malloc+free REALES si deben marcarse (heap) cuando r2_heap lo confirma
    reg3 = _mock_reg(imports="sym.imp.malloc\nsym.imp.free")
    class _Heap:
        def run(self):
            from binoracle.oracles.base import ToolResult
            return ToolResult(True, "r2", "uaf surface detected")
    orig_get = reg3.get
    reg3.get = lambda n: _Heap() if n == "r2_heap" else orig_get(n)
    assert classify_binary("x", reg=reg3) == "uaf"


def test_cfg_branch_note_no_substring_false_positives():
    # Regresion: _branch_note marcaba un bloque como "llama a una funcion sensible" (gets/read...)
    # via substring ("d in c"), asi que una llamada a getsockopt()/readlink()/readdir()/pread()
    # (nada que ver con gets()/read() sin limite) se etiquetaba igual como "sink peligroso" en el
    # grafo del informe. Confirmado: "gets" in "getsockopt" es True en Python.
    from binoracle.workflows.cfg import _branch_note
    insns_safe = [{"txt": "call sym.imp.getsockopt", "addr": "0x0"},
                  {"txt": "cmp eax, 0", "addr": "0x1"},
                  {"txt": "je 0x10", "addr": "0x2"}]
    note = _branch_note(insns_safe)
    assert "getsockopt" not in note or "sensible" not in note
    # el verdadero positivo (gets real) SI debe seguir marcandose
    insns_real = [{"txt": "call sym.imp.gets", "addr": "0x0"},
                  {"txt": "cmp eax, 0", "addr": "0x1"},
                  {"txt": "je 0x10", "addr": "0x2"}]
    note2 = _branch_note(insns_real)
    assert "sensible" in note2 and "gets" in note2


def test_autopoc_find_pc_offset_respects_wall_clock_budget():
    # Regresion: find_pc_offset() (busqueda simbolica del offset a RIP, probada ANTES del metodo
    # estatico rapido en _offset_candidates) solo tenia un tope de 400 PASOS, no de tiempo real --
    # un binario dirigido por menu con malloc/free de tamano simbolico puede hacer que UN SOLO paso
    # tarde minutos (Z3 bit-blasting una multiplicacion simbolica: size*count), asi que el tope de
    # pasos no protegia nada. Confirmado con un sample real del proceso: 100% del tiempo dentro de
    # bit_blaster_tpl::mk_const_case_multiplier mientras exploraba un binario de heap real
    # (heapexp), sin terminar ni con 240s de presupuesto EXTERNO (el timeout real estaba mas
    # arriba, en el trainer, no dentro de la propia busqueda). Ahora corta por reloj real.
    import os
    import time
    try:
        import angr  # noqa
    except ImportError:
        return
    from binoracle.workflows.autopoc import find_pc_offset
    b = "samples/bin/heapexp"
    if not os.path.exists(b):
        return
    t0 = time.time()
    find_pc_offset(b, budget_s=5.0)
    elapsed = time.time() - t0
    assert elapsed < 30, f"find_pc_offset tardo {elapsed:.1f}s con budget_s=5 -- el limite no corta"


def test_symbolic_angr_rebases_pie_addresses_for_auto_verify():
    # Regresion CRITICA (misma familia que reachability.py, aqui en el oraculo angr_reachable que
    # usa auto_verify para promocionar hallazgos de 'grounded' a 'verified' en el informe de
    # Auditar): la direccion objetivo NUNCA se rebasaba del espacio de r2 (PIE reportado como si
    # cargase en base 0) al espacio de angr (siempre carga en su propia base fija, ~0x400000),
    # asi que auto_verify jamas podia promocionar NADA en un binario PIE -- el modo de compilacion
    # por defecto hoy en dia. Verificado end-to-end sobre ret2win_pie real.
    import os
    try:
        import angr  # noqa
    except ImportError:
        return
    from binoracle.oracles import build_registry
    from binoracle.store.session import Finding
    from binoracle.workflows.verify import auto_verify
    b = "samples/bin/ret2win_pie"
    if not os.path.exists(b):
        return
    reg = build_registry(b)
    f = Finding(title="Posible desbordamiento via gets", severity="high", verdict="grounded",
               location="gets", evidence="[radare2] call to gets at 0x11e5",
               rationale="...", recommendation="...")
    findings, notes = auto_verify(reg, [f])
    assert findings[0].verdict == "verified", notes


def test_reachability_rebases_pie_addresses_for_angr():
    # Regresion CRITICA: find_input_to/reachable_findings nunca rebasaba la direccion objetivo del
    # espacio de r2 (que en un binario PIE reporta offsets como si la carga fuera en base 0, p.ej.
    # un sink en 0x11a6) al espacio de angr (que SIEMPRE carga en su propia base fija, tipicamente
    # 0x400000). La funcion de rebase existia pero ambas ramas de su condicional devolvian el valor
    # SIN CAMBIOS (no-op) y ademas nunca se llamaba -- el 'target' pedido a angr caia fuera del
    # espacio de direcciones cargado, asi que la busqueda NUNCA podia tener exito: la capacidad de
    # verificacion por angr (el nivel de evidencia mas fuerte del sistema, 'verified') estaba inerte
    # en TODO binario PIE, que es el modo de compilacion por defecto en toolchains modernas.
    import os
    try:
        import angr  # noqa
    except ImportError:
        return                         # angr no instalado en este entorno: se omite
    from binoracle.workflows.reachability import reachable_findings
    b = "samples/bin/ret2win_pie"
    if not os.path.exists(b):
        return                         # corpus se construye con samples/build.sh
    fs = reachable_findings(b, budget_s=25, max_targets=2)
    assert fs, "angr no alcanzo ningun sink en un PIE real -- el rebase sigue roto"
    assert any(f.verdict == "verified" for f in fs)
    # el input concreto recuperado debe ser la contrasena real del reto (prueba de que la busqueda
    # realmente ejecuto el binario correcto, no una direccion aleatoria que resulto alcanzable)
    assert any("sup3rs3cr3t" in f.evidence for f in fs)


def test_authz_drop_must_guard_the_exec_path(tmp_path):
    # Regresion: 'setuid ejecuta comandos sin soltar privilegios' exigia que setuid/setgid/...
    # estuviera AUSENTE en TODO el binario -- un binario con setuid() en una funcion 'safe_path()'
    # que nunca se invoca desde el camino real que hace exec() se consideraba seguro (falso negativo
    # confirmado con un binario real: setuid+printf en una funcion, execl SIN drop en otra, ambas
    # alcanzables desde main segun argv). Ahora exige que el drop este ausente en la MISMA funcion
    # que hace el exec.
    import os
    from binoracle.workflows.authz import scan_authz
    p = tmp_path / "suidbin"; p.write_bytes(b"\x7fELF"); os.chmod(p, 0o4755)

    # execl llamado desde vuln_path; setuid llamado desde una funcion DISTINTA (safe_path) -> inseguro
    reg = _mock_reg(imports="sym.imp.execl\nsym.imp.setuid",
                    callers={"execl": "sym.vuln_path", "setuid": "sym.safe_path"})
    fs = scan_authz(reg, str(p))
    assert any("sin soltar privilegios" in f.title.lower() for f in fs)
    assert any("vuln_path" in f.evidence for f in fs)

    # execl y setuid llamados desde la MISMA funcion -> seguro (orden no se verifica, pero al menos
    # el drop esta en el camino real, que es la mejora minima grounded)
    reg2 = _mock_reg(imports="sym.imp.execl\nsym.imp.setuid",
                     callers={"execl": "sym.main", "setuid": "sym.main"})
    assert not any("ejecuta comandos" in f.title.lower() for f in scan_authz(reg2, str(p)))


def test_hardening_ld_preload_requires_exact_string_value():
    # Regresion: el check de LD_* disparaba con cualquier setenv/putenv + la SUBCADENA "LD_PRELOAD"
    # en cualquier parte de las strings, incluido un texto de ayuda que solo la MENCIONA ("set
    # LD_PRELOAD to use a custom allocator") sin relacion con ninguna llamada real. Ahora exige que
    # el VALOR de un string sea EXACTAMENTE "LD_PRELOAD"/"LD_LIBRARY_PATH" (el nombre de variable
    # real que se pasaria a setenv), no una mencion dentro de una frase.
    from binoracle.workflows.hardening import scan_hardening
    distractor = _mock_reg(imports="sym.imp.setenv",
                           strings="set LD_PRELOAD to use a custom allocator")
    assert not any("entorno" in f.title.lower() for f in scan_hardening(distractor, "x"))
    real = _mock_reg(imports="sym.imp.setenv", strings="LD_PRELOAD")
    assert any("entorno" in f.title.lower() for f in scan_hardening(real, "x"))


def test_hardening_path_relative_was_dead_code():
    # Regresion CRITICA: el check (c) exigia comillas LITERALES ("cmd") en el texto de r2_strings,
    # pero la tabla `izz` de r2 NUNCA envuelve el valor entre comillas (son celdas de tabla) -- este
    # check no pudo dispararse NUNCA en ningun binario real desde que se escribio (falso negativo
    # del 100%, no falso positivo). Confirmado con un binario real: system("ps aux").
    from binoracle.workflows.hardening import scan_hardening
    # _mock_reg envuelve `strings` como filas reales de tabla `izz` (ver su definicion mas arriba):
    # se le pasa el VALOR plano de cada string, una por linea.
    reg = _mock_reg(imports="sym.imp.system", strings="ps aux")
    titles = " ".join(f.title.lower() for f in scan_hardening(reg, "x"))
    assert "path" in titles, titles
    # una frase que solo MENCIONA un nombre de comando (no lo tiene como primer token) no cuenta
    reg2 = _mock_reg(imports="sym.imp.system", strings="usage: pass -v or ps to see status")
    assert not any("path" in f.title.lower() for f in scan_hardening(reg2, "x"))


def test_commsec_prng_detects_bare_import_name():
    # Regresion: el regex de PRNG exigia el prefijo 'sym.imp.rand' que no siempre aparece en la
    # salida real de r2 (algunos binarios listan solo el nombre bare 'rand') -- falso NEGATIVO real,
    # confirmado con un binario sintetico (rand() para un dado de juego). Con imported_names() se
    # detecta sea cual sea el formato de prefijo.
    from binoracle.workflows.commsec import scan_comms
    reg = _mock_reg(imports="1  0x1000  global  func       rand\n2  0x1010  global  func       srand")
    titles = " ".join(f.title.lower() for f in scan_comms(reg, "x"))
    assert "aleatorios" in titles or "prng" in titles.lower()
    # con un CSPRNG real presente, no se marca
    reg2 = _mock_reg(imports="sym.imp.rand", strings="getrandom")
    assert not any("aleatorios" in f.title.lower() for f in scan_comms(reg2, "x"))


def test_fileperms_getenv_exec_requires_same_function():
    # Regresion: getenv+exec en el binario (en cualquier sitio) ya NO basta -- un getenv("LANG") de
    # un saludo y un system() fijo de un helper de backup, sin relacion, no deben dispararse juntos.
    from binoracle.workflows.fileperms import scan_file_perms
    same = _mock_reg(imports="sym.imp.getenv\nsym.imp.system", same_func=True)
    titles_same = " ".join(f.title.lower() for f in scan_file_perms(same, "x"))
    assert "entorno" in titles_same
    diff = _mock_reg(imports="sym.imp.getenv\nsym.imp.system", same_func=False)
    assert scan_file_perms(diff, "x") == []


def test_versions_uses_max_not_first_glibc_match():
    # Regresion: en un binario dinamico, la tabla de simbolos versionados de glibc (.dynstr) repite
    # 'GLIBC_2.2.5' para casi toda funcion base (nivel ABI minimo casi universal), mientras la
    # version real vinculada tambien aparece pero con menos frecuencia. Tomar la PRIMERA coincidencia
    # (.search) casi siempre devolvia 2.2.x, marcando como 'antigua' una glibc moderna real -- se
    # confirmo en 13 de ~20 binarios del corpus (todos compilados con GCC 13, glibc real 2.34).
    from binoracle.workflows.versions import scan_versions
    reg = _mock_reg(strings="GLIBC_2.2.5\nGLIBC_2.2.5\nGLIBC_2.34\nGLIBC_2.2.5\nGLIBC_2.2.6")
    fs = scan_versions(reg, "x", "es")
    titles = " ".join(f.title.lower() for f in fs)
    assert "glibc 2.34" in titles
    assert "antiguo" not in titles, titles       # 2.34 es moderna; no debe marcarse como antigua
    # un binario que SOLO referencia simbolos antiguos (glibc real vieja) SI debe marcarse
    reg2 = _mock_reg(strings="GLIBC_2.2.5\nGLIBC_2.2.5\nGLIBC_2.2.6")
    fs2 = scan_versions(reg2, "x", "es")
    assert any("antiguo" in f.title.lower() for f in fs2)


def test_authcheck_still_detects_real_hardcoded_credential():
    # No basta con no dar falsos positivos: un strcmp contra un identificador con pinta de credencial
    # real (guion bajo, valor no trivial) SIGUE debiendo dispararse, con la evidencia limpia (el
    # valor real, no una fila de tabla cruda con offsets).
    reg = _mock_reg(imports="sym.imp.strcmp",
                    strings="password: \nMASTER_PASSWORD_2024xk")
    from binoracle.workflows.authcheck import scan_auth
    fs = scan_auth(reg, "x", "es")
    assert any("comparacion" in f.title.lower() for f in fs)
    hi = next(f for f in fs if "comparacion" in f.title.lower())
    assert "MASTER_PASSWORD_2024xk" in hi.evidence
    assert "0x0" not in hi.evidence          # evidencia limpia, sin metadatos de tabla cruda


def test_injection_no_false_positive_on_unrelated_gift_function():
    # Regresion sobre binario real: ret2win.c llama system("/bin/sh") FIJO dentro de win(), sin
    # relacion con gets(buf) de main() -- antes del fix, 'entrada + exec en algun sitio' disparaba
    # 'Superficie de inyeccion' en ~60% del corpus de ejemplo (ret2win, canary, oobwrite...).
    import os
    from binoracle.oracles import build_registry
    from binoracle.workflows.injection import scan_injection
    b = "samples/bin/ret2win"
    if not os.path.exists(b):
        return
    reg = build_registry(b)
    fs = scan_injection(reg, b, "es")
    assert not any("inyeccion" in f.title.lower() for f in fs), [f.title for f in fs]


def test_no_false_positives_on_static_binary():
    # Regresion: un binario ESTATICO minimo (solo un overflow) no debe generar falsos positivos de
    # SQLi / cleartext / logging por strings o simbolos de la glibc embebida (caso informe_staticrop).
    import os
    from binoracle.oracles import build_registry
    from binoracle.workflows.injection import scan_injection
    from binoracle.workflows.commsec import scan_comms
    from binoracle.workflows.logging_check import scan_logging
    from binoracle.workflows._binfacts import is_static, has_network, imported_names
    b = "samples/bin/staticrop"
    if not os.path.exists(b):
        return                         # corpus se construye con samples/build.sh
    reg = build_registry(b)
    assert is_static(reg) is True
    assert has_network(reg) is False               # 'bind' de la cabecera de ii NO cuenta como red
    assert not (imported_names(reg) & {"nth", "bind", "vaddr", "name"})  # cabecera no parseada
    fp = (scan_injection(reg, b, "es") + scan_comms(reg, b, "es") + scan_logging(reg, b, "es"))
    titles = [f.title for f in fp]
    assert not any("sql" in t.lower() for t in titles), titles
    assert not any("cifrar" in t.lower() or "cleartext" in t.lower() for t in titles), titles
    assert not any("logging" in t.lower() or "registro" in t.lower() for t in titles), titles


def test_binfacts_parses_import_names():
    from binoracle.workflows._binfacts import imported_names, has_network, _NET_APIS
    # formato mock 'sym.imp.socket' -> nombre bare 'socket'; y red por marcador CURLOPT
    import sys; sys.path.insert(0, "tests")
    from test_tools_and_config import _mock_reg
    reg = _mock_reg(imports="1 0x1 GLOBAL FUNC libc connect\nsym.imp.socket", strings="")
    names = imported_names(reg)
    assert "connect" in names and "socket" in names and "nth" not in names
    assert has_network(reg) is True
    assert has_network(_mock_reg(imports="sym.imp.MD5_Init", strings="CURLOPT_SSL_VERIFYPEER=0")) is True
    assert has_network(_mock_reg(imports="sym.imp.printf", strings="hello")) is False


def test_decompiled_func_has_ok_property():
    # Regresion: la propiedad `ok` de DecompiledFunc estaba mal ubicada (pegada por error dentro
    # del cuerpo de func_technical(), tras su return, como codigo muerto), asi que la dataclass
    # nunca tenia el atributo. decompile_explain() y _decompile_vuln_funcs() acceden a `d.ok`
    # incondicionalmente, asi que CUALQUIER decompilacion (via CLI o el informe web) lanzaba
    # AttributeError, capturado en silencio y dejando el informe sin la seccion de "Decompilacion
    # anotada" (detectado al regenerar el informe real de Ingrid.exe).
    from binoracle.workflows.decompile import DecompiledFunc
    assert DecompiledFunc(func="main", raw="int main(){}", engine="pdc").ok is True
    assert DecompiledFunc(func="main", raw="   ", engine="pdc").ok is False
    assert DecompiledFunc(func="main").ok is False
