"""Offline smoke tests: no model, no external network. Exercise the grounded pipeline."""
import subprocess
import sys
from pathlib import Path

from binoracle.oracles import build_registry
from binoracle.oracles.base import ToolRegistry
from binoracle.workflows.triage import run_triage
from binoracle.agent.tools import extract_action


def test_extract_action_from_fenced_json():
    text = 'sure!\n```json\n{"action":"tool","tool":"r2_info","args":{}}\n```\n'
    a = extract_action(text)
    assert a and a["action"] == "tool" and a["tool"] == "r2_info"


def test_extract_action_balanced_braces_in_prose():
    text = 'I will call {"action": "final", "answer": "done {ok}", "findings": []} now'
    a = extract_action(text)
    assert a and a["action"] == "final"


def test_extract_action_none_on_garbage():
    assert extract_action("no json here at all") is None


def test_registry_status_never_crashes(tmp_path):
    # a non-binary file: oracles must degrade, not raise
    f = tmp_path / "x.txt"
    f.write_text("hello")
    reg = build_registry(str(f))
    assert isinstance(reg, ToolRegistry)
    status = reg.status()
    assert any("elf_meta" in s for s in status)


def test_triage_runs_without_model(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"\x7fELF" + b"\x02\x01" + b"\x00" * 100)
    reg = build_registry(str(f))
    report = run_triage(reg, str(f))
    # elf_meta must have produced at least the header section
    titles = [t for (t, _s, _x) in report.sections]
    assert any("ELF" in t or "mitigation" in t.lower() for t in titles)


def test_cyclic_matches_pwntools_offset():
    from binoracle.oracles.exploit_helpers import de_bruijn, cyclic_find
    # pwntools: cyclic_find(0x6161616c) == 44
    assert cyclic_find(0x6161616c) == 44
    assert cyclic_find("laaa") == 44
    pat = de_bruijn("abcdefghijklmnopqrstuvwxyz", 4, 16)
    assert pat == b"aaaabaaacaaadaaa"


def test_fmtstr_offset_math():
    from binoracle.oracles.exploit_helpers import ExploitHelperOracle
    o = ExploitHelperOracle()
    r = o._fmt(40, 8)
    assert r.meta["index"] == 5  # 40 / 8


def test_skeleton_is_valid_python(tmp_path):
    import ast as _ast
    from binoracle.oracles import build_registry
    from binoracle.workflows.skeleton import generate_skeleton
    f = tmp_path / "b.bin"
    f.write_bytes(b"\x7fELF" + b"\x02\x01" + b"\x00" * 100)
    reg = build_registry(str(f))
    script = generate_skeleton(reg, str(f), offset=64)
    _ast.parse(script)  # must be syntactically valid Python
    assert "OFFSET = 64" in script


def test_patchdiff_render_no_crash():
    from binoracle.workflows.patchdiff import DiffResult, render_patchdiff
    r = DiffResult(old="a", new="b", changed=["0.5 func x"], raw="raw")
    out = render_patchdiff(r)
    assert "patch-diff" in out and "func x" in out


def test_gate_downgrades_verified_without_proof():
    from binoracle.agent.grounding import GroundingLedger, gate_findings
    from binoracle.store.session import Finding
    led = GroundingLedger()
    led.record(1, "r2_sinks", "radare2: dangerous sinks", "sink: gets main 0x1149 bl sym.imp.gets")
    f = Finding(title="overflow via gets", severity="high", verdict="verified",
                evidence="main 0x1149 bl sym.imp.gets", location="main")
    gated, notes = gate_findings([f], led)
    # no angr/dbg in ledger -> verified must be capped to grounded
    assert gated[0].verdict == "grounded"
    assert any("verified->grounded" in n for n in notes)


def test_gate_flags_empty_evidence():
    from binoracle.agent.grounding import GroundingLedger, gate_findings
    from binoracle.store.session import Finding
    led = GroundingLedger()
    f = Finding(title="hand-wavy claim", severity="high", verdict="grounded", evidence="")
    gated, notes = gate_findings([f], led)
    assert gated[0].verdict == "unverified"


def test_gate_allows_verified_with_angr_proof():
    from binoracle.agent.grounding import GroundingLedger, gate_findings
    from binoracle.store.session import Finding
    led = GroundingLedger()
    led.record(1, "angr: explore(find=0x401176)", "angr: explore(find=0x401176)", "REACHABLE from entry")
    f = Finding(title="win reachable", severity="high", verdict="verified",
                evidence="REACHABLE from entry 0x401176", location="win")
    gated, notes = gate_findings([f], led)
    assert gated[0].verdict == "verified"


def test_fuzz_harness_generation():
    from binoracle.workflows.fuzz import afl_command, libfuzzer_harness
    assert "afl-fuzz" in afl_command("./target")
    h = libfuzzer_harness("parse_header")
    assert "LLVMFuzzerTestOneInput" in h and "parse_header" in h


def test_fmtstring_leak_probe():
    from binoracle.workflows.fmtstring import leak_probe, leak_at
    assert "%1$p" in leak_probe() and leak_at(7) == "%7$p"


def test_shellcode_precompiled_table():
    from binoracle.workflows.shellcode import _PRECOMPILED_SH
    assert len(_PRECOMPILED_SH["amd64"]) == 23  # classic execve /bin/sh
    assert "i386" in _PRECOMPILED_SH


def test_patchdiff_parses_similarity():
    from binoracle.workflows.patchdiff import DiffResult
    # ensure the render path is stable for a changed function line
    from binoracle.workflows.patchdiff import render_patchdiff
    r = DiffResult(old="a", new="b", changed=["sym.f 6 0x1 | MATCH (0.833) | 0x2 6 sym.g"], raw="x")
    assert "0.833" in render_patchdiff(r)


def test_autopoc_script_and_render():
    from binoracle.workflows.autopoc import build_script, render_poc, PoCResult
    sc = build_script("/tmp/x", 72, 0x401176, 0x401016)
    assert "flat({" in sc and "0x401176" in sc and "0x401016" in sc
    r = PoCResult(ok=True, stage="built", offset=72, win=0x401176,
                  script=sc, payload_hex="4141", verified=True)
    out = render_poc(r)
    assert "Auto-PoC" in out and "offset" in out and "SI" in out


def test_autopwn_render():
    from binoracle.workflows.autopwn import AutopwnResult, render_autopwn
    r = AutopwnResult(binary="/tmp/x", verified_findings=3, win_exploit=True,
                      attempts=[("ret2win", True, "offset=72"), ("rop-chain", False, "no")])
    out = render_autopwn(r)
    assert "Auto-explotacion" in out and "ret2win" in out and "EXPLOIT VERIFICADO" in out


def test_autopwn_render_shows_context_and_rationale():
    # El informe debe reflejar el CONTEXTO (defensas) y POR QUE se eligio la tecnica, no solo el
    # resultado -- para que se lea como un analisis de exploiting profesional por binario.
    import json as _json
    from binoracle.workflows.autopwn import AutopwnResult, render_autopwn, autopwn_to_json
    r = AutopwnResult(binary="/tmp/x", verified_findings=1, win_exploit=True,
                      attempts=[("ret2win", False, "canary"),
                                ("canary-bypass", True, "VERIFIED bufsz=72 canary=0x..00")],
                      arch="x86", bits="64",
                      mit={"nx": "true", "pic": "false", "canary": "true", "relro": "partial"},
                      sinks=["system", "read"], has_win=True)
    out = render_autopwn(r)
    assert "Contexto del binario" in out
    assert "canary ON" in out and "NX ON" in out and "PIE off" in out
    assert "por que la tecnica elegida" in out and "fuga del canary" in out
    j = _json.loads(autopwn_to_json(r))
    assert j["context"]["mitigations"]["canary"] == "true"
    assert "fuga del canary" in j["rationale"]


def test_autolibc_render():
    from binoracle.workflows.autolibc import render_libc
    out = render_libc({"ok": True, "verified": True, "detail": "VERIFIED off=88 base=0x7f...",
                       "note": "ret2libc con leak", "output": "shell"})
    assert "ret2libc" in out and "SI" in out
    out2 = render_libc({"ok": False, "note": "docker no disponible"})
    assert "No disponible" in out2


def test_autofmt_render():
    from binoracle.workflows.autofmt import render_fmt
    out = render_fmt({"ok": True, "verified": True, "detail": "VERIFIED offset=6",
                      "note": "format-string", "output": "shell"})
    assert "format-string" in out and "SI" in out


def test_regress_render():
    from binoracle.workflows.regress import RegressResult, render_regress
    r = RegressResult(old="a", new="b", mit_changes=["Canary: false -> true"],
                      new_findings=["X @ y [grounded]"])
    out = render_regress(r)
    assert "Regresiones" in out and "Canary" in out and "NUEVOS" in out


def test_autoheap_render():
    from binoracle.workflows.autoheap import render_heap
    out = render_heap({"ok": True, "confirmed": True,
                       "hits": [{"kind": "double-free", "input": "f", "pattern": "free():",
                                 "output": "free(): double free detected"}]})
    assert "double-free" in out and "SI" in out


def test_cyclic_offset_rejects_bogus_small_value():
    # Regresion: un modelo pequeno solia iterar cyclic_offset con 0,1,2,... quemando pasos.
    # Ahora un valor que no vino de un crash devuelve un error correctivo, no un 'not found' mudo.
    from binoracle.oracles.exploit_helpers import ExploitHelperOracle
    off = next(t for t in ExploitHelperOracle("x").tools() if t.name == "cyclic_offset")
    r = off.run(value=0)
    assert r.ok is False and r.meta.get("bogus") is True
    assert "not a value observed in a crash" in (r.error or "")
    # un valor real del patron ciclico sigue resolviendo el offset
    good = off.run(value="0x6161616c")
    assert good.ok is True and "offset" in good.data


def test_agent_loop_caps_repeated_tool_calls():
    # Regresion: la misma tool con args distintos (cyclic_offset value=0,1,2,...) ya no se
    # ejecuta sin fin; tras el tope por herramienta el loop empuja a otra cosa / final.
    from binoracle.agent.loop import AgentLoop
    from binoracle.config import load_config
    from binoracle.oracles.base import Oracle, Tool, ToolParam, ToolResult, ToolRegistry

    calls = {"n": 0}

    class _Echo(Oracle):
        name = "echo"
        def available(self):
            return True
        def tools(self):
            def run(value):
                calls["n"] += 1
                return ToolResult(True, "echo", f"got {value}")
            return [Tool("echo_tool", "echo", [ToolParam("value", "v")], run, self.name)]

    class _SpamLLM:
        # siempre pide la misma tool con un value incremental (nunca finaliza por si mismo)
        def __init__(self):
            self.i = 0
        def available(self):
            return True
        def chat(self, messages, *, json_mode=False):
            self.i += 1
            return '{"action":"tool","tool":"echo_tool","args":{"value":%d}}' % self.i

    cfg = load_config()
    cfg.max_steps = 12
    reg = ToolRegistry([_Echo()])
    res = AgentLoop(_SpamLLM(), reg, cfg).run("spam", mode="ask")
    # el tope (4) impide que se ejecute mas de 4 veces aunque el modelo lo pida 12
    assert calls["n"] <= 4
    assert res.steps <= cfg.max_steps


def test_gate_allows_verified_with_sandbox_exploit():
    # Un exploit ejecutado y confirmado en sandbox es prueba suficiente para 'verified'
    # (mas fuerte que la alcanzabilidad de angr); no debe degradarse a 'grounded'.
    from binoracle.agent.grounding import GroundingLedger, gate_findings
    from binoracle.store.session import Finding
    led = GroundingLedger()
    led.record(1, "try_ret2win", "autopoc: ret2win (sandbox-verified)",
               "EXPLOIT VERIFICADO offset=72 win=0x401176 ___POC_SHELL___ uid=0(root)")
    f = Finding(title="ret2win", severity="critical", verdict="verified",
                evidence="offset=72 win=0x401176 ___POC_SHELL___", location="win")
    gated, notes = gate_findings([f], led)
    assert gated[0].verdict == "verified"
    assert not any("verified->grounded" in n for n in notes)


def test_annotate_banner_tiers():
    # El banner se ajusta al grounding real, no a si la prosa lleva tags [src:].
    from binoracle.agent.grounding import GroundingLedger
    # 1) prosa ya citada -> sin banner
    led = GroundingLedger()
    led.record(1, "r2_checksec", "radare2: iI", "NX true")
    cited = "NX is enabled [src: radare2: iI]."
    assert led.annotate(cited) == cited
    # 2) sin tags pero con rastro de evidencia -> nota tranquila, no warning
    out = led.annotate("NX is enabled.")
    assert "[!note]" in out and "evidence trail" in out and "[!warning]" not in out
    # 3) sin tags y sin oraculos consultados -> warning duro
    empty = GroundingLedger()
    out2 = empty.annotate("The binary is safe.")
    assert "[!warning]" in out2 and "unverified" in out2


def test_fmtstr_offset_robust_to_bad_word():
    # Regresion: un modelo pequeno pasaba word=False (-> int 0 -> division por cero).
    # Ahora un 'word' invalido (bool/basura/0) se ajusta al tamano de puntero por defecto (8).
    from binoracle.oracles.exploit_helpers import ExploitHelperOracle
    fo = next(t for t in ExploitHelperOracle("x").tools() if t.name == "fmtstr_offset")
    for bad in (False, True, 0, "x", None):
        r = fo.run(byte_offset=32, word=bad)
        assert r.ok is True and "index = 4" in r.data   # 32 // 8
    # un word valido de 4 (x86) sigue respetandose
    assert "index = 8" in fo.run(byte_offset=32, word=4).data


def test_gate_flags_fabricated_citation():
    # Fundamentado: una cita [src: X] que no corresponde a ninguna tool ejecutada se marca.
    from binoracle.agent.grounding import GroundingLedger
    led = GroundingLedger()
    led.record(1, "r2_sinks", "radare2: dangerous sinks (ii + axt @ sym.imp.*)", "printf sink")
    led.record(2, "r2_checksec", "radare2: iI (checksec)", "NX true")
    ans = ("printf is a sink [src: radare2: dangerous sinks]. "
           "There are strings [src: r2_strings].")   # r2_strings NUNCA se llamo
    bad = led.fabricated_citations(ans)
    assert bad == ["r2_strings"]
    out = led.annotate(ans)
    assert "[!warning]" in out and "r2_strings" in out
    # una respuesta con solo citas reales no dispara el aviso
    assert led.fabricated_citations("sink here [src: radare2: iI (checksec)].") == []


def test_debugger_unrunnable_classifier():
    # Fundamentado: distinguir "no pudo ejecutar" (debugserver/ptrace) de un crash util.
    from binoracle.oracles.dynamic_dbg import _unrunnable, _LLDB_BROKEN, _GDB_BROKEN
    assert _unrunnable("error: Lost debug server connection", False, _LLDB_BROKEN) is True
    assert _unrunnable("ptrace: Operation not permitted", False, _GDB_BROKEN) is True
    # si hubo crash real, NO se trata como irrejecutable (el crash es la evidencia util)
    assert _unrunnable("stop reason = EXC_BAD_ACCESS", True, _LLDB_BROKEN) is False
    # una ejecucion normal no dispara
    assert _unrunnable("Process exited with status 0", False, _LLDB_BROKEN) is False


def test_quiet_pwn_sets_error_level():
    # El logger de pwnlib queda en ERROR tras _quiet_pwn (silencia el warning de Unicorn/PLT).
    import logging
    from binoracle import _quiet_pwn
    logging.getLogger("pwnlib").setLevel(logging.DEBUG)
    _quiet_pwn()
    assert logging.getLogger("pwnlib").level == logging.ERROR


def test_agent_loop_does_not_cap_exploration_tools():
    # Regresion: el cap por herramienta NO debe truncar tools de exploracion que aportan
    # info nueva por argumento (p.ej. r2_disasm de varias funciones).
    from binoracle.agent.loop import AgentLoop
    from binoracle.config import load_config
    from binoracle.oracles.base import Oracle, Tool, ToolParam, ToolResult, ToolRegistry

    calls = {"n": 0}

    class _Disasm(Oracle):
        name = "d"
        def available(self):
            return True
        def tools(self):
            def run(target):
                calls["n"] += 1
                return ToolResult(True, "radare2: pdf", f"disasm {target}")
            return [Tool("r2_disasm", "d", [ToolParam("target", "t")], run, self.name)]

    class _LLM:
        def __init__(self):
            self.i = 0
        def available(self):
            return True
        def chat(self, messages, *, json_mode=False):
            self.i += 1
            if self.i > 8:
                return '{"action":"final","answer":"done","findings":[]}'
            return '{"action":"tool","tool":"r2_disasm","args":{"target":"fn%d"}}' % self.i

    cfg = load_config(); cfg.max_steps = 12
    AgentLoop(_LLM(), ToolRegistry([_Disasm()]), cfg).run("x", mode="ask")
    assert calls["n"] >= 8   # r2_disasm esta exento del cap: se ejecuta las 8 veces


def test_autopie_rop_degrades_cleanly():
    # ROP-PIE se apoya en el sandbox binoracle-pwn; sin docker/imagen debe devolver un dict
    # con ok=False y una nota, nunca lanzar (degradacion elegante como el resto de oraculos).
    from binoracle.workflows.autopie import autopie_rop
    r = autopie_rop("samples/bin/ropme_pie")
    assert isinstance(r, dict) and "ok" in r
    if not r["ok"]:
        assert r.get("note")   # explica por que (sin docker / sin imagen)


def test_find_win_gift_regex_no_substring_false_positive():
    # Regresion: "win" dentro de "_Unwind_Resume" (o "winner") NO debe contar como gift function,
    # o el backstop se desvia a un ret2win falso en binarios estaticos con glibc.
    from binoracle.workflows.autopoc import _GIFT_RE
    hit = lambda s: bool(_GIFT_RE.search(s.lower()))
    assert hit("0x7fb20 sym._Unwind_Resume") is False
    assert hit("sym.winner") is False
    assert hit("sym.__libc_start_main") is False
    # los nombres gift reales siguen detectandose
    assert hit("sym.win") and hit("sym.get_flag") and hit("sym.give_shell") and hit("sym.backdoor")


def test_autoheap_shell_degrades_cleanly():
    # heap->shell se apoya en el sandbox binoracle-pwn. Usamos una ruta en un directorio
    # inexistente para ejercer SIEMPRE la degradacion (dict ok=False + nota) sin arrancar el
    # contenedor ni el exploit real, en cualquier entorno.
    from binoracle.workflows.autoheap import autoheap_shell
    r = autoheap_shell("/nonexistent/dir/heapexp")
    assert isinstance(r, dict) and r.get("ok") is False and r.get("note")


def test_autocanary_degrades_cleanly():
    # El bypass de canary por fuga (autocanary) se verifica en sandbox; con una ruta inexistente
    # se ejerce la degradacion limpia (ok=False + nota) sin arrancar nada, en cualquier entorno.
    from binoracle.workflows.autocanary import autocanary, render_canary
    r = autocanary("/nonexistent/dir/canary")
    assert isinstance(r, dict) and r.get("ok") is False and r.get("note")
    assert isinstance(render_canary(r), str) and render_canary(r)


def test_autocanary_verifies_leakable_sample():
    # Verificacion POSITIVA: en el sample `canleak` (canary + fuga real via %s) el bypass obtiene
    # shell de verdad. Se auto-salta donde el sandbox nativo no aplica (sin pwntools / no x86-64 /
    # sin setarch) o el binario aun no esta compilado, de modo que no rompe CI en esos entornos.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/canleak"
    if not os.path.exists(binp):
        pytest.skip("sample canleak no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox nativo no disponible: {why}")
    from binoracle.workflows.autocanary import autocanary
    r = autocanary(binp)
    assert r.get("ok") and r.get("verified"), f"bypass de canary no verificado: {r.get('note')}"
    # el canary de glibc tiene LSB nulo (0x..00): el valor filtrado debe reflejarlo
    import re
    m = re.search(r"canary=(0x[0-9a-fA-F]+)", r.get("detail") or "")
    assert m and int(m.group(1), 16) % 0x100 == 0, f"canary filtrado invalido: {r.get('detail')}"


def test_autocanary_verifies_format_string_leak():
    # Verificacion POSITIVA de la 2a estrategia (fuga del canary por FORMAT-STRING %p, la mas
    # comun en CTF): en `canfmt` el bypass obtiene shell de verdad. Se auto-salta donde el sandbox
    # nativo no aplica o el binario no esta compilado.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/canfmt"
    if not os.path.exists(binp):
        pytest.skip("sample canfmt no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox nativo no disponible: {why}")
    from binoracle.workflows.autocanary import autocanary
    r = autocanary(binp)
    assert r.get("ok") and r.get("verified"), f"bypass de canary (fmt) no verificado: {r.get('note')}"
    assert "(fmt)" in (r.get("detail") or ""), f"se esperaba la ruta de fuga por format-string: {r.get('detail')}"
    import re
    m = re.search(r"canary=(0x[0-9a-fA-F]+)", r.get("detail") or "")
    assert m and int(m.group(1), 16) % 0x100 == 0, f"canary filtrado invalido: {r.get('detail')}"


def test_har_inspect_requests_and_secrets():
    import json
    import os
    import tempfile
    from binoracle.workflows.harinspect import inspect_har, render_har
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://api.example.com/v1?api_key=SECRETKEY123456",
                     "headers": [{"name": "Authorization", "value": "Bearer abcdef0123456789"}]},
         "response": {"status": 200, "content": {"mimeType": "application/json", "size": 10}}},
        {"request": {"method": "POST", "url": "https://api.example.com/login", "headers": [],
                     "postData": {"text": "user=admin&password=hunter2"}},
         "response": {"status": 302, "content": {"mimeType": "text/html", "size": 0}}},
    ]}}
    p = tempfile.mktemp(suffix=".har")
    with open(p, "w") as f:
        json.dump(har, f)
    try:
        r = inspect_har(p)
        assert r["ok"] and r["is_har"] and r["entry_count"] == 2
        assert r["hosts"].get("api.example.com") == 2
        assert r["methods"] == {"GET": 1, "POST": 1}
        kinds = {s["kind"] for s in r["secrets"]}
        assert "api-key-param" in kinds and "authorization-header" in kinds
        assert "HAR" in render_har(r)
    finally:
        os.remove(p)


def test_har_inspect_non_har():
    import os
    import tempfile
    from binoracle.workflows.harinspect import inspect_har
    p = tempfile.mktemp()
    with open(p, "w") as f:
        f.write('{"not":"a har"}')
    try:
        r = inspect_har(p)
        assert r["ok"] and r["is_har"] is False
    finally:
        os.remove(p)


def test_sqlite_inspect_reads_schema_readonly():
    import os
    import sqlite3
    import tempfile
    from binoracle.workflows.sqliteinspect import inspect_sqlite, render_sqlite
    p = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(p)
    c = con.cursor()
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, pw TEXT)")
    c.execute("CREATE INDEX idx_name ON users(name)")
    c.execute('CREATE VIEW admins AS SELECT * FROM users')
    c.execute("CREATE TRIGGER t_ins AFTER INSERT ON users BEGIN SELECT 1; END")
    c.executemany("INSERT INTO users(name,pw) VALUES(?,?)", [("admin", "s3cr3t"), ("bob", "x")])
    con.commit()
    con.close()
    try:
        r = inspect_sqlite(p)
        assert r["ok"] and r["is_sqlite"]
        users = [t for t in r["tables"] if t["name"] == "users"]
        assert users and users[0]["row_count"] == 2
        cols = {c["name"]: c for c in users[0]["columns"]}
        assert cols["id"]["pk"] and cols["name"]["notnull"]
        assert users[0]["sample"] and users[0]["sample"][0]["name"] == "admin"
        assert any(v["name"] == "admins" for v in r["views"])
        assert any(t["name"] == "t_ins" for t in r["triggers"])
        assert r["indexes"]
        assert "SQLite" in render_sqlite(r)
    finally:
        os.remove(p)


def test_sqlite_inspect_non_sqlite():
    import os
    import tempfile
    from binoracle.workflows.sqliteinspect import inspect_sqlite
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"not a database")
    try:
        r = inspect_sqlite(p)
        assert r["ok"] and r["is_sqlite"] is False
    finally:
        os.remove(p)


def test_evm_inspect_selectors_and_metadata():
    import os
    import tempfile
    from binoracle.workflows.evminspect import inspect_evm, render_evm
    code = bytes.fromhex("63" + "70a08231" + "14" + "63" + "a9059cbb" + "14" + "f1")  # 2 sel + CALL
    cbor = (bytes.fromhex("a2") + b"\x64ipfs" + bytes.fromhex("42") + bytes.fromhex("1220")
            + b"\x64solc" + bytes.fromhex("43") + bytes.fromhex("000812"))
    blob = code + cbor + len(cbor).to_bytes(2, "big")
    p = tempfile.mktemp(suffix=".evm")
    try:
        with open(p, "wb") as f:
            f.write(blob)
        r = inspect_evm(p)
        assert r["ok"] and r["is_evm"]
        assert r["selectors"] == ["0x70a08231", "0xa9059cbb"]
        assert r["opcodes"].get("CALL") == 1
        assert r["metadata"]["solc"] == "0.8.18" and r["metadata"]["ipfs"] == "1220"
        assert "EVM" in render_evm(r)
        # hex-text input path
        p2 = tempfile.mktemp()
        with open(p2, "w") as f:
            f.write("0x" + blob.hex())
        try:
            assert inspect_evm(p2)["selectors"] == ["0x70a08231", "0xa9059cbb"]
        finally:
            os.remove(p2)
    finally:
        os.remove(p)


def test_wasm_inspect_parses_synthetic_module():
    # Parser WASM sobre un modulo minimo hecho a mano (sin WABT): type (i32,i32)->i32, un import
    # env.print y un export 'add'.
    import tempfile, os
    from binoracle.workflows.wasminspect import inspect_wasm, render_wasm

    def leb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    def sec(sid, payload):
        return bytes([sid]) + leb(len(payload)) + payload

    def nm(s):
        return leb(len(s)) + s.encode()

    mod = (b"\x00asm" + (1).to_bytes(4, "little")
           + sec(1, leb(1) + b"\x60" + leb(2) + b"\x7f\x7f" + leb(1) + b"\x7f")
           + sec(2, leb(1) + nm("env") + nm("print") + b"\x00" + leb(0))
           + sec(3, leb(1) + leb(0))
           + sec(7, leb(1) + nm("add") + b"\x00" + leb(0)))
    p = tempfile.mktemp(suffix=".wasm")
    try:
        with open(p, "wb") as f:
            f.write(mod)
        r = inspect_wasm(p)
        assert r["ok"] and r["is_wasm"] and r["version"] == 1
        assert [s["name"] for s in r["sections"]] == ["type", "import", "function", "export"]
        assert r["types"] == [{"params": ["i32", "i32"], "results": ["i32"]}]
        assert r["imports"] == [{"module": "env", "name": "print", "kind": "func"}]
        assert r["exports"] == [{"name": "add", "kind": "func"}]
        assert r["counts"]["function"] == 1
        assert "WAT" in render_wasm(r) or "WABT" in render_wasm(r)
    finally:
        try:
            os.remove(p)
        except OSError:
            pass


def test_wasm_inspect_non_wasm():
    from binoracle.workflows.wasminspect import inspect_wasm
    import tempfile, os
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"\x7fELFnot wasm")
    try:
        r = inspect_wasm(p)
        assert r["ok"] and r["is_wasm"] is False
    finally:
        os.remove(p)


def test_elf_layout_mitigations_match_known_samples():
    # El layout ELF debe derivar correctamente las mitigaciones de samples conocidos.
    import os
    import pytest
    from binoracle.workflows.elflayout import inspect_elf, render_elf
    checks = {
        "ret2win": {"position_independent": False, "nx": True, "stack_canary": False, "relro": "Partial"},
        "canary": {"position_independent": False, "stack_canary": True},
        "fmtstring_pie": {"position_independent": True, "relro": "Full"},
    }
    ran = 0
    for name, want in checks.items():
        p = "samples/bin/" + name
        if not os.path.exists(p):
            continue
        ran += 1
        r = inspect_elf(p)
        assert r["ok"] and r["is_elf"]
        m = r["mitigations"]
        for k, v in want.items():
            assert m[k] == v, f"{name}: {k}={m[k]} != {v}"
        assert isinstance(render_elf(r), str) and "mitigacion" in render_elf(r).lower()
    if ran == 0:
        pytest.skip("samples no compilados")


def test_elf_layout_static_canary_caveat():
    # En un estatico, __stack_chk_* puede venir de libc: el tool debe avisarlo honestamente.
    import os
    import pytest
    from binoracle.workflows.elflayout import inspect_elf
    p = "samples/bin/srop"
    if not os.path.exists(p):
        pytest.skip("sample no compilado")
    r = inspect_elf(p)
    if r["mitigations"]["stack_canary"]:
        assert any("estatico" in lim for lim in r.get("limitations", []))


def test_elf_layout_non_elf():
    from binoracle.workflows.elflayout import inspect_elf
    import tempfile, os
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"not an elf at all")
    try:
        r = inspect_elf(p)
        assert r["ok"] and r["is_elf"] is False
    finally:
        os.remove(p)


def test_coredump_reads_signal_registers_mappings():
    # Genera un core real (crash de un sample con overflow) y verifica que el inspector extrae
    # senal, registros por hilo y mapeos. Se auto-salta si el entorno no permite volcar cores.
    import os
    import resource
    import shutil
    import subprocess
    import tempfile
    import pytest
    src = "samples/bin/ret2win"
    if not os.path.exists(src):
        pytest.skip("sample no compilado")
    d = tempfile.mkdtemp()
    try:
        binp = os.path.join(d, "crasher")
        shutil.copy(src, binp)

        def _preexec():
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
            except Exception:
                pass
        subprocess.run([binp], input=b"A" * 120, cwd=d, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, preexec_fn=_preexec, timeout=20)
        cores = [os.path.join(d, f) for f in os.listdir(d) if f == "core" or f.startswith("core.")]
        if not cores:
            pytest.skip("el entorno no vuelca cores a cwd (core_pattern)")
        from binoracle.workflows.coredump import inspect_core, render_core
        r = inspect_core(cores[0])
        assert r["ok"] and r["is_core"]
        assert r["signal_name"] in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL") or r["signal"]
        assert r["threads"] and r["threads"][0]["regs"].get("rip") is not None
        assert r["mappings"]  # al menos el propio binario mapeado
        assert isinstance(render_core(r), str) and "core dump" in render_core(r)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_coredump_non_core_is_rejected():
    import os
    from binoracle.workflows.coredump import inspect_core
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        import pytest
        pytest.skip("sample no compilado")
    r = inspect_core(binp)
    assert r["ok"] and r["is_core"] is False and r.get("note")


def test_goinspect_parses_inline_buildinfo():
    # Parser de build-info Go sobre un blob INLINE sintetico (sin toolchain de Go): debe extraer
    # version, modulo principal, una dependencia con replacement y un build setting.
    from binoracle.workflows.goinspect import inspect_go, MODULE_START, MODULE_END, MAGIC
    import tempfile, os
    def uvarint(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)
    version = b"go1.22.1"
    modtext = (b"path\tgithub.com/acme/tool\n"
               b"mod\tgithub.com/acme/tool\t(devel)\t\n"
               b"dep\tgithub.com/pkg/errors\tv0.9.1\th1:abc\n"
               b"=>\tgithub.com/fork/errors\tv0.9.2\th1:def\n"
               b"build\t-trimpath=true\n"
               b"build\tGOARCH=amd64\n")
    mod = MODULE_START + modtext + MODULE_END
    header = MAGIC + bytes([8, 2])    # [0:14] magic, [14]=ptrSize=8, [15]=flags=0x02 (inline, little)
    header = header + b"\x00" * (32 - len(header))
    blob = b"\x00" * 64 + header + uvarint(len(version)) + version + uvarint(len(mod)) + mod + b"\x00" * 16
    p = tempfile.mktemp(suffix=".gobin")
    try:
        with open(p, "wb") as f:
            f.write(blob)
        r = inspect_go(p)
        assert r["ok"] and r["is_go"] and r["encoding"] == "inline"
        assert r["go_version"] == "go1.22.1"
        assert r["main_path"] == "github.com/acme/tool"
        deps = r["dependencies"]
        assert any(d["path"] == "github.com/pkg/errors" and d["replacement"] and
                   d["replacement"]["path"] == "github.com/fork/errors" for d in deps)
        assert r["build_settings"].get("-trimpath") == "true" and r["build_settings"].get("GOARCH") == "amd64"
    finally:
        try:
            os.remove(p)
        except OSError:
            pass


def test_goinspect_non_go_is_not_a_verdict():
    # Un ELF que NO es Go -> is_go False, pero sin afirmar nada mas (honesto).
    import os
    from binoracle.workflows.goinspect import inspect_go
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        import pytest
        pytest.skip("sample no compilado")
    r = inspect_go(binp)
    assert r["ok"] and r["is_go"] is False and r.get("note")


def test_mcp_server_handshake_and_tools():
    # El servidor MCP debe anunciar binoracle, listar sus tools, marcar el output derivado del
    # binario como contenido no confiable, y manejar una tool call sin sandbox (kb_search).
    import binoracle.mcp_server as m
    assert len(m._TOOLS) >= 10
    names = {t["name"] for t in m._TOOLS}
    assert {"triage", "analyze_chains", "autopwn", "autosrop", "autodlresolve", "kb_search"} <= names
    init = m.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "binoracle"
    assert "tools" in init["result"]["capabilities"]
    # una notificacion no lleva respuesta
    assert m.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tl = m.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert len(tl["result"]["tools"]) == len(m._TOOLS)
    # cada contrato tiene schema de objeto
    for t in tl["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object"
    # tool call sin sandbox + marcador untrusted
    call = m.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "kb_search", "arguments": {"query": "canary", "k": 1}}})
    res = call["result"]
    assert not res.get("isError") and res["content"][0]["text"]
    assert res["_meta"]["provenance"]["untrusted_content"] is True
    # tool desconocida -> error de protocolo
    bad = m.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "nope", "arguments": {}}})
    assert "error" in bad
    # argumento faltante -> error de tool (isError), no crash de protocolo
    miss = m.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                     "params": {"name": "triage", "arguments": {}}})
    assert miss["result"].get("isError") is True


def test_autosrop_verifies_sigreturn_execve():
    # Verificacion POSITIVA de SROP: shell via rt_sigreturn -> execve('/bin/sh') en el sample
    # `srop` (estatico, pobre en gadgets, con syscall gadget + '/bin/sh'). Se auto-salta sin
    # sandbox nativo / sample.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/srop"
    if not os.path.exists(binp):
        pytest.skip("sample srop no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox nativo no disponible: {why}")
    from binoracle.workflows.autosrop import autosrop
    r = autosrop(binp)
    assert r.get("ok") and r.get("verified"), f"SROP no verificado: {r.get('note')}"
    assert "syscall=" in (r.get("detail") or "") and "binsh=" in (r.get("detail") or "")


def test_autosrop_degrades_cleanly():
    # Ruta inexistente -> degradacion limpia (ok=False + nota) sin arrancar nada.
    from binoracle.workflows.autosrop import autosrop, render_srop
    r = autosrop("/nonexistent/dir/srop")
    assert isinstance(r, dict) and r.get("ok") is False and r.get("note")
    assert isinstance(render_srop(r), str) and render_srop(r)


def test_autodlresolve_verifies_no_leak_shell():
    # Verificacion POSITIVA de ret2dlresolve: shell SIN leak de libc forjando el resolver dinamico,
    # en el sample `dlresolve` (dinamico, no-PIE, Partial RELRO, sin win/system). Se auto-salta
    # donde el sandbox nativo no aplica o el binario no esta compilado.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/dlresolve"
    if not os.path.exists(binp):
        pytest.skip("sample dlresolve no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox nativo no disponible: {why}")
    from binoracle.workflows.autodlresolve import autodlresolve
    r = autodlresolve(binp)
    assert r.get("ok")
    # En glibc < 2.35 (o con la libc antigua que trae un reto) verifica shell; aqui (glibc moderno)
    # pwntools igualmente lo logra. Exigimos shell verificada en el sample preparado.
    assert r.get("verified"), f"ret2dlresolve no verificado: {r.get('note')}"
    assert "data=" in (r.get("detail") or "")


def test_autodlresolve_not_applicable_on_pie():
    # ret2dlresolve no aplica a PIE (direcciones aleatorias) -> degrada limpio sin afirmar shell.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/ret2win_pie"
    if not os.path.exists(binp):
        pytest.skip("sample ret2win_pie no compilado")
    ok, _ = native_available(binp)
    if not ok:
        pytest.skip("sandbox nativo no disponible")
    from binoracle.workflows.autodlresolve import autodlresolve
    r = autodlresolve(binp)
    assert r.get("ok") and not r.get("verified")


def test_autodlresolve_degrades_cleanly():
    # Ruta inexistente -> degradacion limpia (ok=False + nota) sin arrancar nada.
    from binoracle.workflows.autodlresolve import autodlresolve, render_dlresolve
    r = autodlresolve("/nonexistent/dir/dlresolve")
    assert isinstance(r, dict) and r.get("ok") is False and r.get("note")
    assert isinstance(render_dlresolve(r), str) and render_dlresolve(r)


def test_chainanalyzer_canary_chain_builds():
    # La cadena determinista 'canary bypass' debe construirse (sin sandbox) cuando hay canary + win,
    # ser factible, y NO arrastrar el break-point de canary (su verificador lo rompe por diseno).
    import os
    import pytest
    from binoracle.workflows.chainanalyzer import analyze_chains
    binp = "samples/bin/canary"
    if not os.path.exists(binp):
        pytest.skip("sample canary no compilado")
    an = analyze_chains(binp, verify=False, lang="en")
    cc = [c for c in an.chains if c.name == "canary bypass"]
    assert cc, "no se emitio la cadena 'canary bypass' pese a canary ON + win()"
    c = cc[0]
    assert c.unmet_requirements == 0 and c.feasible
    assert c.break_points == [], "el canary no debe ser un break-point para la propia cadena de bypass"
