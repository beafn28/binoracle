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


def test_jeb_connector_rpc_and_degrade():
    import os
    import json as _json
    from binoracle.workflows.jebconnect import build_rpc, parse_rpc, jeb_list_tools, render_jeb
    # pure JSON-RPC build/parse (no network)
    req = _json.loads(build_rpc("tools/list", {"x": 1}, rid=7))
    assert req["jsonrpc"] == "2.0" and req["method"] == "tools/list" and req["id"] == 7
    assert req["params"] == {"x": 1}
    ok = parse_rpc(b'{"jsonrpc":"2.0","id":1,"result":{"tools":["a"]}}')
    assert ok["ok"] and ok["result"]["tools"] == ["a"]
    err = parse_rpc(b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"nope"}}')
    assert err["ok"] is False
    # degrade honestly when no endpoint configured
    saved = os.environ.pop("BINORACLE_JEB_MCP_URL", None)
    try:
        r = jeb_list_tools()
        assert r["available"] is False and "BINORACLE_JEB_MCP_URL" in r["note"]
        assert "No disponible" in render_jeb(r)
    finally:
        if saved is not None:
            os.environ["BINORACLE_JEB_MCP_URL"] = saved


def test_native_connectors_degrade():
    # IDA/Hopper connectors: pure degrade when no endpoint is configured (no network).
    import os
    from binoracle.workflows.nativeconnect import (ida_list_tools, hopper_list_tools,
                                                    render_ida, render_hopper)
    saved_i = os.environ.pop("BINORACLE_IDA_MCP_URL", None)
    saved_h = os.environ.pop("BINORACLE_HOPPER_MCP_URL", None)
    try:
        ri = ida_list_tools()
        assert ri["available"] is False and "BINORACLE_IDA_MCP_URL" in ri["note"]
        assert "No disponible" in render_ida(ri)
        rh = hopper_list_tools()
        assert rh["available"] is False and "BINORACLE_HOPPER_MCP_URL" in rh["note"]
        assert "No disponible" in render_hopper(rh)
    finally:
        if saved_i is not None:
            os.environ["BINORACLE_IDA_MCP_URL"] = saved_i
        if saved_h is not None:
            os.environ["BINORACLE_HOPPER_MCP_URL"] = saved_h


def test_flutter_dart_aot_static_reader():
    # Static Flutter/Dart AOT facts from a synthetic libapp.so-shaped blob: the Dart snapshot magic
    # (f5 f5 dc dc), the 32-hex snapshot hash 20 bytes after it, and the Dart VM version string.
    # Nothing is executed; this is pure byte observation.
    import os
    import tempfile
    from binoracle.workflows.flutterinspect import (inspect_flutter, inspect_dart_aot,
                                                     render_flutter, render_dart_aot,
                                                     DART_SNAPSHOT_MAGIC)
    h = b"0123456789abcdef0123456789abcdef"
    blob = b"\x7fELF" + b"\x00" * 60 + DART_SNAPSHOT_MAGIC + b"P" * 16 + h + b"Dart VM version: 3.4.1\x00"
    p = tempfile.mktemp(suffix=".so")
    with open(p, "wb") as f:
        f.write(blob)
    try:
        rd = inspect_dart_aot(p)
        assert rd["ok"] and rd["is_dart_aot"] and h.decode() in rd["snapshot_hashes"]
        assert rd["dart_vm_version"] == "3.4.1"
        assert "Dart AOT" in render_dart_aot(rd)
        rf = inspect_flutter(p)
        assert rf["ok"] and rf["is_flutter"] and h.decode() in rf["snapshot_hashes"]
        assert "Flutter" in render_flutter(rf)
    finally:
        os.remove(p)


def test_flutter_non_flutter_is_not_a_verdict():
    # A plain ELF with no Dart snapshot must degrade honestly, not claim "not Flutter" as proof.
    import os
    import tempfile
    from binoracle.workflows.flutterinspect import inspect_flutter
    p = tempfile.mktemp(suffix=".so")
    with open(p, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 200)
    try:
        r = inspect_flutter(p)
        assert r["ok"] and r["is_flutter"] is False
        assert any("estatica" in l for l in r.get("limitations", []))
    finally:
        os.remove(p)


def test_js_inspect_electron_bundle_and_sourcemap():
    import os
    import json as _json
    import tempfile
    from binoracle.workflows.jsinspect import inspect_js, render_js
    d = tempfile.mkdtemp(prefix="binojs_")
    try:
        with open(os.path.join(d, "main.js"), "w") as f:
            f.write("const {app, BrowserWindow, ipcMain} = require('electron');\n"
                    "const cp = require('child_process');\n"
                    "import axios from 'axios';\n"
                    "ipcMain.handle('do-thing', () => {});\n"
                    "ipcMain.on('ping', () => {});\n"
                    "require('./util');\n")
        with open(os.path.join(d, "preload.js"), "w") as f:
            f.write("const {contextBridge, ipcRenderer} = require('electron');\n"
                    "contextBridge.exposeInMainWorld('api', {});\n")
        # a node_modules dir that must be skipped
        os.makedirs(os.path.join(d, "node_modules", "axios"))
        with open(os.path.join(d, "node_modules", "axios", "index.js"), "w") as f:
            f.write("require('http');\n")
        r = inspect_js(d)
        assert r["ok"] and r["is_js"] and r["is_electron"]
        assert r["file_count"] == 2                      # node_modules skipped
        assert "axios" in r["packages"]
        assert "http" not in r["packages"]               # from node_modules, skipped
        assert "do-thing" in r["ipc_channels"] and "ping" in r["ipc_channels"]
        assert "api" in r["context_bridge"]
        assert any("child_process" in k for k in r["electron"])
        out = render_js(r)
        assert "Electron" in out and "do-thing" in out
        # source map
        mp = os.path.join(d, "bundle.js.map")
        with open(mp, "w") as f:
            _json.dump({"version": 3, "file": "bundle.js",
                        "sources": ["webpack://app/src/index.js", "webpack://app/src/util.js"],
                        "sourcesContent": ["//a", "//b"], "names": []}, f)
        rm = inspect_js(mp)
        assert rm["kind"] == "sourcemap" and rm["source_count"] == 2
        assert rm["has_sources_content"] and rm["generator"] == "webpack"
        assert "index.js" in render_js(rm)
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def test_dynamic_adb_frida_degrade():
    # El modulo dinamico es caller-supplied: sin adb/frida en PATH debe degradar con honestidad.
    import os
    from binoracle.workflows import dynamic as dyn
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        for r, kind in ((dyn.adb_devices(), "adb-devices"), (dyn.adb_packages(), "adb-packages"),
                        (dyn.adb_getprop(), "adb-getprop"), (dyn.frida_processes(), "frida-ps"),
                        (dyn.frida_devices(), "frida-devices")):
            assert r["available"] is False
            assert "No disponible" in dyn.render_dynamic(kind, r)
        # apk-path valida el nombre de paquete antes de tocar adb
        bad = dyn.adb_apk_path("../etc/passwd")
        assert bad["ok"] is False
    finally:
        os.environ["PATH"] = old


def test_dynamic_browser_observes_data_url():
    # Observacion RUNTIME real pero HERMETICA: una data: URL (sin red) con un script inline que
    # contiene un secreto -> el navegador la carga y binoracle extrae metricas + secreto.
    import pytest
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        pytest.skip("Playwright no disponible")
    from binoracle.workflows import dynamic as dyn
    html = ("<html><head><title>BinoDyn</title>"
            "<script>var k='AKIAIOSFODNN7EXAMPLE'; console.log('hi');</script>"
            "</head><body><form><input name=x></form><a href='#'>l</a></body></html>")
    import urllib.parse
    url = "data:text/html," + urllib.parse.quote(html)
    r = dyn.browser_observe(url, timeout_s=20)
    if not r.get("ok"):
        pytest.skip(f"navegador no operativo en este entorno: {r.get('note')}")
    assert r["title"] == "BinoDyn"
    assert r["metrics"]["forms"] == 1 and r["metrics"]["inputs"] == 1
    assert r["inline_scripts"] >= 1
    kinds = {s["kind"] for s in (r.get("secrets") or [])}
    assert "aws-access-key" in kinds
    out = dyn.render_dynamic("browser", r)
    assert "BinoDyn" in out and "RUNTIME" in out


def test_macho_objc_swift_metadata():
    import os
    import struct
    import tempfile
    from binoracle.workflows.machoinspect import inspect_macho, render_macho
    names = b"Foo\x00Bar\x00Baz\x00"            # __objc_classname C-strings
    sels = b"init\x00doThing:\x00"              # __objc_methname C-strings
    HDR = 32
    nsects = 4
    cmdsize = 72 + nsects * 80
    data_off = HDR + cmdsize                     # file region after the load commands
    # section file offsets (within data we append below)
    name_off = data_off
    sel_off = name_off + len(names)
    classlist_off = sel_off + len(sels)          # content irrelevant; only size is read
    swift_off = classlist_off
    blob = names + sels
    # Mach-O 64 header: magic, cputype x86_64, cpusub, filetype DYLIB(6), ncmds=1, sizeofcmds, flags PIE, rsvd
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 6, 1, cmdsize, 0x200000, 0)
    seg = struct.pack("<II16sQQQQiiII", 0x19, cmdsize, b"__DATA", 0x2000, 0x4000, data_off,
                      len(blob), 3, 3, nsects, 0)

    def sect(name, addr, size, off):
        return struct.pack("<16s16sQQIIIIIIII", name, b"__DATA", addr, size, off,
                           0, 0, 0, 0, 0, 0, 0)
    sects = (sect(b"__objc_classname", 0x2000, len(names), name_off)
             + sect(b"__objc_methname", 0x2100, len(sels), sel_off)
             + sect(b"__objc_classlist", 0x2200, 3 * 8, classlist_off)   # 3 class pointers
             + sect(b"__swift5_types", 0x2300, 2 * 4, swift_off))        # 2 type descriptors
    macho = hdr + seg + sects + blob
    p = tempfile.mktemp(suffix=".macho")
    with open(p, "wb") as f:
        f.write(macho)
    try:
        r = inspect_macho(p)
        assert r["ok"] and r["is_macho"]
        im = r["images"][0]
        objc = im["objc"]
        assert objc["present"] and objc["class_count"] == 3
        assert set(objc["classes"]) == {"Foo", "Bar", "Baz"}
        assert "doThing:" in objc["selectors"]
        sw = im["swift"]
        assert sw["present"] and sw["type_count"] == 2
        out = render_macho(r)
        assert "Obj-C" in out and "Swift" in out and "Foo" in out
    finally:
        os.remove(p)


def test_ghidra_decompile_degrades_and_parses():
    import os
    from binoracle.workflows.callertools import ghidra_decompile, parse_ghidra_pseudocode, render_caller
    # degrade honestly when Ghidra is absent (empty PATH + no GHIDRA_* env)
    old = os.environ.get("PATH", "")
    saved = {k: os.environ.pop(k) for k in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME", "GHIDRA_DIR")
             if k in os.environ}
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        r = ghidra_decompile("/tmp/whatever")
        assert r["available"] is False and "Ghidra" in r["note"]
        assert "No disponible" in render_caller("ghidra", r)
    finally:
        os.environ["PATH"] = old
        os.environ.update(saved)
    # the stdout parser recovers the marked pseudocode blocks (no Ghidra needed)
    sample = ("INFO  noise\n"
              "<<<BINO_FN main @ 0x401136>>>\n"
              "undefined8 main(void)\n{\n  puts(\"hi\");\n  return 0;\n}\n"
              "<<<BINO_END>>>\n"
              "<<<BINO_FN helper @ 0x401100>>>\nvoid helper(void){ return; }\n<<<BINO_END>>>\n"
              "<<<BINO_COUNT 2>>>\n")
    fns = parse_ghidra_pseudocode(sample)
    assert len(fns) == 2
    assert fns[0]["name"] == "main" and fns[0]["addr"] == "0x401136"
    assert "puts" in fns[0]["pseudocode"]
    assert fns[1]["name"] == "helper"
    out = render_caller("ghidra", {"ok": True, "count": 2, "functions": fns})
    assert "main @ 0x401136" in out and "```c" in out


def test_autobotcake_verifies_house_of_botcake():
    # Verificacion POSITIVA de house-of-botcake por EJECUCION (glibc real 2.39): un doble-free
    # enrutado por la unsorted bin (esquiva el key del tcache) produce chunks solapados; se
    # envenena el fd (con safe-linking) para asignar sobre `handler` -> win -> shell.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/botcake"
    if not os.path.exists(binp):
        pytest.skip("sample botcake no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autobotcake import autobotcake
    r = autobotcake(binp)
    assert r.get("ok") and r.get("verified"), f"house-of-botcake no verificado: {r.get('note')}"
    assert "a=" in (r.get("detail") or "")


def test_autohos_verifies_house_of_spirit():
    # Verificacion POSITIVA de house-of-spirit por EJECUCION (tcache de glibc real, NO mitigado):
    # se planta el tamano de un chunk falso solapando un puntero de funcion, se libera (entra en
    # tcache), el siguiente malloc lo devuelve y una escritura pone handler=win -> shell.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/hos"
    if not os.path.exists(binp):
        pytest.skip("sample hos no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autohos import autohos
    r = autohos(binp)
    assert r.get("ok") and r.get("verified"), f"house-of-spirit no verificado: {r.get('note')}"
    assert "size=" in (r.get("detail") or "")


def test_autohoe_verifies_house_of_einherjar():
    # Verificacion POSITIVA de house-of-einherjar por EJECUCION: se forja prev_size y se limpia
    # PREV_INUSE del chunk B; al liberarlo, la consolidacion hacia atras lo fusiona con un chunk
    # falso en &handler-0x10; el siguiente malloc devuelve &handler -> escritura -> win -> shell.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/hoe"
    if not os.path.exists(binp):
        pytest.skip("sample hoe no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autohoe import autohoe
    r = autohoe(binp)
    assert r.get("ok") and r.get("verified"), f"house-of-einherjar no verificado: {r.get('note')}"
    assert "size_a=" in (r.get("detail") or "")


def test_autohof_verifies_house_of_force():
    # Verificacion POSITIVA de house-of-force por EJECUCION: se sobrescribe el tamano del top chunk
    # con un valor enorme; una peticion huge (con wraparound) mueve `top` a &handler; la siguiente
    # asignacion devuelve ese puntero -> escritura arbitraria -> handler=win -> shell. glibc >=2.29
    # mitiga el HoF real, por eso el sample reproduce el carve del top-chunk pre-2.29 en el binario.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/hof"
    if not os.path.exists(binp):
        pytest.skip("sample hof no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autohof import autohof
    r = autohof(binp)
    assert r.get("ok") and r.get("verified"), f"house-of-force no verificado: {r.get('note')}"
    assert "need_a=" in (r.get("detail") or "")


def test_autolargebin_verifies_insertion_write():
    # Verificacion POSITIVA del largebin attack por EJECUCION: se corrompe bk_nextsize del chunk
    # residente en la largebin; al insertar un segundo chunk grande, el asignador ejecuta
    # `victim->bk_nextsize->fd_nextsize = victim`, escribiendo &victim en `slot` (direccion elegida);
    # slot apunta ahora a un chunk cuyo contenido controlamos -> se planta win -> shell. glibc >=2.30
    # endurece el largebin real, por eso el sample reproduce la escritura de insercion caracteristica.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/largebin"
    if not os.path.exists(binp):
        pytest.skip("sample largebin no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autolargebin import autolargebin
    r = autolargebin(binp)
    assert r.get("ok") and r.get("verified"), f"largebin attack no verificado: {r.get('note')}"
    assert "slot=" in (r.get("detail") or "")


def test_autostash_verifies_tcache_stashing():
    # Verificacion POSITIVA del tcache-stashing-unlink por EJECUCION: al servir de la smallbin con
    # hueco en el tcache, glibc "stashea" los chunks restantes al tcache; corrompiendo el `bk` de un
    # chunk se mete un chunk FALSO en el tcache -> el siguiente alloc devuelve una direccion elegida
    # -> se escribe win sobre un puntero de funcion -> shell. glibc >=2.31 endurece el bucle con
    # `bck->fd == tc_victim`; el sample reproduce ese chequeo y lo SATISFACE (disparo via calloc).
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/stash"
    if not os.path.exists(binp):
        pytest.skip("sample stash no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autostash import autostash
    r = autostash(binp)
    assert r.get("ok") and r.get("verified"), f"tcache stashing no verificado: {r.get('note')}"
    assert "hobj=" in (r.get("detail") or "")


def test_autocsu_verifies_execve_chain():
    # Verificacion POSITIVA de ret2csu -> execve ENCADENADO por EJECUCION: en csuexec no hay
    # `pop rsi`/`pop rdx`, asi que los gadgets csu fijan rsi=0/rdx=0 (la call forzada de gadget2
    # apunta a un `ret` benigno) y luego pop rdi=&binsh, pop rax=59, syscall -> execve -> shell.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/csuexec"
    if not os.path.exists(binp):
        pytest.skip("sample csuexec no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autocsu import autocsu
    r = autocsu(binp)
    assert r.get("ok") and r.get("verified"), f"ret2csu->execve no verificado: {r.get('note')}"
    assert "mode=execve" in (r.get("detail") or "")


def test_autopivot_verifies_stack_migration():
    # Verificacion POSITIVA de stack pivot por EJECUCION: en pivot el overflow es corto (solo llega
    # a saved rbp + saved rip), asi que se migra RSP a un buffer fijo en .bss (notes) donde se
    # escalona la cadena -> win() -> shell. Prueba saved_rbp=&buf + `leave; ret` + ret-slide 16B.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/pivot"
    if not os.path.exists(binp):
        pytest.skip("sample pivot no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autopivot import autopivot
    r = autopivot(binp)
    assert r.get("ok") and r.get("verified"), f"stack pivot no verificado: {r.get('note')}"
    assert "leave_ret=" in (r.get("detail") or "")


def test_autofmt_verifies_32bit_got_overwrite():
    # Verificacion POSITIVA de format-string de x86-32 por EJECUCION: en fmtgot32 el bug
    # printf(buf) permite sobrescribir printf@GOT con system (Partial RELRO, no-PIE) y luego
    # printf("/bin/sh") lanza shell. Prueba que la deteccion de offset es arch-aware (marcador
    # 0x41414141 de 4 bytes) y que fmtstr_payload escribe en 4 bytes. Auto-salta sin sandbox/sample.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/fmtgot32"
    if not os.path.exists(binp):
        pytest.skip("sample fmtgot32 no compilado (samples/build.sh; requiere multilib)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autofmt import autofmt
    r = autofmt(binp)
    assert r.get("ok") and r.get("verified"), f"format-string 32-bit no verificado: {r.get('note')}"
    assert "printf_got=" in (r.get("detail") or "")


def test_autocsu_verifies_ret2csu():
    # Verificacion POSITIVA de ret2csu por EJECUCION: los gadgets universales de __libc_csu_init
    # fijan rdi/rsi/rdx (edi via r13d) y hacen `call [r12+rbx*8]` sobre win(), que con los args
    # correctos lanza shell. Prueba el control de argumentos + la llamada indirecta + el ret-slide
    # de alineacion 16B. Se auto-salta sin sandbox o sin el sample.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/ret2csu"
    if not os.path.exists(binp):
        pytest.skip("sample ret2csu no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autocsu import autocsu
    r = autocsu(binp)
    assert r.get("ok") and r.get("verified"), f"ret2csu no verificado: {r.get('note')}"
    assert "align=" in (r.get("detail") or "")   # proves the 16B ret-slide was applied


def test_csu_gadget_detection_on_sample():
    import os
    import pytest
    binp = "samples/bin/ret2csu"
    if not os.path.exists(binp):
        pytest.skip("sample ret2csu no compilado")
    from binoracle.workflows.chainanalyzer import _find_csu_gadgets
    r = _find_csu_gadgets(binp)
    assert r and r.get("complete") and r.get("gadget1") and r.get("gadget2")


def test_autosrop_verifies_32bit():
    # Verificacion POSITIVA de SROP de x86-32 por EJECUCION: en srop32 el sigreturn (syscall 119
    # via int 0x80) restaura un frame i386 (con los segmentos cs=0x23/ss=0x2b correctos) que lanza
    # execve('/bin/sh') y obtiene shell. Se auto-salta sin sandbox o sin el sample 32-bit.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/srop32"
    if not os.path.exists(binp):
        pytest.skip("sample srop32 no compilado (samples/build.sh; requiere multilib+glibc-static i386)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autosrop import autosrop
    r = autosrop(binp)
    assert r.get("ok") and r.get("verified"), f"SROP 32-bit no verificado: {r.get('note')}"


def test_autorop_verifies_32bit_ret2libc():
    # Verificacion POSITIVA de una cadena ret2libc de x86-32 (cdecl, argumento en la pila) por
    # EJECUCION: en ret2win32 la cadena system('/bin/sh') obtiene shell de verdad. Confirma que el
    # motor ROP de 32-bit construye+verifica (pwntools rop.call -> layout cdecl) y que el sandbox
    # trae libc6:i386. Se auto-salta donde el sandbox no aplica o el binario no esta compilado.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/ret2win32"
    if not os.path.exists(binp):
        pytest.skip("sample ret2win32 no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autopoc import autorop
    r = autorop(binp, run=True)
    assert r.get("ok") and r.get("verified"), f"ret2libc 32-bit no verificado: {r.get('note')}"
    assert "ret2libc" in (r.get("strategy") or ""), f"estrategia inesperada: {r.get('strategy')}"


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


def test_caller_tools_degrade_when_absent():
    # Sin la herramienta en PATH, cada integracion caller-supplied degrada honestamente nombrandola.
    import os
    from binoracle.workflows.callertools import wat_disassemble, pcap_summary, firmware_scan, render_caller
    # asegura que las herramientas no estan en un PATH vacio
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        for fn, kind, tool in ((wat_disassemble, "wat", "wasm2wat"),
                               (pcap_summary, "pcap", "tshark"),
                               (firmware_scan, "firmware", "binwalk")):
            r = fn("/tmp/whatever")
            assert r["ok"] is False and r["available"] is False and r["tool"] == tool
            assert tool in r["note"]
            assert "No disponible" in render_caller(kind, r)
    finally:
        os.environ["PATH"] = old


def test_signal_tools_degrade_when_absent():
    # sigrok-cli ausente -> inspect_signal_decoders / decode_signal_recording degradan nombrando
    # la herramienta (integracion caller-supplied, igual que TShark/Binwalk).
    import os
    from binoracle.workflows.callertools import signal_decoders, decode_signal, render_caller
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        r = signal_decoders("i2c")
        assert r["ok"] is False and r["available"] is False and r["tool"] == "sigrok-cli"
        assert "sigrok-cli" in r["note"]
        assert "No disponible" in render_caller("signal_decoders", r)
        d = decode_signal("/tmp/cap.sr", "i2c")
        assert d["ok"] is False and d["available"] is False and d["tool"] == "sigrok-cli"
        assert "No disponible" in render_caller("signal", d)
    finally:
        os.environ["PATH"] = old


def test_caller_tool_jadx_decompile(tmp_path):
    import os
    import stat
    from binoracle.workflows.callertools import jadx_decompile
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        assert jadx_decompile("/tmp/x.apk")["available"] is False
    finally:
        os.environ["PATH"] = old
    # fake jadx: writes a couple of .java files into the -d output dir
    fake = tmp_path / "jadx"
    fake.write_text(
        "#!/bin/sh\n"
        "out=\"\"\n"
        "while [ $# -gt 0 ]; do if [ \"$1\" = \"-d\" ]; then out=\"$2\"; fi; shift; done\n"
        "mkdir -p \"$out/sources/com/acme\"\n"
        "echo 'class Main {}' > \"$out/sources/com/acme/Main.java\"\n"
        "echo 'class Api {}' > \"$out/sources/com/acme/Api.java\"\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    os.environ["PATH"] = str(tmp_path) + os.pathsep + old
    try:
        r = jadx_decompile("/tmp/whatever.apk")
        assert r["ok"] and r["java_file_count"] == 2
        assert "com.acme.Main" in r["classes"] and "com.acme.Api" in r["classes"]
    finally:
        os.environ["PATH"] = old


def test_caller_tool_apktool_manifest(tmp_path):
    import os
    import stat
    from binoracle.workflows.callertools import apktool_manifest
    old = os.environ.get("PATH", "")
    # degrade
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        assert apktool_manifest("/tmp/x.apk")["available"] is False
    finally:
        os.environ["PATH"] = old
    # run path: fake apktool that writes a decoded AndroidManifest.xml into the -o dir
    fake = tmp_path / "apktool"
    fake.write_text(
        "#!/bin/sh\n"
        "out=\"\"\n"
        "while [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then out=\"$2\"; fi; shift; done\n"
        "mkdir -p \"$out\"\n"
        "cat > \"$out/AndroidManifest.xml\" <<'XML'\n"
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.acme.app\">\n"
        "  <uses-permission android:name=\"android.permission.INTERNET\"/>\n"
        "  <application><activity android:name=\".Main\"/></application>\n"
        "</manifest>\n"
        "XML\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    os.environ["PATH"] = str(tmp_path) + os.pathsep + old
    try:
        r = apktool_manifest("/tmp/whatever.apk")
        assert r["ok"] and r["package"] == "com.acme.app"
        assert "android.permission.INTERNET" in r["permissions"]
        assert ".Main" in r["components"].get("activity", [])
    finally:
        os.environ["PATH"] = old


def test_caller_tools_one_gadget_and_capinfos(tmp_path):
    import os
    import stat
    from binoracle.workflows.callertools import one_gadget, pcap_fileinfo
    # degrade (empty PATH)
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        assert one_gadget("/tmp/libc")["available"] is False
        assert pcap_fileinfo("/tmp/x.pcap")["available"] is False
    finally:
        os.environ["PATH"] = old
    # run path via fake one_gadget emitting raw offsets
    fake = tmp_path / "one_gadget"
    fake.write_text('#!/bin/sh\necho "0x4f2a5 0x4f302 0x10a2fc"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    os.environ["PATH"] = str(tmp_path) + os.pathsep + old
    try:
        r = one_gadget("/tmp/libc.so.6")
        assert r["ok"] and r["count"] == 3 and r["gadgets"][0] == "0x4f2a5"
    finally:
        os.environ["PATH"] = old


def test_arsenal_one_gadget_integration(tmp_path):
    import os
    import stat
    from binoracle.workflows.chainanalyzer import _detect_one_gadget
    # dynamic binary -> skipped here (libc resolved in autolibc), regardless of tool presence
    assert _detect_one_gadget("/tmp/whatever", {"static": False}) is None
    assert _detect_one_gadget("/tmp/whatever", {"static": None}) is None
    old = os.environ.get("PATH", "")
    # static + tool absent -> honest degrade
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        r = _detect_one_gadget("/tmp/static.elf", {"static": True, "pie": False})
        assert r is not None and r["available"] is False
    finally:
        os.environ["PATH"] = old
    # static + fake one_gadget on PATH -> integrated into arsenal with absolute offsets note
    fake = tmp_path / "one_gadget"
    fake.write_text('#!/bin/sh\necho "0x4f2a5 0x4f302 0x10a2fc"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    os.environ["PATH"] = str(tmp_path) + os.pathsep + old
    try:
        r = _detect_one_gadget("/tmp/static.elf", {"static": True, "pie": False})
        assert r["available"] is True and r["count"] == 3
        assert r["offsets"][0] == "0x4f2a5"
        assert "ABSOLUTAS" in r["note"]
        # PIE static -> note says offsets are load-base relative
        r2 = _detect_one_gadget("/tmp/static.elf", {"static": True, "pie": True})
        assert "base" in r2["note"].lower()
    finally:
        os.environ["PATH"] = old


def test_caller_tool_runs_when_present(tmp_path):
    # Con una herramienta FALSA en PATH que emite WAT conocido, el camino de ejecucion parsea OK.
    import os
    import stat
    fake = tmp_path / "wasm2wat"
    fake.write_text('#!/bin/sh\necho "(module (func $add (param i32 i32) (result i32)))"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = str(tmp_path) + os.pathsep + old
    try:
        from binoracle.workflows.callertools import wat_disassemble
        r = wat_disassemble("/tmp/whatever.wasm")
        assert r["ok"] and r["available"] and r["tool"] == "wasm2wat"
        assert r["functions"] == 1 and "(module" in r["wat"]
    finally:
        os.environ["PATH"] = old


def test_pe_mitigations_decoder():
    from binoracle.workflows.peinspect import decode_mitigations
    m = decode_mitigations(0x0040 | 0x0100 | 0x4000)   # ASLR + DEP + CFG
    assert m["aslr_dynamic_base"] and m["dep_nx"] and m["control_flow_guard"]
    assert not m["no_seh"] and not m["high_entropy_va"]


def test_pe_inspect_on_real_pe_if_present():
    import glob
    import os
    import pytest
    from binoracle.workflows.peinspect import inspect_pe, render_pe
    cands = []
    for root in ("/usr", "/opt"):
        cands += glob.glob(os.path.join(root, "**", "*.dll"), recursive=True)[:50]
        cands += glob.glob(os.path.join(root, "**", "*.exe"), recursive=True)[:50]
    pe = None
    for c in cands:
        r = inspect_pe(c)
        if r.get("is_pe"):
            pe = r
            break
    if pe is None:
        pytest.skip("sin PE real en el sistema")
    assert pe["arch"] and isinstance(pe["mitigations"], dict)
    assert pe["sections"] and all("entropy" in s for s in pe["sections"])
    assert "PE" in render_pe(pe)


def test_pe_inspect_non_pe():
    import os
    from binoracle.workflows.peinspect import inspect_pe
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        import pytest
        pytest.skip("sample no compilado")
    r = inspect_pe(binp)
    assert r["ok"] and r["is_pe"] is False


def test_identify_routes_formats():
    # El identificador unificado debe detectar y enrutar cada formato al lector correcto.
    import os
    import sqlite3
    import tempfile
    import zipfile
    import pytest
    from binoracle.workflows.identify import detect_format, identify, render_identify
    made = []
    try:
        dbp = tempfile.mktemp(suffix=".db")
        con = sqlite3.connect(dbp)
        con.execute("CREATE TABLE t(x)")
        con.commit()
        con.close()
        made.append(dbp)
        wp = tempfile.mktemp(suffix=".wasm")
        with open(wp, "wb") as f:
            f.write(b"\x00asm" + (1).to_bytes(4, "little"))
        made.append(wp)
        ap = tempfile.mktemp(suffix=".apk")
        z = zipfile.ZipFile(ap, "w")
        z.writestr("AndroidManifest.xml", b"\x03\x00")
        z.writestr("classes.dex", b"d")
        z.close()
        made.append(ap)
        plp = tempfile.mktemp(suffix=".plist")
        import plistlib
        with open(plp, "wb") as f:
            plistlib.dump({"CFBundleIdentifier": "com.x.y"}, f, fmt=plistlib.FMT_BINARY)
        made.append(plp)
        arp = tempfile.mktemp(suffix=".asar")
        with open(arp, "wb") as f:
            f.write(_build_asar({"package.json": b'{"name":"z","main":"m.js"}'}))
        made.append(arp)
        assert identify(dbp)["routed"] == "sqlite"
        assert identify(wp)["routed"] == "wasm"
        assert identify(ap)["routed"] == "apk"
        assert identify(plp)["routed"] == "plist"
        assert identify(arp)["routed"] == "asar"
        clp = tempfile.mktemp(suffix=".class")
        with open(clp, "wb") as f:
            f.write(_build_class(major=61))
        made.append(clp)
        jrp = tempfile.mktemp(suffix=".jar")
        import zipfile as _zf
        z2 = _zf.ZipFile(jrp, "w")
        z2.writestr("META-INF/MANIFEST.MF", "Main-Class: X\r\n")
        z2.writestr("a/B.class", _build_class("a/B"))
        z2.close()
        made.append(jrp)
        assert identify(clp)["routed"] == "class"
        assert identify(jrp)["routed"] == "jar"
        if os.path.exists("samples/bin/ret2win"):
            r = identify("samples/bin/ret2win")
            assert r["routed"] == "elf" and "mitigacion" in render_identify(r).lower()
        else:
            pytest.skip("sample ELF no compilado")
    finally:
        for p in made:
            try:
                os.remove(p)
            except OSError:
                pass


def test_apk_inspect_on_synthetic_apk():
    import os
    import tempfile
    import zipfile
    from binoracle.workflows.apkinspect import inspect_apk, render_apk
    p = tempfile.mktemp(suffix=".apk")
    z = zipfile.ZipFile(p, "w")
    z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fakeAXML")
    z.writestr("classes.dex", b"dex\n035\x00")
    z.writestr("classes2.dex", b"dex\n035\x00")
    z.writestr("lib/arm64-v8a/libapp.so", b"FLUTTERSNAP" * 10)
    z.writestr("lib/arm64-v8a/libflutter.so", b"engine")
    z.writestr("META-INF/CERT.RSA", b"cert")
    z.close()
    try:
        r = inspect_apk(p)
        assert r["ok"] and r["is_apk"] and r["has_manifest"]
        assert r["dex"] == ["classes.dex", "classes2.dex"]
        assert "Flutter" in r["frameworks"]
        assert "arm64-v8a" in r["native_abis"]
        assert "arm64-v8a/libapp.so" in r["flutter_snapshots"]
        assert r["signing"]["v1_jar"] == ["META-INF/CERT.RSA"]
        assert "APK" in render_apk(r)
    finally:
        os.remove(p)


def test_apk_inspect_non_apk():
    import os
    import tempfile
    from binoracle.workflows.apkinspect import inspect_apk
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"not a zip at all")
    try:
        r = inspect_apk(p)
        assert r["ok"] and r["is_apk"] is False
    finally:
        os.remove(p)


def test_macho_inspect_on_synthetic_binary():
    import os
    import struct
    import tempfile
    from binoracle.workflows.machoinspect import inspect_macho, render_macho
    e = "<"
    segname = b"__TEXT" + b"\x00" * 10
    seg = (struct.pack(e + "II", 0x19, 72) + segname
           + struct.pack(e + "QQQQiiII", 0x100000000, 0x1000, 0, 0x1000, 5, 5, 0, 0))
    name = b"/usr/lib/libSystem.B.dylib\x00"
    name = name + b"\x00" * ((-len(name)) % 8)
    dcmd = struct.pack(e + "IIIIII", 0x0C, 24 + len(name), 24, 0, 0, 0) + name
    main = struct.pack(e + "IIQQ", 0x80000028, 24, 0x1230, 0)
    cmds = seg + dcmd + main
    hdr = struct.pack(e + "IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 3, len(cmds), 0x200000, 0)
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(hdr + cmds)
    try:
        r = inspect_macho(p)
        assert r["ok"] and r["is_macho"] and not r["fat"]
        im = r["images"][0]
        assert im["arch"] == "x86_64" and im["filetype"] == "EXECUTE" and im["pie"] is True
        assert im["dylibs"] == ["/usr/lib/libSystem.B.dylib"]
        assert any(s["name"] == "__TEXT" and s["perms"] == "r-x" for s in im["segments"])
        assert im["entry"] == 0x1230
        assert "Mach-O" in render_macho(r)
    finally:
        os.remove(p)


def test_macho_inspect_non_macho():
    import os
    from binoracle.workflows.machoinspect import inspect_macho
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        import pytest
        pytest.skip("sample no compilado")
    r = inspect_macho(binp)
    assert r["ok"] and r["is_macho"] is False


def test_dotnet_metadata_parser_on_synthetic_root():
    # Parsea un metadata root BSJB sintetico: version, streams, conteos de tablas y nombres.
    import struct
    from binoracle.workflows.dotnetinspect import parse_metadata
    ver = b"v4.0.30319\x00"
    ver = ver + b"\x00" * (((len(ver) + 3) & ~3) - len(ver))
    valid = (1 << 0) | (1 << 6)  # Module, MethodDef
    tilde = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0) + struct.pack("<II", 1, 3)
    strings = b"\x00MyModule\x00Main\x00Program\x00"
    head = struct.pack("<IHHI", 0x424A5342, 1, 1, 0) + struct.pack("<I", len(ver)) + ver
    head += struct.pack("<H", 0) + struct.pack("<H", 2)
    sh1 = b"#~\x00\x00"
    sh2 = b"#Strings\x00\x00\x00\x00"
    hdr_len = len(head) + 8 + len(sh1) + 8 + len(sh2)
    off_t = hdr_len
    off_s = off_t + len(tilde)
    blob = (head + struct.pack("<II", off_t, len(tilde)) + sh1
            + struct.pack("<II", off_s, len(strings)) + sh2 + tilde + strings)
    r = parse_metadata(blob)
    assert r["version"] == "v4.0.30319"
    assert r["streams"] == ["#~", "#Strings"]
    assert r["tables"] == {"Module": 1, "MethodDef": 3}
    assert r["string_names"] == ["MyModule", "Main", "Program"]


def test_dotnet_inspect_non_pe():
    import os
    from binoracle.workflows.dotnetinspect import inspect_dotnet, render_dotnet
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        import pytest
        pytest.skip("sample no compilado")
    r = inspect_dotnet(binp)
    assert r["ok"] and r.get("is_dotnet") is False
    assert isinstance(render_dotnet(r), str)


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


def test_plist_inspect_bundle_keys_and_privacy():
    import os
    import plistlib
    import tempfile
    from binoracle.workflows.plistinspect import inspect_plist, render_plist
    doc = {
        "CFBundleIdentifier": "com.example.app",
        "CFBundleExecutable": "ExampleApp",
        "CFBundleShortVersionString": "1.2.3",
        "MinimumOSVersion": "15.0",
        "NSCameraUsageDescription": "We need the camera to scan QR codes",
        "NSLocationWhenInUseUsageDescription": "To show nearby stores",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["exampleapp", "exapp"]}],
    }
    for fmt in (plistlib.FMT_BINARY, plistlib.FMT_XML):
        p = tempfile.mktemp(suffix=".plist")
        with open(p, "wb") as f:
            plistlib.dump(doc, f, fmt=fmt)
        try:
            r = inspect_plist(p)
            assert r["ok"] and r["is_plist"]
            assert r["bundle_id"] == "com.example.app"
            assert r["executable"] == "ExampleApp"
            assert r["version"] == "1.2.3"
            assert set(r["url_schemes"]) == {"exampleapp", "exapp"}
            usage = r["usage_descriptions"]
            assert "NSCameraUsageDescription" in usage
            assert "NSLocationWhenInUseUsageDescription" in usage
            out = render_plist(r)
            assert "com.example.app" in out and "privacidad" in out.lower()
        finally:
            os.remove(p)


def _mkraw(opcodes):
    # shape of a radare2 /Rj gadget entry
    return {"opcodes": [{"offset": 0x1000 + i, "opcode": t, "type": ty}
                        for i, (t, ty) in enumerate(opcodes)]}


def test_classify_gadget_kinds():
    from binoracle.workflows.chainanalyzer import _classify
    # pop rdi ; ret
    g = _classify(_mkraw([("pop rdi", "pop"), ("ret", "ret")]))
    assert g.kind == "pop" and "rdi" in g.sets and g.stack_delta == 16
    # syscall gadget
    gs = _classify(_mkraw([("syscall", "syscall")]))
    assert gs.kind == "syscall"
    # write-what-where: mov qword [rdi], rax ; ret
    gw = _classify(_mkraw([("mov qword [rdi], rax", "mov"), ("ret", "ret")]))
    assert gw.kind == "write" and gw.mem_write and "[rdi]" in gw.mem_write
    # reg-to-reg move: mov rsi, rax ; ret
    gm = _classify(_mkraw([("mov rsi, rax", "mov"), ("ret", "ret")]))
    assert gm.kind == "move" and "rsi<-rax" in gm.moves
    # pivot via xchg rsp
    gp = _classify(_mkraw([("xchg rsp, rax", "mov"), ("ret", "ret")]))
    assert gp.kind == "pivot"
    # dirty gadget (jmp) rejected
    assert _classify(_mkraw([("jmp rax", "ujmp")])) is None


def test_render_arsenal_surface():
    from binoracle.workflows.chainanalyzer import render_arsenal
    # not applicable (non-ELF)
    assert "no aplicable" in render_arsenal({"ok": True, "applicable": False,
                                             "note": "binario pe no aplicable"}).lower()
    # a populated arsenal renders every section
    r = {"ok": True, "applicable": True, "arch": "x86_64", "static": True, "pie": False,
         "arsenal": {
             "total_gadgets": 9,
             "arg_regs": {"rdi": {"addr": "0x401000", "text": "pop rdi; ret", "delta": 16, "clobbers": []},
                          "rsi": {"addr": "0x401010", "text": "pop rsi; ret", "delta": 16, "clobbers": ["r15"]}},
             "syscall": {"addr": "0x401100", "text": "syscall"},
             "pivot": {"addr": "0x401200", "text": "leave; ret"},
             "write": {"addr": "0x401300", "mem_write": "mov [rdi], rax"},
             "moves": [{"move": "rdx<-rax", "addr": "0x401400", "text": "mov rdx, rax; ret"}],
             "execve_coverage": {"have": ["rdi", "rsi"], "need": ["rdi", "rsi", "rdx", "rax"],
                                 "complete": False},
             "ret2csu": {"gadget1": "0x4011ba", "gadget2": "0x4011a0", "complete": True},
             "one_gadget": {"available": True, "count": 2, "offsets": ["0x4f2a5", "0x10a2fc"],
                            "note": "absolutas", "constraints": "precondiciones"},
         }}
    out = render_arsenal(r)
    for needle in ("RDI", "pop rdi; ret", "syscall", "write-what-where", "rdx<-rax",
                   "ret2csu", "__libc_csu_init", "one_gadget", "0x4f2a5", "parcial"):
        assert needle in out, needle


def test_execve_arsenal_fallback_notes():
    from binoracle.workflows.chainanalyzer import _execve_arsenal_notes
    # no missing args, empty arsenal -> no notes
    assert _execve_arsenal_notes([], {}) == []
    # missing rsi/rdx + complete ret2csu -> a grounded alternative note mentioning ret2csu
    ars = {"ret2csu": {"gadget1": "0x401190", "gadget2": "0x4011a0", "complete": True}}
    notes = _execve_arsenal_notes(["rsi", "rdx"], ars)
    assert notes and "ret2csu" in notes[0][0] and "__libc_csu_init" in notes[0][1]
    # ret2csu only helps when args are actually missing
    assert _execve_arsenal_notes([], ars) == []
    # one_gadget available -> a shortcut note with the offsets, independent of missing args
    ars2 = {"one_gadget": {"available": True, "count": 2, "offsets": ["0x4f2a5", "0x10a2fc"]}}
    n2 = _execve_arsenal_notes([], ars2)
    assert n2 and "one_gadget" in n2[0][1] and "0x4f2a5" in n2[0][0]
    # unavailable one_gadget -> no shortcut note
    assert _execve_arsenal_notes([], {"one_gadget": {"available": False}}) == []


def test_parse_ret2csu_gadgets():
    from binoracle.workflows.chainanalyzer import _parse_csu
    # synthetic r2 `pdf` of a classic __libc_csu_init tail
    disasm = """
/ (fcn) sym.__libc_csu_init 101
|   0x00401190      4157           push r15
|   0x00401192      4989ff         mov r15, rdi
|   0x004011a0      4c89fa         mov rdx, r15
|   0x004011a3      4c89f6         mov rsi, r14
|   0x004011a6      4489ef         mov edi, r13d
|   0x004011a9      41ff14dc       call qword [r12 + rbx*8]
|   0x004011b6      4883c408       add rsp, 8
|   0x004011ba      5b             pop rbx
|   0x004011bb      5d             pop rbp
|   0x004011bc      415c           pop r12
|   0x004011be      415d           pop r13
|   0x004011c0      415e           pop r14
|   0x004011c2      415f           pop r15
|   0x004011c4      c3             ret
"""
    r = _parse_csu(disasm)
    assert r is not None
    assert r["gadget2"] == hex(0x004011a0)
    assert r["gadget1"] == hex(0x004011ba)
    assert r["complete"] is True
    # a function with no csu shape -> None
    assert _parse_csu("0x401000  90  nop\n0x401001  c3  ret\n") is None


def test_ret2libc_32bit_uses_stack_args():
    import os
    import pytest
    if not os.path.exists("samples/bin/ret2win32"):
        pytest.skip("sample 32-bit no compilado")
    from binoracle.workflows.chainanalyzer import analyze_chains
    an = analyze_chains("samples/bin/ret2win32", None, verify=False, lang="es")
    assert an.arch.endswith("32")
    r2l = [c for c in an.chains if c.name == "ret2libc system"]
    assert r2l, "falta la cadena ret2libc en 32-bit"
    c = r2l[0]
    # cdecl: argumentos en la pila -> NO requiere gadget pop de registro
    assert c.regs_needed == []
    assert not any("pop rdi" in req for req in c.requirements)
    assert any("cdecl" in x.lower() for x in c.constraints)
    # execve chain for the same binary must be the 32-bit int 0x80 variant
    ex = [c for c in an.chains if c.name == "execve syscall"][0]
    assert any("int 0x80" in req for req in ex.requirements)
    assert any("pop eax" in req for req in ex.requirements)


def test_build_arsenal_32bit():
    from binoracle.workflows.chainanalyzer import _classify, _build_arsenal
    def mk(ops):
        return {"opcodes": [{"offset": 0x8048000 + i, "opcode": t, "type": ty}
                            for i, (t, ty) in enumerate(ops)]}
    # x86-32 syscall arsenal: pop ebx/ecx/edx/eax + int 0x80
    gadgets = [
        _classify(mk([("pop ebx", "pop"), ("ret", "ret")])),
        _classify(mk([("pop ecx", "pop"), ("ret", "ret")])),
        _classify(mk([("pop edx", "pop"), ("ret", "ret")])),
        _classify(mk([("pop eax", "pop"), ("ret", "ret")])),
        _classify(mk([("int 0x80", "swi")])),
    ]
    ars = _build_arsenal(gadgets, bits=32)
    assert ars["bits"] == 32
    assert set(ars["arg_regs"]).issuperset({"ebx", "ecx", "edx", "eax"})
    assert ars["syscall"] is not None                  # int 0x80 counts as the syscall gadget
    cov = ars["execve_coverage"]
    assert cov["need"] == ["ebx", "ecx", "edx", "eax"]
    assert cov["complete"] is True
    # int 0x80 classified as a syscall-kind gadget
    gi = _classify(mk([("int 0x80", "swi")]))
    assert gi.kind == "syscall"


def test_build_arsenal_execve_coverage():
    from binoracle.workflows.chainanalyzer import _classify, _build_arsenal
    gadgets = [
        _classify(_mkraw([("pop rdi", "pop"), ("ret", "ret")])),
        _classify(_mkraw([("pop rsi", "pop"), ("ret", "ret")])),
        _classify(_mkraw([("pop rdx", "pop"), ("ret", "ret")])),
        _classify(_mkraw([("pop rax", "pop"), ("ret", "ret")])),
        _classify(_mkraw([("syscall", "syscall")])),
        _classify(_mkraw([("mov qword [rdi], rsi", "mov"), ("ret", "ret")])),
    ]
    ars = _build_arsenal(gadgets)
    assert ars["total_gadgets"] == 6
    assert ars["execve_coverage"]["complete"] is True
    assert ars["syscall"] and ars["write"]
    assert set(ars["arg_regs"]).issuperset({"rdi", "rsi", "rdx", "rax"})
    # drop syscall -> coverage incomplete
    ars2 = _build_arsenal(gadgets[:4])
    assert ars2["execve_coverage"]["complete"] is False


def _build_class(this_name="com/example/Main", super_name="java/lang/Object", major=52):
    # constant pool: 1=Utf8(this), 2=Class->1, 3=Utf8(super), 4=Class->3
    def utf8(s):
        b = s.encode("utf-8")
        return bytes([1]) + len(b).to_bytes(2, "big") + b
    cp = bytearray()
    cp += utf8(this_name)                     # idx 1
    cp += bytes([7]) + (1).to_bytes(2, "big")  # idx 2 Class -> 1
    cp += utf8(super_name)                    # idx 3
    cp += bytes([7]) + (3).to_bytes(2, "big")  # idx 4 Class -> 3
    out = bytearray(b"\xca\xfe\xba\xbe")
    out += (0).to_bytes(2, "big")             # minor
    out += major.to_bytes(2, "big")           # major
    out += (5).to_bytes(2, "big")             # cp_count = 5 (entries 1..4)
    out += cp
    out += (0x0021).to_bytes(2, "big")        # access_flags
    out += (2).to_bytes(2, "big")             # this_class -> cp[2]
    out += (4).to_bytes(2, "big")             # super_class -> cp[4]
    out += (0).to_bytes(2, "big")             # interfaces_count
    out += (0).to_bytes(2, "big")             # fields_count
    out += (0).to_bytes(2, "big")             # methods_count
    out += (0).to_bytes(2, "big")             # attributes_count
    return bytes(out)


def test_java_standalone_class():
    import os
    import tempfile
    from binoracle.workflows.jarinspect import inspect_jar, render_jar
    p = tempfile.mktemp(suffix=".class")
    with open(p, "wb") as f:
        f.write(_build_class(major=61))       # Java 17
    try:
        r = inspect_jar(p)
        assert r["ok"] and r["kind"] == "class"
        assert r["major"] == 61 and r["java_version"] == "17"
        assert r["this_class"] == "com/example/Main"
        assert r["super_class"] == "java/lang/Object"
        assert "17" in render_jar(r)
    finally:
        os.remove(p)


def test_java_jar_manifest_and_classes():
    import os
    import tempfile
    import zipfile
    from binoracle.workflows.jarinspect import inspect_jar, render_jar
    p = tempfile.mktemp(suffix=".jar")
    z = zipfile.ZipFile(p, "w")
    z.writestr("META-INF/MANIFEST.MF",
               "Manifest-Version: 1.0\r\nMain-Class: com.example.App\r\nCreated-By: test\r\n")
    z.writestr("com/example/App.class", _build_class("com/example/App", major=52))
    z.writestr("org/springframework/boot/Boot.class", _build_class("org/springframework/boot/Boot"))
    z.close()
    try:
        r = inspect_jar(p)
        assert r["ok"] and r["kind"] == "jar"
        assert r["main_class"] == "com.example.App"
        assert r["class_count"] == 2
        assert "Spring" in r["frameworks"]
        assert r["bytecode"]["java_version"] in ("8", "17")
        out = render_jar(r)
        assert "com.example.App" in out and "Spring" in out
    finally:
        os.remove(p)


def test_ioc_scan_finds_secrets_and_urls():
    import os
    import tempfile
    from binoracle.workflows.iocscan import scan_iocs, render_iocs
    blob = (b"\x00\x01binary prefix\x00"
            b"connect https://api.example.com/v1/users please\x00"
            b"AKIAIOSFODNN7EXAMPLE\x00"
            b"token=ghp_" + b"A1b2C3d4E5f6G7h8I9j0" * 2 + b"\x00"
            b"contact admin@example.com for help\x00"
            b"server at 203.0.113.42 listening\x00"
            b"-----BEGIN RSA PRIVATE KEY-----\x00"
            b"\xff\xfe random tail \x00")
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(blob)
    try:
        r = scan_iocs(p)
        assert r["ok"], r
        f = r["findings"]
        assert any("api.example.com" in u for u in f.get("url", []))
        assert f.get("aws-access-key") and f["aws-access-key"][0].startswith("AKIAIOSFOD")
        assert f.get("github-token")
        assert any("admin@example.com" in e for e in f.get("email", []))
        assert "203.0.113.42" in f.get("ipv4", [])
        assert f.get("private-key-pem")
        assert "api.example.com" in r["hosts"]
        assert "aws-access-key" in r["secret_kinds"]
        out = render_iocs(r)
        assert "IOC" in out and "aws-access-key" in out
    finally:
        os.remove(p)


def test_ioc_scan_utf16_strings():
    import os
    import tempfile
    from binoracle.workflows.iocscan import scan_iocs
    # UTF-16LE encoded URL (common in Windows PE resources)
    u = "https://evil.example.net/beacon".encode("utf-16-le")
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"MZ\x00\x00" + u + b"\x00\x00")
    try:
        r = scan_iocs(p)
        assert r["ok"]
        assert any("evil.example.net" in x for x in r["findings"].get("url", []))
    finally:
        os.remove(p)


def _build_asar(tree_files):
    """Build a minimal real ASAR archive in memory. tree_files: {path: bytes}."""
    import json as _json
    # lay out file data, recording offsets; build a nested header tree
    data = bytearray()
    root = {"files": {}}
    for path, content in tree_files.items():
        off = len(data)
        data += content
        node = root
        parts = path.split("/")
        for p in parts[:-1]:
            node = node["files"].setdefault(p, {"files": {}})
        node["files"][parts[-1]] = {"size": len(content), "offset": str(off)}
    header_str = _json.dumps(root).encode("utf-8")
    str_len = len(header_str)
    pad = (-(4 + str_len)) % 4
    payload = str_len.to_bytes(4, "little") + header_str + b"\x00" * pad
    payload_len = len(payload)
    header_size = 4 + payload_len
    out = bytearray()
    out += (4).to_bytes(4, "little")             # pickle1 payload len
    out += header_size.to_bytes(4, "little")     # size of pickle2 buffer
    out += payload_len.to_bytes(4, "little")     # pickle2 payload len
    out += payload                               # str_len + json + pad
    out += data                                  # file data region
    return bytes(out)


def test_asar_inspect_tree_and_package():
    import os
    import json as _json
    import tempfile
    from binoracle.workflows.asarinspect import inspect_asar, render_asar
    pkg = _json.dumps({"name": "myapp", "version": "2.0.1", "main": "main.js",
                       "dependencies": {"electron-store": "^8.0.0", "axios": "^1.0.0"}}).encode()
    asar = _build_asar({
        "package.json": pkg,
        "main.js": b"require('./lib/x')\n",
        "lib/x.js": b"module.exports = 1\n",
        "node_modules/axios/index.js": b"// axios\n",
    })
    p = tempfile.mktemp(suffix=".asar")
    with open(p, "wb") as f:
        f.write(asar)
    try:
        r = inspect_asar(p)
        assert r["ok"] and r["is_asar"], r
        assert r["file_count"] == 4
        assert r["package"]["name"] == "myapp"
        assert r["package"]["version"] == "2.0.1"
        assert r["entry_point"] == "main.js"
        assert "axios" in r["package"]["dependencies"]
        assert r["js_count"] == 3
        assert "axios" in r["node_modules"]
        out = render_asar(r)
        assert "myapp" in out and "main.js" in out
    finally:
        os.remove(p)


def test_asar_inspect_non_asar():
    import os
    import tempfile
    from binoracle.workflows.asarinspect import inspect_asar
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"\x00\x01\x02\x03 this is not an asar archive at all")
    try:
        r = inspect_asar(p)
        assert r["ok"] and r["is_asar"] is False
    finally:
        os.remove(p)


def test_plist_inspect_non_plist():
    import os
    import tempfile
    from binoracle.workflows.plistinspect import inspect_plist
    p = tempfile.mktemp()
    with open(p, "wb") as f:
        f.write(b"not a plist at all")
    try:
        r = inspect_plist(p)
        assert r["ok"] and r["is_plist"] is False
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


def test_artifact_size_guard_degrades():
    # Los lectores que leen el fichero completo deben rechazar artefactos sobre el limite, honesto.
    import importlib
    import os
    import tempfile
    os.environ["BINORACLE_MAX_ARTIFACT_BYTES"] = "16"
    try:
        import binoracle.workflows._artifact as a
        importlib.reload(a)
        from binoracle.workflows._artifact import read_bounded, ArtifactTooLarge
        p = tempfile.mktemp()
        with open(p, "wb") as f:
            f.write(b"A" * 100)
        try:
            raised = False
            try:
                read_bounded(p)
            except ArtifactTooLarge:
                raised = True
            assert raised
        finally:
            os.remove(p)
    finally:
        os.environ.pop("BINORACLE_MAX_ARTIFACT_BYTES", None)
        import binoracle.workflows._artifact as a
        importlib.reload(a)


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
