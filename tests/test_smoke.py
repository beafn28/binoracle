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
