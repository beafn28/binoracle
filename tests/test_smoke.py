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
