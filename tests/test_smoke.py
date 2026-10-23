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


def test_autopoc_pe_verifies_ret2win_under_wine():
    # "[M] Windows PE dynamic + symbolic" del ROADMAP v0.3, mitad dinamica: ret2win sobre un
    # PE32+ verificado ejecutando bajo Wine (no una suposicion). win_chall.exe tiene el mismo
    # patron que ret2win.c (overflow lineal + win() sin canary); el offset de la direccion de
    # retorno (72 = 64 de buf + 8 de saved rbp) coincide con la version ELF porque la ABI de
    # pila de x86-64 es la misma independientemente del SO.
    import os
    import shutil
    import pytest
    from binoracle.workflows.autopoc_pe import autopoc_pe, wine_available, find_win_pe, is_pe
    b = "samples/bin/win_chall.exe"
    if not os.path.exists(b):
        pytest.skip("sample win_chall.exe no compilado (samples/build.sh; necesita mingw)")
    if not wine_available():
        pytest.skip("wine no instalado (apt install wine)")
    assert is_pe(b) is True
    assert find_win_pe(b) is not None

    r = autopoc_pe(b)
    assert r.get("ok") and r.get("verified"), f"ret2win (PE/Wine) no verificado: {r.get('note')}"
    assert "off=72" in r.get("detail", "")


def test_autopoc_pe_degrades_cleanly_on_non_pe():
    from binoracle.workflows.autopoc_pe import autopoc_pe
    r = autopoc_pe("samples/bin/ret2win")
    assert r.get("ok") is False
    assert "MZ" in r.get("note", "")


def test_autopwn_routes_pe_binaries_to_wine_ret2win():
    # autopwn() debe desviarse a ret2win-pe (Wine) para un PE, sin intentar el resto de combos
    # que asumen ELF (checksec de r2, pwntools ELF()/ROP(), etc.).
    import os
    import pytest
    from binoracle.workflows.autopoc_pe import wine_available
    b = "samples/bin/win_chall.exe"
    if not os.path.exists(b):
        pytest.skip("sample win_chall.exe no compilado")
    if not wine_available():
        pytest.skip("wine no instalado")
    from binoracle.workflows.autopwn import autopwn
    r = autopwn(b)
    assert r.attempts and r.attempts[0][0] == "ret2win-pe"
    assert r.win_exploit is True


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


def test_autopwn_why_covers_mprotect_and_leakchain_combos():
    # autopwn ahora orquesta tambien mprotect-shellcode y leak-chain (los dos ultimos
    # incrementos de v0.2: ROP builder v2 y automatic infoleak chaining) -- la razon
    # "defensa -> tecnica" del informe debe nombrarlos especificamente, no caer en el generico
    # "seleccionada segun las defensas observadas".
    from binoracle.workflows.autopwn import _why
    mp = _why({}, False, "mprotect-shellcode")
    assert "mprotect" in mp.lower()
    lc = _why({}, False, "leak-chain")
    assert "leak" in lc.lower() and "escritura" in lc.lower()


def test_autopwn_why_covers_ret2csu_and_pivot_combos():
    # Siguientes dos huecos encontrados en la auditoria de autopwn (autocsu/autopivot existian
    # como tools sueltas pero el orquestador nunca las probaba): la razon debe nombrarlos.
    from binoracle.workflows.autopwn import _why
    csu = _why({}, False, "ret2csu")
    assert "csu" in csu.lower()
    pv = _why({}, False, "pivot")
    assert "leave" in pv.lower() or "pivot" in pv.lower()


def test_autocsu_applicable_checks_symbols_cheaply():
    # _csu_applicable es el pre-filtro barato (sin sandbox) que autopwn usa antes de gastar una
    # tanda de ejecucion: necesita win+fnptr (strategy A) o retptr (strategy B).
    import os
    import pytest
    if not os.path.exists("samples/bin/ret2csu") or not os.path.exists("samples/bin/ret2win"):
        pytest.skip("samples ret2csu/ret2win no compilados")
    from binoracle.workflows.autocsu import _csu_applicable
    assert _csu_applicable("samples/bin/ret2csu") is True
    assert _csu_applicable("samples/bin/ret2win") is False


def test_autopivot_applicable_checks_symbols_cheaply():
    import os
    import pytest
    if not os.path.exists("samples/bin/pivot") or not os.path.exists("samples/bin/ret2win"):
        pytest.skip("samples pivot/ret2win no compilados")
    from binoracle.workflows.autopivot import _pivot_applicable
    assert _pivot_applicable("samples/bin/pivot") is True
    # ret2win tiene win() pero NINGUN buffer de staging de nombre conocido
    assert _pivot_applicable("samples/bin/ret2win") is False


def test_autopwn_why_covers_remaining_heap_internals_combos():
    # Ultimo paso del hueco de la auditoria de autopwn: 11 tecnicas de glibc-internals mas
    # (house-of-*, IO_FILE/FSOP, fastbin-dup, unsafe-unlink, tcache-stash) + SROP aarch64.
    from binoracle.workflows.autopwn import _why
    names_fragments = {
        "house-of-force": "top",
        "house-of-spirit": "tcache",
        "house-of-einherjar": "consolidacion",
        "house-of-botcake": "unsorted",
        "largebin-attack": "largebin",
        "house-of-mind": "ar_ptr",
        "iofile-fsop": "vtable",
        "fastbin-dup": "fasttop",
        "unsafe-unlink": "unlink",
        "house-of-corrosion": "global_max_fast",
        "tcache-stash": "stash",
        "srop-aarch64": "aarch64",
    }
    for name, frag in names_fragments.items():
        why = _why({}, False, name)
        assert frag in why.lower(), f"{name}: {why!r} no nombra el mecanismo real"
        assert why != "seleccionada segun las defensas y primitivas observadas"
    # srop-aarch64 no debe caer en el _why() generico de SROP x86 (que no menciona aarch64)
    assert "aarch64" not in _why({}, False, "srop").lower()


def test_heap_internals_applicable_checks_symbols_cheaply():
    # Pre-filtro barato (sin sandbox) de las 11 tecnicas de glibc-internals añadidas al
    # orquestador: True contra su propio fixture, False contra un binario sin esos simbolos.
    import os
    import pytest
    checks = [
        ("hof", "autohof", "_hof_applicable"),
        ("hos", "autohos", "_hos_applicable"),
        ("hoe", "autohoe", "_hoe_applicable"),
        ("botcake", "autobotcake", "_botcake_applicable"),
        ("largebin", "autolargebin", "_largebin_applicable"),
        ("homind", "autohomind", "_homind_applicable"),
        ("iofile", "autoiofile", "_iofile_applicable"),
        ("fastbindup", "autofastbindup", "_fastbindup_applicable"),
        ("unsafeunlink", "autounsafeunlink", "_unsafeunlink_applicable"),
        ("hoc", "autohoc", "_hoc_applicable"),
        ("stash", "autostash", "_stash_applicable"),
    ]
    if not os.path.exists("samples/bin/ret2win"):
        pytest.skip("sample ret2win no compilado")
    import importlib
    for sample, mod_name, fn_name in checks:
        binp = f"samples/bin/{sample}"
        if not os.path.exists(binp):
            continue
        mod = importlib.import_module(f"binoracle.workflows.{mod_name}")
        fn = getattr(mod, fn_name)
        assert fn(binp) is True, f"{fn_name} deberia aplicar a su propio fixture {binp}"
        assert fn("samples/bin/ret2win") is False, f"{fn_name} no deberia aplicar a ret2win"


def test_autolibc_render():
    from binoracle.workflows.autolibc import render_libc
    out = render_libc({"ok": True, "verified": True, "detail": "VERIFIED off=88 base=0x7f...",
                       "note": "ret2libc con leak", "output": "shell"})
    assert "ret2libc" in out and "SI" in out
    out2 = render_libc({"ok": False, "note": "docker no disponible"})
    assert "No disponible" in out2


def test_autolibc_one_gadget_path_is_honest():
    # The aggressive one_gadget path (og_only=True) prefers the one_gadget tool, falls back to an
    # execve-reach pure-python finder, and sweeps alignment+NULL-tails to satisfy stack constraints.
    # Grounding check: it runs cleanly and NEVER claims 'verified' without a real shell (if a firing
    # gadget exists on the sandbox libc the detail says one_gadget=...; many hardened glibc builds
    # have none, in which case it degrades honestly -- both outcomes are acceptable, a false positive
    # is not).
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/ret2libc"
    if not os.path.exists(binp):
        pytest.skip("sample ret2libc no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autolibc import autolibc
    r = autolibc(binp, og_only=True)
    assert r.get("ok")
    if r.get("verified"):
        assert "one_gadget=" in (r.get("detail") or "")   # a shell via a magic gadget, really fired
    else:
        assert "no verificado" in (r.get("note") or "")   # honest degrade, no false claim


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


def test_regression_tests_render():
    from binoracle.workflows.regress import RegressionTest, render_regression_tests
    passed = RegressionTest(technique="ret2win", old_detail="offset=72 win=0x401176",
                            new_verified=False, passed=True)
    failed = RegressionTest(technique="ret2libc", old_detail="leak=0x7f...",
                            new_verified=True, passed=False)
    out = render_regression_tests("old.bin", "new.bin", [passed, failed])
    assert "PASA" in out and "FALLA" in out and "fix incompleto o revertido" in out


def test_autoregress_generates_and_runs_real_regression_test():
    # "[M] Patch-diff v2 (n-day)" del ROADMAP v0.4: en vez de limitarse al diff estructural
    # (radiff2) o a comparar veredictos grounded/verified (run_regress, ya existente), esto
    # GENERA y EJECUTA un test de regresion real: la MISMA tecnica de autopwn que consiguio un
    # exploit verificado contra OLD se reintenta contra NEW. ret2win_patched es el MISMO fuente
    # que ret2win con -fstack-protector-all añadido (el "silent fix" clasico: un canary) --
    # el exploit que funcionaba en OLD debe dejar de verificar en NEW, y el test debe reportarlo.
    import os
    import pytest
    from binoracle.workflows.regress import autoregress_test
    old, new = "samples/bin/ret2win", "samples/bin/ret2win_patched"
    if not os.path.exists(old) or not os.path.exists(new):
        pytest.skip("samples ret2win/ret2win_patched no compilados (samples/build.sh)")
    tests = autoregress_test(old, new, techniques=["ret2win"])
    assert tests, "ret2win debe haber verificado en OLD -- no hay nada que generar"
    t = next(t for t in tests if t.technique == "ret2win")
    assert t.new_verified is False
    assert t.passed is True


def test_autoregress_catches_a_fix_that_did_not_actually_fix_anything():
    # Control: si el "NEW" es el MISMO binario vulnerable (el fix no hizo nada, o se revirtio
    # en silencio), el test de regresion debe FALLAR -- nunca reportar passed=True solo porque
    # se pudo volver a ejecutar.
    import os
    import pytest
    from binoracle.workflows.regress import autoregress_test
    b = "samples/bin/ret2win"
    if not os.path.exists(b):
        pytest.skip("sample ret2win no compilado")
    tests = autoregress_test(b, b, techniques=["ret2win"])
    assert tests
    t = tests[0]
    assert t.new_verified is True
    assert t.passed is False


def test_ci_gate_passes_on_a_real_fix_no_llm_needed():
    # "[M] CI action" del ROADMAP v0.5: la verdad PASS/FAIL para una GitHub Action. Audit
    # (run_audit) necesita un LLM local, que un runner de CI generico no tiene -- este gate usa
    # el pipeline grounded (run_regress, llm=None) en su lugar, confirmado SIN ningun backend
    # LLM disponible. ret2win_patched es el fix real (canary anadido): debe PASAR -- anadir una
    # proteccion nunca debe fallar el build.
    import os
    import pytest
    from binoracle.config import Config
    from binoracle.workflows.ci_gate import run_ci_gate, render_ci_gate
    old, new = "samples/bin/ret2win", "samples/bin/ret2win_patched"
    if not os.path.exists(old) or not os.path.exists(new):
        pytest.skip("samples ret2win/ret2win_patched no compilados (samples/build.sh)")
    r = run_ci_gate(old, new, Config())
    assert r.ok, r.note
    assert r.passed is True, r.fail_reasons
    assert "PASA" in render_ci_gate(r)


def test_ci_gate_fails_on_a_real_exploit_regression():
    # Control: NEW es el MISMO binario vulnerable (ningun fix real) -- con --gen-test, el
    # exploit verificado en OLD SIGUE verificando en NEW, y el gate debe FALLAR con el motivo
    # correcto, nunca solo "paso porque se pudo volver a ejecutar".
    import os
    import pytest
    from binoracle.config import Config
    from binoracle.workflows.ci_gate import run_ci_gate, render_ci_gate
    b = "samples/bin/ret2win"
    if not os.path.exists(b):
        pytest.skip("sample ret2win no compilado")
    r = run_ci_gate(b, b, Config(), gen_test=True, techniques=["ret2win"])
    assert r.ok, r.note
    assert r.passed is False
    assert any("ret2win" in reason for reason in r.fail_reasons)
    assert "FALLA" in render_ci_gate(r)


def test_ci_gate_does_not_fail_on_strengthened_mitigation_alone():
    # Un mit_change de False->True (p.ej. Canary se ENCIENDE) no debe, por si solo, aparecer
    # como motivo de fallo -- solo un DEBILITAMIENTO (True->False) debe hacerlo.
    from binoracle.workflows.ci_gate import run_ci_gate
    from binoracle.workflows.regress import RegressResult

    class _FakeConfig:
        pass

    import binoracle.workflows.ci_gate as cg_mod
    fake = RegressResult(old="a", new="b", mit_changes=["Canary: False -> True"])
    orig = cg_mod.run_regress
    cg_mod.run_regress = lambda old, new, config: fake
    try:
        r = run_ci_gate("a", "b", _FakeConfig())
    finally:
        cg_mod.run_regress = orig
    assert r.ok and r.passed is True, r.fail_reasons


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


def test_agent_loop_uses_native_tool_calling_when_backend_and_config_opt_in():
    # "[M] Model quality" del ROADMAP.md -- "better native tool-calling for capable local
    # models". Simula lo que un backend real (Ollama/OpenAI-compat) devuelve cuando el modelo
    # usa function-calling de verdad: un backend fake que implementa `_supports_native_tools`
    # y de verdad lee el `tools=` que el loop le pasa (confirma que SI se construyo y envio el
    # esquema, con la tool synthetic 'finish' incluida), y devuelve la llamada convertida al
    # MISMO texto JSON portable que extract_action ya entiende -- exactamente como hacen
    # OllamaBackend/OpenAICompatBackend de verdad (ver sus propios chat()). Dirige un AgentLoop
    # REAL de principio a fin: una llamada a la tool real, luego 'finish'.
    import json
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

    class _NativeToolsLLM:
        _supports_native_tools = True
        def __init__(self):
            self.step = 0
            self.seen_tools_arg = None
        def available(self):
            return True
        def chat(self, messages, *, json_mode=False, tools=None):
            self.seen_tools_arg = tools   # confirma que el loop SI construyo/envio el esquema
            self.step += 1
            if self.step == 1:
                return json.dumps({"name": "echo_tool", "arguments": {"value": "hola"}})
            return json.dumps({"name": "finish",
                               "arguments": {"answer": "listo", "findings": []}})

    cfg = load_config()
    cfg.native_tools = True
    reg = ToolRegistry([_Echo()])
    llm = _NativeToolsLLM()
    res = AgentLoop(llm, reg, cfg).run("usa echo_tool y termina", mode="ask")

    assert calls["n"] == 1, "la llamada nativa a echo_tool debia ejecutar la tool real"
    assert res.answer.strip().startswith("listo") or "listo" in res.answer
    assert res.stopped_reason == "final"
    assert llm.seen_tools_arg is not None, "el esquema de tools no se envio al backend"
    names = {f["function"]["name"] for f in llm.seen_tools_arg}
    assert "echo_tool" in names and "finish" in names


def test_agent_loop_never_sends_tools_when_native_tools_is_off_by_default():
    # Opt-in de verdad: sin native_tools=True (el default), el loop NUNCA debe pasar `tools`
    # al backend, ni aunque el backend SI lo soporte -- un backend/modelo que lo soporta pero
    # que el usuario no activo explicitamente debe seguir usando el protocolo JSON portable.
    from binoracle.agent.loop import AgentLoop
    from binoracle.config import load_config
    from binoracle.oracles.base import ToolRegistry

    class _CapableButNotOptedInLLM:
        _supports_native_tools = True
        def available(self):
            return True
        def chat(self, messages, *, json_mode=False):   # a proposito SIN kwarg `tools`
            return '{"action":"final","answer":"ok","findings":[]}'

    cfg = load_config()
    assert cfg.native_tools is False, "native_tools debe ser False por defecto"
    res = AgentLoop(_CapableButNotOptedInLLM(), ToolRegistry([]), cfg).run("x", mode="ask")
    assert res.stopped_reason == "final"   # no lanzo TypeError por un kwarg `tools` inesperado


def test_ollama_backend_converts_native_tool_call_to_portable_json():
    # Confirma el backend REAL (no el fake de arriba): OllamaBackend.chat() con native_tools
    # activo construye el payload `tools` y convierte la respuesta `message.tool_calls` de
    # Ollama de vuelta al MISMO texto JSON portable {"name":...,"arguments":...} que
    # agent/tools.py.extract_action ya sabe parsear -- sin tocar la red real.
    from binoracle.agent.tools import extract_action
    from binoracle.config import load_config
    from binoracle.llm.ollama import OllamaBackend

    cfg = load_config()
    cfg.native_tools = True
    backend = OllamaBackend(cfg)
    captured = {}
    def _fake_post(path, payload, timeout):
        captured["payload"] = payload
        return {"message": {"tool_calls": [
            {"function": {"name": "r2_checksec", "arguments": {}}}
        ]}}
    backend._post = _fake_post
    out = backend.chat([], json_mode=True, tools=[{"type": "function",
                       "function": {"name": "r2_checksec", "description": "d",
                                   "parameters": {"type": "object", "properties": {}}}}])
    assert "tools" in captured["payload"]
    assert "format" not in captured["payload"], "format=json no debe mezclarse con tool-calling nativo"
    action = extract_action(out)
    assert action == {"action": "tool", "tool": "r2_checksec", "args": {}}


def test_ollama_backend_ignores_tools_when_native_tools_config_is_off():
    # Sin native_tools (el default), OllamaBackend.chat() NUNCA debe mandar `tools` al
    # servidor ni aunque el llamador se lo pase -- confirma el opt-in a nivel de backend,
    # no solo a nivel del agent loop.
    from binoracle.config import load_config
    from binoracle.llm.ollama import OllamaBackend

    cfg = load_config()
    assert cfg.native_tools is False
    backend = OllamaBackend(cfg)
    captured = {}
    def _fake_post(path, payload, timeout):
        captured["payload"] = payload
        return {"message": {"content": "hola"}}
    backend._post = _fake_post
    out = backend.chat([], json_mode=True, tools=[{"type": "function", "function": {"name": "x"}}])
    assert "tools" not in captured["payload"]
    assert out == "hola"


def test_openai_compat_backend_converts_native_tool_call_to_portable_json():
    # Simetrico al test de OllamaBackend, para el otro backend real (llama.cpp server/vLLM/LM
    # Studio via la API estilo OpenAI): tool_calls -> el mismo texto JSON portable.
    import urllib.request
    from binoracle.agent.tools import extract_action
    from binoracle.config import load_config
    from binoracle.llm.openai_compat import OpenAICompatBackend

    cfg = load_config()
    cfg.native_tools = True
    backend = OpenAICompatBackend(cfg)
    captured = {}

    class _FakeResp:
        def __init__(self, body):
            self._body = body
        def read(self):
            import json as _json
            return _json.dumps(self._body).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=None):
        import json as _json
        captured["payload"] = _json.loads(req.data.decode("utf-8"))
        return _FakeResp({"choices": [{"message": {"tool_calls": [
            {"function": {"name": "r2_checksec", "arguments": "{}"}}
        ]}}]})

    orig = urllib.request.urlopen
    urllib.request.urlopen = _fake_urlopen
    try:
        out = backend.chat([], json_mode=True, tools=[{"type": "function",
                           "function": {"name": "r2_checksec", "description": "d",
                                       "parameters": {"type": "object", "properties": {}}}}])
    finally:
        urllib.request.urlopen = orig
    assert "tools" in captured["payload"]
    assert "response_format" not in captured["payload"]
    assert extract_action(out) == {"action": "tool", "tool": "r2_checksec", "args": {}}


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


def test_native_query_static_tools():
    # First-class static function-level tools over the shared r2 session: analyze a function, read
    # the call graph, resolve xrefs/address, and find a static call path. r2 DISASSEMBLES (never
    # runs the target); skip cleanly when r2/r2pipe or the sample is unavailable.
    import os
    import pytest
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        pytest.skip("sample ret2win no compilado (samples/build.sh)")
    from binoracle.oracles import r2session
    if r2session.get(binp) is None:
        pytest.skip("radare2/r2pipe no disponible")
    from binoracle.workflows.nativequery import (analyze_function, get_call_graph,
                                                 find_xrefs_to_name, address_name, call_path)
    af = analyze_function(binp, "main")
    assert af["ok"] and af["func"].endswith("main") and len(af["disasm"]) > 0
    g = get_call_graph(binp)
    assert g["ok"] and g["function_count"] > 0 and isinstance(g["edges"], list)
    x = find_xrefs_to_name(binp, "win")
    assert x["ok"] and x["xref_count"] >= 1
    an = address_name(binp, hex(af["addr"]))
    assert an["ok"] and (an["function"] or "").endswith("main")
    cp = call_path(binp, "main", "win")
    assert cp["ok"] and cp["reachable"] and cp["path"][0]["name"].endswith("main")
    from binoracle.workflows.nativequery import inspect_native_api, binary_overview
    api = inspect_native_api(binp)
    assert api["ok"] and api["import_count"] >= 1 and any("libc" in l for l in api["libraries"])
    ov = binary_overview(binp)
    assert ov["ok"] and ov["bits"] == 64 and ov["function_count"] > 0 and ov["section_count"] > 0
    from binoracle.workflows.nativequery import trace_feature
    tf = trace_feature(binp, "win")
    assert tf["ok"] and tf["hit_count"] >= 1
    assert any((f["name"] or "").endswith("win") for f in tf["functions"])


def test_web_bundle_imports_and_webmcp(tmp_path):
    # analyze_web_bundle (bundler + module estimate), trace_web_module_imports (external/relative/
    # dynamic edges), discover_webmcp_tools (WebMCP signals + candidate tool names). All static.
    import os
    from binoracle.workflows.jsinspect import (analyze_web_bundle, trace_web_module_imports,
                                               discover_webmcp_tools)
    (tmp_path / "app.bundle.js").write_text(
        "!function(e){function __webpack_require__(n){}webpackChunkapp=[];}();\n"
        "0:function(){};\n1:function(){};\n")
    b = analyze_web_bundle(str(tmp_path / "app.bundle.js"))
    assert b["ok"] and "webpack" in b["bundlers"] and b["is_bundle"]

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.js").write_text(
        "import x from 'react';\nconst y = require('./util');\nimport('./lazy');\n")
    ti = trace_web_module_imports(str(tmp_path))
    assert ti["ok"] and "react" in ti["packages"]
    kinds = {e["kind"] for e in ti["edges"]}
    assert {"external", "relative", "dynamic"} <= kinds

    (tmp_path / "mcp.js").write_text(
        "navigator.modelContext.registerTool({name:'search_files'});\n"
        "window.mcp = 1;\nregisterTool({name:'run_query'});\n")
    w = discover_webmcp_tools(str(tmp_path))
    assert w["ok"] and w["is_webmcp"]
    assert "search_files" in w["tool_names"] and "run_query" in w["tool_names"]
    assert "navigator.modelContext" in w["signals"]


def test_recover_javascript_sources(tmp_path):
    # Reconstruct the original source tree a bundle shipped in its .js.map (sourcesContent), with
    # path traversal neutralized so nothing escapes out_dir. Nothing executed.
    import json
    import os
    from binoracle.workflows.jsinspect import recover_js_sources, render_js_recover, _safe_rel
    assert _safe_rel("webpack://app/../../etc/passwd") == os.path.join("app", "etc", "passwd")
    assert _safe_rel("/abs/x.js") == os.path.join("abs", "x.js")
    mp = tmp_path / "bundle.js.map"
    mp.write_text(json.dumps({
        "version": 3,
        "sources": ["webpack://app/src/a.js", "webpack://app/../evil.js", "b.js"],
        "sourcesContent": ["console.log('a')", "EVIL", "export const b=1"]}))
    out = tmp_path / "recovered"
    r = recover_js_sources(str(mp), out_dir=str(out))
    assert r["ok"] and r["recovered"] == 3 and r["with_content"] == 3
    assert (out / "app" / "src" / "a.js").read_text() == "console.log('a')"
    # the "../evil.js" entry is contained under out_dir, never written outside it
    assert not (tmp_path / "evil.js").exists()
    assert "Recuperacion" in render_js_recover(r)
    # a map without sourcesContent yields nothing to recover, honestly
    mp2 = tmp_path / "nc.js.map"
    mp2.write_text(json.dumps({"version": 3, "sources": ["x.js"]}))
    assert recover_js_sources(str(mp2))["recovered"] == 0


def test_native_binary_session_lifecycle():
    # Stateful session over the cached r2 analysis: open -> handle resolves to the path and drives
    # the query tools -> analysis view -> close frees the handle. r2-gated skip.
    import os
    import pytest
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        pytest.skip("sample ret2win no compilado (samples/build.sh)")
    from binoracle.oracles import r2session
    if r2session.get(binp) is None:
        pytest.skip("radare2/r2pipe no disponible")
    from binoracle.workflows import nativesession as NS
    from binoracle.workflows.nativequery import analyze_function
    o = NS.open_binary(binp, label="demo")
    assert o["ok"] and o["warmed"] and o["session_id"].startswith("bin_")
    sid = o["session_id"]
    assert NS.resolve(sid) == os.path.abspath(binp)          # handle -> path
    assert analyze_function(NS.resolve(sid), "main")["ok"]    # query by handle
    v = NS.inspect_analysis_view(sid)
    assert v["ok"] and v["function_count"] > 0
    assert NS.binary_session(sid)["closed"] is False
    assert NS.close_binary(sid)["ok"] and NS.resolve(sid) is None   # closed -> no longer resolvable
    assert any(s["session_id"] == sid and s["closed"] for s in NS.list_binary_sessions()["sessions"])


def test_native_binary_session_bad_handle():
    from binoracle.workflows import nativesession as NS
    assert NS.open_binary("/nonexistent")["ok"] is False
    assert NS.inspect_analysis_view("bin_doesnotexist")["ok"] is False
    assert NS.close_binary("bin_doesnotexist")["ok"] is False


def test_native_query_degrades_without_r2(monkeypatch):
    # With no r2 session, every native-query tool degrades honestly (available False), never crashes.
    from binoracle.oracles import r2session
    from binoracle.workflows import nativequery
    monkeypatch.setattr(r2session, "get", lambda *a, **k: None)
    for fn, args in ((nativequery.analyze_function, ("x", "main")),
                     (nativequery.get_call_graph, ("x",)),
                     (nativequery.find_xrefs_to_name, ("x", "win")),
                     (nativequery.address_name, ("x", "0x1000")),
                     (nativequery.call_path, ("x", "main", "win")),
                     (nativequery.inspect_native_api, ("x",)),
                     (nativequery.binary_overview, ("x",))):
        r = fn(*args)
        assert r["ok"] is False and r["available"] is False and "radare2" in r["note"]


def test_android_query_over_decompiled_tree(tmp_path, monkeypatch):
    # Android class/method queries over a (seeded) JADX source tree: search, package listing, class
    # body + methods, and reference tracing. The JADX run itself is monkeypatched out so the query
    # logic is tested without the tool; the real tools degrade honestly when JADX is absent.
    import os
    from binoracle.workflows import androidquery as A
    root = tmp_path / "sources"
    (root / "com" / "app" / "net").mkdir(parents=True)
    (root / "com" / "app" / "MainActivity.java").write_text(
        "package com.app;\npublic class MainActivity {\n public void onCreate(){ Net.send(secretKey); }\n}\n")
    (root / "com" / "app" / "net" / "Net.java").write_text(
        "package com.app.net;\npublic class Net { public static void send(String s){} String secretKey; }\n")
    monkeypatch.setattr(A, "_decompile", lambda apk, timeout=240: (str(root), None))
    assert A.search_android_classes("x.apk", "Net")["classes"] == ["com.app.net.Net"]
    assert A.inspect_android_package("x.apk", "com.app.net")["classes"] == ["com.app.net.Net"]
    cl = A.inspect_android_class("x.apk", "com.app.MainActivity")
    assert cl["ok"] and "onCreate" in cl["methods"] and "class MainActivity" in cl["java"]
    refs = A.trace_android_references("x.apk", "secretKey")
    assert refs["ref_count"] == 2
    classes = {r["class"] for r in refs["references"]}
    assert "com.app.MainActivity" in classes and "com.app.net.Net" in classes


def test_android_method_extraction(tmp_path, monkeypatch):
    # inspect_android_method pulls one method's brace-matched body from the class Java (JADX stubbed).
    from binoracle.workflows import androidquery as A
    root = tmp_path / "sources"
    (root / "com" / "app").mkdir(parents=True)
    (root / "com" / "app" / "C.java").write_text(
        "package com.app;\nclass C {\n public void foo(){ if (x) { y(); } }\n int bar(){ return 1; }\n}\n")
    monkeypatch.setattr(A, "_decompile", lambda apk, timeout=240: (str(root), None))
    r = A.inspect_android_method("x.apk", "com.app.C", "foo")
    assert r["ok"] and r["method"] == "foo" and "if (x)" in r["body"] and "bar" not in r["body"]
    miss = A.inspect_android_method("x.apk", "com.app.C", "nope")
    assert miss["ok"] is False and "bar" in miss["methods_available"]


def test_android_manifest_graph_and_resources(tmp_path, monkeypatch):
    # Mobile application graph from a decoded AndroidManifest: components + exported flag + intent
    # actions. The manifest XML parsing is pure; apktool is stubbed via a seeded decode dir.
    from binoracle.workflows import androidmanifest as AM
    xml = ('<?xml version="1.0"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">\n'
           ' <uses-permission android:name="android.permission.INTERNET"/>\n'
           ' <application>\n'
           '  <activity android:name=".MainActivity">\n'
           '   <intent-filter><action android:name="android.intent.action.MAIN"/>'
           '<category android:name="android.intent.category.LAUNCHER"/></intent-filter>\n'
           '  </activity>\n'
           '  <service android:name="com.demo.Bg" android:exported="false"/>\n'
           ' </application>\n</manifest>\n')
    m = AM.parse_manifest_xml(xml)
    assert m["ok"] and m["package"] == "com.demo"
    comps = {c["name"]: c for c in m["components"]}
    assert comps[".MainActivity"]["exported"] is True
    assert "android.intent.action.MAIN" in comps[".MainActivity"]["actions"]
    assert comps["com.demo.Bg"]["exported"] is False

    out = tmp_path / "out"
    (out / "res" / "layout").mkdir(parents=True)
    (out / "res" / "layout" / "main.xml").write_text("<x/>")
    (out / "res" / "drawable").mkdir()
    (out / "res" / "drawable" / "ic.png").write_bytes(b"\x89PNG")
    (out / "AndroidManifest.xml").write_text(xml)
    monkeypatch.setattr(AM, "_apktool_decode", lambda apk, timeout=240: (str(out), None))
    g = AM.project_mobile_application_graph("x.apk")
    assert g["ok"] and g["component_count"] == 2 and g["exported_count"] == 1
    assert any(e["kind"] == "intent-action" and e["to"].endswith("MAIN") for e in g["edges"])
    res = AM.decode_android_resources("x.apk")
    assert res["ok"] and res["resource_total"] == 2 and res["resource_buckets"]["layout"] == 1


def test_android_manifest_degrades_without_apktool(monkeypatch):
    import os
    from binoracle.workflows import androidmanifest as AM
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        for fn in (AM.project_mobile_application_graph, AM.decode_android_resources):
            r = fn("x.apk")
            assert r["ok"] is False and r["available"] is False and "apktool" in r["note"]
    finally:
        os.environ["PATH"] = old


def test_android_query_degrades_without_jadx(monkeypatch):
    # With no jadx on PATH, every Android query tool degrades honestly (available False).
    import os
    from binoracle.workflows import androidquery as A
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent-empty-dir"
    try:
        for fn, a in ((A.search_android_classes, ("x.apk",)),
                      (A.inspect_android_class, ("x.apk", "C")),
                      (A.inspect_android_package, ("x.apk", "p")),
                      (A.trace_android_references, ("x.apk", "n"))):
            r = fn(*a)
            assert r["ok"] is False and r["available"] is False and "JADX" in r["note"]
    finally:
        os.environ["PATH"] = old


def test_android_audit_java_patterns_tagged_with_owasp_cwe(tmp_path):
    # _scan_java's findings must carry the real MASVS/MASWE + CWE IDs assigned to each pattern
    # (androidaudit._PATTERNS), not just a title/severity/recommendation.
    from binoracle.store.session import Finding
    from binoracle.workflows import androidaudit as AA
    root = tmp_path / "sources"
    (root / "com" / "app").mkdir(parents=True)
    (root / "com" / "app" / "Secrets.java").write_text(
        'package com.app;\nclass Secrets {\n'
        '  String apiKey = "sk_live_abcdef123456";\n'
        '  byte[] h = MessageDigest.getInstance("MD5").digest(x);\n'
        '}\n')
    findings = AA._scan_java(str(root), Finding)
    by_title = {f.title: f for f in findings}
    secret = next(f for f in findings if "secreto" in f.title.lower())
    assert secret.owasp == "MASWE-0004" and secret.cwe == "CWE-798"
    md5 = next(f for f in findings if "hash debil" in f.title.lower() or "MD5" in f.evidence)
    assert md5.owasp == "MASWE-0008" and md5.cwe == "CWE-328"
    assert len(by_title) == 2
    for f in findings:
        assert f.verdict == "grounded" and f.evidence and f.recommendation


def test_android_audit_manifest_flags_and_exported_tagged_with_owasp_cwe(tmp_path, monkeypatch):
    # Manifest flags (debuggable/allowBackup/usesCleartextTraffic) and the exported-components
    # finding must carry their assigned OWASP MASVS/MASWE + CWE IDs.
    from binoracle.store.session import Finding
    from binoracle.workflows import androidaudit as AA
    from binoracle.workflows import androidmanifest as AM
    xml = ('<?xml version="1.0"?>\n'
           '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">\n'
           ' <application android:debuggable="true" android:allowBackup="true"'
           ' android:usesCleartextTraffic="true">\n'
           '  <activity android:name=".MainActivity" android:exported="true">\n'
           '   <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>\n'
           '  </activity>\n'
           ' </application>\n</manifest>\n')
    out = tmp_path / "decoded"
    out.mkdir()
    (out / "AndroidManifest.xml").write_text(xml)
    monkeypatch.setattr(AM, "_apktool_decode", lambda apk, timeout=240: (str(out), None))
    findings, meta, limitation = AA._manifest_findings("x.apk", Finding)
    assert limitation is None and meta["package"] == "com.demo"
    tagged = {f.title: (f.owasp, f.cwe) for f in findings}
    debug_f = next(f for f in findings if "debuggable" in f.title)
    assert debug_f.owasp == "MASWE-0063" and debug_f.cwe == "CWE-489"
    backup_f = next(f for f in findings if "allowBackup" in f.title)
    assert backup_f.owasp == "MASWE-0006" and backup_f.cwe == "CWE-530"
    cleartext_f = next(f for f in findings if "usesCleartextTraffic" in f.title)
    assert cleartext_f.owasp == "MASWE-0026" and cleartext_f.cwe == "CWE-319"
    exported_f = next(f for f in findings if "exportado" in f.title)
    assert exported_f.owasp == "MASWE-0018" and exported_f.cwe == "CWE-926"
    assert len(tagged) == 4


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


def _build_libapp_fixture(snapshot_hash=b"a" * 32,
                          features=b"product no-causal_async_stacks x64-sysv"):
    # Minimal but REAL ELF64 .so: one PT_LOAD (identity VA=offset), a .dynsym/.dynstr carrying the
    # four _kDart*Snapshot* symbols, and a genuine Dart snapshot header (magic + length + 32-hex
    # version hash at +20 + null-terminated features string at +52) at the VM/Isolate data symbols.
    # Lets the reader exercise VA->offset mapping and snapshot-header parsing without a toolchain.
    import struct
    MAGIC = b"\xf5\xf5\xdc\xdc"
    snap = MAGIC + struct.pack("<q", 0x4000) + struct.pack("<q", 2) + snapshot_hash + features + b"\x00"
    SNAP_OFF, DYNSTR_OFF, DYNSYM_OFF, SH_OFF = 0x1000, 0x1800, 0x1900, 0x1c00
    names = [b"_kDartVmSnapshotData", b"_kDartIsolateSnapshotData",
             b"_kDartVmSnapshotInstructions", b"_kDartIsolateSnapshotInstructions"]
    dynstr = b"\x00"
    noff = {}
    for n in names:
        noff[n] = len(dynstr)
        dynstr += n + b"\x00"

    def sym(nameoff, val, size):
        return struct.pack("<IBBHQQ", nameoff, 0x12, 0, 1, val, size)
    dynsym = sym(0, 0, 0)
    dynsym += sym(noff[b"_kDartVmSnapshotData"], SNAP_OFF, len(snap))
    dynsym += sym(noff[b"_kDartIsolateSnapshotData"], SNAP_OFF, len(snap))
    dynsym += sym(noff[b"_kDartVmSnapshotInstructions"], SNAP_OFF + 0x100, 0x10)
    dynsym += sym(noff[b"_kDartIsolateSnapshotInstructions"], SNAP_OFF + 0x200, 0x10)
    shstr = b"\x00"
    shn = {}
    for s in (b".dynsym", b".dynstr", b".shstrtab"):
        shn[s] = len(shstr)
        shstr += s + b"\x00"
    SHSTR_OFF = SH_OFF + 4 * 64
    total = max(SHSTR_OFF + len(shstr), SNAP_OFF + len(snap),
                DYNSTR_OFF + len(dynstr), DYNSYM_OFF + len(dynsym))
    buf = bytearray(total + 16)
    hdr = struct.pack("<4sBBBBB7xHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0, 3, 0x3e, 1, 0,
                      0x40, SH_OFF, 0, 64, 56, 1, 64, 4, 3)
    buf[0:len(hdr)] = hdr
    buf[0x40:0x40 + 56] = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, len(buf), len(buf), 0x1000)
    buf[SNAP_OFF:SNAP_OFF + len(snap)] = snap
    buf[DYNSTR_OFF:DYNSTR_OFF + len(dynstr)] = dynstr
    buf[DYNSYM_OFF:DYNSYM_OFF + len(dynsym)] = dynsym
    buf[SHSTR_OFF:SHSTR_OFF + len(shstr)] = shstr

    def sh(name, typ, off, size, link, entsize):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, 0, off, size, link, 0, 0, entsize)
    sh_all = (sh(0, 0, 0, 0, 0, 0)
              + sh(shn[b".dynsym"], 11, DYNSYM_OFF, len(dynsym), 2, 24)
              + sh(shn[b".dynstr"], 3, DYNSTR_OFF, len(dynstr), 0, 0)
              + sh(shn[b".shstrtab"], 3, SHSTR_OFF, len(shstr), 0, 0))
    buf[SH_OFF:SH_OFF + len(sh_all)] = sh_all
    struct.pack_into("<H", buf, 0x3e, 3)
    return bytes(buf)


def test_dart_aot_deep_snapshot_parse(tmp_path):
    # Deep path: resolve the four AOT symbols from .dynsym, map the snapshot-data symbols through
    # PT_LOAD, parse the snapshot header, and decode the features string -> target arch + runtime mode.
    from binoracle.workflows.flutterinspect import inspect_dart_aot, inspect_flutter, render_dart_aot
    p = tmp_path / "libapp.so"
    p.write_bytes(_build_libapp_fixture())
    r = inspect_dart_aot(str(p))
    assert r["ok"] and r["is_dart_aot"]
    assert r["elf_arch"] == "x86-64" and r["elf_bits"] == 64
    assert r["dart_target_arch"] == "x64"          # decoded from the features string, not guessed
    assert r["dart_runtime_mode"] == "product"
    assert set(r["aot_snapshot_symbols"]) == {
        "_kDartVmSnapshotData", "_kDartIsolateSnapshotData",
        "_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions"}
    syms = {s["symbol"] for s in r["snapshots"]}
    assert "_kDartVmSnapshotData" in syms and "_kDartIsolateSnapshotData" in syms
    assert all(s["version_hash"] == "a" * 32 for s in r["snapshots"])
    assert all("x64-sysv" in (s["features"] or "") for s in r["snapshots"])
    assert "Dart AOT" in render_dart_aot(r)
    # identify_flutter_build surfaces the same decoded facts
    rf = inspect_flutter(str(p))
    assert rf["is_flutter"] and rf["dart_target_arch"] == "x64" and rf["dart_runtime_mode"] == "product"


def test_flutter_apk_engine_and_assets(tmp_path):
    # inspect_flutter on an APK surfaces the libflutter.so engine fingerprint (build-id revision,
    # labeled Dart version line, render backend, graphics APIs, toolchain) AND the flutter_assets
    # bundle (build type, AssetManifest, FontManifest, shaders/NOTICES, version.json). All static.
    import json
    import struct
    import zipfile
    from binoracle.workflows.flutterinspect import inspect_flutter, render_flutter
    libapp = _build_libapp_fixture()
    note = struct.pack("<III", 4, 16, 3) + b"GNU\x00" + bytes(range(16))   # .note.gnu.build-id
    engine = (libapp + note
              + b"\x00Dart VM version: 3.4.1 (stable) on android_arm64\x00"
              + b"\x00Impeller\x00vkCreateInstance\x00glGetString\x00"
              + b"Android (12345 based on r487747) clang version 17\x00")
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libapp.so", libapp)
        z.writestr("lib/arm64-v8a/libflutter.so", engine)
        z.writestr("assets/flutter_assets/AssetManifest.json",
                   json.dumps({"assets/a.png": ["assets/a.png"], "assets/b.json": ["assets/b.json"]}))
        z.writestr("assets/flutter_assets/FontManifest.json",
                   json.dumps([{"family": "Roboto", "fonts": [{"asset": "fonts/Roboto.ttf"}]}]))
        z.writestr("assets/flutter_assets/NOTICES.Z", b"\x78\x9c\x03\x00\x00\x00\x00\x01")
        z.writestr("assets/flutter_assets/shaders/ink_sparkle.frag", b"\x00")
        z.writestr("assets/flutter_assets/version.json",
                   json.dumps({"app_name": "demo", "version": "1.2.3",
                               "build_number": "45", "package_name": "com.demo"}))
    r = inspect_flutter(str(apk))
    assert r["is_flutter"] and r["abis"] == ["arm64-v8a"]
    eng = r["engine"]
    assert eng and eng["build_id"] == "000102030405060708090a0b0c0d0e0f"
    assert eng["dart_version_line"].startswith("Dart VM version: 3.4.1")
    assert "Impeller" in eng["render_backends"]
    assert "Vulkan" in eng["graphics_apis"] and "OpenGL ES" in eng["graphics_apis"]
    assert eng["toolchain"] and "clang" in eng["toolchain"][0]
    a = r["flutter_assets"]
    assert a and a["asset_manifest_format"] == "json" and a["declared_assets"] == 2
    assert a["font_families"] == ["Roboto"] and a["has_shaders"] and a["has_notices"]
    assert a["version_json"]["package_name"] == "com.demo"
    assert a["build_type"].startswith("AOT")
    assert "flutter_assets" in render_flutter(r) and "Impeller" in render_flutter(r)


def test_standard_message_codec_decoder():
    # Decode Flutter's StandardMessageCodec from HAND-ENCODED bytes (independent of any encoder):
    # buffer-relative Float64 alignment, the varint size (>=254 -> uint16), nested list/map, and the
    # modern AssetManifest.bin shape Map<String, List<Map<String,Object>>> with {asset,dpr} variants.
    import struct
    from binoracle.workflows.flutterinspect import decode_standard_message, _parse_asset_manifest_bin

    # Float64 2.0: type byte at offset 0, 7 pad bytes, then the double at offset 8 (8-aligned).
    assert decode_standard_message(b"\x06" + b"\x00" * 7 + struct.pack("<d", 2.0)) == 2.0

    def S(x):
        x = x.encode()
        return bytes([7, len(x)]) + x

    def L(items):
        return bytes([12, len(items)]) + b"".join(items)

    def M(pairs):
        body = b"".join(k + v for k, v in pairs)
        return bytes([13, len(pairs)]) + body

    # size varint over 253 -> 254 + uint16
    big = "x" * 300
    assert decode_standard_message(bytes([7, 254]) + struct.pack("<H", 300) + big.encode()) == big

    # a realistic manifest: {"a.png": [], "img/b.png": [{"asset":"img/2.0x/b.png"}]}
    manifest = M([
        (S("a.png"), L([])),
        (S("img/b.png"), L([M([(S("asset"), S("img/2.0x/b.png"))])])),
    ])
    v = decode_standard_message(manifest)
    assert v["a.png"] == [] and v["img/b.png"][0]["asset"] == "img/2.0x/b.png"
    summ = _parse_asset_manifest_bin(manifest)
    assert summ["decoded"] and summ["declared_assets"] == 2 and summ["variant_count"] == 1
    assert "img/b.png" in summ["assets"]


def test_flutter_apk_assetmanifest_bin(tmp_path):
    # inspect_flutter decodes a real AssetManifest.bin (StandardMessageCodec) inside an APK and
    # reports the declared assets + variant count, not just "binary; not decoded".
    import zipfile
    from binoracle.workflows.flutterinspect import inspect_flutter

    def S(x):
        x = x.encode()
        return bytes([7, len(x)]) + x

    def L(items):
        return bytes([12, len(items)]) + b"".join(items)

    def M(pairs):
        return bytes([13, len(pairs)]) + b"".join(k + v for k, v in pairs)
    manifest = M([(S("assets/logo.png"), L([S("assets/logo.png")])),
                  (S("assets/data.json"), L([S("assets/data.json")]))])
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/flutter_assets/AssetManifest.bin", manifest)
        z.writestr("assets/flutter_assets/libapp_marker", b"x")
    r = inspect_flutter(str(apk))
    a = r["flutter_assets"]
    assert a["asset_manifest_format"].startswith("bin (StandardMessageCodec)")
    assert a["declared_assets"] == 2 and a["manifest_variants"] == 2
    assert "assets/logo.png" in a["manifest_assets"]


def test_flutter_apk_debug_kernel_build(tmp_path):
    # A debug/JIT APK ships kernel_blob.bin in flutter_assets and (often) no libapp.so; the reader
    # must label it debug/JIT from that marker, not misreport it as AOT.
    import zipfile
    from binoracle.workflows.flutterinspect import inspect_flutter
    apk = tmp_path / "debug.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("assets/flutter_assets/kernel_blob.bin", b"\x90\x0b\xf0\x00" + b"\x00" * 64)
        z.writestr("assets/flutter_assets/AssetManifest.bin", b"\x00\x01\x02")
    r = inspect_flutter(str(apk))
    assert r["is_flutter"] is True
    a = r["flutter_assets"]
    assert a["has_kernel_blob"] and "debug/JIT" in a["build_type"]
    assert a["asset_manifest_format"].startswith("bin")


def test_dart_aot_release_build_version_capped(tmp_path):
    # A release snapshot with no "product/profile" token and no "Dart VM version:" label must report
    # the absence honestly (dart_version_capped) rather than inventing a mode/version.
    from binoracle.workflows.flutterinspect import inspect_dart_aot
    p = tmp_path / "libapp.so"
    p.write_bytes(_build_libapp_fixture(features=b"arm64-sysv no-causal_async_stacks"))
    r = inspect_dart_aot(str(p))
    assert r["is_dart_aot"] and r["dart_target_arch"] == "arm64"
    assert r["dart_runtime_mode"] == "release/jit"
    assert r["dart_vm_version"] is None and r["dart_version_capped"] is True


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


def test_autosrop_aarch64_applicability_and_honesty():
    # SROP aarch64: on a non-aarch64 binary it must say NOT applicable and never claim a shell. If an
    # aarch64 sample exists AND an aarch64 runtime is present, it verifies a shell; otherwise it
    # degrades honestly (built, not executable here) -- a false positive is never allowed.
    import os
    from binoracle.workflows.autosrop_aarch64 import autosrop_aarch64, render_srop_aarch64
    # non-aarch64 input -> not applicable, not verified
    if os.path.exists("samples/bin/ret2win"):
        r = autosrop_aarch64("samples/bin/ret2win")
        assert r.get("verified") is not True and "no aplica" in (r.get("note") or "")
        assert "SROP aarch64" in render_srop_aarch64(r)
    # aarch64 sample (only where the cross-toolchain built it): verify or honest degrade, never false
    binp = "samples/bin/srop_aarch64"
    if os.path.exists(binp):
        r2 = autosrop_aarch64(binp)
        if r2.get("verified"):
            assert "tramp=" in (r2.get("detail") or "")
        else:
            assert "no verificado" in (r2.get("note") or "")


def test_autohomind_verifies():
    # Verificacion POSITIVA de house-of-mind por EJECUCION: free() toma la arena de
    # heap_for_ptr(p)->ar_ptr; con ar_ptr falso, arena->fastbinsY[idx]=&chunk escribe en &hom_slot
    # -> se llama al puntero de funcion del chunk (win) -> shell. Reproduce la seleccion de arena.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/homind"
    if not os.path.exists(binp):
        pytest.skip("sample homind no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autohomind import autohomind
    r = autohomind(binp)
    assert r.get("ok") and r.get("verified"), f"house-of-mind no verificado: {r.get('note')}"
    assert "ar_ptr=" in (r.get("detail") or "")


def test_autoiofile_verifies_fsop():
    # Verificacion POSITIVA de IO_FILE/FSOP por EJECUCION: se reapunta fp->vtable a una vtable falsa
    # cuyo slot __overflow (vtable+0x18) = win; la operacion de flujo lo invoca -> shell. Reproduce
    # la llamada vtable[__overflow](fp) (glibc moderno chequea la vtable; por eso se reproduce).
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/iofile"
    if not os.path.exists(binp):
        pytest.skip("sample iofile no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autoiofile import autoiofile
    r = autoiofile(binp)
    assert r.get("ok") and r.get("verified"), f"FSOP no verificado: {r.get('note')}"
    assert "fake_vtable=" in (r.get("detail") or "")


def test_autofastbindup_verifies():
    # Verificacion POSITIVA de fastbin-dup clasico por EJECUCION: el doble-free A,B,A esquiva el
    # chequeo debil ==fasttop; se envenena fd hacia un chunk falso (con size valido) y una alloc
    # posterior devuelve &hslot.fn -> se escribe win -> shell. Reproduce el fastbin pre-2.32.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/fastbindup"
    if not os.path.exists(binp):
        pytest.skip("sample fastbindup no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autofastbindup import autofastbindup
    r = autofastbindup(binp)
    assert r.get("ok") and r.get("verified"), f"fastbin-dup no verificado: {r.get('note')}"
    assert "hslot=" in (r.get("detail") or "")


def test_autounsafeunlink_verifies():
    # Verificacion POSITIVA de unsafe-unlink por EJECUCION: fd=&ptr-0x18 y bk=&ptr-0x10 satisfacen el
    # chequeo 2.3.4+ (FD->bk==P && BK->fd==P) y unlink deja ptr=&ptr-0x18; editando a traves de ptr se
    # redirige ptr a &handler y se escribe win -> shell. El sample reproduce la escritura de unlink +
    # el chequeo de consistencia.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/unsafeunlink"
    if not os.path.exists(binp):
        pytest.skip("sample unsafeunlink no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autounsafeunlink import autounsafeunlink
    r = autounsafeunlink(binp)
    assert r.get("ok") and r.get("verified"), f"unsafe-unlink no verificado: {r.get('note')}"
    assert "chunkptr=" in (r.get("detail") or "")


def test_autohoc_verifies_house_of_corrosion():
    # Verificacion POSITIVA de house-of-corrosion por EJECUCION: al corromper global_max_fast a un
    # valor enorme, free() trata un chunk grande como fastbin e indexa fastbinsY[(size-0x20)>>4] sin
    # cota; un `size` elegido hace que ese indice alias &hook_slot.target y la insercion escribe
    # &chunk ahi -> se llama al puntero de funcion del chunk (win) -> shell. glibc real encadena
    # hacia _IO_list_all/stdout; el sample reproduce la escritura de indice de fastbin sin cota.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/hoc"
    if not os.path.exists(binp):
        pytest.skip("sample hoc no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autohoc import autohoc
    r = autohoc(binp)
    assert r.get("ok") and r.get("verified"), f"house-of-corrosion no verificado: {r.get('note')}"
    assert "idx=" in (r.get("detail") or "")


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


def test_heap_families_as_verified_chains():
    # The dedicated heap verifiers are exposed as CHAINS in the chain-analyzer graph and, with
    # verify=True, run in the sandbox. Each sample's own family appears as a chain and verifies.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    cases = [("samples/bin/hos", "house-of-spirit"),
             ("samples/bin/largebin", "largebin attack"),
             ("samples/bin/stash", "tcache stashing unlink"),
             ("samples/bin/hoc", "house-of-corrosion"),
             ("samples/bin/unsafeunlink", "unsafe-unlink"),
             ("samples/bin/fastbindup", "fastbin-dup"),
             ("samples/bin/homind", "house-of-mind"),
             ("samples/bin/iofile", "IO_FILE/FSOP")]
    ran = 0
    from binoracle.workflows.chainanalyzer import analyze_chains
    for binp, chain_name in cases:
        if not os.path.exists(binp):
            continue
        ok, _why = native_available(binp)
        if not ok:
            continue
        an = analyze_chains(binp, verify=True)
        match = [c for c in an.chains if c.name == chain_name]
        assert match, f"{chain_name} no aparece como cadena para {binp}"
        assert any(c.verified for c in match), f"{chain_name} no verificada en {binp}"
        # a verified chain carries its proof strategy
        vc = next(c for c in match if c.verified)
        assert vc.proof.get("strategy")
        ran += 1
    if ran == 0:
        pytest.skip("sin samples de heap o sandbox no disponible")


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


def test_autoropmprotect_verifies_nx_bypass():
    # Verificacion POSITIVA del tercer sub-item de "[M] ROP builder v2" (ROADMAP) por EJECUCION:
    # mprotectshell.c hace un primer read() que deja shellcode en un buffer .bss fijo conocido
    # (shellbuf, sin leak -- no-PIE), y un segundo read() desborda la pila con una cadena ROP que
    # llama a mprotect(shellbuf, 0x1000, RWX) y salta al buffer -- el shellcode real corre y abre
    # una shell. Prueba que pwntools encontro los gadgets para fijar rdi/rsi/rdx (incluido el
    # "pop rdx; ret" deliberadamente incluido en el fixture) y que el barrido de offset/padding
    # dio con el layout real del frame.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/mprotectshell"
    if not os.path.exists(binp):
        pytest.skip("sample mprotectshell no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autoropmprotect import autoropmprotect
    r = autoropmprotect(binp)
    assert r.get("ok") and r.get("verified"), f"mprotect()+shellcode no verificado: {r.get('note')}"
    assert "mprotect=" in (r.get("detail") or "")
    assert "stage=" in (r.get("detail") or "")


def test_autoropmprotect_degrades_cleanly_without_mprotect_symbol():
    # Control negativo: ret2win no referencia mprotect() -- el simbolo no es resoluble, asi que
    # no debe inventarse un primitivo; NOT_APPLICABLE honesto, no un falso "verified".
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        pytest.skip("sample ret2win no compilado")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autoropmprotect import autoropmprotect
    r = autoropmprotect(binp)
    assert r.get("ok")
    assert r.get("verified") is False
    assert "NOT_APPLICABLE" in (r.get("output") or "")


def test_autoleakchain_verifies_leak_informed_hijack():
    # Verificacion POSITIVA de "[M] Automatic infoleak chaining" (ROADMAP) por EJECUCION:
    # leakchain.c tiene UN solo bug (table[idx] sin cota) usado dos veces en la MISMA
    # ejecucion -- como OOB READ filtra un puntero libc YA resuelto (printf_leak, cuyo valor
    # real depende del build de libc y NUNCA se asume de antemano) y como OOB WRITE hijacka un
    # function-pointer con system() calculado a partir de ESE leak. Prueba que el oraculo
    # compuso ambos pasos en una sola cadena -- no dos hallazgos sueltos que un humano tendria
    # que unir a mano -- y que la shell final es real.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/leakchain"
    if not os.path.exists(binp):
        pytest.skip("sample leakchain no compilado (samples/build.sh)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autoleakchain import autoleakchain
    r = autoleakchain(binp)
    assert r.get("ok") and r.get("verified"), f"infoleak chaining no verificado: {r.get('note')}"
    assert "leak_fn=printf" in (r.get("detail") or "")
    assert "system=" in (r.get("detail") or "")


def test_autoleakchain_degrades_cleanly_without_known_symbols():
    # Control negativo: ret2win no tiene table/<fn>_leak/callback -- no debe inventarse una
    # cadena; NOT_APPLICABLE honesto, nunca un falso "verified".
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/ret2win"
    if not os.path.exists(binp):
        pytest.skip("sample ret2win no compilado")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox no disponible: {why}")
    from binoracle.workflows.autoleakchain import autoleakchain
    r = autoleakchain(binp)
    assert r.get("ok")
    assert r.get("verified") is False
    assert "NOT_APPLICABLE" in (r.get("output") or "")


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


def test_process_capture_normalizes_and_diffs():
    # Captura de escenario de proceso (runtime): la NORMALIZACION hace que dos corridas con el mismo
    # argv pero salida no determinista (PID) comparen IGUAL; un cambio real de exit_code se detecta.
    import shutil
    import pytest
    if shutil.which("sh") is None:
        pytest.skip("sin /bin/sh")
    from binoracle.workflows.proccapture import capture_process, compare_captures
    a = capture_process(["sh", "-c", "echo run pid=$$"])
    b = capture_process(["sh", "-c", "echo run pid=$$"])
    assert a["ok"] and b["ok"]
    cmp = compare_captures(a["scenario"], b["scenario"])
    assert cmp["identical"] is True and cmp["stdout_diff"] == []
    # un cambio de comportamiento real (exit code) se reporta y rompe la identidad
    c = capture_process(["sh", "-c", "exit 3"])
    d = capture_process(["sh", "-c", "exit 0"])
    cmp2 = compare_captures(c["scenario"], d["scenario"])
    assert cmp2["identical"] is False
    assert any("exit_code: 3 -> 0" in ch for ch in cmp2["behavior_changes"])


def test_managed_compare_verify_boundaries(monkeypatch):
    # Managed (.NET) member comparison + reconstruction verification + native-boundary surface,
    # grounded on the CLI metadata reader (stubbed here so the logic is tested without a .NET sample).
    from binoracle.workflows import managedquery as M

    facts = {
        "orig.dll": {"ok": True, "is_dotnet": True, "runtime_version": "4.0",
                     "tables": {"TypeDef": 10, "MethodDef": 40, "ImplMap": 2},
                     "string_names": ["Foo", "Bar", "Baz", "send", "kernel32.dll"]},
        "recon.dll": {"ok": True, "is_dotnet": True, "runtime_version": "4.0",
                      "tables": {"TypeDef": 10, "MethodDef": 39, "ImplMap": 2},
                      "string_names": ["Foo", "Bar", "send", "kernel32.dll"]},  # missing Baz
    }
    monkeypatch.setattr(M, "inspect_dotnet", lambda p: facts[p])

    c = M.compare_managed_members("orig.dll", "recon.dll")
    assert c["ok"] and c["removed"] == ["Baz"] and c["table_delta"]["MethodDef"] == [40, 39]

    v = M.verify_reconstruction("orig.dll", "recon.dll", threshold=0.9)
    assert v["ok"] and v["verified"] is False and "Baz" in v["missing_members"]
    v2 = M.verify_reconstruction("orig.dll", "recon.dll", threshold=0.8)
    assert v2["verified"] is True        # 83% coverage clears a 0.8 obligation

    nb = M.verify_managed_native_boundaries("orig.dll")
    assert nb["pinvoke_implmap_rows"] == 2 and "kernel32.dll" in nb["native_libraries"]


def _build_dotnet_metadata():
    # Hand-build a minimal CLI metadata root (BSJB) with #Strings + #~ tables Module/TypeRef/TypeDef,
    # so the token-level type-graph parser can be tested without a real .NET assembly or pefile.
    import struct
    strings = bytearray(b"\x00")
    offs = {}

    def addn(s):
        offs[s] = len(strings)
        strings.extend(s.encode() + b"\x00")
    for n in ("App", "Foo", "Bar", "Base", "Sys", "Mod"):
        addn(n)
    valid = (1 << 0) | (1 << 1) | (1 << 2)                 # Module, TypeRef, TypeDef present
    hdr = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    counts = struct.pack("<III", 1, 1, 2)
    mod = struct.pack("<HHHHH", 0, offs["Mod"], 0, 0, 0)
    tref = struct.pack("<HHH", 0, offs["Base"], offs["Sys"])          # ResolutionScope null
    td1 = struct.pack("<IHHHHH", 0, offs["Foo"], offs["App"], 5, 1, 1)  # extends TypeRef#1 (Base)
    td2 = struct.pack("<IHHHHH", 0, offs["Bar"], offs["App"], 4, 1, 1)  # extends TypeDef#1 (Foo)
    tstream = hdr + counts + mod + tref + td1 + td2
    ver = b"v4.0.30319\x00"
    ver += b"\x00" * ((4 - len(ver) % 4) % 4)

    def sh(offset, size, name):
        nb = name.encode() + b"\x00"
        nb += b"\x00" * ((4 - len(nb) % 4) % 4)
        return struct.pack("<II", offset, size) + nb
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(ver)) + ver + struct.pack("<HH", 0, 2)
    header_len = len(root) + len(sh(0, 0, "#Strings")) + len(sh(0, 0, "#~"))
    str_off = header_len
    ts_off = str_off + len(strings)
    return (root + sh(str_off, len(strings), "#Strings") + sh(ts_off, len(tstream), "#~")
            + bytes(strings) + tstream)


def test_dotnet_type_graph_by_token():
    # Parse the CLI metadata tables and resolve TypeDef/TypeRef Extends tokens into a type graph.
    from binoracle.workflows.dotnetgraph import build_graph_from_metadata, render_type_graph
    g = build_graph_from_metadata(_build_dotnet_metadata())
    assert g["typedef_count"] == 2 and g["typeref_count"] == 1
    assert g["types"] == ["App.Foo", "App.Bar"] and g["external_types"] == ["Sys.Base"]
    edges = {(e["from"], e["kind"], e["to"], e["external"]) for e in g["edges"]}
    assert ("App.Foo", "extends", "Sys.Base", True) in edges       # resolved to the external TypeRef
    assert ("App.Bar", "extends", "App.Foo", False) in edges        # resolved to the internal TypeDef
    assert "Grafo de tipos" in render_type_graph({**g, "ok": True})


def test_dotnet_type_graph_non_dotnet_degrades():
    from binoracle.workflows.dotnetgraph import project_type_graph
    r = project_type_graph("/nonexistent.dll")
    assert r["ok"] is False and r.get("note")


def test_dotnet_cil_call_graph_by_token():
    # Decode CIL method bodies and resolve call tokens: App.Foo::DoA calls the internal MethodDef
    # App.Bar::DoB and the external MemberRef Sys.Console::WriteLine. Metadata + IL are hand-built.
    import struct
    from binoracle.workflows.dotnetgraph import _Tables, build_call_graph, render_call_graph
    strings = bytearray(b"\x00")
    o = {}

    def addn(s):
        o[s] = len(strings)
        strings.extend(s.encode() + b"\x00")
    for s in ("App", "Foo", "Bar", "Sys", "Console", "DoA", "DoB", "WriteLine"):
        addn(s)
    valid = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 6) | (1 << 10)
    hdr = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    counts = struct.pack("<IIIII", 1, 1, 2, 2, 1)
    mod = struct.pack("<HHHHH", 0, o["App"], 0, 0, 0)
    tref = struct.pack("<HHH", 0, o["Console"], o["Sys"])
    td1 = struct.pack("<IHHHHH", 0, o["Foo"], o["App"], 0, 1, 1)   # MethodList=1
    td2 = struct.pack("<IHHHHH", 0, o["Bar"], o["App"], 0, 1, 2)   # MethodList=2
    md1 = struct.pack("<IHHHHH", 0x100, 0, 0, o["DoA"], 0, 1)
    md2 = struct.pack("<IHHHHH", 0x200, 0, 0, o["DoB"], 0, 1)
    mr1 = struct.pack("<HHH", 9, o["WriteLine"], 0)               # parent = TypeRef#1 ((1<<3)|1)
    tstream = hdr + counts + mod + tref + td1 + td2 + md1 + md2 + mr1
    ver = b"v4.0\x00"
    ver += b"\x00" * ((4 - len(ver) % 4) % 4)

    def sh(off, size, name):
        nb = name.encode() + b"\x00"
        nb += b"\x00" * ((4 - len(nb) % 4) % 4)
        return struct.pack("<II", off, size) + nb
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(ver)) + ver + struct.pack("<HH", 0, 2)
    hl = len(root) + len(sh(0, 0, "#Strings")) + len(sh(0, 0, "#~"))
    so = hl
    to = so + len(strings)
    md = root + sh(so, len(strings), "#Strings") + sh(to, len(tstream), "#~") + bytes(strings) + tstream

    tables = _Tables(md)
    il = bytes([0x28, 0x02, 0x00, 0x00, 0x06, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A])
    bodies = {0x100: bytes([(len(il) << 2) | 2]) + il, 0x200: bytes([(1 << 2) | 2, 0x2A])}
    g = build_call_graph(tables, lambda rva: bodies.get(rva))
    assert g["method_count"] == 2 and g["scanned_methods"] == 2
    e = {(x["from"], x["to"], x["external"]) for x in g["edges"]}
    assert ("App.Foo::DoA", "App.Bar::DoB", False) in e
    assert ("App.Foo::DoA", "Sys.Console::WriteLine", True) in e
    assert "Grafo de llamadas" in render_call_graph({**g, "ok": True})


def test_managed_non_dotnet_degrades(monkeypatch):
    # A non-.NET input degrades honestly rather than inventing members.
    from binoracle.workflows import managedquery as M
    monkeypatch.setattr(M, "inspect_dotnet",
                        lambda p: {"ok": True, "is_dotnet": False, "note": "PE nativo"})
    r = M.verify_managed_native_boundaries("x.exe")
    assert r["ok"] is False and "nativo" in (r.get("note") or "")


def test_find_changed_behavior_and_correlate(tmp_path):
    # find_changed_behavior: two scripts with different observable output -> changed; identical ->
    # not changed. correlate_static_and_runtime: a caller marker that appears at runtime is reported.
    import os
    import shutil
    import stat
    import pytest
    if shutil.which("sh") is None:
        pytest.skip("sin /bin/sh")
    from binoracle.workflows.proccapture import find_changed_behavior, correlate_static_and_runtime

    def script(name, body):
        p = tmp_path / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)
        return str(p)
    a = script("a.sh", "echo ALPHA; exit 0")
    b = script("b.sh", "echo BETA; exit 7")
    same = script("same.sh", "echo ALPHA; exit 0")

    r = find_changed_behavior(a, b)
    assert r["ok"] and r["changed"] is True
    assert any("exit_code" in c for c in r["behavior_changes"])
    r2 = find_changed_behavior(a, same)
    assert r2["ok"] and r2["changed"] is False

    cor = correlate_static_and_runtime(a, markers=["ALPHA", "NOTPRESENT"])
    assert cor["ok"]
    names = {h["name"] for h in cor["correlations"]}
    assert "ALPHA" in names and "NOTPRESENT" not in names


def test_evidence_ledger_obligation_and_bundle(tmp_path):
    # El ledger solo cierra una incognita cuando una evidencia ALCANZA su obligacion
    # (authority+confidence); exporta/importa bundles sellados y rechaza los alterados.
    import json
    import os
    from binoracle.workflows import ledger as L
    lp = str(tmp_path / "led.json")
    u = L.record_unknown("branch X needs external svc?", severity="high", domain="protocol",
                         required_authority="controlled-replay", required_confidence="reproduced", ledger=lp)
    uid = u["unknown"]["id"]
    assert u["ok"] and u["unknown"]["revision"] == 1 and u["unknown"]["status"] == "open"
    # nada -> sigue abierta
    assert L.verify_unknown_resolution(uid, ledger=lp)["verified"] is False
    # evidencia debil no basta
    ew = L.add_evidence("static hint", authority="static-only", confidence="observed", ledger=lp)["evidence"]["id"]
    L.update_unknown(uid, supporting_evidence_ids=[ew], resolution="needs replay", ledger=lp)
    assert L.verify_unknown_resolution(uid, ledger=lp)["verified"] is False
    # evidencia fuerte cumple la obligacion
    es = L.add_evidence("replayed branch", authority="controlled-replay",
                        confidence="reproduced", ledger=lp)["evidence"]["id"]
    rev = L.list_unknowns(ledger=lp)["unknowns"][0]["revision"]
    L.update_unknown(uid, expected_revision=rev, supporting_evidence_ids=[ew, es], ledger=lp)
    v = L.verify_unknown_resolution(uid, ledger=lp)
    assert v["verified"] is True and v["status"] == "resolved"
    # concurrencia optimista: una revision caduca falla
    assert L.update_unknown(uid, expected_revision=1, status="open", ledger=lp)["ok"] is False
    # bundle sellado round-trip + deteccion de alteracion
    bp = str(tmp_path / "bundle.json")
    exp = L.export_evidence_bundle(bp, ledger=lp)
    assert exp["ok"] and exp["digest"].startswith("sha256:")
    imp = L.import_evidence_bundle(bp, ledger=str(tmp_path / "led2.json"))
    assert imp["ok"] and imp["unknown_count"] == 1 and imp["evidence_count"] == 2
    b = json.load(open(bp))
    b["payload"]["unknowns"][uid]["severity"] = "low"
    json.dump(b, open(bp, "w"))
    assert L.import_evidence_bundle(bp, ledger=str(tmp_path / "led3.json"))["ok"] is False


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
    # Bug real encontrado en vivo (pytest-timeout lo atrapo con -300s de limite): la version
    # anterior usaba glob.glob(root/**/*.dll, recursive=True), que recorre el arbol COMPLETO de
    # /usr (y /opt) antes de aplicar el [:50] -- el slice llega demasiado tarde para acotar nada.
    # En un contenedor con /usr lleno (paquetes de Python, docs, locales, r2/angr/docker...) ese
    # recorrido puede tardar minutos o mas; en una suite sin timeout por test, se traga la suite
    # entera en silencio. Ahora para en cuanto encuentra un PE real (es lo unico que necesita:
    # UN candidato para probar inspect_pe contra algo real), con os.walk acotado por numero de
    # directorios visitados en vez de un glob recursivo sin limite.
    import os
    import pytest
    from binoracle.workflows.peinspect import inspect_pe, render_pe
    pe = None
    MAX_DIRS = 4000   # tope duro de directorios visitados, no de resultados: para de verdad
    for root in ("/usr", "/opt"):
        if not os.path.isdir(root):
            continue
        visited = 0
        for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda e: None):
            visited += 1
            if visited > MAX_DIRS:
                break
            for fn in filenames:
                if not fn.lower().endswith((".dll", ".exe")):
                    continue
                r = inspect_pe(os.path.join(dirpath, fn))
                if r.get("is_pe"):
                    pe = r
                    break
            if pe is not None:
                break
        if pe is not None:
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


def test_autodlresolve_verifies_32bit():
    # Verificacion POSITIVA de ret2dlresolve en 32-bit (i386, cdecl): forja Elf32_Rel+Elf32_Sym y
    # llama al stub del resolver -> system('/bin/sh'), sin leak. Auto-salta sin multilib o sandbox.
    import os
    import pytest
    from binoracle.workflows._sandbox import native_available
    binp = "samples/bin/dlresolve32"
    if not os.path.exists(binp):
        pytest.skip("sample dlresolve32 no compilado (sin multilib i386)")
    ok, why = native_available(binp)
    if not ok:
        pytest.skip(f"sandbox nativo no disponible: {why}")
    from binoracle.workflows.autodlresolve import autodlresolve
    r = autodlresolve(binp)
    assert r.get("ok") and r.get("verified"), f"ret2dlresolve 32-bit no verificado: {r.get('note')}"
    assert "bits=32" in (r.get("detail") or "")


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


def test_funcid_render_no_crash():
    from binoracle.workflows.funcid import FuncIdResult, FuncMatch, render_funcid
    r = FuncIdResult(ok=True, note="1 funcion recuperada", stripped="s", reference="r",
                     matches=[FuncMatch(addr=0x1209, size=37, stripped_name="fcn.00001209",
                                        recovered_name="sym.win", confidence="exact-calls", score=1.0)])
    out = render_funcid(r)
    assert "sym.win" in out and "fcn.00001209" in out and "ALTA" in out
    assert "No disponible" in render_funcid(FuncIdResult(ok=False, note="radare2 no esta instalado"))


def test_funcid_recovers_win_across_optimization_levels():
    # "[M] Stripped-binary function ID" del ROADMAP v0.4: recupera el nombre de una funcion en
    # un binario STRIPPED comparando su firma de llamadas (import calls resueltas via .dynsym,
    # que sobrevive a `strip`) contra un binario de referencia NOMBRADO -- no un no-op de
    # comparar un binario contra su propia copia stripped (eso emparejaria trivialmente por
    # direccion/tamanio). Aqui el target es la MISMA fuente recompilada a -O1 y luego stripped:
    # win() cambia de prologo/epilogo por completo (gana endbr64, pierde push/pop rbp) pero su
    # firma de llamadas (puts, system) debe seguir matcheando EXACTO y sin ambiguedad.
    import os
    import shutil
    import subprocess
    import pytest
    from binoracle.workflows.funcid import r2_available, identify_stripped_functions
    ref, src = "samples/bin/ret2win", "samples/src/ret2win.c"
    if not os.path.exists(ref) or not os.path.exists(src):
        pytest.skip("sample ret2win/fuente no disponibles (samples/build.sh)")
    if not r2_available():
        pytest.skip("radare2 no disponible (apt install radare2)")
    if not shutil.which("gcc") or not shutil.which("strip"):
        pytest.skip("gcc/strip no disponibles")

    o1 = "/tmp/binoracle_test_ret2win_O1"
    o1_stripped = o1 + "_stripped"
    try:
        subprocess.run(["gcc", "-O1", "-o", o1, src], capture_output=True, timeout=60)
        if not os.path.exists(o1):
            pytest.skip("no se pudo compilar ret2win a -O1 en este entorno")
        shutil.copy(o1, o1_stripped)
        subprocess.run(["strip", o1_stripped], capture_output=True, timeout=30)

        r = identify_stripped_functions(o1_stripped, ref)
        assert r.ok, r.note
        win_matches = [m for m in r.matches if m.recovered_name == "sym.win"]
        assert win_matches, f"win() no se recupero: {[(m.stripped_name, m.recovered_name) for m in r.matches]}"
        assert win_matches[0].confidence == "exact-calls" and win_matches[0].score == 1.0
        # ninguna OTRA funcion anonima debe reclamar el mismo nombre (sin ambiguedad)
        assert len(win_matches) == 1
    finally:
        for p in (o1, o1_stripped):
            if os.path.exists(p):
                os.remove(p)


def test_funcid_degrades_cleanly_without_named_reference():
    # Control negativo: si la "referencia" no tiene ninguna funcion nombrada que comparar
    # (p.ej. tambien esta stripped), no debe inventar ningun match -- debe degradar con nota.
    import os
    import pytest
    from binoracle.workflows.funcid import r2_available, identify_stripped_functions
    b = "samples/bin/ret2win.stripped"
    if not os.path.exists(b):
        pytest.skip("sample ret2win.stripped no disponible")
    if not r2_available():
        pytest.skip("radare2 no disponible")
    r = identify_stripped_functions(b, "/nonexistent/reference/binary")
    assert r.ok is False
    assert "nombradas" in r.note or "no tiene" in r.note or r.note


def test_funcid_degrades_cleanly_without_r2(monkeypatch):
    # Si r2/radare2 no esta en PATH, debe fallar limpio con una nota clara, nunca lanzar.
    from binoracle.workflows import funcid
    monkeypatch.setattr(funcid.shutil, "which", lambda name: None)
    r = funcid.identify_stripped_functions("samples/bin/ret2win.stripped", "samples/bin/ret2win")
    assert r.ok is False
    assert "radare2" in r.note.lower()


def test_rawshellcode_identifies_real_execve_shellcode_as_x86_64():
    # "[S] More formats & backends" del ROADMAP v0.4 -- "raw shellcode analysis": un blob SIN
    # contenedor ELF/PE. Usa el shellcode amd64 REAL (no sintetico) que este proyecto ya genera
    # en workflows/shellcode.py (execve("/bin/sh")) y confirma que x86-64 queda rankeado
    # primero, con la instruccion `syscall` detectada y la cadena `/bin//sh` extraida -- no solo
    # que "algo" se devuelva.
    import pytest
    from binoracle.workflows.rawshellcode import analyze_raw_shellcode as _ars, _HAVE_CAPSTONE
    from binoracle.workflows.shellcode import _PRECOMPILED_SH
    if not _HAVE_CAPSTONE:
        pytest.skip("capstone no disponible")
    r = _ars(_PRECOMPILED_SH["amd64"])
    assert r.ok
    assert r.best.arch == "x86-64"
    assert r.best.n_syscall_insns >= 1
    assert any("/bin" in s for s in r.strings)


def test_rawshellcode_degrades_cleanly_on_empty_input():
    from binoracle.workflows.rawshellcode import analyze_raw_shellcode, render_raw_shellcode
    r = analyze_raw_shellcode(b"")
    assert r.ok is False and r.note
    assert isinstance(render_raw_shellcode(r), str) and render_raw_shellcode(r)


def test_rustinspect_detects_real_stripped_rust_binary():
    # "[S] More formats & backends" del ROADMAP v0.4 -- "Rust binary heuristics". Compila una
    # fuente Rust minima, la STRIPEA, y confirma que las firmas (hash de commit de rustc, al
    # menos un crate de dependencia de Cargo) sobreviven y se recuperan -- no un no-op de leer
    # un binario ya nombrado.
    import os
    import shutil
    import subprocess
    import pytest
    from binoracle.workflows.rustinspect import inspect_rust
    if not shutil.which("rustc") or not shutil.which("strip"):
        pytest.skip("rustc/strip no disponibles")

    src = "/tmp/binoracle_test_rust_hello.rs"
    binp = "/tmp/binoracle_test_rust_hello"
    stripped = binp + ".stripped"
    with open(src, "w") as f:
        f.write('fn main() { println!("hola desde rust"); }\n')
    try:
        subprocess.run(["rustc", "-O", "-o", binp, src], capture_output=True, timeout=120)
        if not os.path.exists(binp):
            pytest.skip("no se pudo compilar el fixture Rust en este entorno")
        shutil.copy(binp, stripped)
        subprocess.run(["strip", stripped], capture_output=True, timeout=30)

        r = inspect_rust(stripped)
        assert r.ok
        assert r.is_likely_rust, r.note
        assert r.rustc_commit or r.dep_crates, "ninguna senal de alta confianza sobrevivio al strip"
    finally:
        for p in (src, binp, stripped):
            if os.path.exists(p):
                os.remove(p)


def test_rustinspect_c_binary_is_not_flagged_as_rust():
    # Control negativo: un binario C real (ret2win) no debe reportar is_likely_rust=True.
    import os
    import pytest
    from binoracle.workflows.rustinspect import inspect_rust
    b = "samples/bin/ret2win"
    if not os.path.exists(b):
        pytest.skip("sample ret2win no disponible")
    r = inspect_rust(b)
    assert r.ok
    assert r.is_likely_rust is False
    assert not r.rustc_commit and not r.dep_crates


def test_rustinspect_degrades_cleanly_on_missing_file():
    from binoracle.workflows.rustinspect import inspect_rust
    r = inspect_rust("/nonexistent/binary")
    assert r.ok is False and r.note


def test_identify_routes_real_rust_binary_to_elf_rust():
    # El identificador unificado (usado por `binoracle identify`/la web UI) debe preferir Go,
    # luego las heuristicas de Rust, antes de caer al layout ELF generico -- confirmado contra
    # un binario Rust REAL (no un ELF sintetico con bytes a mano).
    import os
    import shutil
    import subprocess
    import pytest
    from binoracle.workflows.identify import identify
    if not shutil.which("rustc") or not shutil.which("strip"):
        pytest.skip("rustc/strip no disponibles")
    src = "/tmp/binoracle_test_rust_identify.rs"
    binp = "/tmp/binoracle_test_rust_identify"
    with open(src, "w") as f:
        f.write('fn main() { println!("x"); }\n')
    try:
        subprocess.run(["rustc", "-O", "-o", binp, src], capture_output=True, timeout=120)
        if not os.path.exists(binp):
            pytest.skip("no se pudo compilar el fixture Rust en este entorno")
        subprocess.run(["strip", binp], capture_output=True, timeout=30)
        r = identify(binp)
        assert r["ok"] and r["routed"] == "elf-rust"
    finally:
        for p in (src, binp):
            if os.path.exists(p):
                os.remove(p)


def test_gadget_cache_hit_skips_the_real_r2_scan():
    # "[L] Cross-engagement knowledge base" del ROADMAP v0.5 -- reuso de gadgets DESCUBIERTOS
    # entre targets. chainanalyzer._enum_gadgets corre un escaneo ROP real via radare2 (/Rj por
    # patron); esto confirma que una SEGUNDA llamada sobre el MISMO contenido (mismo hash sha256)
    # NUNCA vuelve a invocar r2 -- devuelve los gadgets cacheados tal cual, byte-identicos porque
    # la clave ES el contenido.
    import os
    import shutil
    import tempfile
    import pytest
    import binoracle.oracles.r2session as r2s
    import binoracle.workflows.chainanalyzer as ca
    from binoracle.config import Config
    b = "samples/bin/ret2win"
    if not os.path.exists(b):
        pytest.skip("sample ret2win no compilado")
    if not (shutil.which("r2") or shutil.which("radare2")):
        pytest.skip("radare2 no disponible")

    state_dir = tempfile.mkdtemp()
    old_env = os.environ.get("BINORACLE_STATE_DIR")
    os.environ["BINORACLE_STATE_DIR"] = state_dir
    try:
        g1 = ca._enum_gadgets(b, bits=64)
        assert g1, "el scan real no encontro ningun gadget -- nada que cachear/verificar"

        orig_get = r2s.get
        calls = {"n": 0}
        def _spy(*a, **kw):
            calls["n"] += 1
            return orig_get(*a, **kw)
        r2s.get = _spy
        try:
            g2 = ca._enum_gadgets(b, bits=64)
        finally:
            r2s.get = orig_get
        assert calls["n"] == 0, "cache MISS -- r2 se invoco de nuevo pese a contenido identico"
        assert [g.addr for g in g1] == [g.addr for g in g2]
        assert [g.text for g in g1] == [g.text for g in g2]
    finally:
        if old_env is None:
            os.environ.pop("BINORACLE_STATE_DIR", None)
        else:
            os.environ["BINORACLE_STATE_DIR"] = old_env
        shutil.rmtree(state_dir, ignore_errors=True)


def test_gadget_cache_degrades_cleanly_on_a_bad_db_path():
    # Si el cache de gadgets no se puede leer/escribir (ruta invalida), _enum_gadgets debe
    # seguir devolviendo el escaneo real via r2 -- nunca lanzar ni devolver [] por el fallo del
    # cache en si.
    import os
    import shutil
    import pytest
    import binoracle.workflows.chainanalyzer as ca
    b = "samples/bin/ret2win"
    if not os.path.exists(b):
        pytest.skip("sample ret2win no compilado")
    if not (shutil.which("r2") or shutil.which("radare2")):
        pytest.skip("radare2 no disponible")
    import binoracle.store.gadget_cache as gc
    orig_load = gc.load_gadgets
    orig_save = gc.save_gadgets
    gc.load_gadgets = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("cache roto"))
    gc.save_gadgets = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("cache roto"))
    try:
        g = ca._enum_gadgets(b, bits=64)
        assert g, "el fallo del cache no debe impedir el escaneo real"
    finally:
        gc.load_gadgets = orig_load
        gc.save_gadgets = orig_save


def test_ruff_lint_gate_passes_clean():
    # Cross-cutting quality (ROADMAP.md) -- "Type hints + mypy, ruff lint, and a coverage gate
    # in CI". El gate real es `ruff check binoracle` (ver [tool.ruff] en pyproject.toml, select
    # = ["F"] a proposito -- pyflakes puro, confirmado en cero). Este test reproduce EXACTAMENTE
    # ese comando para que una regresion de lint la capture la propia suite, no solo el CI.
    import os as _os
    import shutil
    import subprocess
    import pytest
    if not (shutil.which("ruff") or _module_importable("ruff")):
        pytest.skip("ruff no instalado (pip install ruff, o extra [dev])")
    r = subprocess.run(["python3", "-m", "ruff", "check", "binoracle"],
                       cwd=_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"ruff encontro hallazgos de pyflakes (F):\n{r.stdout}\n{r.stderr}"


def _module_importable(name: str) -> bool:
    import importlib
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False


def test_import_availability_probes_are_not_silently_broken():
    # Regresion especifica: el propio auto-fix de ruff (al limpiar F401 "unused import") borro
    # SILENCIOSAMENTE dos `try: import X ... except: _HAVE_X = False` -- un patron deliberado
    # donde el import solo existe para que su ImportError sea atrapado (el NOMBRE nunca se usa
    # despues), asi que un chequeo de "import sin usar" no puede distinguirlo de uno de verdad
    # muerto. Confirmado en vivo: tras el auto-fix, `_HAVE_R2PIPE`/`_HAVE_ANGR` quedaban SIEMPRE
    # en True (el try ya no podia fallar), incluso sin r2pipe/angr instalados -- restaurados con
    # `# noqa: F401` explicito. Este test fija el contrato: ambos modulos deben seguir teniendo
    # el import real (no solo la bandera) para que el ImportError real siga pudiendo ocurrir.
    import ast
    import os as _os

    def _has_real_import_inside_try(path: str, module_name: str, flag_name: str) -> bool:
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            has_import = any(
                isinstance(n, ast.Import) and any(a.name == module_name for a in n.names)
                for n in ast.walk(node)
            )
            sets_flag = any(
                isinstance(n, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == flag_name for t in n.targets
                )
                for n in node.body
            )
            if has_import and sets_flag:
                return True
        return False

    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    assert _has_real_import_inside_try(
        _os.path.join(root, "binoracle", "oracles", "capstone_fallback.py"), "r2pipe", "_HAVE_R2PIPE")
    assert _has_real_import_inside_try(
        _os.path.join(root, "binoracle", "workflows", "autopoc.py"), "angr", "_HAVE_ANGR")


def test_quiet_angr_silences_all_three_loggers_and_is_shared():
    # "Quieter optional dependencies (pwntools/angr logging)" del ROADMAP.md. angr SI se importa
    # directo en este proceso (symbolic_angr.py, concolic.py, autopoc.py) -- ahi la duplicacion
    # (3 copias del mismo getLogger().setLevel() x3) era real, y una de las 3 copias
    # (symbolic_angr.py) ni siquiera quietaba pyvex. Factorizado en `binoracle._quiet_angr()`,
    # usado por los 3. (`_quiet_pwn()` SIGUE existiendo y con llamadores reales -- un intento
    # anterior de borrarlo por "sin uso" solo greppeo imports de `pwn` en columna 0 y se perdio
    # 4 `from pwn import` indentados dentro de un `try:` a nivel de proceso host en rop.py/
    # shellcode.py/fmtstring.py/autopoc.py; lo capturo una ejecucion real de `autopwn`, no un
    # analisis estatico -- ver test_quiet_pwn_sets_error_level y test_autopwn_rop_chain_combo_
    # does_not_crash_on_missing_quiet_pwn mas abajo.)
    import logging
    import binoracle
    for name in ("angr", "cle", "pyvex"):
        logging.getLogger(name).setLevel(logging.DEBUG)   # reset para que la asercion sea real
    binoracle._quiet_angr()
    for name in ("angr", "cle", "pyvex"):
        assert logging.getLogger(name).level == logging.ERROR, f"{name} no quedo en ERROR"


def test_angr_importing_modules_all_use_the_shared_quiet_helper():
    import ast
    import os as _os
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    for rel in ("binoracle/oracles/symbolic_angr.py", "binoracle/oracles/concolic.py",
               "binoracle/workflows/autopoc.py"):
        path = _os.path.join(root, rel)
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        assert "_quiet_angr" in src, f"{rel} importa angr pero no usa el helper compartido"
        ast.parse(src)   # y sigue siendo sintacticamente valido


def test_quiet_pwn_has_real_host_process_callers():
    # Regresion especifica (ver comentario en test_quiet_angr_silences_all_three_loggers_and_is_
    # shared): `_quiet_pwn` tiene 5 llamadores reales a nivel de proceso HOST (no dentro de un
    # driver-string que corre como subproceso aparte) -- rop.py, shellcode.py, fmtstring.py,
    # autopoc.py y autofuzz.py. Confirmado en vivo: sin `_quiet_pwn`, `rop.py`'s `_HAVE_PWN`
    # queda en False con el motivo real siendo un ImportError de `_quiet_pwn` mismo (no "pwntools
    # no instalado" -- un fallo mucho mas confuso), y `binoracle autopwn` sobre un binario con
    # canary (donde SI se intenta la combo rop-chain) reporta literalmente "pwntools no
    # disponible: cannot import name '_quiet_pwn'" en vez de un motivo real de por que la cadena
    # ROP no se pudo construir.
    import shutil
    import pytest
    from binoracle.workflows.rop import _HAVE_PWN
    if not shutil.which("python3"):
        pytest.skip("python3 no disponible")
    try:
        import pwn  # noqa: F401
    except Exception:
        pytest.skip("pwntools no instalado -- _HAVE_PWN=False es la respuesta correcta, nada que verificar")
    assert _HAVE_PWN is True, "rop.py no detecto pwntools -- revisa que binoracle._quiet_pwn exista"


def test_docs_site_builds_real_valid_html_from_every_source_page():
    # "A docs site with a guided tutorial over the samples/ corpus" del ROADMAP.md. Corre el
    # generador DE VERDAD (docs/build_site.py) contra las fuentes reales del repo (no fixtures
    # sinteticas) y confirma que cada pagina (incluido el tutorial) sale como HTML valido con
    # contenido real -- no solo que el script "no lanzo excepcion".
    import glob
    import importlib.util
    import os
    import shutil
    import tempfile
    from html.parser import HTMLParser
    import pytest
    if importlib.util.find_spec("markdown") is None:
        pytest.skip("markdown no instalado (pip install -e '.[docs]')")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    site_dir = os.path.join(root, "docs", "site")
    pre_existing = os.path.isdir(site_dir)
    try:
        import subprocess
        r = subprocess.run(["python3", os.path.join(root, "docs", "build_site.py")],
                           cwd=root, capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr

        pages = sorted(glob.glob(os.path.join(site_dir, "*.html")))
        assert len(pages) == 5, f"se esperaban 5 paginas (index + 4), se generaron: {pages}"

        class _Strict(HTMLParser):
            def error(self, message):
                raise AssertionError(message)

        for p in pages:
            with open(p, "r", encoding="utf-8") as f:
                content = f.read()
            assert len(content) > 500, f"{p} parece vacio/truncado"
            _Strict().feed(content)   # lanza si el HTML esta mal formado

        with open(os.path.join(site_dir, "tutorial.html"), "r", encoding="utf-8") as f:
            tut = f.read()
        assert "<pre>" in tut and "ret2win" in tut and "SHELL VERIFICADA" in tut
    finally:
        if not pre_existing and os.path.isdir(site_dir):
            shutil.rmtree(site_dir)


def test_r2_heap_does_not_false_positive_on_reallocarray_as_bare_realloc():
    # Bug real encontrado investigando un CVE REAL contra un binario REAL (no un sample de
    # juguete): sudo 1.8.31 (CVE-2021-3156) importa `reallocarray` pero no una `realloc` suelta.
    # `_heap()`'s chequeo anterior ("realloc" in <texto de ii>) daba un falso positivo porque
    # "realloc" es substring literal de "reallocarray" -- pedia `axt @ sym.imp.realloc` sobre un
    # simbolo que NO EXISTE, y esa consulta invalida colgaba INDEFINIDAMENTE la sesion de
    # r2pipe de larga duracion de este oraculo (confirmado: una query equivalente en un proceso
    # r2 nuevo responde "Invalid address" en <1s -- es la sesion persistente la que se cuelga).
    # Esto bloqueaba `triage`/`audit`/`investigate_cve --binary` ENTEROS, sin limite de tiempo,
    # en CUALQUIER binario con reallocarray pero sin realloc -- bastante comun. Reproduce el
    # caso minimo real (compilado aqui, no el binario completo de sudo) y confirma que: (a)
    # termina rapido (el timeout de esta prueba es la red de seguridad, no el mecanismo real:
    # el fix real es el chequeo de nombre exacto en el propio oraculo); (b) solo reporta
    # reallocarray, nunca realloc.
    import os
    import shutil
    import subprocess
    import tempfile
    import pytest
    from binoracle.oracles.static_r2 import R2Oracle
    if not shutil.which("gcc"):
        pytest.skip("gcc no disponible")
    src = os.path.join(tempfile.mkdtemp(), "reallocarray_only.c")
    binp = src[:-2]
    with open(src, "w") as f:
        f.write("#include <stdlib.h>\nint main(){ void *p = reallocarray(NULL, 4, sizeof(int)); "
               "free(p); return 0; }\n")
    r = subprocess.run(["gcc", "-o", binp, src], capture_output=True, timeout=30)
    if r.returncode != 0 or not os.path.exists(binp):
        pytest.skip("no se pudo compilar el fixture minimo en este entorno")
    try:
        o = R2Oracle(binp)
        if not o.available():
            pytest.skip("radare2 no disponible")
        res = o._heap()
    finally:
        for p in (src, binp):
            if os.path.exists(p):
                os.remove(p)
    assert res.ok
    assert "reallocarray" in res.data
    assert "sym.imp.realloc:" not in res.data and "  realloc:" not in res.data


def test_r2oracle_cmd_timed_degrades_instead_of_hanging_forever():
    # El mecanismo de defensa general (no solo el bug especifico de arriba): CUALQUIER comando
    # que se quede colgado en la sesion persistente de r2pipe debe degradar, nunca bloquear el
    # pipeline para siempre. Simula el cuelgue (un r2.cmd que nunca retorna) sin depender de
    # encontrar OTRO bug real de r2 -- confirma el mecanismo en si, con un timeout de prueba
    # corto para no alargar la suite.
    import shutil as _shutil
    import time as _time
    import pytest
    from binoracle.oracles.static_r2 import R2Oracle
    if not (_shutil.which("r2") or _shutil.which("radare2")):
        pytest.skip("radare2 no disponible")

    o = R2Oracle("samples/bin/ret2win" if __import__("os").path.exists("samples/bin/ret2win")
                 else __file__)
    o.cmd_timeout_s = 1.0   # corto a proposito -- es la red de seguridad, no el bug real

    class _HangingR2:
        process = type("P", (), {"kill": lambda self: None})()
        def cmd(self, c):
            _time.sleep(10)   # mas largo que cmd_timeout_s -- simula el pipe colgado
            return "nunca llega aqui"

    out = o._cmd_timed(_HangingR2(), "cualquier comando")
    assert out is None, "un comando colgado debe degradar (None), nunca bloquear indefinidamente"
    assert o._r2 is None and o._analyzed is False, "el pipe colgado debe descartarse para la siguiente llamada"
