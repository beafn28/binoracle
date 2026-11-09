"""CI gate: pass/fail verdict for a binoracle GitHub Action -- fails a PR on new *verified*
findings or security regressions.

ROADMAP v0.5 "[M] CI action" -- "A `binoracle` GitHub Action that fails a PR on new *verified*
findings or regressions." Audited first: `run_audit` (the LLM-driven agent loop) is the wrong
engine to sit in a generic CI runner -- it needs a local LLM backend reachable, which most CI
runners don't have. `workflows/regress.py`'s `run_regress` already runs the GROUNDED pipeline
(triage + hunt + angr verification, `llm=None` -- confirmed it genuinely works without any LLM)
between an OLD and a NEW build and reports what changed; `autoregress_test` (shipped earlier,
"[M] Patch-diff v2") already re-runs every autopwn technique verified on OLD against NEW and
reports whether it still verifies. Neither on its own is a CI PASS/FAIL VERDICT -- this module is
that verdict: it classifies `run_regress`'s string-formatted diffs (new findings, verdict
escalations, mitigation changes) and `autoregress_test`'s results into "fails the build" vs.
"fine", so an action can simply check an exit code. Deliberately narrow: a MITIGATION change only
fails the gate if it WEAKENS something that was on (Canary/NX/PIE/FORTIFY/CFI/SafeStack True ->
False) -- turning one ON is a fix, not a regression, and must never fail the build."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .regress import RegressResult, run_regress

_BOOL_TRUE = {"true", "1", "yes"}
_NEW_FINDING_RE = re.compile(r"^(.*) \[(\w+)\]$")
_VERDICT_CHANGE_RE = re.compile(r"^(.*): (\w+) -> (\w+)$")
_MIT_CHANGE_RE = re.compile(r"^([A-Za-z]+): (\S+) -> (\S+)$")


def _is_true(v: str) -> bool:
    return v.strip().lower() in _BOOL_TRUE


@dataclass
class CiGateResult:
    ok: bool = False
    passed: bool = False
    note: str = ""
    old: str = ""
    new: str = ""
    regress: Optional[RegressResult] = None
    regression_tests: list = field(default_factory=list)
    fail_reasons: List[str] = field(default_factory=list)


def run_ci_gate(old: str, new: str, config, gen_test: bool = False,
               techniques: Optional[List[str]] = None) -> CiGateResult:
    """Corre el pipeline grounded (sin LLM) sobre OLD y NEW y devuelve un veredicto PASS/FAIL
    para CI. `gen_test=True` ademas corre `autoregress_test` (mas lento, re-intenta cada tecnica
    de autopwn que verifico en OLD contra NEW de verdad en el sandbox) -- esa es la senal mas
    fuerte posible de "sigue siendo explotable", asi que si esta disponible pesa mas que
    cualquier heuristica de texto sobre hallazgos."""
    res = CiGateResult(old=old, new=new)
    try:
        rr = run_regress(old, new, config)
    except Exception as e:
        res.note = f"error corriendo el pipeline grounded: {e}"
        return res
    res.ok = True
    res.regress = rr
    reasons = []

    for line in rr.new_findings:
        m = _NEW_FINDING_RE.match(line)
        if m and m.group(2) == "verified":
            reasons.append(f"hallazgo NUEVO y VERIFICADO: {m.group(1)}")

    for line in rr.verdict_changes:
        m = _VERDICT_CHANGE_RE.match(line)
        if m and m.group(2) != "verified" and m.group(3) == "verified":
            reasons.append(f"hallazgo escalo a VERIFICADO: {m.group(1)} ({m.group(2)} -> verified)")

    for line in rr.mit_changes:
        m = _MIT_CHANGE_RE.match(line)
        if m and _is_true(m.group(2)) and not _is_true(m.group(3)):
            reasons.append(f"mitigacion DEBILITADA: {m.group(1)} ({m.group(2)} -> {m.group(3)})")

    if gen_test:
        try:
            from .regress import autoregress_test
            tests = autoregress_test(old, new, config=config, techniques=techniques)
            res.regression_tests = tests
            for t in tests:
                if not t.passed:
                    reasons.append(f"regresion de exploit: {t.technique} SIGUE verificando en NEW")
        except Exception as e:
            reasons.append(f"no se pudo correr autoregress_test: {e}")

    res.fail_reasons = reasons
    res.passed = not reasons
    res.note = "PASA -- sin hallazgos nuevos verificados ni regresiones" if res.passed else \
        f"FALLA -- {len(reasons)} motivo(s)"
    return res


def render_ci_gate(r: CiGateResult) -> str:
    out = ["## CI gate (binoracle)\n"]
    if not r.ok:
        return "\n".join(out + ["No disponible: " + r.note])
    verdict = "PASA" if r.passed else "FALLA"
    out.append(f"- veredicto: **{verdict}**")
    out.append(f"- {r.note}\n")
    if r.fail_reasons:
        out.append("### Motivos\n")
        for reason in r.fail_reasons:
            out.append(f"- {reason}")
    return "\n".join(out)
