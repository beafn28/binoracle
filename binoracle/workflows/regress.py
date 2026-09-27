"""Security regression detection between two builds of a binary (Shadow-CI).

Runs the grounded pipeline (triage + hunt + angr verification) on an OLD and a NEW binary
and reports what changed: findings that appeared or disappeared, verdict changes, and
mitigation differences. This is what catches "a fix that silently came back"."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..oracles import build_registry
from .triage import run_triage
from .vulnhunt import run_hunt
from .verify import auto_verify


def _sig(f) -> str:
    return f"{f.title} @ {f.location}"


def _analyze(binary: str, config) -> Tuple[Dict[str, str], Dict[str, str]]:
    reg = build_registry(binary)
    run_triage(reg, binary)
    hunt = run_hunt(reg, binary, llm=None, config=config)
    findings, _ = auto_verify(reg, hunt.findings)
    fmap = {_sig(f): f.verdict for f in findings}
    cs = reg.get("r2_checksec").run()
    mit = cs.meta if cs.ok else {}
    hard = reg.get("r2_hardening").run().data if reg.get("r2_hardening") else ""
    def hd(name):
        for line in hard.splitlines():
            if line.lower().startswith(name.lower()):
                return "not detected" not in line.lower()
        return False
    mitmap = {"NX": str(mit.get("nx")), "PIE": str(mit.get("pic")),
              "Canary": str(mit.get("canary")), "FORTIFY": str(hd("FORTIFY")),
              "CFI": str(hd("CFI")), "SafeStack": str(hd("SafeStack"))}
    return fmap, mitmap


@dataclass
class RegressResult:
    old: str
    new: str
    new_findings: List[str] = field(default_factory=list)
    fixed_findings: List[str] = field(default_factory=list)
    verdict_changes: List[str] = field(default_factory=list)
    mit_changes: List[str] = field(default_factory=list)


def run_regress(old: str, new: str, config) -> RegressResult:
    of, om = _analyze(old, config)
    nf, nm = _analyze(new, config)
    r = RegressResult(old=old, new=new)
    for s in nf:
        if s not in of:
            r.new_findings.append(f"{s} [{nf[s]}]")
    for s in of:
        if s not in nf:
            r.fixed_findings.append(f"{s} [{of[s]}]")
    for s in nf:
        if s in of and of[s] != nf[s]:
            r.verdict_changes.append(f"{s}: {of[s]} -> {nf[s]}")
    for k in nm:
        if om.get(k) != nm.get(k):
            r.mit_changes.append(f"{k}: {om.get(k)} -> {nm.get(k)}")
    return r


def render_regress(r: RegressResult) -> str:
    out = [f"# Regresiones\n- old: `{r.old}`\n- new: `{r.new}`\n"]
    def block(title, items, warn=False):
        out.append(f"## {title} ({len(items)})")
        if not items:
            out.append("_ninguno_\n")
        else:
            pref = "> [!warning] " if warn else ""
            out.append(pref + "\n".join(f"- {i}" for i in items) + "\n")
    block("Mitigaciones que cambian", r.mit_changes)
    block("Hallazgos NUEVOS (posible regresion)", r.new_findings, warn=bool(r.new_findings))
    block("Hallazgos ARREGLADOS", r.fixed_findings)
    block("Cambios de veredicto", r.verdict_changes)
    return "\n".join(out)
