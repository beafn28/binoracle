"""Markdown rendering for reports."""
from __future__ import annotations

from datetime import datetime
from typing import List

from ..store.session import Finding

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_BADGE = {
    "critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO",
}


def _hdr(binary: str) -> str:
    return (f"# binoracle report\n\n"
            f"- target: `{binary}`\n"
            f"- generated: {datetime.now().isoformat(timespec='seconds')}\n"
            f"- note: every fact below is attributed to the oracle that produced it.\n")


def render_triage(report, findings: List[Finding] = None) -> str:
    out = [_hdr(report.binary), "\n## Triage (grounded facts)\n"]
    for title, source, text in report.sections:
        out.append(f"### {title}\nsource: `{source}`\n\n```\n{text.strip()}\n```\n")
    if findings:
        out.append(render_findings(findings))
    return "\n".join(out)


def render_findings(findings: List[Finding]) -> str:
    if not findings:
        return "## Findings\n\n_No evidence-backed findings._\n"
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
    out = ["## Findings\n"]
    for f in findings:
        badge = SEV_BADGE.get(f.severity, f.severity.upper())
        out.append(
            f"### [{badge}] {f.title}\n"
            f"- verdict: **{f.verdict}**\n"
            f"- location: `{f.location or 'n/a'}`\n\n"
            f"**Rationale**\n\n{f.rationale or '(none)'}\n\n"
            f"**Evidence**\n\n```\n{(f.evidence or '(none)').strip()}\n```\n\n"
            f"**Recommendation**\n\n{f.recommendation or '(none)'}\n"
        )
    return "\n".join(out)


def render_agent_result(binary: str, result) -> str:
    out = [_hdr(binary), "\n## Answer\n", result.answer, "\n"]
    if result.findings:
        out.append(render_findings(result.findings))
    out.append("\n" + result.ledger.evidence_trail())
    out.append(f"\n_stopped: {result.stopped_reason} after {result.steps} step(s)._")
    return "\n".join(out)


def findings_to_json(binary: str, findings, ledger=None) -> str:
    """Machine-readable export for CI / programmatic use."""
    import json
    from datetime import datetime
    data = {
        "target": binary,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "findings": [
            {
                "title": f.title, "severity": f.severity, "verdict": f.verdict,
                "location": f.location, "rationale": f.rationale,
                "evidence": f.evidence, "recommendation": f.recommendation,
            } for f in (findings or [])
        ],
        "sources_consulted": ledger.sources() if ledger is not None else [],
    }
    return json.dumps(data, indent=2)
