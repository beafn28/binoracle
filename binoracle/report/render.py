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


# OWASP Desktop App Security Top 10 -- the framework a professional binary/desktop pentest
# reports coverage against (methodology Fase 9). Findings are mapped by keyword; categories
# with no finding are listed as "reviewed, nothing found" so the report shows what was checked.
# Tokens are deliberately specific (multi-char, non-overlapping) to avoid mis-classifying a
# finding: e.g. never "des" (matches "desbordamiento"), "system"/"shell" (match exploit prose)
# or "log"/"string". Better to under-map than to put a finding in the wrong OWASP box.
_OWASP_DESKTOP = [
    ("DA1", "Injection", ("command injection", "inyeccion de comando", "inyección de comando",
                          "os command", "sql injection", "backdoor de comando")),
    ("DA2", "Broken Authentication", ("broken auth", "session fixation", "autenticacion rota")),
    ("DA3", "Sensitive Data Exposure", ("secreto", "credencial", "hardcoded", "api key",
                                        "clave hardcode", "informacion sensible")),
    ("DA4", "Improper Cryptography Usage", ("sha-1", "sha1", "md5", "rc4", "hashing debil",
                                            "criptograf", "cifrado debil", "weak crypto")),
    ("DA5", "Improper Authorization", ("escalada de privilegio", "privilege escalation",
                                       "setuid", "uac bypass", "token de privilegio")),
    ("DA6", "Security Misconfiguration", ("dll hijack", "authenticode", "sin firma", "permiso",
                                          "acl ", "sandbox", "misconfigur")),
    ("DA7", "Insecure Communication", ("sin cifrar", "texto en claro", "cleartext", "http://",
                                       "telnet", "ftp ", "mitm", "insecure communication")),
    ("DA8", "Poor Code Quality", ("overflow", "desbord", "gets", "format string", "format-string",
                                  "uaf", "use-after", "double free", "double-free", "heap", "rop",
                                  "ret2", "buffer", "memcpy", "strcpy", "tcache")),
    ("DA9", "Using Components with Known Vulnerabilities", ("cve-", "desactualiz", "obsolet",
                                                            "outdated", "known vulnerab")),
    ("DA10", "Insufficient Logging & Monitoring", ("insufficient logging", "sin registro de auditoria")),
]


def owasp_desktop_coverage(findings):
    """Map findings to OWASP Desktop Top 10 categories by keyword. Returns an ordered list of
    (id, name, [finding titles]) so the report can show both what was found AND what was
    reviewed with nothing found (professional coverage, methodology Fase 9)."""
    out = []
    for cid, name, kws in _OWASP_DESKTOP:
        hits = []
        for f in findings or []:
            blob = f"{f.title} {f.rationale} {f.location}".lower()
            if any(k in blob for k in kws):
                hits.append(f.title)
        out.append((cid, name, hits))
    return out


def render_owasp(findings) -> str:
    cov = owasp_desktop_coverage(findings)
    out = ["## OWASP Desktop Top 10 -- cobertura\n",
           "Mapeo de hallazgos al marco OWASP Desktop App Security Top 10 (metodologia Fase 9). "
           "Las categorias sin hallazgo se marcan como revisadas.\n",
           "| Categoria | Estado | Hallazgos |", "|---|---|---|"]
    for cid, name, hits in cov:
        estado = "⚠ con hallazgos" if hits else "revisado, sin hallazgo"
        det = "; ".join(dict.fromkeys(hits)) if hits else "—"
        out.append(f"| {cid} {name} | {estado} | {det} |")
    return "\n".join(out)


def render_methodology_note() -> str:
    """Fact-vs-inference framing (methodology Fase 5): what each verdict means in this report."""
    return ("## Metodologia y veredictos (hecho vs inferencia)\n\n"
            "Cada afirmacion sobre el binario procede de un oraculo real y se clasifica:\n\n"
            "- **verified** — hecho probado por EJECUCION o alcanzabilidad simbolica "
            "(exploit en sandbox, crash de depurador o prueba de angr). Es un hecho, no una opinion.\n"
            "- **grounded** — patron reconocible respaldado por evidencia estatica, pero no "
            "probado dinamicamente (hipotesis fuerte).\n"
            "- **unverified** — no se pudo respaldar con una herramienta; se marca y no se trata "
            "como hecho.\n\n"
            "El veredicto lo fija el codigo (gate anti-falso-positivo), no la narrativa del modelo.")


def render_agent_result(binary: str, result) -> str:
    out = [_hdr(binary), "\n## Answer\n", result.answer, "\n"]
    if result.findings:
        out.append(render_findings(result.findings))
        out.append("\n" + render_owasp(result.findings))
    out.append("\n" + render_methodology_note())
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
