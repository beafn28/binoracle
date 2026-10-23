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
# Cada categoria lleva un flag `covered`: True solo si binoracle tiene un scanner REAL que la
# examina (secrets, fileperms, commsec, backdoors, vulnhunt/chains, dynamic). Las que NO se
# escanean (autenticacion, componentes con CVEs, logging) NO se marcan como "revisadas": se
# marcan "no evaluado", para no afirmar una revision que no ocurrio (honestidad del informe).
_OWASP_DESKTOP = [
    ("DA1", "Injection", True, ("command injection", "inyeccion de comando", "inyección de comando",
                                "os command", "sql injection", "inyeccion sql", "backdoor de comando",
                                "superficie de inyeccion", "injection surface", "inyeccion / ")),
    ("DA2", "Broken Authentication", True, ("broken auth", "session fixation", "autenticacion rota",
                                            "autenticacion por comparacion", "authentication by comparison",
                                            "sin hashing", "without hashing", "auth / ")),
    ("DA3", "Sensitive Data Exposure", True, ("secreto", "credencial", "hardcoded", "api key",
                                              "clave hardcode", "informacion sensible")),
    ("DA4", "Improper Cryptography Usage", True, ("sha-1", "sha1", "md5", "rc4", "hashing debil",
                                                  "criptograf", "cifrado debil", "weak crypto")),
    ("DA5", "Improper Authorization", True, ("escalada de privilegio", "privilege escalation",
                                             "setuid", "setgid", "uac bypass", "token de privilegio",
                                             "sin soltar privilegios", "without dropping privileges",
                                             "autorizacion / ")),
    ("DA6", "Security Misconfiguration", True, ("dll hijack", "authenticode", "sin firma", "permiso",
                                                "acl ", "sandbox", "misconfigur", "rpath", "runpath",
                                                "endurecimiento", "hardening", "configuracion / ",
                                                "ld_", "path hijack", "por path", "via path")),
    ("DA7", "Insecure Communication", True, ("sin cifrar", "texto en claro", "cleartext", "http://",
                                             "telnet", "ftp ", "mitm", "insecure communication",
                                             "certificado", "runtime / red")),
    ("DA8", "Poor Code Quality", True, ("overflow", "desbord", "gets", "format string", "format-string",
                                        "uaf", "use-after", "double free", "double-free", "heap", "rop",
                                        "ret2", "buffer", "memcpy", "strcpy", "tcache",
                                        "sink alcanzable", "sink reachable")),
    ("DA9", "Using Components with Known Vulnerabilities", True, ("cve-", "desactualiz", "obsolet",
                                                                  "outdated", "known vulnerab",
                                                                  "componente antiguo", "outdated component")),
    ("DA10", "Insufficient Logging & Monitoring", True, ("insufficient logging", "sin registro de auditoria",
                                                         "registro/auditoria insuficiente",
                                                         "insufficient logging/auditing")),
]


def owasp_desktop_coverage(findings):
    """Mapea hallazgos a OWASP Desktop Top 10 por palabra clave. Devuelve una lista ordenada de
    (id, name, [titulos], covered) donde covered indica si binoracle EXAMINA de verdad esa
    categoria. Asi el informe distingue 'revisado, sin hallazgo' de 'no evaluado'."""
    out = []
    for cid, name, covered, kws in _OWASP_DESKTOP:
        hits = []
        for f in findings or []:
            blob = f"{f.title} {f.rationale} {f.location}".lower()
            if any(k in blob for k in kws):
                hits.append(f.title)
        out.append((cid, name, hits, covered))
    return out


def render_owasp(findings) -> str:
    cov = owasp_desktop_coverage(findings)
    out = ["## OWASP Desktop Top 10 -- cobertura\n",
           "Mapeo de hallazgos al marco OWASP Desktop App Security Top 10 (metodologia Fase 9). "
           "Solo se marca 'revisado, sin hallazgo' lo que binoracle examina de verdad; el resto se "
           "marca 'no evaluado' (fuera del alcance del analisis actual).\n",
           "| Categoria | Estado | Hallazgos |", "|---|---|---|"]
    for cid, name, hits, covered in cov:
        if hits:
            estado = "con hallazgos"
        elif covered:
            estado = "revisado, sin hallazgo"
        else:
            estado = "no evaluado (fuera de alcance)"
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


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _slug(text: str) -> str:
    import re
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:48] or "finding"


def findings_to_sarif(binary: str, findings, ledger=None) -> str:
    """Exporta los hallazgos en SARIF 2.1.0 (estandar de code-scanning: GitHub, CI, dashboards).

    Cada hallazgo es un `result` con nivel por severidad (critical/high->error, medium->warning,
    low/info->note), su `ruleId` (clase de vulnerabilidad), y propiedades con el veredicto y, si el
    paquete cvss esta disponible, el vector + score (`security-severity`, que GitHub usa para pintar
    la severidad). Grounded: el veredicto verified/grounded del hallazgo se conserva tal cual."""
    import json
    import os
    from datetime import datetime, timezone
    try:
        from .cvss import cvss_for, classify
    except Exception:
        cvss_for = classify = None

    rules = {}          # ruleId -> rule object
    results = []
    uri = os.path.basename(binary) or "binary"
    for f in (findings or []):
        cls = classify(f) if classify else None
        rule_id = cls or _slug(f.title)
        cv = cvss_for(f) if cvss_for else None
        if rule_id not in rules:
            props = {"tags": ["binoracle", "reverse-engineering"]}
            if getattr(f, "cwe", ""):
                props["tags"].append(f"external/cwe/cwe-{f.cwe}")
            if getattr(f, "owasp", ""):
                props["tags"].append(f"external/owasp/{f.owasp.lower()}")
            if cv and cv.base is not None:
                props["security-severity"] = f"{cv.base:.1f}"
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                "properties": props,
            }
        msg = f.rationale or f.title
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}},
                "logicalLocations": [{"fullyQualifiedName": f.location or "?",
                                      "kind": "function"}],
            }],
            "properties": {
                "verdict": f.verdict,
                "severity": f.severity,
                "recommendation": f.recommendation,
            },
        }
        if getattr(f, "owasp", ""):
            result["properties"]["owasp"] = f.owasp
        if getattr(f, "cwe", ""):
            result["properties"]["cwe"] = f"CWE-{f.cwe}"
        if cv:
            result["properties"]["cvss_v4_vector"] = cv.vector
            if cv.base is not None:
                result["properties"]["cvss_v4_base"] = cv.base
                result["properties"]["security-severity"] = f"{cv.base:.1f}"
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "binoracle",
                "informationUri": "https://github.com/beafn28/binoracle",
                "rules": list(rules.values()),
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }],
            "properties": {"target": binary,
                           "sources_consulted": ledger.sources() if ledger is not None else []},
        }],
    }
    return json.dumps(sarif, indent=2)


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
                "owasp": getattr(f, "owasp", ""), "cwe": getattr(f, "cwe", ""),
            } for f in (findings or [])
        ],
        "sources_consulted": ledger.sources() if ledger is not None else [],
    }
    return json.dumps(data, indent=2)
