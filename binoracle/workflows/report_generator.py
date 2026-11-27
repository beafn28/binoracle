"""Professional security report generator.

Produces a top-tier security firm quality report from an Investigation object.
For AUTHORIZED security research / pentest / CTF only.

Usage:
    from binoracle.workflows.report_generator import generate_report, save_report
    report = generate_report(inv, lang="es")
    path = save_report(report)
    print(report.to_markdown())
"""
from __future__ import annotations

import datetime
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

try:
    from .cve_agent import Investigation  # type: ignore
except Exception:
    Investigation = Any  # type: ignore


# ── Vuln class → professional title ──────────────────────────────────────────

_TITLES_ES: Dict[str, str] = {
    "sqli":                   "Inyección SQL — Lectura Arbitraria de Base de Datos",
    "sql-injection":          "Inyección SQL — Lectura Arbitraria de Base de Datos",
    "xss":                    "Cross-Site Scripting — Secuestro de Sesión",
    "stored-xss":             "XSS Almacenado — Ejecución Persistente en Cliente",
    "reflected-xss":          "XSS Reflejado — Ejecución en Cliente",
    "rce":                    "Ejecución Remota de Código — Compromiso Total del Sistema",
    "code-injection":         "Inyección de Código — Ejecución Remota",
    "command-injection":      "Inyección de Comandos OS — Ejecución Remota",
    "path-traversal":         "Path Traversal — Lectura Arbitraria de Ficheros",
    "lfi":                    "Inclusión Local de Ficheros — Ejecución de Código PHP",
    "file-upload":            "Subida Arbitraria de Ficheros — Despliegue de Webshell",
    "arbitrary-file-upload":  "Subida Arbitraria de Ficheros — Despliegue de Webshell",
    "missing-authorization":  "Falta de Autorización — Escalada de Privilegios",
    "ssrf":                   "Server-Side Request Forgery — Acceso a Red Interna",
    "auth-bypass":            "Bypass de Autenticación — Acceso No Autorizado",
    "idor":                   "IDOR — Acceso a Recursos de Otros Usuarios",
    "csrf":                   "CSRF — Acciones No Autorizadas en Nombre del Usuario",
    "ssti":                   "Server-Side Template Injection — Ejecución de Código",
    "xxe":                    "XML External Entity — Lectura de Ficheros / SSRF",
    "deserialization":        "Deserialización Insegura — Ejecución de Código",
    "open-redirect":          "Redirección Abierta — Phishing / Bypass OAuth",
    "dos":                    "Denegación de Servicio — Interrupción del Servicio",
    "redos":                  "ReDoS — Denegación de Servicio por Expresión Regular",
    "buffer-overflow":        "Corrupción de Memoria — Ejecución de Código",
    "stack-overflow":         "Desbordamiento de Pila — Ejecución de Código",
    "heap-overflow":          "Desbordamiento de Heap — Ejecución de Código",
    "uaf":                    "Use-After-Free — Corrupción de Memoria",
    "double-free":            "Double Free — Corrupción de Memoria",
    "format-string":          "Format String — Lectura/Escritura Arbitraria",
    "integer-overflow":       "Desbordamiento de Entero — Corrupción de Memoria",
    "type-confusion":         "Confusión de Tipos — Ejecución de Código",
    "oob-write":              "Escritura Fuera de Límites — Corrupción de Memoria",
    "oob-read":               "Lectura Fuera de Límites — Fuga de Información",
}

_TITLES_EN: Dict[str, str] = {
    "sqli":                   "SQL Injection — Arbitrary Database Read",
    "sql-injection":          "SQL Injection — Arbitrary Database Read",
    "xss":                    "Cross-Site Scripting — Session Hijacking",
    "stored-xss":             "Stored XSS — Persistent Client-Side Execution",
    "reflected-xss":          "Reflected XSS — Client-Side Execution",
    "rce":                    "Remote Code Execution — Full System Compromise",
    "code-injection":         "Code Injection — Remote Code Execution",
    "command-injection":      "OS Command Injection — Remote Code Execution",
    "path-traversal":         "Path Traversal — Arbitrary File Read",
    "lfi":                    "Local File Inclusion — PHP Code Execution",
    "file-upload":            "Arbitrary File Upload — Webshell Deployment",
    "arbitrary-file-upload":  "Arbitrary File Upload — Webshell Deployment",
    "missing-authorization":  "Missing Authorization — Privilege Escalation",
    "ssrf":                   "Server-Side Request Forgery — Internal Network Access",
    "auth-bypass":            "Authentication Bypass — Unauthorized Access",
    "idor":                   "IDOR — Unauthorized Access to User Resources",
    "csrf":                   "CSRF — Unauthorized Actions on Behalf of User",
    "ssti":                   "Server-Side Template Injection — Code Execution",
    "xxe":                    "XML External Entity — File Read / SSRF",
    "deserialization":        "Insecure Deserialization — Code Execution",
    "open-redirect":          "Open Redirect — Phishing / OAuth Bypass",
    "dos":                    "Denial of Service — Service Disruption",
    "redos":                  "ReDoS — Denial of Service via Regex",
    "buffer-overflow":        "Memory Corruption — Code Execution",
    "stack-overflow":         "Stack Overflow — Code Execution",
    "heap-overflow":          "Heap Overflow — Code Execution",
    "uaf":                    "Use-After-Free — Memory Corruption",
    "double-free":            "Double Free — Memory Corruption",
    "format-string":          "Format String — Arbitrary Read/Write",
    "integer-overflow":       "Integer Overflow — Memory Corruption",
    "type-confusion":         "Type Confusion — Code Execution",
    "oob-write":              "Out-of-Bounds Write — Memory Corruption",
    "oob-read":               "Out-of-Bounds Read — Information Leak",
}

_IMPACT_ES: Dict[str, str] = {
    "sqli":                  "Lectura y modificación arbitraria de la base de datos, incluyendo credenciales de usuarios y datos sensibles.",
    "xss":                   "Ejecución de JavaScript en el navegador de la víctima: robo de cookies/sesión, redirección a phishing, keylogging.",
    "rce":                   "Ejecución de comandos arbitrarios en el servidor. Compromiso total: exfiltración de datos, persistencia, pivoting.",
    "code-injection":        "Ejecución de código arbitrario en el servidor. Compromiso total.",
    "command-injection":     "Ejecución de comandos OS en el servidor. Compromiso total.",
    "path-traversal":        "Lectura de ficheros arbitrarios del servidor: claves privadas, credenciales, código fuente.",
    "file-upload":           "Subida de webshell al servidor. Ejecución de código arbitrario.",
    "missing-authorization": "Acceso a funciones restringidas sin autenticación. Modificación de datos de otros usuarios o administración del sistema.",
    "ssrf":                  "El servidor realiza peticiones HTTP a destinos internos. Enumeración de red interna, acceso a metadatos cloud (AWS IMDSv1).",
    "auth-bypass":           "Acceso a la aplicación sin credenciales válidas. Posible toma de control de cuentas.",
    "idor":                  "Acceso y modificación de recursos pertenecientes a otros usuarios cambiando un identificador.",
    "uaf":                   "Corrupción de memoria que puede derivar en ejecución de código arbitrario o escalada de privilegios.",
    "buffer-overflow":       "Corrupción de memoria. Con las condiciones adecuadas, ejecución de código arbitrario.",
    "format-string":         "Lectura arbitraria de memoria (infoleak) y escritura arbitraria (posible ejecución de código).",
}

_IMPACT_EN: Dict[str, str] = {
    "sqli":                  "Arbitrary read and write of the database, including user credentials and sensitive data.",
    "xss":                   "JavaScript execution in the victim's browser: session/cookie theft, phishing redirect, keylogging.",
    "rce":                   "Arbitrary command execution on the server. Full compromise: data exfiltration, persistence, pivoting.",
    "code-injection":        "Arbitrary code execution on the server. Full compromise.",
    "command-injection":     "OS command execution on the server. Full compromise.",
    "path-traversal":        "Read arbitrary server files: private keys, credentials, source code.",
    "file-upload":           "Upload a webshell to the server. Arbitrary code execution.",
    "missing-authorization": "Access to restricted functions without authentication. Modify other users' data or administer the system.",
    "ssrf":                  "Server makes HTTP requests to internal targets. Internal network enumeration, cloud metadata access (AWS IMDSv1).",
    "auth-bypass":           "Access the application without valid credentials. Possible account takeover.",
    "idor":                  "Access and modify resources belonging to other users by changing an identifier.",
    "uaf":                   "Memory corruption that may lead to arbitrary code execution or privilege escalation.",
    "buffer-overflow":       "Memory corruption. Under the right conditions, arbitrary code execution.",
    "format-string":         "Arbitrary memory read (infoleak) and arbitrary write (possible code execution).",
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class SecurityReport:
    cve_id:       str
    generated_at: str
    lang:         str
    sections:     List[str] = field(default_factory=list)
    metadata:     dict      = field(default_factory=dict)

    def to_markdown(self) -> str:
        return "\n\n".join(self.sections)

    def to_json(self) -> str:
        return json.dumps(self.metadata, indent=2, ensure_ascii=False)


# ── CVSS vector parser ────────────────────────────────────────────────────────

_CVSS_MEANINGS: Dict[str, Dict[str, str]] = {
    "AV": {"N": "Network — remotely exploitable", "A": "Adjacent network", "L": "Local access required", "P": "Physical access required"},
    "AC": {"L": "Low — no special conditions", "H": "High — specific conditions required"},
    "PR": {"N": "None — no privileges required", "L": "Low — authenticated user", "H": "High — admin/privileged"},
    "UI": {"N": "None — no user interaction", "R": "Required — victim must interact"},
    "S":  {"U": "Unchanged — impact stays in component", "C": "Changed — impact crosses scope boundary"},
    "C":  {"N": "None", "L": "Low — partial confidentiality impact", "H": "High — full confidentiality impact"},
    "I":  {"N": "None", "L": "Low — partial integrity impact", "H": "High — full integrity impact"},
    "A":  {"N": "None", "L": "Low — partial availability impact", "H": "High — full availability impact"},
}
_CVSS_FULL: Dict[str, str] = {
    "AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required",
    "UI": "User Interaction", "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability",
}


def _parse_cvss_vector(vector: str) -> List[dict]:
    """Parse CVSS 3.x vector string into list of {metric, value, full_name, meaning}."""
    result = []
    for part in vector.split("/"):
        if ":" not in part:
            continue
        metric, value = part.split(":", 1)
        if metric in ("CVSS", "cvss"):
            continue
        result.append({
            "metric":    metric,
            "value":     value,
            "full_name": _CVSS_FULL.get(metric, metric),
            "meaning":   _CVSS_MEANINGS.get(metric, {}).get(value, value),
        })
    return result


# ── Section builders ──────────────────────────────────────────────────────────

def _s_header(inv: Any, lang: str) -> str:
    titles = _TITLES_ES if lang == "es" else _TITLES_EN
    vc = (getattr(inv, "vuln_class", None) or "").lower()
    title = titles.get(vc, f"Vulnerability — {vc.upper() or 'Unknown Class'}")
    cve_id = getattr(inv, "cve_id", "CVE-UNKNOWN")
    date = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    conf = "Confidencial" if lang == "es" else "Confidential"
    return f"# [{cve_id}] — {title}\n*binoracle | {date} | {lang.upper()} | {conf}*"


def _s_executive_summary(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Resumen Ejecutivo" if es else "## Executive Summary"
    cve_id = getattr(inv, "cve_id", "?")
    score = getattr(inv, "cvss_score", None)
    severity = (getattr(inv, "cvss_severity", "") or "").upper()
    score_str = f"{score} ({severity})" if score else ("N/A")

    # Risk label — enhanced if EPSS/KEV available
    _notes = getattr(inv, "llm_notes", {}) or {}
    epss = _notes.get("epss_score") or getattr(inv, "epss_score", None)
    in_kev = _notes.get("in_cisa_kev") or getattr(inv, "in_cisa_kev", False)
    epss_pct = getattr(inv, "epss_percentile", None)
    if in_kev:
        risk = "CRITICAL-WEAPONIZED (CISA KEV — active exploitation in the wild)" if not es else "CRÍTICO-ARMADO (CISA KEV — explotación activa confirmada)"
    elif score and score >= 9.0:
        risk = "CRITICAL" if not es else "CRÍTICO"
    elif score and score >= 7.0:
        risk = "HIGH" if not es else "ALTO"
    elif score and score >= 4.0:
        risk = "MEDIUM" if not es else "MEDIO"
    else:
        risk = "LOW" if not es else "BAJO"

    has_exploit = getattr(inv, "is_gap", True)
    exploit_str = ("NO — CVE sin PoC público (HUECO)" if has_exploit else "SÍ") if es else \
                  ("NO — no public PoC (GAP)" if has_exploit else "YES")
    verified = getattr(inv, "verified", False)
    verified_str = ("SÍ — verificado en sandbox Docker" if verified else "NO — no verificado dinámicamente") if es else \
                   ("YES — verified in Docker sandbox" if verified else "NO — not dynamically verified")
    target = (_notes.get("source_url") or _notes.get("target_binary") or
              getattr(inv, "source_url", "") or "—")
    published = getattr(inv, "published", "—") or "—"

    rows = [
        ("CVE", cve_id),
        (("Puntuación CVSS" if es else "CVSS Score"), score_str),
        (("Nivel de Riesgo" if es else "Risk Level"), risk),
    ]
    if epss is not None:
        pct_str = f" — {epss_pct:.0%} percentile" if epss_pct else ""
        rows.append(("EPSS", f"{epss:.4f}{pct_str}"))
    rows += [
        (("Exploit Público" if es else "Public Exploit"), exploit_str),
        (("Verificado" if es else "Verified"), verified_str),
        (("Objetivo" if es else "Target"), target),
        (("Publicada (NVD)" if es else "Published (NVD)"), published),
    ]
    table = "| " + ("Campo" if es else "Field") + " | " + ("Valor" if es else "Value") + " |\n|---|---|\n"
    table += "\n".join(f"| {r} | {v} |" for r, v in rows)
    return f"{hdr}\n\n{table}"


def _s_description(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Descripción de la Vulnerabilidad" if es else "## Vulnerability Description"
    desc = (getattr(inv, "description", "") or "").strip()
    vc = (getattr(inv, "vuln_class", "") or "").lower()
    impacts = _IMPACT_ES if es else _IMPACT_EN
    impact_ctx = impacts.get(vc, "")
    if not desc:
        body = ("No se pudo obtener la descripción de la NVD." if es else
                "Could not retrieve description from NVD.")
    else:
        # Avoid verbatim NVD copy — wrap with professional framing
        preamble = (f"La vulnerabilidad afecta a **{(getattr(inv, 'llm_notes', {}) or {}).get('source_url', 'el componente objetivo')}** "
                    f"y pertenece a la clase **{vc.upper() or 'desconocida'}**. " if es else
                    f"The vulnerability affects **{(getattr(inv, 'llm_notes', {}) or {}).get('source_url', 'the target component')}** "
                    f"and belongs to the **{vc.upper() or 'unknown'}** class. ")
        body = preamble + desc
    if impact_ctx:
        body += "\n\n**" + ("Impacto técnico:" if es else "Technical impact:") + f"** {impact_ctx}"
    return f"{hdr}\n\n{body}"


def _s_attack_chain(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Cadena de Ataque" if es else "## Attack Chain"
    notes = (getattr(inv, "llm_notes", {}) or {})
    vc = (getattr(inv, "vuln_class", "") or "").lower()
    endpoint = notes.get("endpoint", "")
    method = notes.get("http_method", "POST")
    params = notes.get("parameters", [])
    param_str = ", ".join(f"`{p}`" for p in params) if params else "`<parameter>`"
    funcs = notes.get("vulnerable_functions", [])
    func_str = funcs[0] if funcs else "<vulnerable_function>"
    payload = (notes.get("payload_example") or notes.get("hueco_payload_hint") or
               notes.get("sqli_payload") or notes.get("xss_payload") or "<payload>")
    auth = notes.get("auth_required", "")
    auth_note = (f"- **Autenticación requerida:** {auth}" if es else
                 f"- **Authentication required:** {auth}") if auth else ""
    impacts_es = _IMPACT_ES
    impacts_en = _IMPACT_EN
    impact = (impacts_es if es else impacts_en).get(vc, "impacto según clase de vulnerabilidad" if es else "impact as per vulnerability class")

    steps: List[str] = []
    if endpoint:
        steps.append(("El atacante envía una petición HTTP " if es else "Attacker sends HTTP ") +
                     f"`{method} {endpoint}`")
    if param_str != "`<parameter>`":
        steps.append(("El parámetro " if es else "Parameter ") + param_str +
                     (" llega a `" if es else " reaches `") + func_str + ("` sin saneamiento adecuado" if es else "` without proper sanitization"))
    if str(payload) != "<payload>":
        steps.append(("El payload " if es else "Payload ") + f"`{str(payload)[:100]}`" +
                     (" activa la vulnerabilidad" if es else " triggers the vulnerability"))
    steps.append(("**Resultado:** " if es else "**Result:** ") + impact)

    if not steps:
        return (f"{hdr}\n\n" +
                ("Información insuficiente para construir la cadena de ataque completa. "
                 "Revisar `llm_notes` del Investigation object." if es else
                 "Insufficient data to build a complete attack chain. Check Investigation `llm_notes`."))

    chain = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
    auth_line = f"\n\n{auth_note}" if auth_note else ""
    return f"{hdr}\n\n{chain}{auth_line}"


def _s_proof_of_concept(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Prueba de Concepto (PoC)" if es else "## Proof of Concept (PoC)"
    notes = (getattr(inv, "llm_notes", {}) or {})
    verified = getattr(inv, "verified", False)
    verified_ev = (getattr(inv, "verified_evidence", {}) or {})

    # Prefer confirmed evidence from Docker lab over LLM hypothesis when verified
    if verified and verified_ev:
        method = verified_ev.get("metodo") or verified_ev.get("method") or notes.get("http_method", "GET")
        endpoint = verified_ev.get("endpoint") or notes.get("endpoint", "/")
        _param = (verified_ev.get("parametro_ganador") or verified_ev.get("path_param")
                  or verified_ev.get("sqli_param") or "param")
        _payload = verified_ev.get("payload_ganador") or verified_ev.get("payload") or "PAYLOAD"
        params = [_param]
        payload = _payload
        custom_headers = notes.get("custom_headers", {}) or {}
        _confirmed_note = ("\n> ✅ **PoC confirmado en laboratorio Docker** — payload verificado empíricamente." if es else
                           "\n> ✅ **Lab-confirmed PoC** — payload verified empirically in isolated Docker sandbox.")
    else:
        method = notes.get("http_method", "POST")
        endpoint = notes.get("endpoint", "/wp-admin/admin-ajax.php")
        params = notes.get("parameters", [])
        payload = (notes.get("payload_example") or notes.get("hueco_payload_hint") or
                   notes.get("sqli_payload") or notes.get("xss_payload") or "PAYLOAD")
        custom_headers = notes.get("custom_headers", {}) or {}
        _confirmed_note = ""

    target = (notes.get("source_url") or "target.example.com").replace("https://", "").replace("http://", "").rstrip("/")

    headers_str = ""
    if custom_headers:
        headers_str = "\n".join(f"{k}: {v}" for k, v in custom_headers.items()) + "\n"

    if params:
        body = "&".join(f"{p}={payload if i == 0 else '<value>'}" for i, p in enumerate(params))
    else:
        body = f"param={payload}"

    if method.upper() == "GET":
        poc = f"GET {endpoint}?{body} HTTP/1.1\nHost: {target}\n{headers_str}"
        poc_body = ""
    else:
        ct = "Content-Type: application/x-www-form-urlencoded\n"
        poc = f"POST {endpoint} HTTP/1.1\nHost: {target}\n{ct}{headers_str}"
        poc_body = body

    http_block = f"```http\n{poc}\n{poc_body}\n```"

    # Also show curl
    if method.upper() == "GET":
        curl = f"curl -sk 'https://{target}{endpoint}?{body}'"
    else:
        curl = f"curl -sk -X POST 'https://{target}{endpoint}' \\\n  --data-urlencode '{body}'"

    gap_note = ""
    if getattr(inv, "is_gap", False):
        hueco_src = notes.get("hueco_source", "")
        conf = notes.get("hueco_confidence", 0.0)
        src_lbl = ("descripción NVD únicamente" if hueco_src == "description_only" else "análisis de código fuente") if es else \
                  ("NVD description only" if hueco_src == "description_only" else "source code analysis")
        gap_note = (f"\n> ⚠️ **Sin PoC público.** Este PoC fue derivado por el LLM desde {src_lbl} "
                    f"(confidence={conf:.0%}). Validar en laboratorio antes de usar." if es else
                    f"\n> ⚠️ **No public PoC.** This PoC was derived by the LLM from {src_lbl} "
                    f"(confidence={conf:.0%}). Validate in lab before use.")

    return f"{hdr}{_confirmed_note}{gap_note}\n\n{http_block}\n\n```bash\n# curl equivalent\n{curl}\n```"


def _s_verification(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Evidencia de Verificación" if es else "## Verification Evidence"
    verified = getattr(inv, "verified", False)
    dv = (getattr(inv, "dynamic_verify", {}) or {})
    attempted = dv.get("attempted", False)

    if verified:
        status = ("✅ **VERIFICADO** — reproducido en sandbox Docker aislado" if es else
                  "✅ **VERIFIED** — reproduced in isolated Docker sandbox")
    elif attempted:
        status = ("⚠️ **INTENTADO, NO CONFIRMADO** — el laboratorio no produjo evidencia definitiva" if es else
                  "⚠️ **ATTEMPTED, NOT CONFIRMED** — lab did not produce definitive evidence")
    else:
        status = ("❌ **NO VERIFICADO DINÁMICAMENTE** — solo análisis estático / hipótesis LLM" if es else
                  "❌ **NOT DYNAMICALLY VERIFIED** — static analysis / LLM hypothesis only")

    lines = [hdr, "", status]

    # HTTP evidence
    http_ev = dv.get("http_evidence") or dv.get("evidence") or dv.get("response_body", "")
    if http_ev:
        truncated = str(http_ev)[:500]
        lines.append("\n**" + ("Evidencia HTTP (truncada):" if es else "HTTP Evidence (truncated):") + "**")
        lines.append(f"```\n{truncated}\n```")

    # Screenshots
    screenshots = getattr(inv, "screenshots", []) or []
    if screenshots:
        lines.append("\n**" + ("Capturas de pantalla:" if es else "Screenshots:") + f"** {len(screenshots)} " +
                     ("captura(s) disponible(s) en el informe HTML." if es else "screenshot(s) available in the HTML report."))

    # Verification steps
    steps = dv.get("steps", [])
    if steps:
        lines.append("\n**" + ("Pasos de verificación:" if es else "Verification steps:") + "**")
        for s in steps[:5]:
            lines.append(f"- {s}")

    # Weaponization evidence — concrete post-verification impact extracted
    _wep = dv.get("weaponization") or (getattr(inv, "verified_evidence", {}) or {}).get("weaponization")
    if _wep and _wep.get("impact"):
        lines.append("")
        lines.append("**" + ("Impacto extraído (post-verificación):" if es else "Extracted Impact (post-verification):") + "**")
        lines.append(f"> {_wep['impact']}")
        _wdata = _wep.get("data") or {}
        if _wdata:
            lines.append("")
            lines.append("```json")
            import json as _jw
            lines.append(_jw.dumps(_wdata, ensure_ascii=False, indent=2)[:600])
            lines.append("```")

    # Rich exploitation evidence (SQLi extraction, SSTI RCE, LFI escalation, etc.)
    _ev = getattr(inv, "verified_evidence", {}) or {}
    _rich_items = []
    # SQLi UNION / bool-blind extraction
    if _ev.get("mysql_version_extraida") or _ev.get("extracted_version"):
        _v = _ev.get("mysql_version_extraida") or _ev.get("extracted_version")
        _rich_items.append(("MySQL version extraída" if es else "MySQL version extracted", _v))
    if _ev.get("db_user") or _ev.get("extracted_user"):
        _rich_items.append(("DB user" , _ev.get("db_user") or _ev.get("extracted_user")))
    if _ev.get("extracted_database"):
        _rich_items.append(("DB nombre actual" if es else "Current database name", _ev.get("extracted_database")))
    if _ev.get("db_tables"):
        _tbl_list = _ev["db_tables"]
        _rich_items.append(("Tablas del esquema" if es else "Schema tables",
                            ", ".join(_tbl_list[:10]) + ("..." if len(_tbl_list) > 10 else "")))
    if _ev.get("wp_users_hashes"):
        _rich_items.append(("Hashes wp_users (truncado)" if es else "wp_users hashes (truncated)",
                            str(_ev["wp_users_hashes"])[:200]))
    # SSTI RCE escalation
    if _ev.get("ssti_rce"):
        _rce = _ev["ssti_rce"]
        _rich_items.append(("SSTI → RCE técnica" if es else "SSTI → RCE technique",
                            f"{_rce.get('technique')} (token: {_rce.get('token_confirmed')})"))
    if _ev.get("ssti_rce_id_output"):
        _rich_items.append(("Salida de id (SSTI RCE)" if es else "id output (SSTI RCE)",
                            _ev["ssti_rce_id_output"]))
    # LFI post-exploitation
    if _ev.get("aws_credentials_found"):
        _rich_items.append(("AWS credentials vía LFI" if es else "AWS credentials via LFI",
                            _ev["aws_credentials_found"]))
    if _ev.get("k8s_service_account_token_found"):
        _rich_items.append(("K8s SA token vía LFI" if es else "K8s SA token via LFI",
                            _ev["k8s_service_account_token_found"]))
    if _ev.get("etc_shadow_readable"):
        _rich_items.append(("/etc/shadow legible" if es else "/etc/shadow readable",
                            "root hash expuesto" if es else "root hash exposed"))
    # IDOR user metadata
    if _ev.get("user_idor", {}).get("has_email"):
        _ui = _ev["user_idor"]
        _rich_items.append(("IDOR user metadata (admin ID=1)" if es else "IDOR user metadata (admin ID=1)",
                            f"email leakeado, status={_ui.get('status')}" if es else
                            f"email leaked, status={_ui.get('status')}"))
    # SSTI post-exploit weaponization (from weaponize.py _weaponize_ssti)
    _wep_data = (_wep or {}).get("data") or {}
    if _wep and _wep.get("technique") == "ssti_post_exploit":
        if _wep_data.get("id_output"):
            _rich_items.append(("SSTI RCE id output" if es else "SSTI RCE id output",
                                _wep_data["id_output"]))
        if _wep_data.get("etc_passwd_lines"):
            _rich_items.append(("/etc/passwd (SSTI file read)" if es else "/etc/passwd (SSTI file read)",
                                " | ".join(_wep_data["etc_passwd_lines"][:2])))
    # Direct SSTI /etc/passwd read (from wpverify.py ssti_etc_passwd)
    if _ev.get("ssti_etc_passwd"):
        _rich_items.append(("/etc/passwd (SSTI directo)" if es else "/etc/passwd (SSTI direct)",
                            " | ".join(str(l) for l in _ev["ssti_etc_passwd"][:2])))
    # SSRF internal metadata (from weaponize.py _weaponize_ssrf)
    if _wep and _wep.get("technique") == "ssrf_probe":
        _probed = _wep_data.get("probed") or {}
        for _lbl, _probe_info in list(_probed.items())[:3]:
            _rich_items.append((f"SSRF → {_lbl}", _probe_info.get("snippet", "")[:100]))
    if _rich_items:
        lines.append("")
        lines.append("**" + ("Datos extraídos de la explotación:" if es else "Data extracted via exploitation:") + "**")
        lines.append("")
        lines.append("| " + ("Campo" if es else "Field") + " | " + ("Valor" if es else "Value") + " |")
        lines.append("|---|---|")
        for _field, _val in _rich_items:
            lines.append(f"| {_field} | `{str(_val)[:120]}` |")

    return "\n".join(lines)


def _s_technical_analysis(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Análisis Técnico" if es else "## Technical Analysis"
    notes = (getattr(inv, "llm_notes", {}) or {})
    sg = (getattr(inv, "source_grounding", {}) or {})
    mitigations = (getattr(inv, "mitigations", "") or "")
    lines = [hdr]

    # Vulnerable code grounding
    found = sg.get("found", {})
    if found:
        lines.append("\n### " + ("Funciones vulnerables confirmadas en código real" if es else "Vulnerable functions confirmed in real source"))
        for fn, locs in found.items():
            loc_str = locs[0] if locs else "?"
            lines.append(f"- `{fn}` → `{loc_str}`")

    # Source analysis
    rationale = getattr(inv, "rationale", "") or notes.get("reasoning", "") or ""
    if rationale:
        lines.append("\n### " + ("Análisis del flujo vulnerable" if es else "Vulnerable flow analysis"))
        lines.append(str(rationale)[:1500])

    # HUECO step-by-step reasoning
    hueco_steps = notes.get("hueco_reasoning", [])
    if hueco_steps:
        lines.append("\n### " + ("Derivación del ataque (sin fuente pública)" if es else "Attack derivation (no public source)"))
        for i, s in enumerate(hueco_steps, 1):
            lines.append(f"{i}. {s}")

    # Mitigation context
    if mitigations:
        lines.append("\n### " + ("Mitigaciones presentes en el binario/app" if es else "Mitigations in binary/app"))
        lines.append(str(mitigations)[:600])

    if len(lines) == 1:
        lines.append("No hay evidencia de código fuente disponible. Ver sección PoC para la hipótesis." if es else
                     "No source code evidence available. See PoC section for the hypothesis.")

    return "\n".join(lines)


def _s_cvss_breakdown(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Desglose CVSS 3.1" if es else "## CVSS 3.1 Breakdown"
    vector = (getattr(inv, "cvss_vector", "") or "").strip()
    if not vector or ":" not in vector:
        return f"{hdr}\n\n" + ("Vector CVSS no disponible." if es else "CVSS vector not available.")
    parsed = _parse_cvss_vector(vector)
    if not parsed:
        return f"{hdr}\n\n" + (f"Vector: `{vector}`")
    table_hdr = "| Métrica | Valor | Significado |" if es else "| Metric | Value | Meaning |"
    rows = "\n".join(f"| {p['full_name']} (`{p['metric']}`) | `{p['value']}` | {p['meaning']} |"
                     for p in parsed)
    return f"{hdr}\n\n`{vector}`\n\n{table_hdr}\n|---|---|---|\n{rows}"


class _InvAsFinding:
    """Thin adapter so enrich.map_cwe / auto_cvss can consume an Investigation."""
    def __init__(self, inv: Any):
        notes = (getattr(inv, "llm_notes", {}) or {})
        self.evidence = " ".join([
            getattr(inv, "description", "") or "",
            (getattr(inv, "vuln_class", "") or ""),
            str(notes.get("endpoint", "")),
            str(notes.get("payload_example", "")),
            str(notes.get("hueco_payload_hint", "")),
        ])
        self.title    = f"{getattr(inv, 'cve_id', '')} {getattr(inv, 'vuln_class', '')}"
        self.rationale = str(notes.get("reasoning", "") or getattr(inv, "rationale", "") or "")
        sev = getattr(inv, "cvss_severity", "medium") or "medium"
        self.severity = sev.lower()
        self.verdict  = "verified" if getattr(inv, "verified", False) else "grounded"


def _s_cwe(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Clasificación CWE" if es else "## CWE Classification"
    # Prefer CWEs from the first enriched finding if available
    findings = getattr(inv, "findings", []) or []
    cwes: List[str] = []
    for f in findings:
        if hasattr(f, "cwes") and f.cwes:
            cwes = list(f.cwes)[:5]
            break
    if not cwes:
        try:
            from .enrich import map_cwe
            cwes = map_cwe(_InvAsFinding(inv))
        except Exception:
            cwes = []
    if not cwes:
        return f"{hdr}\n\n" + ("CWE no determinado automáticamente." if es else "CWE not automatically determined.")
    items = "\n".join(f"- [{c}](https://cwe.mitre.org/data/definitions/{c.split(':')[0].replace('CWE-','')}.html)" for c in cwes)
    return f"{hdr}\n\n{items}"


def _s_remediation(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Remediación" if es else "## Remediation"
    notes = (getattr(inv, "llm_notes", {}) or {})
    source_url = notes.get("source_url", "")
    affected_version = notes.get("affected_version", "")
    vc = (getattr(inv, "vuln_class", "") or "").lower()

    _fixes_es: Dict[str, str] = {
        "sqli":                  "Usar consultas parametrizadas (prepared statements). Nunca concatenar variables de usuario en SQL.",
        "xss":                   "Escapar toda salida HTML con `esc_html()` / `htmlspecialchars()`. CSP estricta como defensa en profundidad.",
        "rce":                   "Validar y sanitizar todas las entradas antes de pasarlas a `eval()`, `call_user_func()` o similares. Deshabilitar funciones peligrosas en `php.ini`.",
        "code-injection":        "Eliminar el uso de `eval()` / `call_user_func()` sobre datos del usuario. Usar un allowlist de funciones permitidas.",
        "command-injection":     "Usar `escapeshellarg()` / `escapeshellcmd()`. Preferir APIs nativas sobre comandos de shell.",
        "path-traversal":        "Validar que la ruta resulta ser un path de tipo canonicalizado dentro del directorio permitido. Usar `realpath()` y verificar el prefijo.",
        "file-upload":           "Validar la extensión y tipo MIME en el servidor. Almacenar fuera de webroot. Renombrar el fichero con un nombre aleatorio.",
        "missing-authorization": "Añadir `current_user_can()` / `check_ajax_referer()` al inicio del handler AJAX.",
        "ssrf":                  "Validar y filtrar las URLs contra una allowlist de dominios. Deshabilitar redirects. Bloquear rangos IP internos.",
        "auth-bypass":           "Revisar todos los puntos de entrada para validación de sesión/token consistente.",
        "deserialization":       "No deserializar datos no confiables. Usar JSON en lugar de formatos binarios. Implementar HMAC sobre los datos serializados.",
        "ssti":                  "Pasar datos al motor de plantillas como variables de contexto, nunca como parte de la plantilla misma.",
    }
    _fixes_en: Dict[str, str] = {
        "sqli":                  "Use parameterized queries (prepared statements). Never concatenate user variables into SQL.",
        "xss":                   "Escape all HTML output with `esc_html()` / `htmlspecialchars()`. Strict CSP as defense in depth.",
        "rce":                   "Validate and sanitize all inputs before passing to `eval()`, `call_user_func()` or similar. Disable dangerous functions in `php.ini`.",
        "code-injection":        "Remove use of `eval()` / `call_user_func()` on user data. Use an allowlist of permitted functions.",
        "command-injection":     "Use `escapeshellarg()` / `escapeshellcmd()`. Prefer native APIs over shell commands.",
        "path-traversal":        "Validate that the resolved path is within the allowed directory using `realpath()` and prefix check.",
        "file-upload":           "Validate extension and MIME type server-side. Store outside webroot. Rename with a random filename.",
        "missing-authorization": "Add `current_user_can()` / `check_ajax_referer()` at the top of the AJAX handler.",
        "ssrf":                  "Validate and filter URLs against a domain allowlist. Disable redirects. Block internal IP ranges.",
        "auth-bypass":           "Review all entry points for consistent session/token validation.",
        "deserialization":       "Do not deserialize untrusted data. Use JSON instead of binary formats. Implement HMAC over serialized data.",
        "ssti":                  "Pass data to the template engine as context variables, never as part of the template string itself.",
    }
    fixes = _fixes_es if es else _fixes_en
    fix = fixes.get(vc, ("Revisar el código del componente afectado y aplicar el parche oficial." if es else
                         "Review the affected component's code and apply the official patch."))

    lines = [hdr, "", "### " + ("Corrección específica" if es else "Specific fix"), fix]
    if affected_version:
        lines.append("\n**" + ("Versión afectada:" if es else "Affected version:") + f"** `{affected_version}`")
    if source_url:
        lines.append("**" + ("Referencia del parche:" if es else "Patch reference:") + f"** [{source_url}]({source_url})")

    patch_summary = getattr(inv, "patch_summary", "") or ""
    if patch_summary:
        lines.append("\n### " + ("Resumen del parche" if es else "Patch summary"))
        lines.append(str(patch_summary)[:600])

    return "\n".join(lines)


def _s_references(inv: Any, lang: str) -> str:
    es = lang == "es"
    hdr = "## Referencias" if es else "## References"
    cve_id = getattr(inv, "cve_id", "")
    lines = [hdr, "", f"- NVD: https://nvd.nist.gov/vuln/detail/{cve_id}"]
    if cve_id:
        lines.append(f"- MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
        lines.append(f"- OSV: https://osv.dev/vulnerability/{cve_id}")

    exploit_refs = getattr(inv, "exploit_refs", []) or []
    for ref in exploit_refs[:6]:
        url = getattr(ref, "url", str(ref)) if not isinstance(ref, str) else ref
        source = getattr(ref, "source", "exploit") if not isinstance(ref, str) else "ref"
        if url:
            lines.append(f"- [{source.upper()}]: {url}")

    notes = (getattr(inv, "llm_notes", {}) or {})
    source_url = notes.get("source_url", "")
    if source_url and source_url not in "\n".join(lines):
        lines.append("- " + ("Código fuente afectado:" if es else "Affected source:") + f" {source_url}")

    return "\n".join(lines)


# ── Main generator ────────────────────────────────────────────────────────────

def generate_report(inv: Any, lang: str = "es") -> SecurityReport:
    """Generate a world-class professional security report from an Investigation."""
    cve_id = getattr(inv, "cve_id", "CVE-UNKNOWN")
    generated_at = datetime.datetime.utcnow().isoformat() + "Z"

    sections = [
        _s_header(inv, lang),
        _s_executive_summary(inv, lang),
        _s_description(inv, lang),
        _s_attack_chain(inv, lang),
        _s_proof_of_concept(inv, lang),
        _s_verification(inv, lang),
        _s_technical_analysis(inv, lang),
        _s_cvss_breakdown(inv, lang),
        _s_cwe(inv, lang),
        _s_remediation(inv, lang),
        _s_references(inv, lang),
    ]

    # Build metadata dict for JSON export
    notes = (getattr(inv, "llm_notes", {}) or {})
    try:
        from .enrich import map_cwe, auto_cvss
        _fake = _InvAsFinding(inv)
        cwes = map_cwe(_fake)
        cvss_est = auto_cvss(_fake)
        cvss_meta = {"vector": cvss_est.vector, "score": cvss_est.score}
    except Exception:
        cwes = []
        cvss_meta = {}

    metadata = {
        "cve_id":         cve_id,
        "generated_at":   generated_at,
        "lang":           lang,
        "cvss_score":     getattr(inv, "cvss_score", None),
        "cvss_severity":  getattr(inv, "cvss_severity", ""),
        "cvss_vector":    getattr(inv, "cvss_vector", ""),
        "cvss_estimated": cvss_meta,
        "epss_score":     getattr(inv, "epss_score", None),
        "epss_percentile": getattr(inv, "epss_percentile", None),
        "in_cisa_kev":    getattr(inv, "in_cisa_kev", False),
        "vuln_class":     getattr(inv, "vuln_class", ""),
        "verified":       getattr(inv, "verified", False),
        "is_gap":         getattr(inv, "is_gap", False),
        "published":      getattr(inv, "published", ""),
        "cwes":           cwes,
        "endpoint":       notes.get("endpoint", ""),
        "parameters":     notes.get("parameters", []),
        "auth_required":  notes.get("auth_required", ""),
        "affected_version": notes.get("affected_version", ""),
        "source_url":     notes.get("source_url", ""),
    }

    return SecurityReport(
        cve_id=cve_id,
        generated_at=generated_at,
        lang=lang,
        sections=sections,
        metadata=metadata,
    )


# ── Save to disk ──────────────────────────────────────────────────────────────

def save_report(report: SecurityReport, output_dir: str = "") -> str:
    """Save report markdown to ~/.binoracle/reports/{CVE_ID}.md. Returns path."""
    if not output_dir:
        output_dir = os.path.join(os.path.expanduser("~"), ".binoracle", "reports")
    os.makedirs(output_dir, exist_ok=True)
    fname = f"{report.cve_id}.md"
    path = os.path.join(output_dir, fname)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report.to_markdown())
    return path
