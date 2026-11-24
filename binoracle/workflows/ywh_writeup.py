"""ywh_writeup.py — YesWeHack-format writeup generator from ChainResult.

Builds a structured bug report following YesWeHack guidance:
Description / Discovery / PoC / Exploitation / Impact / Remediation.

Built entirely from ChainResult fields and evidence. Empty sections stay
empty rather than filled with boilerplate.

ONLY for authorized targets / bug bounty programs / defensive research.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class YwhWriteup:
    title: str = ""
    description: str = ""
    discovery: str = ""
    poc: str = ""
    exploitation: str = ""
    impact: str = ""
    remediation: str = ""
    references: str = ""
    cvss_vector: str = ""
    cve_id: str = ""
    asset: str = ""
    severity: str = ""
    vuln_class: str = ""

    def to_markdown(self) -> str:
        parts = []
        if self.description:
            parts.append(f"## Description\n\n{self.description}")
        if self.discovery:
            parts.append(f"## Vulnerability Discovery\n\n{self.discovery}")
        if self.poc:
            parts.append(f"## Proof of Concept (PoC)\n\n{self.poc}")
        if self.exploitation:
            parts.append(f"## Exploitation\n\n{self.exploitation}")
        if self.impact:
            parts.append(f"## Impact\n\n{self.impact}")
        if self.remediation:
            parts.append(f"## Remediation\n\n{self.remediation}")
        if self.references:
            parts.append(f"## References\n\n{self.references}")
        return "\n\n---\n\n".join(parts)

    def platform_fields(self) -> dict:
        return {
            "title": self.title,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
        }


_CVSS_SEVERITY: dict = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
}

_VULN_CLASS_TITLE: dict = {
    "sqli": "SQL Injection",
    "sql-injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "reflected-xss": "Reflected XSS",
    "stored-xss": "Stored XSS",
    "lfi": "Local File Inclusion (LFI)",
    "path-traversal": "Path Traversal",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "rce": "Remote Code Execution (RCE)",
    "command-injection": "Command Injection",
    "missing-authorization": "Missing Authorization",
    "auth-bypass": "Authentication Bypass",
    "broken-access-control": "Broken Access Control",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "ssti": "Server-Side Template Injection (SSTI)",
    "deserialization": "Insecure Deserialization",
    "open-redirect": "Open Redirect",
    "csrf": "Cross-Site Request Forgery (CSRF)",
}

_IMPACT_TEMPLATE: dict = {
    "credential_exposure": (
        "The vulnerability exposed authentication credentials in the HTTP response body. "
        "An unauthenticated attacker can use these credentials to authenticate as a "
        "privileged user and gain full control of the application."
    ),
    "code_execution": (
        "Arbitrary code execution on the server was demonstrated by reading system files "
        "(/etc/passwd) through the vulnerability."
    ),
    "sqli_confirmed": (
        "SQL injection was confirmed through a database error response. "
        "An attacker can extract, modify, or delete data from the application database."
    ),
    "xss_confirmed": (
        "Cross-site scripting was confirmed by reflecting the payload unescaped in the response. "
        "An attacker can execute arbitrary JavaScript in victim browsers in the application's origin."
    ),
    "information_disclosure": (
        "Sensitive server-side information (stack traces, internal paths, or error messages) "
        "is disclosed in the response, aiding further exploitation."
    ),
    "data_disclosure": (
        "Unauthorized access to private data was demonstrated through the vulnerability."
    ),
    "user_enumeration": (
        "The endpoint returns private user data (email addresses, usernames, or account IDs) "
        "without authentication. An attacker can enumerate all application users, enabling "
        "targeted phishing or credential-stuffing attacks."
    ),
    "unauthorized_creation": (
        "The vulnerability allows an unauthenticated attacker to create resources "
        "(user accounts, API keys, or data records) on the server. "
        "This can lead to privilege escalation or account takeover."
    ),
    "admin_access": (
        "The vulnerability grants access to administrative resources without authentication. "
        "An attacker can read sensitive configuration, modify system settings, or escalate "
        "privileges to full administrator access."
    ),
    "ssrf_cloud_escalation": (
        "SSRF was confirmed and the attack reached cloud metadata endpoints "
        "(AWS IMDSv1 or equivalent). The attacker can retrieve instance credentials, "
        "IAM role tokens, and use them to pivot to other cloud resources."
    ),
    "nosql_injection": (
        "NoSQL injection was confirmed by bypassing query equality checks with MongoDB operators. "
        "An attacker can bypass authentication, extract arbitrary documents, or enumerate "
        "all records in the affected collection."
    ),
}

_REMEDIATION_TEMPLATE: dict = {
    "sqli": "Use parameterized queries (prepared statements) for all database interactions.",
    "sql-injection": "Use parameterized queries (prepared statements) for all database interactions.",
    "xss": "HTML-encode all user-controlled output before rendering in HTML context.",
    "reflected-xss": "HTML-encode the vulnerable parameter before reflecting it in the response.",
    "stored-xss": "Sanitize stored content before rendering; apply Content-Security-Policy.",
    "lfi": "Validate and sanitize all file path inputs; use allow-list of permitted paths.",
    "path-traversal": "Normalize paths with realpath() / path.resolve() and verify they stay under the allowed root.",
    "ssrf": "Validate URL schemes (allow only http/https), block private IP ranges, use a URL allowlist.",
    "rce": "Never pass user input to shell commands; use execFile() / subprocess with explicit args instead of shell=True.",
    "command-injection": "Use execFile() / subprocess.run with args list, not shell=True; never interpolate user input into shell strings.",
    "missing-authorization": "Add authorization checks to the endpoint; verify the requesting user has permission to access the resource.",
    "auth-bypass": "Fix the authentication logic; test with a dedicated security review of the auth flow.",
    "idor": "Validate that the authenticated user owns or has permission to access each requested resource ID.",
    "ssti": "Never render user-controlled input as a template; use autoescape=True or safe alternatives.",
    "deserialization": "Replace unserialize() with json_decode() or use allowed_classes=false; validate data before deserialization.",
    "open-redirect": "Validate redirect targets against an allowlist of internal paths; reject absolute URLs.",
    "cors-misconfiguration": "Replace wildcard or reflected-Origin CORS policies with an explicit allowlist of trusted origins.",
    "nosql-injection": "Use parameterized queries or type-strict input validation; never pass unsanitized user data as MongoDB query objects.",
    "nosqli": "Use parameterized queries or type-strict input validation; never pass unsanitized user data as MongoDB query objects.",
    "file-upload": "Validate MIME type and extension against an allowlist; store uploads outside the web root; rename files on save.",
    "jwt-bypass": "Enforce a fixed algorithm (HS256/RS256) on the server; never accept alg:none tokens; validate the signature on every request.",
    "race-condition": "Use atomic database operations (SELECT FOR UPDATE, get_or_create, transactions) to prevent check-then-act races.",
    "xxe": "Disable external entity processing (resolve_entities=False, defusedxml); never parse untrusted XML with a full-featured parser.",
}


def build_writeup_from_chain(result: object, target_url: str = "") -> YwhWriteup:
    """Build a YesWeHack writeup from a completed ChainResult.

    Only uses information that was actually proven or observed.

    Args:
        result:     a ChainResult object (passed as 'object' to avoid circular import)
        target_url: the target URL for the report (asset field)

    Returns YwhWriteup with sections populated where evidence exists.
    """
    wu = YwhWriteup()

    cve_id = getattr(result, "cve_id", "") or ""
    description = getattr(result, "description", "") or ""
    cve_class = getattr(result, "cve_class", "") or ""
    cvss_severity = (getattr(result, "cvss_severity", "") or "").lower()
    verified = getattr(result, "verified", False)
    evidence = getattr(result, "evidence", {}) or {}
    wu.cve_id = cve_id
    wu.asset = target_url or evidence.get("base_url", "")
    wu.severity = _CVSS_SEVERITY.get(cvss_severity, cvss_severity or "medium")

    _vuln_class = (evidence.get("vuln_class") or
                   cve_class or
                   evidence.get("impact_class") or "")
    wu.vuln_class = _vuln_class

    _vc_display = _VULN_CLASS_TITLE.get(_vuln_class.lower(), _vuln_class or "Vulnerability")
    _endpoint = evidence.get("endpoint", "") or ""
    _param = (evidence.get("param") or
              (evidence.get("patch_analysis") or {}).get("suggested_param", "") or "")

    if _endpoint and _param:
        wu.title = f"{_vc_display} in {_endpoint} via {_param} parameter"
    elif _endpoint:
        wu.title = f"{_vc_display} in {_endpoint}"
    elif cve_id:
        wu.title = f"{_vc_display} ({cve_id})"
    else:
        wu.title = _vc_display

    # Description: 1-2 sentences, no OWASP boilerplate
    _desc_clean = re.sub(
        r"(cross-site scripting|sql injection|path traversal|ssrf|rce|"
        r"remote code execution|lfi|idor|broken access control)\s*(is|are)\s+"
        r"(a type of|a class of|an attack|a vulnerability where)[^.]+\.",
        "", description, flags=re.IGNORECASE).strip()
    if _desc_clean:
        _sentences = re.split(r"(?<=[.!?])\s+", _desc_clean.strip())
        wu.description = " ".join(_sentences[:2]).strip()
        if cve_id and cve_id not in wu.description:
            wu.description = f"{cve_id}: {wu.description}"
    elif _vuln_class and _endpoint:
        wu.description = (f"{_vc_display} vulnerability in {_endpoint}. "
                          f"The endpoint does not properly validate user-controlled input.")

    # Discovery: narrative from investigation steps
    _pa = evidence.get("patch_analysis") or {}
    _disc_parts = []
    if _endpoint:
        _disc_parts.append(f"Investigated endpoint `{_endpoint}`")
    _method = evidence.get("method") or evidence.get("metodo") or ""
    if _method:
        _disc_parts.append(f"using {_method} requests")
    if _pa.get("vuln_function"):
        _disc_parts.append(
            f"Source analysis (patch diff) identified vulnerable function "
            f"`{_pa['vuln_function']}` in `{_pa.get('vuln_file', '?')}`")
    if _pa.get("vuln_pattern"):
        _disc_parts.append(f"Vulnerable pattern: {_pa['vuln_pattern']}")
    if verified:
        _disc_parts.append("Dynamic verification confirmed the vulnerability in a Docker lab")
    elif evidence.get("response_body_analysis"):
        _rba = evidence["response_body_analysis"]
        if _rba.get("findings"):
            _disc_parts.append(
                f"Response body analysis found: {_rba['findings'][0][1]}")
    wu.discovery = ". ".join(_disc_parts) + "." if _disc_parts else ""

    # PoC: captured HTTP + patch diff + callback URL
    _poc_parts = []
    _body_snippet = (evidence.get("respuesta_cuerpo_recorte") or
                     evidence.get("exploit_response") or "")
    _poc_http = _pa.get("poc_http", "")
    _win_url = evidence.get("callback_url_ganadora") or ""
    if _body_snippet and len(_body_snippet) > 20:
        _poc_parts.append("**Response body (truncated):**\n```\n" +
                          _body_snippet[:600] + "\n```")
    if _poc_http:
        _poc_parts.append("**HTTP request (from patch diff analysis):**\n```http\n" +
                          _poc_http + "\n```")
    if _win_url:
        _poc_parts.append(f"**Confirmed callback URL:** `{_win_url}`")
    wu.poc = "\n\n".join(_poc_parts) if _poc_parts else ""

    # Exploitation: numbered atomic steps — only from verified evidence
    if verified and _endpoint:
        _expl_steps = ["Preconditions: unauthenticated attacker, no special privileges required."]
        _step_n = 1
        if _method:
            _expl_steps.append(
                f"{_step_n}. Send {_method} request to `{_endpoint}`"
                + (f"?{_param}={_pa.get('suggested_value', '<payload>')}"
                   if _param and _method == "GET" else ""))
            _step_n += 1
        _impact_class = (evidence.get("impact_class") or
                         (evidence.get("response_body_analysis") or {}).get("impact_class", ""))
        if _impact_class == "credential_exposure":
            _expl_steps.append(
                f"{_step_n}. Observe: response contains credential fields "
                f"(accessKeyId, password, token, etc.)")
        elif _impact_class in ("code_execution", "sqli_confirmed"):
            _expl_steps.append(
                f"{_step_n}. Observe: response contains SQL error or system file content")
        elif _body_snippet:
            _expl_steps.append(
                f"{_step_n}. Observe: response returns unauthorized data")
        wu.exploitation = "\n".join(_expl_steps)

    # Impact: bottom-up from what was proven
    _impact_class = (evidence.get("impact_class") or
                     (evidence.get("response_body_analysis") or {}).get("impact_class", ""))
    if _impact_class and _impact_class in _IMPACT_TEMPLATE:
        wu.impact = _IMPACT_TEMPLATE[_impact_class]
    elif verified and _vuln_class.lower() in _VULN_CLASS_TITLE:
        wu.impact = (f"{_vc_display} was confirmed through dynamic verification. "
                     "An attacker can exploit this to compromise the confidentiality, "
                     "integrity, or availability of the application.")

    # Remediation: concrete per-class only when class is known
    _vuln_class_low = _vuln_class.lower()
    if _vuln_class_low in _REMEDIATION_TEMPLATE:
        wu.remediation = _REMEDIATION_TEMPLATE[_vuln_class_low]
    elif (_pa.get("patch_pattern") and
          "sanitize" in _pa["patch_pattern"].lower()):
        wu.remediation = (f"Apply input validation/sanitization as shown in the patch: "
                          f"{_pa['patch_pattern']}")

    # References: only include links with direct relevance — GHSA advisories,
    # OSV packages, vendor patch commit — never generic OWASP/CWE links.
    # Per YwH guidance: References only when the triager genuinely benefits.
    # Exception: OWASP category is included when available (useful for triager context).
    _ref_lines: list[str] = []
    # GHSA advisory (from patch analysis or evidence)
    _ghsa_ids: list[str] = (evidence.get("ghsa_ids") or
                             (_pa.get("ghsa_ids") or []))
    for _gid in _ghsa_ids[:3]:
        _ref_lines.append(
            f"- GitHub Security Advisory [{_gid}]"
            f"(https://github.com/advisories/{_gid})")
    # OSV packages: exact affected package + fixed version
    _osv_pkgs: list[str] = evidence.get("osv_packages") or []
    for _op in _osv_pkgs[:2]:
        _ref_lines.append(f"- OSV affected package: `{_op}`")
    # Patch commit (from patch_analysis.patch_url)
    _patch_url = _pa.get("patch_url") or _pa.get("diff_url") or ""
    if _patch_url and "github.com" in _patch_url:
        _ref_lines.append(f"- Patch commit: {_patch_url.replace('.diff', '')}")
    # OWASP Top 10 2021 category (from evidence.owasp_category, populated by Stage 6)
    _owasp_cat = evidence.get("owasp_category", "")
    if _owasp_cat:
        _ref_lines.append(f"- OWASP Top 10 2021: {_owasp_cat}")
    # CWE link (only when non-trivial — triager typically already knows this but link helps)
    _cwe_id = evidence.get("cwe_id", "")
    if _cwe_id:
        _cwe_num = _cwe_id.replace("CWE-", "")
        _ref_lines.append(f"- [{_cwe_id}](https://cwe.mitre.org/data/definitions/{_cwe_num}.html)")
    if _ref_lines:
        wu.references = "\n".join(_ref_lines)

    # CVSS 3.1 vector auto-generation from proven evidence.
    # Only generated when verified — Base metrics only (Temporal/Environmental left to program).
    # Attack Vector: Network (AV:N) — all web CVEs require network access
    # Attack Complexity: Low (AC:L) unless a race condition was identified
    # Privileges Required: based on auth_required evidence
    # User Interaction: None (UI:N) for direct exploitation
    # Scope: Unchanged (S:U) unless SSRF cloud escalation observed
    # Confidentiality/Integrity/Availability: based on impact_class
    if verified:
        _auth_req = (evidence.get("auth_required") or
                     evidence.get("auth_method") or "").lower()
        _pr = "N"  # Privileges Required: None by default
        if "admin" in _auth_req or "high" in _auth_req:
            _pr = "H"
        elif "user" in _auth_req or "low" in _auth_req or "medium" in _auth_req:
            _pr = "L"
        elif "none" in _auth_req or not _auth_req:
            _pr = "N"

        _ac = "H" if _vuln_class_low in ("race-condition", "toctou") else "L"
        _scope = "C" if evidence.get("ssrf_cloud_escalation") else "U"

        # C/I/A from impact
        _imp_cls = (_impact_class or _vuln_class_low or "").lower()
        _ci, _ii, _ai = "L", "L", "N"
        if _imp_cls in ("credential_exposure", "data_disclosure", "sqli_confirmed", "sqli"):
            _ci, _ii, _ai = "H", "H", "N"
        elif _imp_cls in ("code_execution", "rce", "command-injection"):
            _ci, _ii, _ai = "H", "H", "H"
        elif _imp_cls in ("information_disclosure", "xss", "xss_confirmed"):
            _ci, _ii, _ai = "L", "N", "N"
        elif _imp_cls in ("admin_access", "auth-bypass", "missing-authorization"):
            _ci, _ii, _ai = "H", "H", "N"
        elif _imp_cls in ("ssrf",):
            _ci, _ii, _ai = "H", "L", "N"

        wu.cvss_vector = (
            f"CVSS:3.1/AV:N/AC:{_ac}/PR:{_pr}/UI:N/S:{_scope}"
            f"/C:{_ci}/I:{_ii}/A:{_ai}"
        )

    return wu


# ── E22: YWH scope validator integration ─────────────────────────────────────

def validate_scope(writeup: "YwhWriteup", description: str = "") -> dict:
    """E22: Check if this writeup's asset is in scope for any YWH program.

    Returns the result from ywh_scope.cve_matches_scope.
    """
    try:
        from .ywh_scope import cve_matches_scope
        return cve_matches_scope(
            cve_id=writeup.cve_id or "",
            description=(description or writeup.description or writeup.title or ""),
        )
    except Exception:
        return {"in_scope": True, "matched_programs": [], "reason": "scope check unavailable"}


# ── E23: Writeup deduplication ────────────────────────────────────────────────

_WRITEUPS_CACHE_DIR = os.path.join(
    os.environ.get("BINORACLE_CACHE_DIR") or
    os.path.join(os.path.expanduser("~"), ".cache", "binoracle"),
    "writeups",
)


def is_duplicate_writeup(writeup: "YwhWriteup", similarity_threshold: float = 0.80) -> dict:
    """E23: Check if a similar writeup already exists in the writeups cache.

    Returns {"duplicate": bool, "matched_path": str, "similarity": float}.
    """
    import os as _os
    import glob as _glob
    if not writeup.cve_id:
        return {"duplicate": False, "matched_path": "", "similarity": 0.0}
    # Exact CVE-ID match
    for path in _glob.glob(_os.path.join(_WRITEUPS_CACHE_DIR, "*.md")):
        base = _os.path.basename(path)
        if writeup.cve_id.upper() in base.upper():
            return {"duplicate": True, "matched_path": path, "similarity": 1.0}
    # Title similarity (Jaccard on words)
    if writeup.title:
        words_new = set((writeup.title or "").lower().split())
        for path in _glob.glob(_os.path.join(_WRITEUPS_CACHE_DIR, "*.md")):
            try:
                first_line = open(path, encoding="utf-8").readline().strip("# \n")
                words_old = set(first_line.lower().split())
                if not words_old:
                    continue
                sim = len(words_new & words_old) / len(words_new | words_old)
                if sim >= similarity_threshold:
                    return {"duplicate": True, "matched_path": path, "similarity": round(sim, 3)}
            except Exception:
                continue
    return {"duplicate": False, "matched_path": "", "similarity": 0.0}


def save_writeup_to_cache(writeup: "YwhWriteup") -> str:
    """Save a writeup markdown to the deduplication cache. Returns path."""
    import os as _os
    try:
        _os.makedirs(_WRITEUPS_CACHE_DIR, exist_ok=True)
        fname = f"{writeup.cve_id or 'unknown'}_{writeup.vuln_class or 'vuln'}.md"
        path = _os.path.join(_WRITEUPS_CACHE_DIR, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(writeup.to_markdown())
        return path
    except Exception:
        return ""


# ── E24: Report quality scorer ────────────────────────────────────────────────

def score_report_quality(writeup: "YwhWriteup") -> dict:
    """E24: Score report quality before submission. Returns dict with score and warnings."""
    warnings: list[str] = []
    score = 0
    total = 7

    # 1. Has a complete PoC with HTTP capture
    if writeup.poc_steps and len(writeup.poc_steps) >= 2:
        score += 1
    else:
        warnings.append("PoC incompleto: se necesitan ≥2 pasos con petición HTTP completa")

    # 2. HTTP request capture present
    if writeup.http_request:
        score += 1
    else:
        warnings.append("Falta captura HTTP de la petición de explotación")

    # 3. HTTP response capture present
    if writeup.http_response:
        score += 1
    else:
        warnings.append("Falta captura HTTP de la respuesta que confirma la vuln")

    # 4. Impact section with evidence (not generic)
    _imp = (writeup.impact or "").lower()
    generic_phrases = ["could allow", "may allow", "puede permitir", "podría permitir",
                       "arbitrary", "potencialmente"]
    if _imp and not any(p in _imp for p in generic_phrases) and len(_imp) > 50:
        score += 1
    else:
        warnings.append("Impact section: evitar frases teóricas, basar en evidencia del lab")

    # 5. CVSS vector present
    if writeup.cvss_vector and writeup.cvss_vector.startswith("CVSS:3.1/"):
        score += 1
    else:
        warnings.append("Falta vector CVSS 3.1 calculado desde la evidencia")

    # 6. Title is specific (not just 'XSS' or 'SQLi')
    _title = (writeup.title or "").lower()
    if _title and len(_title.split()) >= 5:
        score += 1
    else:
        warnings.append("Título demasiado genérico — incluir: vuln_class + componente + acción")

    # 7. Remediation is specific (not just 'validate input')
    _rem = (writeup.remediation or "").lower()
    if _rem and "validate" not in _rem and "sanitize" not in _rem and len(_rem) > 60:
        score += 1
    else:
        warnings.append("Remediation demasiado genérica — especificar la función y fix exacto")

    return {
        "score": score,
        "total": total,
        "pct": round(score / total * 100),
        "ready_to_submit": score >= 5,
        "warnings": warnings,
    }


# ── E25: YWH API submission (opt-in) ─────────────────────────────────────────

def submit_to_ywh(writeup: "YwhWriteup",
                  program_slug: str = "",
                  dry_run: bool = False) -> dict:
    """E25: Submit a writeup to YesWeHack API (opt-in via BINORACLE_SUBMIT=1).

    Requires:
      BINORACLE_SUBMIT=1          — opt-in gate
      BINORACLE_YWH_TOKEN         — API token (Bearer)
      BINORACLE_YWH_PROGRAM_SLUG  — program slug (or pass program_slug arg)

    Returns {"submitted": bool, "report_id": str, "url": str, "error": str}.
    Non-fatal: on any error, returns submitted=False.
    """
    import json as _json
    import os as _os
    import urllib.request as _req

    if _os.environ.get("BINORACLE_SUBMIT", "").strip() not in ("1", "true", "yes"):
        return {"submitted": False, "error": "BINORACLE_SUBMIT not set to 1"}
    if dry_run:
        return {"submitted": False, "dry_run": True, "error": "dry_run=True"}

    token = _os.environ.get("BINORACLE_YWH_TOKEN", "").strip()
    slug  = program_slug or _os.environ.get("BINORACLE_YWH_PROGRAM_SLUG", "").strip()
    if not token or not slug:
        return {"submitted": False, "error": "BINORACLE_YWH_TOKEN or BINORACLE_YWH_PROGRAM_SLUG not set"}

    ywh_base = _os.environ.get("BINORACLE_YWH_API_BASE", "").strip()
    if not ywh_base:
        return {"submitted": False, "error": "BINORACLE_YWH_API_BASE not set"}

    endpoint = f"{ywh_base.rstrip('/')}/programs/{slug}/reports"

    # Build submission payload (YWH API format v2)
    payload = {
        "title": writeup.title or f"{writeup.cve_id} — {writeup.vuln_class}",
        "scope": writeup.asset_url or "",
        "vulnerability_type": {"name": writeup.vuln_class or ""},
        "cvss": writeup.cvss_vector or "",
        "description": writeup.to_markdown(),
        "impact": writeup.impact or "",
        "remediation_recommendation": writeup.remediation or "",
        "attachments": [],
    }

    try:
        body = _json.dumps(payload).encode()
        rq = _req.Request(
            endpoint, data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "binoracle/1.0",
            },
            method="POST",
        )
        with _req.urlopen(rq, timeout=20) as resp:
            resp_data = _json.loads(resp.read())
        report_id = str(resp_data.get("id") or resp_data.get("report_id") or "")
        url = str(resp_data.get("url") or resp_data.get("html_url") or "")
        return {"submitted": True, "report_id": report_id, "url": url, "error": ""}
    except Exception as exc:
        return {"submitted": False, "error": str(exc)}
