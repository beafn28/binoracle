"""E21: CVSS 3.1 auto-scoring from verified CVE evidence.

Derives a best-effort CVSS 3.1 vector and base score from the vuln class
and what was actually proven in the lab (not what NVD says). No external
dependencies — stdlib only.

Usage:
    from .cvss_autoscore import compute_cvss
    result = compute_cvss(
        vuln_class="sqli",
        auth_required=False,
        user_interaction=False,
    )
    # {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "source": "auto"}
"""
from __future__ import annotations

_VULN_CLASS_DEFAULTS: dict[str, dict] = {
    "sqli":               {"C": "H", "I": "H", "A": "H"},
    "sql-injection":      {"C": "H", "I": "H", "A": "H"},
    "rce":                {"C": "H", "I": "H", "A": "H"},
    "remote-code-execution": {"C": "H", "I": "H", "A": "H"},
    "ssrf":               {"C": "H", "I": "L", "A": "N"},
    "lfi":                {"C": "H", "I": "N", "A": "N"},
    "path-traversal":     {"C": "H", "I": "N", "A": "N"},
    "xxe":                {"C": "H", "I": "L", "A": "N"},
    "ssti":               {"C": "H", "I": "H", "A": "H"},
    "xss":                {"C": "L", "I": "L", "A": "N"},
    "reflected-xss":      {"C": "L", "I": "L", "A": "N"},
    "stored-xss":         {"C": "H", "I": "L", "A": "N"},
    "csrf":               {"C": "N", "I": "H", "A": "N"},
    "idor":               {"C": "H", "I": "L", "A": "N"},
    "broken-auth":        {"C": "H", "I": "H", "A": "N"},
    "auth-bypass":        {"C": "H", "I": "H", "A": "N"},
    "privesc":            {"C": "H", "I": "H", "A": "H"},
    "privilege-escalation": {"C": "H", "I": "H", "A": "H"},
    "file-upload":        {"C": "H", "I": "H", "A": "H"},
    "deserialization":    {"C": "H", "I": "H", "A": "H"},
    "php-object-injection": {"C": "H", "I": "H", "A": "H"},
    "open-redirect":      {"C": "L", "I": "L", "A": "N"},
    "dos":                {"C": "N", "I": "N", "A": "H"},
    "race-condition":     {"C": "L", "I": "H", "A": "N"},
    "command-injection":  {"C": "H", "I": "H", "A": "H"},
    "header-injection":   {"C": "L", "I": "L", "A": "N"},
    "default":            {"C": "L", "I": "L", "A": "N"},
}

# UI-required classes (browser interaction needed)
_UI_REQUIRED = {"xss", "reflected-xss", "csrf", "open-redirect", "header-injection"}

# Scope-changing classes
_SCOPE_CHANGED = {"xss", "reflected-xss", "stored-xss", "csrf", "ssrf", "open-redirect"}


def _impact_score(C: str, I: str, A: str) -> float:
    _m = {"N": 0.0, "L": 0.22, "H": 0.56}
    ISCBase = 1 - (1 - _m[C]) * (1 - _m[I]) * (1 - _m[A])
    return ISCBase


def _base_score(AV: str, AC: str, PR: str, UI: str, S: str, C: str, I: str, A: str) -> float:
    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC = {"L": 0.77, "H": 0.44}
    _PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI  = {"N": 0.85, "R": 0.62}
    _imp = {"N": 0.0, "L": 0.22, "H": 0.56}

    ISCBase = 1 - (1 - _imp[C]) * (1 - _imp[I]) * (1 - _imp[A])
    if S == "U":
        ISC = 6.42 * ISCBase
    else:
        ISC = 7.52 * (ISCBase - 0.029) - 3.25 * ((ISCBase - 0.02) ** 15)

    _PR_m = _PR_C if S == "C" else _PR_U
    Exploitability = 8.22 * _AV[AV] * _AC[AC] * _PR_m.get(PR, 0.85) * _UI[UI]

    if ISCBase <= 0:
        return 0.0
    if S == "U":
        raw = min(ISC + Exploitability, 10)
    else:
        raw = min(1.08 * (ISC + Exploitability), 10)
    # Roundup to 1 decimal
    return float(round(raw + 0.05, 1) if round(raw, 1) < raw + 0.05 else round(raw, 1))


def compute_cvss(
    vuln_class: str = "",
    auth_required: bool = True,
    user_interaction: bool | None = None,
    scope_changed: bool | None = None,
    confidentiality: str = "",
    integrity: str = "",
    availability: str = "",
) -> dict | None:
    """E21: Compute a best-effort CVSS 3.1 base score.

    Returns {"score": float, "vector": str, "source": "auto"} or None on error.
    """
    try:
        vc_key = (vuln_class or "").lower().replace("_", "-").strip()
        defaults = _VULN_CLASS_DEFAULTS.get(vc_key) or _VULN_CLASS_DEFAULTS["default"]

        C = (confidentiality or defaults["C"]).upper()[:1]
        I = (integrity      or defaults["I"]).upper()[:1]
        A = (availability   or defaults["A"]).upper()[:1]
        # Validate
        for v in (C, I, A):
            if v not in ("N", "L", "H"):
                return None

        AV = "N"  # always network-exploitable for web CVEs
        AC = "L"  # low complexity unless known otherwise
        PR = "N" if not auth_required else "L"
        if user_interaction is None:
            UI = "R" if vc_key in _UI_REQUIRED else "N"
        else:
            UI = "R" if user_interaction else "N"
        if scope_changed is None:
            S = "C" if vc_key in _SCOPE_CHANGED else "U"
        else:
            S = "C" if scope_changed else "U"

        score = _base_score(AV, AC, PR, UI, S, C, I, A)
        vector = f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"
        return {"score": score, "vector": vector, "source": "auto"}
    except Exception:
        return None
