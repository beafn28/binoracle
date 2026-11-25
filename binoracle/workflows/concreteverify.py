"""concreteverify.py — Concrete CMS (formerly concrete5) web CVE verifier.

Concrete CMS is PHP + MySQL/SQLite. Admin authentication uses CSRF tokens
and cookie sessions. This verifier spins up a minimal Concrete lab.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, ssti, command-injection.
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request

_CONCRETE_PORT = 8080
_CONCRETE_ADMIN_EMAIL = "admin@binoracle.dev"
_CONCRETE_ADMIN_PASSWORD = "Binoracle123!"


def detect_concrete(source_dir: str) -> bool:
    """Return True if source looks like a Concrete CMS project."""
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = json.loads(open(composer).read())
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            if any(k in reqs for k in ("concrete5/core", "concretecms/core",
                                        "concrete5/concrete5", "concretecms/concretecms")):
                return True
        except Exception:
            pass
    # Concrete CMS directory markers
    for marker in ("concrete/bootstrap/start.php", "concrete/dispatcher.php",
                   "application/bootstrap/app.php"):
        if os.path.isfile(os.path.join(source_dir, marker)):
            return True
    return False


def _get_concrete_session(base_url: str, step: Callable) -> Optional[str]:
    """Obtain a Concrete CMS admin session cookie.

    1. GET /login → extract ccm_token CSRF
    2. POST /login/authenticate/concrete with uName + uPassword + ccm_token
    Returns "CONCRETE5=...; ccm_token=..." or None.
    """
    login_url = base_url.rstrip("/") + "/login"
    try:
        r = _http_request("GET", login_url, timeout=10)
        csrf_token = ""
        m = re.search(r'ccm_token["\s]+value=["\']([^"\']+)', r.body or "")
        if not m:
            m = re.search(r'name=["\']ccm_token["\'][^>]+value=["\']([^"\']+)', r.body or "")
        if m:
            csrf_token = m.group(1)
        cookies_hdr = ""
        if r.headers:
            for h, v in r.headers:
                if h.lower() == "set-cookie":
                    cookies_hdr += v.split(";")[0] + "; "
        auth_url = base_url.rstrip("/") + "/login/authenticate/concrete"
        body = f"uName={_CONCRETE_ADMIN_EMAIL}&uPassword={_CONCRETE_ADMIN_PASSWORD}"
        if csrf_token:
            body += f"&ccm_token={csrf_token}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookies_hdr:
            headers["Cookie"] = cookies_hdr.strip("; ")
        r2 = _http_request("POST", auth_url, data=body, headers=headers, timeout=12)
        if r2.status in (200, 302):
            session_cookie = ""
            if r2.headers:
                for h, v in r2.headers:
                    if h.lower() == "set-cookie":
                        session_cookie += v.split(";")[0] + "; "
            if session_cookie:
                step("  concreteverify: sesión admin obtenida")
                return session_cookie.strip("; ")
    except Exception as e:
        step(f"  concreteverify: auth error — {e}")
    return None


def verify_concrete_web_cve(
    source_path: str,
    endpoint: str,
    vuln_class: str = "xss",
    http_method: str = "GET",
    parameters: Optional[list] = None,
    payload: str = "",
    confirm_string: str = "",
    auth_required: bool = False,
    pkg_version: str = "",
    on_step: Optional[Callable] = None,
    budget_s: float = 240.0,
) -> WpVerifyResult:
    """Verify a Concrete CMS CVE dynamically.

    Spins up Concrete CMS in Docker via generic PHP lab, fires PoC,
    checks confirm_string.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    try:
        from .genericverify import _bootstrap_generic_lab
        boot = _bootstrap_generic_lab(source_path, step, res, budget_s,
                                       pkg_version=pkg_version)
        if not boot:
            return res
        lab, base_url, container = boot
        step("  concreteverify: lab PHP arrancado para Concrete CMS")

        cookie = None
        if auth_required:
            cookie = _get_concrete_session(base_url, step)

        target_url = base_url + endpoint
        headers = {}
        if cookie:
            headers["Cookie"] = cookie

        body, target_url, headers = _build_http_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  concreteverify: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status
        res.evidence["body_snippet"] = (r.body or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status in (200, 201):
            if confirm_string and confirm_string in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Concrete CMS"
                step("  concreteverify: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
            else:
                res.ok = True
                res.detail = "HTTP 200 — confirm_string no encontrado"
        elif r.status in (401, 403):
            res.detail = f"HTTP {r.status} — acceso denegado (auth requerida?)"
        else:
            res.detail = f"HTTP {r.status}"
    except Exception as e:
        res.detail = f"Error: {e}"

    return res
