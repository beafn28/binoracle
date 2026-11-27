"""modxverify.py — MODX CMS (Revolution) web CVE verifier.

MODX Revolution is PHP + MySQL. The admin connector uses a token-based
auth. This verifier spins up a minimal MODX lab via PHP generic lab.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, ssti, command-injection.
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional

from .genericverify import _build_http_params
from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request

_MODX_PORT = 8080
_MODX_ADMIN_USER = "admin"
_MODX_ADMIN_PASSWORD = "Binoracle123!"


def detect_modx(source_dir: str) -> bool:
    """Return True if source looks like a MODX Revolution project."""
    # MODX Revolution directory structure
    for marker in ("core/model/modx/modx.class.php",
                   "core/components/",
                   "manager/index.php"):
        if os.path.exists(os.path.join(source_dir, marker)):
            # Confirm it's MODX not some other PHP CMS
            if os.path.isdir(os.path.join(source_dir, "core/model/modx")):
                return True
    # Check composer.json
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = json.loads(open(composer).read())
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            if any("modx" in k.lower() for k in reqs):
                return True
        except Exception:
            pass
    # Check for MODX-specific config
    if os.path.isfile(os.path.join(source_dir, "config.core.php")):
        try:
            content = open(os.path.join(source_dir, "config.core.php")).read()
            if "MODX_CORE_PATH" in content:
                return True
        except Exception:
            pass
    return False


def _get_modx_session(base_url: str, step: Callable) -> Optional[str]:
    """Obtain a MODX admin session cookie.

    MODX Revolution connector-based auth:
    POST /connectors/index.php with action=security/login

    Falls back to /manager/ standard login form.
    Returns "PHPSESSID=..." cookie or None.
    """
    # Try connector-based auth first
    connector_url = base_url.rstrip("/") + "/connectors/index.php"
    try:
        # Get login page first to obtain any CSRF/nonce
        mgr_login_url = base_url.rstrip("/") + "/manager/"
        r0 = _http_request("GET", mgr_login_url, timeout=10)
        cookies_hdr = ""
        if r0.headers:
            for h, v in r0.headers:
                if h.lower() == "set-cookie":
                    cookies_hdr += v.split(";")[0] + "; "

        body = (f"action=security%2Flogin&username={_MODX_ADMIN_USER}"
                f"&password={_MODX_ADMIN_PASSWORD}&login_context=mgr")
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "X-HTTP-Method-Override": "POST"}
        if cookies_hdr:
            headers["Cookie"] = cookies_hdr.strip("; ")

        r = _http_request("POST", connector_url, data=body, headers=headers, timeout=12)
        if r.status_code in (200, 302):
            session_cookie = ""
            if r.headers:
                for h, v in r.headers:
                    if h.lower() == "set-cookie":
                        part = v.split(";")[0]
                        if "PHPSESSID" in part or "modx" in part.lower():
                            session_cookie += part + "; "
            if not session_cookie and cookies_hdr:
                # Reuse session from GET if POST didn't set new cookie
                session_cookie = cookies_hdr
            # Try to parse JSON response for success
            try:
                resp_json = json.loads(r.text or "{}")
                if resp_json.get("success") or resp_json.get("code") == 1:
                    step("  modxverify: sesión admin obtenida (connector)")
                    return session_cookie.strip("; ") if session_cookie else None
            except Exception:
                pass
            if session_cookie:
                step("  modxverify: cookie de sesión obtenida")
                return session_cookie.strip("; ")
    except Exception as e:
        step(f"  modxverify: connector auth error — {e}")

    # Fallback: manager form login
    try:
        login_url = base_url.rstrip("/") + "/manager/index.php"
        body = (f"username={_MODX_ADMIN_USER}&password={_MODX_ADMIN_PASSWORD}"
                "&login_context=mgr&f=1")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        r = _http_request("POST", login_url, data=body, headers=headers, timeout=12)
        if r.status_code in (200, 302):
            cookie_str = ""
            if r.headers:
                for h, v in r.headers:
                    if h.lower() == "set-cookie":
                        cookie_str += v.split(";")[0] + "; "
            if cookie_str:
                step("  modxverify: sesión admin obtenida (manager form)")
                return cookie_str.strip("; ")
    except Exception as e:
        step(f"  modxverify: manager form auth error — {e}")

    return None


def verify_modx_web_cve(
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
    """Verify a MODX Revolution CVE dynamically.

    Spins up MODX in Docker via generic PHP lab, fires PoC,
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
        step("  modxverify: lab PHP arrancado para MODX Revolution")

        cookie = None
        if auth_required:
            cookie = _get_modx_session(base_url, step)

        target_url = base_url + endpoint
        headers = {}
        if cookie:
            headers["Cookie"] = cookie

        body, target_url, headers = _build_http_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  modxverify: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status_code
        res.evidence["body_snippet"] = (r.text or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status_code in (200, 201):
            if confirm_string and confirm_string in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta MODX"
                step("  modxverify: VERIFICADO")
            elif not confirm_string and payload and payload in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
            else:
                res.ok = True
                res.detail = "HTTP 200 — confirm_string no encontrado"
        elif r.status_code in (401, 403):
            res.detail = f"HTTP {r.status_code} — acceso denegado (auth requerida?)"
        else:
            res.detail = f"HTTP {r.status_code}"
    except Exception as e:
        res.detail = f"Error: {e}"

    return res
