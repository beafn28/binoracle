"""payloadverify.py — Payload CMS web CVE verifier.

Payload CMS (payloadcms/payload) uses Node.js + MongoDB or PostgreSQL.
Admin authentication uses JWT: POST /api/users/login → {"token": "..."}.
This verifier spins up a Payload container for PoC verification.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, idor, auth-bypass.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request

_PAYLOAD_PORT = 3000
_PAYLOAD_ADMIN_EMAIL = "binoracle@test.local"
_PAYLOAD_ADMIN_PASSWORD = "Binoracle123!Test"


def detect_payload(source_dir: str) -> bool:
    """Return True if source looks like a Payload CMS project."""
    pkg = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg):
        try:
            data = json.loads(open(pkg).read())
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "payload" in deps or "@payloadcms/richtext-lexical" in deps:
                return True
        except Exception:
            pass
    # payload.config.ts / payload.config.js
    for marker in ("payload.config.ts", "payload.config.js", "src/payload.config.ts"):
        if os.path.isfile(os.path.join(source_dir, marker)):
            return True
    return False


def _get_payload_token(base_url: str, step: Callable) -> Optional[str]:
    """Get Payload CMS admin JWT via /api/users/login.

    Tries:
    1. POST /api/users/login  (Payload 2.x)
    2. POST /api/users/first-register (create first admin if none exists)
    3. POST /api/users/login again after registration

    Returns "JWT <token>" or None.
    """
    login_url = base_url.rstrip("/") + "/api/users/login"
    register_url = base_url.rstrip("/") + "/api/users/first-register"
    creds = {"email": _PAYLOAD_ADMIN_EMAIL, "password": _PAYLOAD_ADMIN_PASSWORD}
    body = json.dumps(creds)
    headers = {"Content-Type": "application/json"}

    # Try direct login first
    try:
        r = _http_request("POST", login_url, data=body, headers=headers, timeout=10)
        if r.status in (200, 201):
            data = json.loads(r.body or "{}")
            token = data.get("token") or (data.get("user") or {}).get("token") or ""
            if token:
                step("  payloadverify: JWT obtenido via /api/users/login")
                return f"JWT {token}"
    except Exception:
        pass

    # Try first-register (Payload requires this if no users exist)
    try:
        r2 = _http_request("POST", register_url,
                           data=json.dumps({**creds, "confirm-password": _PAYLOAD_ADMIN_PASSWORD}),
                           headers=headers, timeout=10)
        if r2.status in (200, 201):
            step("  payloadverify: primer admin creado, intentando login")
            # Now login
            r3 = _http_request("POST", login_url, data=body, headers=headers, timeout=10)
            if r3.status in (200, 201):
                data = json.loads(r3.body or "{}")
                token = data.get("token") or ""
                if token:
                    step("  payloadverify: JWT obtenido tras registro")
                    return f"JWT {token}"
    except Exception as e:
        step(f"  payloadverify: auth error — {e}")
    return None


def verify_payload_web_cve(
    source_path: str,
    endpoint: str,
    vuln_class: str = "missing-authorization",
    http_method: str = "GET",
    parameters: Optional[list] = None,
    payload: str = "",
    confirm_string: str = "",
    auth_required: bool = False,
    pkg_version: str = "",
    on_step: Optional[Callable] = None,
    budget_s: float = 240.0,
) -> WpVerifyResult:
    """Verify a Payload CMS CVE dynamically.

    Uses _bootstrap_generic_lab (Node.js auto-Dockerfile) for the lab,
    then authenticates via /api/users/login JWT flow.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    try:
        from .genericverify import _bootstrap_generic_lab
        boot = _bootstrap_generic_lab(source_path, step, res, budget_s)
        if not boot or not boot[0]:
            res.detail = "generic lab no arrancó"
            return res

        _lab, base_url, container = boot
        step("  payloadverify: lab Node.js arrancado para Payload CMS")

        # Auth
        bearer = None
        if auth_required:
            bearer = _get_payload_token(base_url, step)

        target_url = base_url + endpoint
        headers = {}
        if bearer:
            headers["Authorization"] = bearer

        param = (parameters or [None])[0] if parameters else None
        body_data = None
        if http_method.upper() == "POST" and param:
            body_data = json.dumps({param: payload})
            headers["Content-Type"] = "application/json"
        elif param and payload:
            target_url += f"?{param}={payload}"

        step(f"  payloadverify: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body_data, headers=headers, timeout=15)
        res.evidence["status"] = r.status
        res.evidence["body_snippet"] = (r.body or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status in (200, 201):
            if confirm_string and confirm_string in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Payload"
                step("  payloadverify: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
            else:
                res.ok = True
                res.detail = "HTTP 200 — confirm_string no encontrado"
        else:
            res.detail = f"HTTP {r.status}"

    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    return res
