"""Dynamic verifier for Ghost CMS CVEs (XSS, SSRF, missing-auth, path-traversal).

Ghost uses a modern Node.js architecture with a JSON Admin API (Bearer token auth)
and a Content API (key-based). This verifier:
  1. Spins up an ephemeral Ghost + SQLite Docker lab
  2. Authenticates via POST /ghost/api/admin/session (email+password)
  3. Fires the PoC against the Admin or Content API
  4. Checks confirm_string in response body

Supported vuln classes: xss, ssrf, missing-authorization, path-traversal, sqli.

First version covers the Admin API auth flow only. Ghost public API (content key)
and theme-injection XSS added when needed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host
from .genericverify import _build_json_params

_GHOST_IMAGE = "ghost:5-alpine"
_GHOST_PORT = 2368
_GHOST_ADMIN_EMAIL = "binoracle@test.local"
_GHOST_ADMIN_PASSWORD = "Binoracle123!Test"
_GHOST_TITLE = "binoracle-test"


def _ghost_wait_ready(base_url: str, timeout: int = 60, step=None) -> bool:
    """Poll Ghost health endpoint until ready."""
    _step = step or (lambda m: None)
    health_url = base_url + "/ghost/api/admin/site/"
    for _i in range(timeout):
        try:
            r = _http_request("GET", health_url, timeout=3)
            if r.status in (200, 401, 403):
                _step("  ghost: servidor listo")
                return True
        except Exception:
            pass
        time.sleep(1)
    _step("  ghost: timeout esperando servidor")
    return False


def _ghost_setup(container: str, base_url: str, step) -> bool:
    """Create Ghost admin user via CLI and return True on success."""
    # Ghost 5 requires setup via the admin registration endpoint on first run
    setup_url = base_url + "/ghost/api/admin/authentication/setup/"
    try:
        r = _http_request("POST", setup_url,
                          data=json.dumps({"setup": [{
                              "name": "binoracle",
                              "email": _GHOST_ADMIN_EMAIL,
                              "password": _GHOST_ADMIN_PASSWORD,
                              "blogTitle": _GHOST_TITLE,
                          }]}),
                          headers={"Content-Type": "application/json",
                                   "Origin": base_url},
                          timeout=15)
        if r.status in (200, 201):
            step("  ghost: admin setup OK")
            return True
        if r.status == 403:
            # Already set up — try to get a session directly
            step("  ghost: ya configurado, intentando login directo")
            return True
    except Exception as e:
        step(f"  ghost: setup error — {e}")
    return False


def _ghost_get_token(base_url: str, step) -> str:
    """Login to Ghost admin and return Bearer token."""
    session_url = base_url + "/ghost/api/admin/session/"
    try:
        r = _http_request("POST", session_url,
                          data=json.dumps({"username": _GHOST_ADMIN_EMAIL,
                                           "password": _GHOST_ADMIN_PASSWORD}),
                          headers={"Content-Type": "application/json",
                                   "Origin": base_url},
                          timeout=10)
        if r.status in (200, 201):
            # Ghost session uses cookies; extract ghost-admin-api-session
            cookie_hdr = r.headers.get("set-cookie", "")
            m = re.search(r"ghost-admin-api-session=([^;]+)", cookie_hdr)
            if m:
                step("  ghost: session cookie obtenida")
                return f"ghost-admin-api-session={m.group(1)}"
    except Exception as e:
        step(f"  ghost: login error — {e}")
    return ""


def verify_ghost_cve(
    source_path: str,
    endpoint: str,
    vuln_class: str = "xss",
    http_method: str = "GET",
    parameters: Optional[list] = None,
    payload: str = "",
    confirm_string: str = "",
    auth_required: bool = True,
    on_step: Optional[Callable] = None,
    budget_s: float = 180.0,
) -> WpVerifyResult:
    """Verify a Ghost CMS CVE dynamically.

    Spins up Ghost 5 in Docker, sets up admin, fires PoC, checks confirm_string.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    container = f"bo_ghost_{os.urandom(4).hex()}"
    network = f"bo_ghost_net_{os.urandom(4).hex()}"

    try:
        # Create isolated network
        subprocess.run(["docker", "network", "create", network],
                       capture_output=True, timeout=10)

        step(f"  ghost: arrancando {_GHOST_IMAGE} en puerto {_GHOST_PORT}…")
        # Ghost 5 with SQLite (no MySQL needed for testing)
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "--network", network,
              "-p", f"{_GHOST_PORT}:{_GHOST_PORT}",
              "-e", f"url=http://localhost:{_GHOST_PORT}",
              "-e", "database__client=sqlite3",
              "-e", "database__connection__filename=/var/lib/ghost/content/data/ghost.db",
              "-e", "NODE_ENV=development",
              _GHOST_IMAGE], timeout=30)

        host = _lab_host()
        base_url = f"http://{host}:{_GHOST_PORT}"

        if not _ghost_wait_ready(base_url, timeout=60, step=step):
            res.detail = "Ghost no arrancó a tiempo"
            return res

        # Setup admin
        _ghost_setup(container, base_url, step)
        time.sleep(2)

        # Get auth token if needed
        auth_header = ""
        if auth_required:
            auth_header = _ghost_get_token(base_url, step)

        # Fire PoC
        target_url = base_url + endpoint
        headers = {}
        if auth_header:
            if auth_header.startswith("Bearer "):
                headers["Authorization"] = auth_header
            else:
                headers["Cookie"] = auth_header
        headers["Origin"] = base_url

        body, target_url, headers = _build_json_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  ghost: {http_method} {target_url}")
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
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Ghost"
                step("  ghost: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
                step("  ghost: payload reflejado")
            else:
                res.ok = True
                res.detail = "HTTP 200 — confirm_string no encontrado"
        else:
            res.detail = f"HTTP {r.status} — endpoint no accesible"

    except subprocess.CalledProcessError as e:
        res.detail = f"Docker error: {e}"
    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
            subprocess.run(["docker", "network", "rm", network],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    return res


# Convenience alias kept for backwards compat
verify_ghost_xss = verify_ghost_cve
