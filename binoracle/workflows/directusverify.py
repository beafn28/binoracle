"""Dynamic verifier for Directus CMS CVEs.

Directus is a Node.js headless CMS. This verifier:
  1. Spins up directus/directus Docker with SQLite
  2. Authenticates via POST /auth/login -> data.access_token
  3. Fires the PoC against the REST or GraphQL API
  4. Checks confirm_string in response body

Supported vuln classes: xss, sqli, ssrf, missing-authorization, idor,
path-traversal, broken-access-control.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host

_DIRECTUS_PORT = 8055
_DIRECTUS_ADMIN_EMAIL = "admin@binoracle.dev"
_DIRECTUS_ADMIN_PASSWORD = "Admin1234!Binoracle"
_DIRECTUS_KEY = "ffffffff-ffff-ffff-ffff-ffffffffffff"
_DIRECTUS_SECRET = "binoracle-directus-secret-32chars!"


def detect_directus(source_dir: str) -> bool:
    """Return True if source looks like a Directus project."""
    pkg_path = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg_path):
        try:
            content = open(pkg_path, encoding="utf-8", errors="ignore").read().lower()
            if '"directus"' in content or "@directus/" in content:
                return True
        except Exception:
            pass
    return False


def _get_directus_token(base_url: str, step) -> Optional[str]:
    """Login to Directus and return Bearer access token."""
    login_url = base_url + "/auth/login"
    try:
        r = _http_request(
            "POST", login_url,
            data=json.dumps({"email": _DIRECTUS_ADMIN_EMAIL,
                             "password": _DIRECTUS_ADMIN_PASSWORD}),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status in (200, 201):
            body = json.loads(r.body or "{}")
            token = ((body.get("data") or {}).get("access_token") or
                     body.get("access_token") or "")
            if token:
                step("  directus: Bearer token obtenido")
                return f"Bearer {token}"
        step(f"  directus: login falló — HTTP {r.status}")
    except Exception as e:
        step(f"  directus: login error — {e}")
    return None


def verify_directus_web_cve(
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
    """Verify a Directus CMS CVE dynamically in an ephemeral Docker lab."""
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    container = f"bo_directus_{os.urandom(4).hex()}"
    # Use versioned image; fall back to latest if pkg_version not usable
    _image = f"directus/directus:{pkg_version}" if pkg_version else "directus/directus:latest"

    try:
        step(f"  directus: arrancando {_image} en puerto {_DIRECTUS_PORT}…")
        _run([
            "docker", "run", "-d", "--rm", "--name", container,
            "-p", f"{_DIRECTUS_PORT}:{_DIRECTUS_PORT}",
            "-e", f"KEY={_DIRECTUS_KEY}",
            "-e", f"SECRET={_DIRECTUS_SECRET}",
            "-e", f"ADMIN_EMAIL={_DIRECTUS_ADMIN_EMAIL}",
            "-e", f"ADMIN_PASSWORD={_DIRECTUS_ADMIN_PASSWORD}",
            "-e", "DB_CLIENT=sqlite3",
            "-e", "DB_FILENAME=/directus/database/data.db",
            "-e", f"PUBLIC_URL=http://localhost:{_DIRECTUS_PORT}",
            _image,
        ], timeout=30)

        # Poll until port is open (up to 90s — Directus is slow to start)
        import socket as _sock
        host = _lab_host()
        for _i in range(90):
            try:
                with _sock.create_connection((host, _DIRECTUS_PORT), timeout=1):
                    break
            except OSError:
                time.sleep(1)
        else:
            res.detail = f"Timeout esperando puerto {_DIRECTUS_PORT}"
            return res

        base_url = f"http://{host}:{_DIRECTUS_PORT}"
        # Give Directus extra time to initialize its DB
        time.sleep(5)

        # Auth
        bearer = None
        if auth_required:
            bearer = _get_directus_token(base_url, step)

        # Fire PoC
        target_url = base_url + endpoint
        headers = {}
        if bearer:
            headers["Authorization"] = bearer

        param = (parameters or [None])[0] if parameters else None
        body = None
        if http_method.upper() == "POST" and param:
            body = json.dumps({param: payload})
            headers["Content-Type"] = "application/json"
        elif http_method.upper() == "PATCH" and param:
            body = json.dumps({param: payload})
            headers["Content-Type"] = "application/json"
        elif param and payload:
            target_url += f"?{param}={payload}"

        step(f"  directus: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status
        res.evidence["body_snippet"] = (r.body or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status in (200, 201, 204):
            if confirm_string and confirm_string in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Directus"
                step("  directus: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
            else:
                res.ok = True
                res.detail = f"HTTP {r.status} — confirm_string no encontrado"
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
        except Exception:
            pass

    return res
