"""Verificador especializado para CVEs de apps Node.js: Express, Fastify, NestJS, Koa, Hapi.

Extiende genericverify.py con:
  - Deteccion de framework via package.json dependencies
  - Auth generica JWT: register+login en rutas REST comunes para Bearer token
  - Deteccion del puerto desde scripts/app.js/index.js/server.js
  - Dispatcher principal verify_node_web_cve()
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request


# ── Framework detection ───────────────────────────────────────────────────────

_JS_FRAMEWORK_SIGNALS: dict[str, list[str]] = {
    "nestjs":       ["@nestjs/core", "@nestjs/common", "@nestjs/platform-express"],
    "fastify":      ["fastify"],
    "koa":          ["koa"],
    "hapi":         ["@hapi/hapi", "hapi"],
    "nextjs":       ["next"],
    "express":      ["express"],
}


def detect_js_framework(source_dir: str) -> str:
    """Return framework name from package.json deps, or 'unknown'."""
    if not source_dir or not os.path.isdir(source_dir):
        return "unknown"

    pkg_path = os.path.join(source_dir, "package.json")
    if not os.path.isfile(pkg_path):
        # Check one level deeper (monorepo)
        for entry in os.scandir(source_dir):
            if entry.is_dir():
                p = os.path.join(entry.path, "package.json")
                if os.path.isfile(p):
                    pkg_path = p
                    break
        else:
            return "unknown"

    try:
        data = json.loads(open(pkg_path, encoding="utf-8", errors="replace").read(16000))
    except Exception:
        return "unknown"

    all_deps: set[str] = set()
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        all_deps.update(data.get(section) or {})

    # Check in priority order (NestJS before Express since it uses Express internally)
    for fw, signals in _JS_FRAMEWORK_SIGNALS.items():
        if any(s in all_deps for s in signals):
            return fw

    # Has package.json but no recognized framework — still Node
    if os.path.isfile(os.path.join(source_dir, "package.json")):
        return "generic-node"
    return "unknown"


# ── Port detection ────────────────────────────────────────────────────────────

_PORT_RE = re.compile(r'(?:listen|PORT)[^\d]*(\d{3,5})', re.I)


def _find_node_port(source_dir: str) -> int:
    """Scan source for the port the server listens on; default 3000."""
    pkg_path = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg_path):
        try:
            scripts = json.loads(
                open(pkg_path, encoding="utf-8", errors="replace").read(8000)
            ).get("scripts") or {}
            for v in scripts.values():
                m = re.search(r'PORT=(\d{3,5})', str(v))
                if m:
                    return int(m.group(1))
        except Exception:
            pass

    for fname in ("app.js", "index.js", "server.js", "main.js", "src/main.js",
                  "src/index.js", "src/app.js"):
        fpath = os.path.join(source_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            content = open(fpath, encoding="utf-8", errors="replace").read(4000)
            m = _PORT_RE.search(content)
            if m:
                port = int(m.group(1))
                if 1024 <= port <= 65535:
                    return port
        except Exception:
            continue

    return 3000


# ── Generic JWT auth ──────────────────────────────────────────────────────────

_JWT_CREDS = {
    "username": "binoracle_test",
    "email":    "test@binoracle.dev",
    "password": "Binoracle123!",
    "name":     "binoracle_test",
}

_REGISTER_LOGIN_PAIRS = [
    ("/api/auth/register",    "/api/auth/login"),
    ("/auth/signup",          "/auth/signin"),
    ("/auth/register",        "/auth/login"),
    ("/register",             "/login"),
    ("/api/users",            "/api/sessions"),
    ("/api/signup",           "/api/signin"),
    ("/api/v1/users/register","/api/v1/users/login"),
    ("/api/v1/auth/register", "/api/v1/auth/login"),
]

_TOKEN_KEYS = ["token", "access_token", "accessToken", "jwt", "id_token"]


def _extract_token(body: str) -> Optional[str]:
    """Extract JWT from JSON response body."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    for k in _TOKEN_KEYS:
        v = data.get(k)
        if isinstance(v, str) and len(v) > 10:
            return v
    if isinstance(data.get("data"), dict):
        for k in _TOKEN_KEYS:
            v = data["data"].get(k)
            if isinstance(v, str) and len(v) > 10:
                return v
    return None


def _try_jwt_auth_node(base_url: str, step: Callable) -> Optional[str]:
    """Try common Node.js register+login REST flows; return 'Bearer <token>' or None."""
    base = base_url.rstrip("/")
    for reg_path, login_path in _REGISTER_LOGIN_PAIRS:
        try:
            _http_request("POST", base + reg_path,
                          data=json.dumps(_JWT_CREDS),
                          headers={"Content-Type": "application/json"},
                          timeout=8)
        except Exception:
            pass
        try:
            r = _http_request("POST", base + login_path,
                              data=json.dumps(_JWT_CREDS),
                              headers={"Content-Type": "application/json"},
                              timeout=8)
            if r.status in range(200, 300):
                token = _extract_token(r.body or "")
                if token:
                    step(f"  jsverify: JWT obtenido via {login_path}")
                    return f"Bearer {token}"
        except Exception:
            continue
    step("  jsverify: no se pudo obtener JWT (todos los endpoints fallaron)")
    return None


# ── Main verifier ─────────────────────────────────────────────────────────────

def verify_node_web_cve(source_path: str, endpoint: str,
                        vuln_class: str = "xss",
                        http_method: str = "GET",
                        parameters: Optional[list] = None,
                        payload: str = "",
                        confirm_string: str = "",
                        auth_required: bool = False,
                        pkg_version: str = "",
                        on_step: Optional[Callable] = None,
                        budget_s: float = 180.0) -> WpVerifyResult:
    """Verifier for Node.js/Express/Fastify/NestJS CVEs.

    Detects framework, starts container via _bootstrap_generic_lab (uses the
    package.json entry in _STACK_SIGNALS), optionally auto-authenticates via JWT,
    fires the PoC request, and checks the response for confirm_string.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    framework = detect_js_framework(source_path)
    step(f"  jsverify: framework={framework}, vuln_class={vuln_class}")

    from .genericverify import _bootstrap_generic_lab
    boot = _bootstrap_generic_lab(source_path, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot

    try:
        # Auth
        auth_headers: dict = {}
        if auth_required:
            token = _try_jwt_auth_node(base_url, step)
            if token:
                auth_headers["Authorization"] = token

        # Build request
        target_url = base_url.rstrip("/") + endpoint
        headers = {"Content-Type": "application/json", **auth_headers}
        param = (parameters or [None])[0] if parameters else None
        body = None

        if http_method.upper() in ("POST", "PUT", "PATCH") and param and payload:
            body = json.dumps({param: payload})
        elif param and payload:
            target_url += f"?{param}={payload}"

        step(f"  jsverify: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status
        res.evidence["body_snippet"] = (r.body or "")[:300]
        res.evidence["endpoint"] = target_url
        res.evidence["framework"] = framework

        if r.status in range(200, 300):
            if confirm_string and confirm_string in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: confirm_string '{confirm_string}' en respuesta"
                step("  jsverify: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado en respuesta"
                step("  jsverify: payload reflejado")
            else:
                res.ok = True
                res.detail = f"Endpoint accesible ({r.status}) — confirm_string no encontrado"
        elif r.status == 401 and auth_required and not auth_headers:
            res.detail = "HTTP 401 — auth requerida pero no se pudo obtener token"
        elif r.status == 403:
            res.detail = "HTTP 403 — endpoint bloqueado"
        else:
            res.detail = f"HTTP {r.status} — endpoint no accesible"

    except Exception as e:
        res.detail = f"Error: {e}"
        step(f"  jsverify error: {e}")
    finally:
        try:
            lab.teardown()
        except Exception:
            pass

    return res
