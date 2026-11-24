"""Verificador especializado para CVEs de apps Go y Rust.

Extiende genericverify.py con:
  - Deteccion de framework Go (Gin/Echo/Fiber/Chi/Gorilla/net-http) y Rust (Actix/Axum/Warp)
  - Auth generica JWT: intenta register+login en rutas REST comunes para obtener Bearer token
  - Auth generica API key: escanea fuente para defaults de API_KEY / MASTER_KEY
  - Dispatcher principal verify_go_web_cve()
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request


# ── Framework detection ───────────────────────────────────────────────────────

_GO_FRAMEWORK_SIGNALS = {
    "gin":     ["gin-gonic/gin", "github.com/gin-gonic"],
    "echo":    ["labstack/echo", "github.com/labstack/echo"],
    "fiber":   ["gofiber/fiber", "github.com/gofiber/fiber"],
    "chi":     ["go-chi/chi", "github.com/go-chi/chi"],
    "gorilla": ["gorilla/mux", "github.com/gorilla/mux"],
    "net-http": ["net/http"],
}

_RUST_FRAMEWORK_SIGNALS = {
    "rust-actix": ["actix-web", "actix_web"],
    "rust-axum":  ["axum =", "axum="],
    "rust-warp":  ["warp =", "warp="],
}


def detect_go_framework(source_dir: str) -> str:
    """Return framework name from go.mod or Cargo.toml, or 'unknown'."""
    if not source_dir or not os.path.isdir(source_dir):
        return "unknown"

    # Check go.mod
    go_mod = os.path.join(source_dir, "go.mod")
    if os.path.isfile(go_mod):
        try:
            content = open(go_mod, encoding="utf-8", errors="replace").read(8000)
            for fw, signals in _GO_FRAMEWORK_SIGNALS.items():
                if any(s in content for s in signals):
                    return fw
            return "generic-go"
        except OSError:
            return "generic-go"

    # Check Cargo.toml
    cargo = os.path.join(source_dir, "Cargo.toml")
    if os.path.isfile(cargo):
        try:
            content = open(cargo, encoding="utf-8", errors="replace").read(8000)
            for fw, signals in _RUST_FRAMEWORK_SIGNALS.items():
                if any(s in content for s in signals):
                    return fw
            return "generic-rust"
        except OSError:
            return "generic-rust"

    # Walk one level deeper for monorepos
    for entry in os.scandir(source_dir):
        if not entry.is_dir():
            continue
        for fname, fw_checker in [("go.mod", _GO_FRAMEWORK_SIGNALS),
                                   ("Cargo.toml", _RUST_FRAMEWORK_SIGNALS)]:
            fpath = os.path.join(entry.path, fname)
            if os.path.isfile(fpath):
                try:
                    content = open(fpath, encoding="utf-8", errors="replace").read(8000)
                    for fw, signals in fw_checker.items():
                        if any(s in content for s in signals):
                            return fw
                    return "generic-go" if fname == "go.mod" else "generic-rust"
                except OSError:
                    pass

    return "unknown"


# ── Generic JWT auth ──────────────────────────────────────────────────────────

_JWT_CREDS = {
    "username": "binoracle_test",
    "email":    "test@binoracle.dev",
    "password": "Binoracle123!",
    "name":     "binoracle_test",
}

_REGISTER_LOGIN_PAIRS = [
    ("/api/auth/register",   "/api/auth/login"),
    ("/auth/register",       "/auth/login"),
    ("/api/v1/auth/register","/api/v1/auth/login"),
    ("/api/signup",          "/api/signin"),
    ("/users",               "/sessions"),
    ("/api/users",           "/api/sessions"),
    ("/api/register",        "/api/login"),
    ("/register",            "/login"),
]

_TOKEN_KEYS = ["token", "access_token", "jwt", "accessToken", "id_token"]


def _extract_token(body: str) -> Optional[str]:
    """Try to extract a JWT token from a JSON response body."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    # Direct keys
    for k in _TOKEN_KEYS:
        if k in data and isinstance(data[k], str) and len(data[k]) > 10:
            return data[k]
    # Nested under "data"
    if isinstance(data.get("data"), dict):
        for k in _TOKEN_KEYS:
            v = data["data"].get(k)
            if isinstance(v, str) and len(v) > 10:
                return v
    return None


def _try_generic_jwt_auth(base_url: str, step: Callable) -> Optional[str]:
    """Try common register+login REST flows; return 'Bearer <token>' or None."""
    base = base_url.rstrip("/")
    for reg_path, login_path in _REGISTER_LOGIN_PAIRS:
        try:
            # Register (ignore failure — user may already exist)
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
                    step(f"  goverify: JWT obtenido via {login_path}")
                    return f"Bearer {token}"
        except Exception:
            continue
    step("  goverify: no se pudo obtener JWT (todos los endpoints fallaron)")
    return None


# ── API key auth ──────────────────────────────────────────────────────────────

_API_KEY_ENV_RE = re.compile(
    r'(?:API_KEY|MASTER_KEY|SECRET_KEY|ADMIN_KEY|ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,64})',
    re.I,
)

_API_KEY_SCAN_EXTS = (".go", ".rs", ".env", ".example", ".yaml", ".yml", ".toml", ".json")


def _try_api_key_auth(source_dir: str, base_url: str, step: Callable) -> Optional[dict]:
    """Scan source for API key defaults; return header dict or None."""
    if source_dir and os.path.isdir(source_dir):
        for root, dirs, fnames in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "vendor", "target", "node_modules")]
            for fn in fnames:
                if not any(fn.endswith(ext) for ext in _API_KEY_SCAN_EXTS):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    content = open(fpath, encoding="utf-8", errors="replace").read(4000)
                except OSError:
                    continue
                m = _API_KEY_ENV_RE.search(content)
                if m:
                    key_val = m.group(1)
                    step(f"  goverify: API key encontrada en {os.path.basename(fn)}: {key_val[:12]}…")
                    return {"X-API-Key": key_val, "Authorization": f"ApiKey {key_val}"}

    # Try unauthenticated status endpoint — maybe no auth needed
    try:
        r = _http_request("GET", base_url.rstrip("/") + "/api/status", timeout=6)
        if r.status == 200:
            step("  goverify: /api/status responde 200 — app puede estar sin auth")
    except Exception:
        pass

    return None


# ── Route scanner ────────────────────────────────────────────────────────────

def _scan_go_routes(source_dir: str) -> list:
    """Scan Go source for HTTP route definitions (Gin, Echo, Fiber, Chi, net/http).

    Returns a deduplicated list of route paths found (up to 30).
    """
    if not source_dir or not os.path.isdir(source_dir):
        return []

    _ROUTE_RES = [
        # Gin: r.GET("/path", ...) / r.POST("/path", ...)
        re.compile(r'\b(?:r|g|router|group|v\d+)\s*\.\s*(?:GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(\s*"([^"]+)"',
                   re.IGNORECASE),
        # Echo: e.GET("/path", ...) / g.GET("/path", ...)
        re.compile(r'\b(?:e|echo|srv|g|api|v\d+)\s*\.\s*(?:GET|POST|PUT|PATCH|DELETE|Add)\s*\(\s*"([^"]+)"',
                   re.IGNORECASE),
        # Fiber: app.Get("/path", ...) / app.Post("/path", ...)
        re.compile(r'\bapp\s*\.\s*(?:Get|Post|Put|Patch|Delete|Add|All)\s*\(\s*"([^"]+)"',
                   re.IGNORECASE),
        # Chi: r.Get("/path", ...) / r.Route("/path", ...)
        re.compile(r'\b(?:r|router|mux)\s*\.\s*(?:Get|Post|Put|Patch|Delete|Route|Handle|Mount)\s*\(\s*"([^"]+)"',
                   re.IGNORECASE),
        # net/http: http.HandleFunc("/path", ...) / mux.HandleFunc("/path", ...)
        re.compile(r'(?:http|mux|srv|router|r)\s*\.\s*HandleFunc\s*\(\s*"([^"]+)"',
                   re.IGNORECASE),
    ]

    seen: set = set()
    routes: list = []

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "vendor", "testdata")]
        for fname in files:
            if not fname.endswith(".go"):
                continue
            fpath = os.path.join(root, fname)
            try:
                txt = open(fpath, encoding="utf-8", errors="ignore").read(100_000)
                for pat in _ROUTE_RES:
                    for m in pat.finditer(txt):
                        path = m.group(1).strip()
                        if path and path not in seen and not path.startswith("http"):
                            if not path.startswith("/"):
                                path = "/" + path
                            seen.add(path)
                            routes.append(path)
                            if len(routes) >= 30:
                                return routes
            except Exception:
                continue
    return routes


# ── Main verifier ─────────────────────────────────────────────────────────────

def verify_go_web_cve(source_path: str, endpoint: str,
                      vuln_class: str = "missing-authorization",
                      http_method: str = "GET",
                      parameters: Optional[list] = None,
                      payload: str = "",
                      confirm_string: str = "",
                      auth_required: bool = False,
                      pkg_version: str = "",
                      on_step: Optional[Callable] = None,
                      budget_s: float = 180.0) -> WpVerifyResult:
    """Verifier for Go and Rust web CVEs.

    Detects framework, starts container via _bootstrap_generic_lab (uses the
    go.mod entry in _STACK_SIGNALS), optionally auto-authenticates via JWT or
    API key, fires the PoC, and checks the response.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    framework = detect_go_framework(source_path)
    step(f"  goverify: framework={framework}, vuln_class={vuln_class}")

    # Pre-scan routes from source when no endpoint is given
    _candidate_endpoints: list = []
    if not endpoint:
        _candidate_endpoints = _scan_go_routes(source_path)
        if _candidate_endpoints:
            endpoint = _candidate_endpoints[0]
            step(f"  goverify: endpoint seed desde source scanner: {endpoint} "
                 f"({len(_candidate_endpoints)} candidatos)")

    from .genericverify import _bootstrap_generic_lab
    boot = _bootstrap_generic_lab(source_path, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot

    # Augment from OpenAPI spec (after container is up)
    if not endpoint or not _candidate_endpoints:
        try:
            from .genericverify import _discover_routes_from_openapi
            _openapi = _discover_routes_from_openapi(base_url, step)
            if _openapi:
                _candidate_endpoints = (_candidate_endpoints or []) + _openapi
                if not endpoint:
                    endpoint = _openapi[0]
                    step(f"  goverify: endpoint desde OpenAPI spec: {endpoint}")
        except Exception:
            pass

    try:
        # Auth
        auth_headers: dict = {}
        if auth_required:
            # Try universal auth layer first, fall back to local implementations
            try:
                from .genericverify import _try_auto_auth
                _auto = _try_auto_auth(base_url, source_path, step)
                if _auto.get("headers"):
                    auth_headers.update(_auto["headers"])
            except Exception:
                pass
            if not auth_headers:
                token = _try_generic_jwt_auth(base_url, step)
                if token:
                    auth_headers["Authorization"] = token
                else:
                    api_key_hdrs = _try_api_key_auth(source_path, base_url, step)
                    if api_key_hdrs:
                        auth_headers.update(api_key_hdrs)

        # Build request
        target_url = base_url.rstrip("/") + endpoint
        headers = {"Content-Type": "application/json", **auth_headers}
        param = (parameters or [None])[0] if parameters else None
        body = None

        if http_method.upper() in ("POST", "PUT", "PATCH") and param and payload:
            body = json.dumps({param: payload})
        elif param and payload:
            target_url += f"?{param}={payload}"

        step(f"  goverify: {http_method} {target_url}")
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
                step("  goverify: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado en respuesta"
                step("  goverify: payload reflejado")
            else:
                res.ok = True
                res.detail = f"Endpoint accesible ({r.status}) — confirm_string no encontrado"
        elif r.status == 401 and auth_required and not auth_headers:
            res.detail = "HTTP 401 — auth requerida pero no se pudo obtener token"
        elif r.status == 403:
            res.detail = "HTTP 403 — endpoint bloqueado (posible bypass fallido)"
        else:
            res.detail = f"HTTP {r.status} — endpoint no accesible"

    except Exception as e:
        res.detail = f"Error: {e}"
        step(f"  goverify error: {e}")
    finally:
        try:
            lab.teardown()
        except Exception:
            pass

    return res
