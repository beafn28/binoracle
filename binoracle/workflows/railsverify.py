"""railsverify.py — Ruby on Rails web CVE verifier.

Supports Rails 6/7 apps using Devise or token auth.
Spins up an ephemeral SQLite-backed Rails Docker lab and fires PoC.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import time
from typing import Callable, Optional

from .genericverify import _build_http_params
from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host

_RAILS_PORT = 3000
_RAILS_ADMIN_EMAIL = "admin@binoracle.dev"
_RAILS_ADMIN_PASSWORD = "Binoracle123!"


def detect_rails(source_dir: str) -> bool:
    """Return True if Gemfile contains a 'rails' dependency."""
    if not source_dir or not os.path.isdir(source_dir):
        return False
    gemfile = os.path.join(source_dir, "Gemfile")
    if not os.path.isfile(gemfile):
        return False
    try:
        content = open(gemfile, encoding="utf-8", errors="replace").read(16_000)
        return bool(re.search(r"gem\s+['\"]rails['\"]", content, re.IGNORECASE))
    except OSError:
        return False


def _rails_dockerfile(port: int = _RAILS_PORT) -> str:
    """Generate a minimal Rails Dockerfile using SQLite (no MySQL needed for lab)."""
    return f"""\
FROM ruby:3.2-slim
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential libsqlite3-dev curl git nodejs npm \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile* ./
RUN gem install bundler --no-document && \
    bundle config set --local without 'development test' && \
    bundle install --retry 3 || bundle install --retry 1 || true
COPY . .
RUN bundle exec rails db:create db:migrate 2>/dev/null || \
    bundle exec rake db:create db:migrate 2>/dev/null || true
RUN bundle exec rails assets:precompile 2>/dev/null || true
ENV RAILS_ENV=development SECRET_KEY_BASE=binoracle_test_secret_key_base_32chars_min
EXPOSE {port}
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "{port}"]
"""


def _get_rails_csrf_token(base_url: str, path: str, session_cookie: str = "",
                          step: Optional[Callable] = None) -> str:
    """GET path and extract csrf-token from meta tag or X-CSRF-Token header."""
    _step = step or (lambda m: None)
    try:
        hdrs = {}
        if session_cookie:
            hdrs["Cookie"] = session_cookie
        r = _http_request("GET", base_url + path, headers=hdrs, timeout=8)
        body = r.text or ""
        # <meta name="csrf-token" content="...">
        m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
                      body, re.IGNORECASE)
        if m:
            return m.group(1)
        # Also check response header
        csrf = r.headers.get("x-csrf-token", "") if hasattr(r, "headers") else ""
        if csrf:
            return csrf
    except Exception:
        pass
    return ""


def _get_rails_session(base_url: str, step: Callable) -> Optional[str]:
    """POST /users/sign_in (Devise) and return a session cookie string.

    Strategy:
    1. GET /users/sign_in to extract authenticity_token
    2. POST /users/sign_in with Devise form params
    3. Also tries /admin/sign_in and /auth/sign_in as fallbacks

    Returns "sessionid=...; _session_id=..." or None.
    """
    login_paths = ["/users/sign_in", "/admin/sign_in", "/auth/sign_in",
                   "/login", "/account/login"]
    for lpath in login_paths:
        try:
            r_get = _http_request("GET", base_url + lpath, timeout=8)
            if r_get.status not in (200, 404):
                continue
            body = r_get.body or ""
            # Extract authenticity_token
            m = re.search(r'<input[^>]+name=["\']authenticity_token["\'][^>]+value=["\']([^"\']+)["\']',
                          body, re.IGNORECASE)
            if not m:
                m = re.search(r'authenticity_token["\']?\s*[,=:]\s*["\']([A-Za-z0-9+/=_-]{20,})',
                              body, re.IGNORECASE)
            auth_token = m.group(1) if m else ""
            # Extract cookies from GET
            cookie_hdr = r_get.headers.get("set-cookie", "") if hasattr(r_get, "headers") else ""
            session_cookies: list[str] = []
            for part in cookie_hdr.split(","):
                part = part.strip()
                if "_session_id=" in part or "remember_user_token=" in part:
                    kv = part.split(";")[0].strip()
                    session_cookies.append(kv)

            # POST sign_in
            post_path = lpath
            post_data = (
                f"utf8=%E2%9C%93"
                f"&authenticity_token={auth_token}"
                f"&user%5Bemail%5D={_RAILS_ADMIN_EMAIL}"
                f"&user%5Bpassword%5D={_RAILS_ADMIN_PASSWORD}"
                f"&user%5Bremember_me%5D=0"
                f"&commit=Sign+in"
            )
            hdrs: dict[str, str] = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": base_url + lpath,
            }
            if session_cookies:
                hdrs["Cookie"] = "; ".join(session_cookies)

            r_post = _http_request("POST", base_url + post_path, data=post_data,
                                   headers=hdrs, timeout=10)
            # Successful Devise login → 302 redirect with new session cookie
            post_cookie = r_post.headers.get("set-cookie", "") if hasattr(r_post, "headers") else ""
            final_cookies: list[str] = []
            for part in post_cookie.split(","):
                kv = part.strip().split(";")[0].strip()
                if kv and ("_session_id=" in kv or "remember_user_token=" in kv):
                    final_cookies.append(kv)
            if final_cookies:
                step(f"  rails: session cookie obtenida vía {lpath}")
                return "; ".join(final_cookies)
        except Exception:
            continue
    return None


def _get_rails_token_auth(base_url: str, step: Callable) -> Optional[str]:
    """Try Rails API token auth endpoints (Devise Token Auth / simple_token_authentication).

    Returns "Token token=<value>" header value or None.
    """
    for ep in ["/auth/sign_in", "/api/v1/auth/sign_in", "/api/auth/sign_in",
               "/users/sign_in.json"]:
        try:
            import json as _j
            r = _http_request("POST", base_url + ep,
                              data=_j.dumps({"email": _RAILS_ADMIN_EMAIL,
                                             "password": _RAILS_ADMIN_PASSWORD}),
                              headers={"Content-Type": "application/json"}, timeout=8)
            if r.status_code in (200, 201):
                body = _j.loads(r.text or "{}")
                token = (body.get("token") or
                         (body.get("data") or {}).get("token") or
                         body.get("auth_token") or "")
                if token:
                    step(f"  rails: token auth obtenido vía {ep}")
                    return f"Token token={token}"
        except Exception:
            continue
    return None


def verify_rails_web_cve(
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
    """Build a Rails Docker lab and verify a web CVE.

    Uses SQLite (no MySQL needed), Devise session auth or token auth.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    container = f"bo_lab_rails_{os.urandom(4).hex()}"

    try:
        # Build Dockerfile from source or generate one
        source_dir = str(source_path)
        df_path = os.path.join(source_dir, "Dockerfile")
        df_exists = os.path.isfile(df_path)
        _t0 = time.time()

        if not df_exists:
            # Generate a Dockerfile if none present
            gen_df = _rails_dockerfile(_RAILS_PORT)
            df_path = os.path.join(source_dir, "_binoracle_Dockerfile")
            with open(df_path, "w") as f:
                f.write(gen_df)
            step("  rails: Dockerfile generado automáticamente")

        step(f"  rails: construyendo imagen {container}…")
        _run(["docker", "build", "-t", container,
              "-f", df_path, source_dir], timeout=180)

        step(f"  rails: arrancando en puerto {_RAILS_PORT}…")
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "-p", f"{_RAILS_PORT}:{_RAILS_PORT}",
              "-e", "RAILS_ENV=development",
              "-e", "SECRET_KEY_BASE=binoracle_test_secret_key_base_32chars_min",
              container], timeout=30)

        host = _lab_host()
        base_url = f"http://{host}:{_RAILS_PORT}"

        # Port polling (up to 45s)
        for _i in range(45):
            if time.time() - _t0 > budget_s - 30:
                break
            try:
                with socket.create_connection((host, _RAILS_PORT), timeout=1):
                    break
            except OSError:
                time.sleep(1)
        else:
            res.detail = f"timeout esperando puerto {_RAILS_PORT}"
            return res

        step("  rails: servidor listo")

        # Auth
        cookie = None
        token_header = None
        if auth_required:
            # Try session auth first (Devise), then token auth
            cookie = _get_rails_session(base_url, step)
            if not cookie:
                token_header = _get_rails_token_auth(base_url, step)

        # Fire PoC
        target_url = base_url + endpoint
        headers: dict[str, str] = {}
        if cookie:
            headers["Cookie"] = cookie
            # Get CSRF token for state-changing requests
            if http_method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                csrf = _get_rails_csrf_token(base_url, endpoint, cookie, step)
                if csrf:
                    headers["X-CSRF-Token"] = csrf
        if token_header:
            headers["Authorization"] = token_header

        body, target_url, headers = _build_http_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  rails: {http_method} {target_url}")
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
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Rails"
                step("  rails: VERIFICADO")
            elif not confirm_string and payload and payload in (r.text or ""):
                res.ok = True
                res.confidence = "probable"
                res.evidence["not_verified_reason"] = (
                    "payload reflejado en la respuesta no es prueba de ejecucion ni de explotacion -- muchos endpoints benignos reflejan el input del atacante (mensajes de error, formularios re-renderizados, busquedas, logs) sin que eso implique que el payload se ejecuto o que la vulnerabilidad es real")
                res.detail = "LEAD (no confirmado): payload reflejado en respuesta"
            else:
                res.ok = True
                res.detail = "HTTP 200 — confirm_string no encontrado"
        elif r.status_code in (401, 403):
            res.detail = f"HTTP {r.status_code} — acceso denegado (auth insuficiente)"
        else:
            res.detail = f"HTTP {r.status_code}"

    except subprocess.CalledProcessError as e:
        res.detail = f"Docker build/run error: {e}"
    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    return res
