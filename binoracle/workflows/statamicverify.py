"""statamicverify.py — Statamic CMS web CVE verifier.

Statamic 3/4 is a Laravel-based PHP CMS (composer package statamic/cms).
Admin authentication uses CSRF tokens + Laravel session cookies.
This verifier spins up a minimal Statamic container for PoC verification.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, ssti.
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request

_STATAMIC_PORT = 8080
_STATAMIC_ADMIN_EMAIL = "binoracle@test.local"
_STATAMIC_ADMIN_PASSWORD = "Bin0racleTest!"
_STATAMIC_ADMIN_NAME = "binoracle"
_STATAMIC_SITE = "BinOracle Test"


def detect_statamic(source_dir: str) -> bool:
    """Return True if source looks like a Statamic CMS project."""
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = json.loads(open(composer).read())
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            if "statamic/cms" in reqs:
                return True
        except Exception:
            pass
    # Statamic-specific directory markers
    for marker in ("content", "users", "resources/views/vendor/statamic"):
        if os.path.isdir(os.path.join(source_dir, marker)):
            if os.path.isfile(os.path.join(source_dir, "composer.json")):
                return True
    return False


def _statamic_dockerfile(port: int = _STATAMIC_PORT) -> str:
    """Generate a minimal Statamic 4 Dockerfile for lab use."""
    return f"""FROM php:8.2-apache
RUN apt-get update -qq && apt-get install -y -qq \\
    libzip-dev libpng-dev libjpeg-dev libfreetype6-dev \\
    libicu-dev unzip curl git libsqlite3-dev \\
    && docker-php-ext-configure gd --with-freetype --with-jpeg \\
    && docker-php-ext-install -j4 pdo pdo_sqlite zip gd intl bcmath opcache \\
    && a2enmod rewrite \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
RUN composer create-project statamic/statamic statamic --no-interaction --prefer-dist 2>&1 \\
    || (echo "statamic download failed" && exit 1)
WORKDIR /var/www/html/statamic
ENV APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \\
    APP_ENV=local \\
    APP_DEBUG=true \\
    APP_URL=http://localhost:{port} \\
    DB_CONNECTION=sqlite \\
    DB_DATABASE=/var/www/html/statamic/database/database.sqlite \\
    STATAMIC_LICENSE_KEY=
COPY . /var/www/html/statamic/
RUN php artisan key:generate --force || true
RUN touch database/database.sqlite
RUN php artisan migrate --force 2>/dev/null || true
RUN php please make:user \\
    --name="{_STATAMIC_ADMIN_NAME}" \\
    --email="{_STATAMIC_ADMIN_EMAIL}" \\
    --password="{_STATAMIC_ADMIN_PASSWORD}" \\
    --super 2>/dev/null || true
RUN chown -R www-data:www-data /var/www/html/statamic
EXPOSE {port}
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port={port}"]
"""


def _get_statamic_session(base_url: str, step: Callable) -> Optional[str]:
    """Get Statamic admin session cookie via CSRF + Laravel login."""
    # Grab CSRF token from login page
    login_url = base_url + "/cp/auth/login"
    try:
        r = _http_request("GET", login_url, timeout=12)
        csrf = ""
        m = re.search(r'name="_token"\s+value="([^"]+)"', r.text or "")
        if m:
            csrf = m.group(1)
        # Also try meta tag
        if not csrf:
            m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', r.text or "")
            if m:
                csrf = m.group(1)
        # Collect session cookie from initial GET
        cookies: dict = {}
        for hdr_val in r.headers.get("set-cookie", "").split(", "):
            for part in hdr_val.split(";"):
                part = part.strip()
                if "=" in part and not part.lower().startswith(("path", "expires",
                                                                 "domain", "samesite",
                                                                 "max-age", "httponly")):
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        post_data = (
            f"email={_STATAMIC_ADMIN_EMAIL}"
            f"&password={_STATAMIC_ADMIN_PASSWORD}"
            + (f"&_token={csrf}" if csrf else "")
        )
        r2 = _http_request(
            "POST", login_url, data=post_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": cookie_str,
                "Referer": login_url,
            },
            timeout=12,
        )
        # Collect session cookie from POST response
        for hdr_val in r2.headers.get("set-cookie", "").split(", "):
            for part in hdr_val.split(";"):
                part = part.strip()
                if "=" in part and not part.lower().startswith(("path", "expires",
                                                                 "domain", "samesite",
                                                                 "max-age", "httponly")):
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()

        final_cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if any("session" in k.lower() or "laravel" in k.lower() for k in cookies):
            step(f"  sesion Statamic obtenida ({len(cookies)} cookies)")
            return final_cookie
    except Exception as e:
        step(f"  error en autenticacion Statamic: {e}")
    return None


def verify_statamic_cve(
    source_dir: str,
    cve_id: str,
    endpoint: str,
    http_method: str = "GET",
    payload: str = "",
    confirm_string: str = "",
    auth_required: bool = True,
    vuln_class: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    bypass_header: str = "",
    bypass_value: str = "",
    pkg_version: str = "",
) -> WpVerifyResult:
    """Verify a Statamic CMS CVE in a fresh Docker lab.

    Spins up a Statamic 4 container, optionally authenticates as admin,
    sends the probe request, and checks the response for confirmation.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    step("[Statamic lab] generando Dockerfile…")
    df_body = _statamic_dockerfile(_STATAMIC_PORT)

    # Bootstrap the lab using the generic orchestrator
    from .genericverify import _bootstrap_generic_lab
    boot = _bootstrap_generic_lab(
        source_dir, step, res, budget_s,
        dockerfile_body=df_body,
        pkg_version=pkg_version,
    )
    if boot is None:
        return res
    lab, base_url, container = boot

    try:
        m = (http_method or "GET").upper().strip() or "GET"
        url = base_url + endpoint
        auth_header = ""

        if auth_required:
            step("[Statamic lab] autenticando…")
            cookie = _get_statamic_session(base_url, step)
            if cookie:
                auth_header = f"Cookie: {cookie}"
            else:
                res.limitations.append("autenticacion Statamic fallida — continuando sin sesion")
                step("  autenticacion fallida, continuando sin sesion")

        # Build headers
        headers: dict = {}
        if auth_header.startswith("Cookie: "):
            headers["Cookie"] = auth_header[len("Cookie: "):]
        if bypass_header and bypass_value:
            headers[bypass_header] = bypass_value
        if payload and m in ("POST", "PUT", "PATCH"):
            headers.setdefault("Content-Type", "application/json")

        step(f"[Statamic lab] probando {m} {url}")
        body_data: Optional[str] = payload if m in ("POST", "PUT", "PATCH") else None
        try:
            r = _http_request(m, url, headers=headers, data=body_data,
                              timeout=15, allow_redirects=True)
            status = r.status_code
            body = getattr(r, "body", "") or getattr(r, "text", "") or ""
        except Exception as e:
            res.detail = f"error de red: {e}"
            return res

        string_ok = (not confirm_string) or (confirm_string in body)
        bypassed = status in range(200, 300)

        res.evidence = {
            "base_url": base_url,
            "endpoint": endpoint,
            "metodo": m,
            "status": status,
            "confirm_string": confirm_string,
            "confirm_string_presente": string_ok,
            "body_snippet": body[:500],
            "vuln_class": vuln_class,
        }

        if bypassed and string_ok:
            res.verified = True
            res.ok = True
            res.detail = (
                f"VERIFICADO: {m} {endpoint} → HTTP {status}"
                + (f" — confirm_string '{confirm_string}' presente" if confirm_string else "")
            )
            step(f"[Statamic lab] VERIFICADO: HTTP {status}")
        else:
            res.ok = True
            # Semantic body analysis for partial confidence signals
            if bypassed and not string_ok and body:
                from .genericverify import _analyze_response_body
                _analysis = _analyze_response_body(
                    body, vuln_class, payload=payload,
                    confirm_string=confirm_string, status_code=status)
                if _analysis.get("interesting"):
                    res.evidence["response_analysis"] = _analysis
            res.detail = (
                f"no confirmado: {m} {endpoint} → HTTP {status}"
                + (f", confirm_string={string_ok}" if confirm_string else "")
                + (f" — señales semánticas: {res.evidence.get('response_analysis', {}).get('partial_confidence', 0):.0%}"
                   if res.evidence.get("response_analysis") else "")
            )
            step(f"[Statamic lab] no confirmado: HTTP {status}")

        return res
    except Exception as e:
        res.detail = f"error interno: {e}"
        return res
    finally:
        step("[Statamic lab] desmontando laboratorio…")
        lab.teardown()
