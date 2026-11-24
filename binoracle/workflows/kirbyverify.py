"""kirbyverify.py — Kirby CMS web CVE verifier.

Kirby 3/4 is a flat-file PHP CMS (composer package getkirby/cms).
Admin authentication via /panel/api/auth/login (JSON, returns auth token).
No database required — user accounts stored as YAML files in site/accounts/.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, ssti.
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request

_KIRBY_PORT = 8080
_KIRBY_ADMIN_EMAIL = "binoracle@test.local"
_KIRBY_ADMIN_PASSWORD = "Bin0racleTest!"
_KIRBY_ADMIN_NAME = "binoracle"


def detect_kirby(source_dir: str) -> bool:
    """Return True if source looks like a Kirby CMS project."""
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = json.loads(open(composer).read())
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            if "getkirby/cms" in reqs:
                return True
        except Exception:
            pass
    # Kirby directory markers (index.php + site/ structure)
    for marker in ("site/config/config.php", "kirby/bootstrap.php",
                   "site/accounts", "content"):
        if os.path.exists(os.path.join(source_dir, marker)):
            if os.path.isfile(os.path.join(source_dir, "index.php")):
                return True
    return False


def _kirby_dockerfile(port: int = _KIRBY_PORT) -> str:
    """Generate a minimal Kirby 4 Dockerfile."""
    return f"""FROM php:8.2-apache
RUN apt-get update -qq && apt-get install -y -qq \\
    libzip-dev libpng-dev libjpeg-dev libfreetype6-dev \\
    unzip curl git \\
    && docker-php-ext-configure gd --with-freetype --with-jpeg \\
    && docker-php-ext-install -j4 pdo zip gd \\
    && a2enmod rewrite \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
RUN composer create-project getkirby/starterkit kirby --no-interaction --prefer-dist 2>&1 \\
    || (echo "kirby download failed" && exit 1)
WORKDIR /var/www/html/kirby
COPY . /var/www/html/kirby/
RUN mkdir -p site/accounts
# Create admin user (Kirby stores accounts as YAML files)
RUN php -r "
\\$hash = password_hash('{_KIRBY_ADMIN_PASSWORD}', PASSWORD_DEFAULT);
\\$yaml = \\\"email: {_KIRBY_ADMIN_EMAIL}\\n\\\"
        . \\\"language: en\\n\\\"
        . \\\"name: {_KIRBY_ADMIN_NAME}\\n\\\"
        . \\\"password: \\$hash\\n\\\"
        . \\\"role: admin\\n\\\";
file_put_contents('site/accounts/{_KIRBY_ADMIN_EMAIL}.yml', \\$yaml);
"
RUN chown -R www-data:www-data /var/www/html/kirby
ENV PHP_PORT={port}
EXPOSE {port}
CMD ["apache2-foreground"]
"""


def _get_kirby_token(base_url: str, step: Callable) -> Optional[str]:
    """Authenticate against Kirby Panel API, return Bearer token."""
    login_url = base_url + "/panel/api/auth/login"
    payload = json.dumps({"email": _KIRBY_ADMIN_EMAIL, "password": _KIRBY_ADMIN_PASSWORD})
    try:
        r = _http_request(
            "POST", login_url, data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=12,
        )
        body = getattr(r, "body", "") or getattr(r, "text", "") or ""
        try:
            data = json.loads(body)
            token = data.get("token") or data.get("access_token") or data.get("csrf")
            if token:
                step(f"  token Kirby obtenido (len={len(token)})")
                return str(token)
        except Exception:
            pass
        # Kirby 3 uses X-CSRF cookie: grab from Set-Cookie
        cookies: dict = {}
        for hdr_val in r.headers.get("set-cookie", "").split(", "):
            for part in hdr_val.split(";"):
                part = part.strip()
                if "=" in part and not part.lower().startswith(("path", "expires",
                                                                 "domain", "samesite",
                                                                 "max-age", "httponly")):
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            step(f"  sesion Kirby via cookie ({len(cookies)} cookies)")
            return f"Cookie::{cookie_str}"
    except Exception as e:
        step(f"  error autenticacion Kirby: {e}")
    return None


def verify_kirby_cve(
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
    """Verify a Kirby CMS CVE in a fresh Docker lab.

    Spins up a Kirby 4 container, optionally authenticates via Panel API,
    sends the probe request, and checks the response for confirmation.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    step("[Kirby lab] generando Dockerfile…")
    df_body = _kirby_dockerfile(_KIRBY_PORT)

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
        headers: dict = {}

        if auth_required:
            step("[Kirby lab] autenticando…")
            token_raw = _get_kirby_token(base_url, step)
            if token_raw:
                if token_raw.startswith("Cookie::"):
                    headers["Cookie"] = token_raw[len("Cookie::"):]
                else:
                    # Kirby Panel API accepts X-CSRF-Token or Authorization: Bearer
                    headers["Authorization"] = f"Bearer {token_raw}"
                    headers["X-CSRF-Token"] = token_raw
            else:
                res.limitations.append("autenticacion Kirby fallida — continuando sin auth")
                step("  autenticacion fallida, continuando sin auth")

        if bypass_header and bypass_value:
            headers[bypass_header] = bypass_value
        if payload and m in ("POST", "PUT", "PATCH"):
            headers.setdefault("Content-Type", "application/json")

        step(f"[Kirby lab] probando {m} {url}")
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
            step(f"[Kirby lab] VERIFICADO: HTTP {status}")
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
            step(f"[Kirby lab] no confirmado: HTTP {status}")

        return res
    except Exception as e:
        res.detail = f"error interno: {e}"
        return res
    finally:
        step("[Kirby lab] desmontando laboratorio…")
        lab.teardown()
