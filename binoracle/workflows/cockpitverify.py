"""cockpitverify.py — Cockpit CMS web CVE verifier.

Cockpit CMS v2 is a headless PHP CMS (agentejo/cockpit or Cockpit-HQ/Cockpit).
Authentication: POST /api/user/login → {"token": "..."} (API-key/JWT).
No database config required — ships with SQLite as default driver.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, ssti.
"""
from __future__ import annotations

import json
import os
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request

_COCKPIT_PORT = 8080
_COCKPIT_ADMIN_USER = "admin"
_COCKPIT_ADMIN_PASSWORD = "Bin0racleTest!"
_COCKPIT_ADMIN_EMAIL = "binoracle@test.local"


def detect_cockpit(source_dir: str) -> bool:
    """Return True if source looks like a Cockpit CMS project."""
    for marker in ("cockpit.php", "bootstrap/app.php", "modules/Cockpit"):
        if os.path.exists(os.path.join(source_dir, marker)):
            return True
    # Composer check
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = json.loads(open(composer).read())
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            if any("cockpit" in k.lower() for k in reqs):
                return True
        except Exception:
            pass
    return False


def _cockpit_dockerfile(port: int = _COCKPIT_PORT) -> str:
    """Generate a minimal Cockpit CMS v2 Dockerfile."""
    return f"""FROM php:8.1-apache
RUN apt-get update -qq && apt-get install -y -qq \\
    libzip-dev libpng-dev libsqlite3-dev \\
    unzip curl git \\
    && docker-php-ext-install -j4 pdo pdo_sqlite zip gd \\
    && a2enmod rewrite \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
# Install Cockpit CMS v2 (Cockpit-HQ/Cockpit)
RUN composer create-project cockpit-hq/cockpit cockpit --no-interaction --prefer-dist 2>&1 \\
    || (echo "cockpit download failed" && exit 1)
WORKDIR /var/www/html/cockpit
COPY . /var/www/html/cockpit/
RUN mkdir -p storage && chmod 777 storage
# Bootstrap Cockpit with admin user via CLI install script
RUN php cockpit.php install --username="{_COCKPIT_ADMIN_USER}" \\
    --password="{_COCKPIT_ADMIN_PASSWORD}" \\
    --email="{_COCKPIT_ADMIN_EMAIL}" 2>/dev/null || true
# Fallback: write config manually if CLI fails
RUN php -r "
define('COCKPIT_DIR', '/var/www/html/cockpit');
\\$storage = COCKPIT_DIR . '/storage';
\\$users_dir = \\$storage . '/data/cockpit/users';
if (!is_dir(\\$users_dir)) mkdir(\\$users_dir, 0777, true);
\\$user = [
    '_id'      => '000000000000000000000001',
    'user'     => '{_COCKPIT_ADMIN_USER}',
    'email'    => '{_COCKPIT_ADMIN_EMAIL}',
    'active'   => true,
    'password' => password_hash('{_COCKPIT_ADMIN_PASSWORD}', PASSWORD_DEFAULT),
    'i18n'     => 'en',
    'role'     => 'admin',
    '_created' => time(),
    '_modified'=> time(),
];
file_put_contents(\\$users_dir . '/admin.json', json_encode(\\$user, JSON_PRETTY_PRINT));
echo 'admin user written';
" || true
RUN chown -R www-data:www-data /var/www/html/cockpit
# Apache config to handle Cockpit's front controller
RUN echo 'Options -Indexes\\nDirectoryIndex index.php\\n<IfModule mod_rewrite.c>\\nRewriteEngine On\\nRewriteBase /\\nRewriteCond %{{REQUEST_FILENAME}} !-f\\nRewriteRule ^(.*)$ index.php [QSA,L]\\n</IfModule>' \\
    > /etc/apache2/conf-available/cockpit.conf \\
    && a2enconf cockpit
EXPOSE {port}
CMD ["apache2-foreground"]
"""


def _get_cockpit_token(base_url: str, step: Callable) -> Optional[str]:
    """Authenticate to Cockpit API, return API token."""
    # Cockpit v2 login: POST /api/user/login
    for login_path in ("/api/user/login", "/auth/login", "/api/auth"):
        url = base_url + login_path
        payload = json.dumps({"user": _COCKPIT_ADMIN_USER,
                              "password": _COCKPIT_ADMIN_PASSWORD})
        try:
            r = _http_request(
                "POST", url, data=payload,
                headers={"Content-Type": "application/json",
                         "Accept": "application/json"},
                timeout=10,
            )
            if r.status_code not in range(200, 300):
                continue
            body = getattr(r, "body", "") or getattr(r, "text", "") or ""
            try:
                data = json.loads(body)
                # Cockpit v2 returns {"_id":..., "token": "..."}
                token = (data.get("token") or data.get("api_key") or
                         data.get("access_token") or "")
                if token:
                    step(f"  token Cockpit obtenido via {login_path} (len={len(token)})")
                    return str(token)
            except Exception:
                pass
        except Exception as e:
            step(f"  error en Cockpit {login_path}: {e}")
            continue
    return None


def verify_cockpit_cve(
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
    """Verify a Cockpit CMS CVE in a fresh Docker lab.

    Spins up a Cockpit CMS v2 container, optionally authenticates via
    the REST API, sends the probe request, and checks the response.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    step("[Cockpit lab] generando Dockerfile…")
    df_body = _cockpit_dockerfile(_COCKPIT_PORT)

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
            step("[Cockpit lab] autenticando…")
            token = _get_cockpit_token(base_url, step)
            if token:
                # Cockpit accepts Cockpit-Token header or api_key query param
                headers["Cockpit-Token"] = token
                headers["Authorization"] = f"Bearer {token}"
            else:
                res.limitations.append("autenticacion Cockpit fallida — continuando sin token")
                step("  autenticacion fallida, continuando sin token")

        if bypass_header and bypass_value:
            headers[bypass_header] = bypass_value
        if payload and m in ("POST", "PUT", "PATCH"):
            headers.setdefault("Content-Type", "application/json")

        step(f"[Cockpit lab] probando {m} {url}")
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
            step(f"[Cockpit lab] VERIFICADO: HTTP {status}")
        else:
            res.ok = True
            res.detail = (
                f"no confirmado: {m} {endpoint} → HTTP {status}"
                + (f", confirm_string={string_ok}" if confirm_string else "")
            )
            step(f"[Cockpit lab] no confirmado: HTTP {status}")

        return res
    except Exception as e:
        res.detail = f"error interno: {e}"
        return res
    finally:
        step("[Cockpit lab] desmontando laboratorio…")
        lab.teardown()
