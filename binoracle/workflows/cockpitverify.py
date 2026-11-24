"""cockpitverify.py — Cockpit CMS web CVE verifier.

Cockpit CMS v2 is a headless PHP CMS (agentejo/cockpit or Cockpit-HQ/Cockpit).
Authentication:
  v1: GET/POST /api/cockpit/authToken?user=admin&password=admin → {"token": "..."}
  v2: POST /api/user/login → {"_id": ..., "token": "..."}
No separate database config required — ships with SQLite as default driver.

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
    for marker in (
        "cockpit.php",           # v1 entry point
        "cockpit/bootstrap.php", # nested install
        "modules/Cockpit",       # v1 module structure
        "lib/Cockpit",           # v1 lib structure
        "storage/cockpit.sqlite",
        "bootstrap/app.php",     # v2 (Laravel-like bootstrap)
    ):
        if os.path.exists(os.path.join(source_dir, marker)):
            return True
    # Composer check: agentejo/cockpit (v1) or cockpit-hq/cockpit (v2)
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = json.loads(open(composer).read())  # noqa: WPS515
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            name = data.get("name", "").lower()
            if any("cockpit" in k.lower() for k in reqs):
                return True
            if "cockpit" in name:
                return True
        except Exception:
            pass
    # package.json check for "cockpit-core"
    pkg = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg):
        try:
            data = json.loads(open(pkg).read())  # noqa: WPS515
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if any("cockpit" in k.lower() for k in deps):
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
COPY . .
RUN composer install --no-dev --no-interaction 2>/dev/null || true
RUN mkdir -p storage/data/cockpit/users storage/cache storage/tmp && chmod -R 777 storage
# Bootstrap admin user via CLI or fallback JSON write
RUN php cockpit.php install \\
    --username="{_COCKPIT_ADMIN_USER}" \\
    --password="{_COCKPIT_ADMIN_PASSWORD}" \\
    --email="{_COCKPIT_ADMIN_EMAIL}" 2>/dev/null || true
# Fallback: write admin user JSON directly (Cockpit v1 & v2 storage format)
RUN php -r "
define('STORAGE', getcwd() . '/storage');
\\$users_dir = STORAGE . '/data/cockpit/users';
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
RUN chown -R www-data:www-data /var/www/html
# Apache rewrite for Cockpit front controller
RUN echo '<Directory /var/www/html>\\n  Options -Indexes\\n  AllowOverride All\\n  Require all granted\\n</Directory>' \\
    >> /etc/apache2/apache2.conf && a2enmod rewrite
EXPOSE {port}
CMD ["apache2-foreground"]
"""


def _get_cockpit_token(base_url: str, step: Callable) -> Optional[str]:
    """Authenticate to Cockpit API, return API token.

    Tries v1 endpoints (authToken GET/POST) then v2 (user/login),
    then tries unauthenticated access as a last resort.
    """
    # Strategy 1: Cockpit v1 — GET /api/cockpit/authToken?user=...&password=...
    v1_get = (f"{base_url}/api/cockpit/authToken"
              f"?user={_COCKPIT_ADMIN_USER}&password={_COCKPIT_ADMIN_PASSWORD}")
    try:
        r = _http_request("GET", v1_get, timeout=10,
                          headers={"Accept": "application/json"})
        if r.status in range(200, 300):
            try:
                data = json.loads(r.body or "")
                token = data.get("token") or data.get("api_key") or ""
                if token:
                    step(f"  cockpit v1 GET authToken OK (len={len(token)})")
                    return str(token)
            except Exception:
                pass
    except Exception:
        pass

    # Strategy 2: Cockpit v1 — POST /api/cockpit/authToken
    try:
        r = _http_request("POST", base_url + "/api/cockpit/authToken",
                          data=json.dumps({"user": _COCKPIT_ADMIN_USER,
                                           "password": _COCKPIT_ADMIN_PASSWORD}),
                          headers={"Content-Type": "application/json",
                                   "Accept": "application/json"},
                          timeout=10)
        if r.status in range(200, 300):
            try:
                data = json.loads(r.body or "")
                token = data.get("token") or data.get("api_key") or ""
                if token:
                    step(f"  cockpit v1 POST authToken OK (len={len(token)})")
                    return str(token)
            except Exception:
                pass
    except Exception:
        pass

    # Strategy 3: Cockpit v2 — POST /api/user/login
    for login_path in ("/api/user/login", "/auth/login", "/api/auth"):
        try:
            r = _http_request("POST", base_url + login_path,
                              data=json.dumps({"user": _COCKPIT_ADMIN_USER,
                                               "password": _COCKPIT_ADMIN_PASSWORD}),
                              headers={"Content-Type": "application/json",
                                       "Accept": "application/json"},
                              timeout=10)
            if r.status in range(200, 300):
                try:
                    data = json.loads(r.body or "")
                    token = (data.get("token") or data.get("api_key") or
                             data.get("access_token") or "")
                    if token:
                        step(f"  cockpit v2 login OK via {login_path} (len={len(token)})")
                        return str(token)
                except Exception:
                    pass
        except Exception:
            continue

    # Strategy 4: Try to create admin via POST /api/accounts/create
    try:
        r = _http_request("POST", base_url + "/api/accounts/create",
                          data=json.dumps({
                              "user": _COCKPIT_ADMIN_USER,
                              "email": _COCKPIT_ADMIN_EMAIL,
                              "password": _COCKPIT_ADMIN_PASSWORD,
                              "group": "admin",
                          }),
                          headers={"Content-Type": "application/json"},
                          timeout=10)
        if r.status in range(200, 300):
            step("  cockpit admin created via /api/accounts/create, retrying login…")
            # Retry login after creation
            for lp in ("/api/user/login", "/api/cockpit/authToken"):
                try:
                    rl = _http_request("POST", base_url + lp,
                                       data=json.dumps({"user": _COCKPIT_ADMIN_USER,
                                                        "password": _COCKPIT_ADMIN_PASSWORD}),
                                       headers={"Content-Type": "application/json"},
                                       timeout=10)
                    if rl.status in range(200, 300):
                        try:
                            token = json.loads(rl.body or "").get("token", "")
                            if token:
                                return str(token)
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception:
        pass

    step("  cockpit auth: sin token obtenido")
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

    Spins up a Cockpit CMS container, optionally authenticates via
    the REST API (v1 or v2 token), sends the probe request, and checks the response.
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

    from .genericverify import _bootstrap_generic_lab, _escalate_missing_auth_impact
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
                # Cockpit accepts Cockpit-Token header, Bearer, or api_key query param
                headers["Cockpit-Token"] = token
                headers["Authorization"] = f"Bearer {token}"
                headers["Api-Key"] = token
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
            status = r.status
            body = r.body or ""
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

            # Impact escalation for missing-auth class
            _ESCALATE = {"missing-authorization", "auth-bypass",
                         "broken-access-control", "idor"}
            if vuln_class and vuln_class.lower().replace(" ", "-") in _ESCALATE:
                _bypass_hdrs = {}
                if bypass_header and bypass_value:
                    _bypass_hdrs[bypass_header] = bypass_value
                _esc = _escalate_missing_auth_impact(
                    base_url, endpoint, _bypass_hdrs, step, budget_s=60.0)
                if _esc:
                    res.evidence["impact_escalation"] = _esc
                    res.detail += f"\n\nImpacto escalado: {_esc['escalation_summary']}"
                    step(f"  escalación: {_esc['impact_class']} / {_esc['max_impact_found']}")
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
