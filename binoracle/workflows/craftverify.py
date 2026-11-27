"""craftverify.py — Craft CMS web CVE verifier.

Craft CMS 4/5 uses PHP + a SQLite/MySQL/PostgreSQL database.
Admin authentication uses CSRF tokens + cookie sessions.
This verifier spins up a minimal Craft container for PoC verification.

Supported vuln classes: xss, sqli, ssrf, missing-authorization,
path-traversal, rce, ssti.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host

_CRAFT_PORT = 8080
_CRAFT_ADMIN_USER = "binoracle@test.local"
_CRAFT_ADMIN_PASSWORD = "Binoracle123!Test"
_CRAFT_ADMIN_NAME = "binoracle"


def detect_craft(source_dir: str) -> bool:
    """Return True if source looks like a Craft CMS project OR library."""
    import json as _j
    composer = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer):
        try:
            data = _j.loads(open(composer).read())
            # Craft CMS project: requires craftcms/cms
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}
            if "craftcms/cms" in reqs:
                return True
            # Craft CMS library itself: name == "craftcms/cms"
            if data.get("name") == "craftcms/cms":
                return True
        except Exception:
            pass
    # Check for craft-specific directories
    for marker in ("config/app.php", "config/db.php", "web/index.php"):
        if os.path.isfile(os.path.join(source_dir, marker)):
            if os.path.isdir(os.path.join(source_dir, "config")):
                return True
    # Check for CraftCMS library source markers (src/Craft.php or src/console/)
    if (os.path.isfile(os.path.join(source_dir, "src", "Craft.php"))
            or os.path.isdir(os.path.join(source_dir, "src", "web"))):
        return True
    return False


def _craft_dockerfile(port: int = _CRAFT_PORT, cms_version: str = "") -> str:
    """Generate a minimal Craft CMS Dockerfile with SQLite.

    cms_version: pin to a specific craftcms/cms version (e.g. "5.6.16").
    Without it, the latest version is installed (may be patched).
    """
    # Pin to vulnerable version when specified; otherwise install a Craft 4 baseline
    if cms_version:
        _cms_req = f"craftcms/cms:{cms_version}"
        _create_proj = "craftcms/craft"
    else:
        _cms_req = ""
        _create_proj = "craftcms/craft"
    _pin_step = (
        f'RUN composer require "{_cms_req}" --no-interaction 2>&1 | tail -3'
        if cms_version else
        "# cms_version not set — using whatever create-project pulls in"
    )
    return f"""FROM php:8.2-apache
RUN apt-get update -qq && apt-get install -y -qq \\
    libzip-dev libpng-dev libjpeg-dev libwebp-dev libfreetype6-dev \\
    libicu-dev unzip curl git libsqlite3-dev \\
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \\
    && docker-php-ext-install -j4 pdo pdo_sqlite zip gd intl bcmath opcache \\
    && a2enmod rewrite \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
# Enable register_argc_argv (CVE-2024-56145 and similar argv-injection CVEs) + display errors
RUN echo "register_argc_argv = On" >> /usr/local/etc/php/php.ini-development \\
    && echo "display_errors = On" >> /usr/local/etc/php/php.ini-development \\
    && echo "display_startup_errors = On" >> /usr/local/etc/php/php.ini-development \\
    && echo "error_reporting = E_ALL" >> /usr/local/etc/php/php.ini-development \\
    && cp /usr/local/etc/php/php.ini-development /usr/local/etc/php/php.ini
# Configure Apache to listen on {port} (not the default 80) so -p {port}:{port} works correctly
RUN sed -i 's/^Listen 80$/Listen {port}/' /etc/apache2/ports.conf \\
    && sed -i 's/<VirtualHost \\*:80>/<VirtualHost *:{port}>/' /etc/apache2/sites-available/000-default.conf
WORKDIR /var/www/html
RUN composer create-project {_create_proj} craft --no-interaction --prefer-dist \\
    || (echo "craft download failed" && exit 1)
WORKDIR /var/www/html/craft
{_pin_step}
# Configure Apache DocumentRoot to point at Craft's web/ directory
RUN sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/craft/web|g' /etc/apache2/sites-available/000-default.conf \\
    && sed -i 's|<Directory /var/www/html>|<Directory /var/www/html/craft/web>|g' /etc/apache2/apache2.conf \\
    && echo '<Directory /var/www/html/craft/web>\\n    Options Indexes FollowSymLinks\\n    AllowOverride All\\n    Require all granted\\n</Directory>' >> /etc/apache2/sites-available/000-default.conf
# Configure SQLite
ENV CRAFT_DB_DRIVER=sqlite \\
    CRAFT_DB_DATABASE=/var/www/html/craft/storage/craft.db \\
    CRAFT_SECURITY_KEY=binoracle-test-key-32chars-00000 \\
    CRAFT_ENVIRONMENT=dev \\
    CRAFT_ALLOW_ADMIN_CHANGES=true \\
    PHP_PORT={port}
RUN chown -R www-data:www-data /var/www/html/craft
EXPOSE {port}
CMD ["apache2-foreground"]
"""


def _get_craft_session(base_url: str, step: Callable) -> Optional[str]:
    """Get Craft admin session cookie via CSRF + login flow."""
    # Step 1: Get CSRF token from login page
    login_url = base_url + "/index.php?p=admin/login"
    try:
        r = _http_request("GET", login_url, timeout=10)
        csrf = ""
        m = re.search(r'name="CRAFT_CSRF_TOKEN"\s+value="([^"]+)"', r.text or "")
        if m:
            csrf = m.group(1)
        else:
            # Try JSON CSRF endpoint
            r2 = _http_request("GET", base_url + "/index.php?p=actions/users/session-info",
                                headers={"Accept": "application/json"}, timeout=5)
            try:
                data = json.loads(r2.body or "{}")
                csrf = data.get("csrfTokenValue", "")
            except Exception:
                pass

        # Extract any existing cookies from login page
        cookie_hdr = r.headers.get("set-cookie", "")
        cookies = {}
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

        # Step 2: POST login
        login_data = (
            f"loginName={_CRAFT_ADMIN_USER}&password={_CRAFT_ADMIN_PASSWORD}"
            + (f"&CRAFT_CSRF_TOKEN={csrf}" if csrf else "")
            + "&action=users/login"
        )
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        r3 = _http_request(
            "POST", login_url, data=login_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": cookie_str,
            },
            timeout=10,
        )
        new_cookies = r3.headers.get("set-cookie", "")
        m2 = re.search(r"CraftSessionId=([^;]+)", new_cookies)
        if m2:
            step("  craftverify: session cookie obtenida")
            return f"CraftSessionId={m2.group(1)}"
    except Exception as e:
        step(f"  craftverify: auth error — {e}")
    return None


def verify_craft_web_cve(
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
    json_body: bool = False,
    setup_cmds: Optional[list] = None,
) -> WpVerifyResult:
    """Verify a Craft CMS CVE dynamically.

    Spins up Craft CMS in Docker, fires PoC, checks confirm_string.
    Falls back to genericverify lab when Craft-specific Docker fails.

    setup_cmds: optional list of shell commands to run inside the container
    (via docker exec) after startup but before the HTTP attack. Use for
    multi-step exploits that require pre-conditioning the container state,
    e.g. writing a PHP gadget file for Yii2 PhpManager RCE (CVE-2025-32432).
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    # Nuclei-style {{nonce}} / {nonce} substitution: replace with a random
    # 10-digit integer so the value appears in the error response (register_argc_argv
    # CVEs like CVE-2024-56145 use this pattern to prove path is processed).
    import random as _rand_nonce
    _nonce_val = str(_rand_nonce.randint(1000000000, 9999999999))
    _had_nonce = "{nonce}" in endpoint or "{{nonce}}" in endpoint
    endpoint = endpoint.replace("{{nonce}}", _nonce_val).replace("{nonce}", _nonce_val)
    confirm_string = confirm_string.replace("{{nonce}}", _nonce_val).replace(
        "{nonce}", _nonce_val
    )
    # If confirm_string was the nonce placeholder (now a number), or was empty and
    # the endpoint had a nonce, fall back to checking the nonce itself in the response.
    _nonce_confirm = confirm_string if confirm_string else (_nonce_val if _had_nonce else "")

    # Prefer generic lab: Craft's Docker setup takes >3min; for most CVEs
    # (path traversal, XSS, SQLi) the generic PHP lab is faster and sufficient.
    # BUT: only use the generic lab when it has pre-built infra (source is a full
    # project with its own Dockerfile/compose). For the craftcms/cms library source
    # (no Dockerfile), the generic lab would call an LLM which generates a broken
    # Dockerfile — skip straight to the craft-specific Docker in that case.
    _has_own_docker = (
        os.path.isfile(os.path.join(source_path, "Dockerfile")) or
        os.path.isfile(os.path.join(source_path, "docker-compose.yml")) or
        os.path.isfile(os.path.join(source_path, "docker-compose.yaml"))
    )
    try:
        from .genericverify import _bootstrap_generic_lab
        boot = _bootstrap_generic_lab(source_path, step, res, budget_s) if _has_own_docker else None
        if boot and boot[0]:
            lab, base_url, container = boot
            step("  craftverify: usando lab genérico PHP para Craft CMS")

            cookie = None
            csrf_token = ""
            if auth_required:
                cookie = _get_craft_session(base_url, step)
            # Fetch CSRF token for POST endpoints (needed even without full auth login)
            if http_method.upper() not in ("GET", "HEAD"):
                try:
                    _csrf_r = _http_request("GET", base_url + "/index.php?p=admin/dashboard",
                                            timeout=5)
                    m_csrf = re.search(r'name="CRAFT_CSRF_TOKEN"\s+value="([^"]+)"',
                                       _csrf_r.body or "")
                    if m_csrf:
                        csrf_token = m_csrf.group(1)
                    if not csrf_token:
                        import json as _jcsrf
                        _csrf_r2 = _http_request(
                            "GET", base_url + "/index.php?p=actions/users/session-info",
                            headers={"Accept": "application/json"}, timeout=5)
                        csrf_token = (_jcsrf.loads(_csrf_r2.body or "{}").get(
                            "csrfTokenValue") or "")
                except Exception:
                    pass

            target_url = base_url + endpoint
            headers = {}
            if cookie:
                headers["Cookie"] = cookie
            if csrf_token:
                headers["X-CSRF-Token"] = csrf_token

            # Build request body/params from parameters (dict or list)
            body = None
            if isinstance(parameters, dict) and parameters:
                if http_method.upper() == "POST":
                    if json_body:
                        import json as _jb
                        body = _jb.dumps(parameters)
                        headers["Content-Type"] = "application/json"
                    else:
                        from urllib.parse import urlencode as _urlencode
                        body = _urlencode(parameters)
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    from urllib.parse import urlencode as _urlencode
                    target_url += "?" + _urlencode(parameters)
            else:
                param = (parameters or [None])[0] if parameters else None
                if http_method.upper() == "POST" and param:
                    body = f"{param}={payload}"
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                elif param and payload:
                    target_url += f"?{param}={payload}"

            step(f"  craftverify: {http_method} {target_url}")
            r = _http_request(http_method.upper(), target_url,
                              data=body, headers=headers, timeout=15)
            res.evidence["status"] = r.status_code
            res.evidence["body_snippet"] = (r.text or "")[:300]
            res.evidence["endpoint"] = target_url

            body_text = r.text or ""
            _effective_confirm = confirm_string or _nonce_confirm
            if r.status_code in (200, 201, 500):
                if _effective_confirm and _effective_confirm in body_text:
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = f"VERIFICADO: '{_effective_confirm}' en respuesta Craft"
                    step("  craftverify: VERIFICADO")
                elif not _effective_confirm and payload and payload in body_text:
                    res.verified = True
                    res.ok = True
                    res.confidence = "probable"
                    res.detail = "VERIFICADO (probable): payload reflejado"
                elif _had_nonce and "mkdir" in body_text.lower():
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = "VERIFICADO: mkdir() en respuesta Craft (register_argc_argv)"
                    step("  craftverify: VERIFICADO (mkdir fallback)")
                else:
                    res.ok = True
                    res.detail = "HTTP %d — confirm_string no encontrado" % r.status_code
            else:
                res.detail = f"HTTP {r.status_code} — endpoint no accesible"
            return res
    except Exception as e:
        step(f"  craftverify: generic lab error — {e}, trying Craft-specific lab")

    # Fallback: Craft-specific Docker (slow but accurate for Craft-specific auth flows)
    container = f"bo_craft_{os.urandom(4).hex()}"
    try:
        dockerfile_content = _craft_dockerfile(_CRAFT_PORT, cms_version=pkg_version or "")
        import tempfile, pathlib

        # Cache the base image under a stable tag so Docker reuses layers across
        # multiple runs with the same CraftCMS version (composer install only runs once).
        # Include a short hash of the Dockerfile to auto-invalidate when it changes.
        import hashlib as _hashlib
        _df_hash = _hashlib.sha1(dockerfile_content.encode()).hexdigest()[:8]
        _safe_ver = (pkg_version or "latest").replace(":", "_").replace("/", "_").replace(".", "_")
        _cache_tag = f"binoracle_craft_base:{_safe_ver}_{_df_hash}"
        _cache_exists = False
        try:
            _inspect = _run(["docker", "image", "inspect", _cache_tag], timeout=5)
            _cache_exists = (_inspect.returncode == 0)
        except Exception:
            pass

        with tempfile.TemporaryDirectory(prefix="bo_craft_") as tmpdir:
            pathlib.Path(tmpdir, "Dockerfile").write_text(dockerfile_content)
            if _cache_exists:
                step(f"  craftverify: imagen cacheada {_cache_tag} encontrada — reutilizando")
            else:
                step("  craftverify: construyendo imagen Craft CMS (primera vez, ~3-5 min)…")
                _run(["docker", "build", "-t", _cache_tag, tmpdir], timeout=480)
                step(f"  craftverify: imagen construida y cacheada como {_cache_tag}")
            _run(["docker", "run", "-d", "--rm", "--name", container,
                  "-p", f"{_CRAFT_PORT}:{_CRAFT_PORT}", _cache_tag], timeout=30)

            import socket as _sock
            host = _lab_host()
            for _ in range(60):
                try:
                    with _sock.create_connection((host, _CRAFT_PORT), timeout=1):
                        break
                except OSError:
                    time.sleep(1)

            base_url = f"http://{host}:{_CRAFT_PORT}"

            # Run pre-exploit setup commands inside the container.
            # Used for multi-step exploits that need to pre-condition container state
            # (e.g. write a PHP gadget file for Yii2 PhpManager RCE, or install a CMS).
            for _cmd in (setup_cmds or []):
                try:
                    step(f"  craftverify: setup_cmd: {_cmd[:100]}")
                    _run(["docker", "exec", container, "sh", "-c", _cmd], timeout=120)
                except Exception as _se:
                    step(f"  craftverify: setup_cmd error — {_se}")

            cookie = None
            csrf_token = ""
            if auth_required:
                cookie = _get_craft_session(base_url, step)
            # Fetch CSRF token for POST endpoints (needed even without full auth login)
            if http_method.upper() not in ("GET", "HEAD"):
                try:
                    _csrf_r = _http_request("GET", base_url + "/index.php?p=admin/dashboard",
                                            timeout=5)
                    m_csrf = re.search(r'name="CRAFT_CSRF_TOKEN"\s+value="([^"]+)"',
                                       _csrf_r.body or "")
                    if m_csrf:
                        csrf_token = m_csrf.group(1)
                    if not csrf_token:
                        import json as _jcsrf
                        _csrf_r2 = _http_request(
                            "GET", base_url + "/index.php?p=actions/users/session-info",
                            headers={"Accept": "application/json"}, timeout=5)
                        csrf_token = (_jcsrf.loads(_csrf_r2.body or "{}").get(
                            "csrfTokenValue") or "")
                except Exception:
                    pass

            # Session-poisoning pre-attack for gadget chains (e.g. CVE-2025-32432 PhpManager).
            # If parameters contains "{pre_attack_path}" key, perform a GET to that path first.
            # The PHPSESSID from Set-Cookie is extracted and {session_file} placeholders in
            # all parameter values are replaced with /tmp/sess_{PHPSESSID}.
            if isinstance(parameters, dict) and "{pre_attack_path}" in parameters:
                _pre_path = parameters.pop("{pre_attack_path}")
                try:
                    _pre_r = _http_request("GET", base_url + _pre_path, timeout=10)
                    _sc_hdr = _pre_r.headers.get("set-cookie", "") or ""
                    _sess_m = re.search(r"PHPSESSID=([a-f0-9]+)", _sc_hdr)
                    if _sess_m:
                        _sf = f"/tmp/sess_{_sess_m.group(1)}"
                        step(f"  craftverify: sesión envenenada → {_sf}")
                        import json as _jrepl
                        _ps = _jrepl.dumps(parameters)
                        parameters = _jrepl.loads(_ps.replace("{session_file}", _sf))
                except Exception as _pre_e:
                    step(f"  craftverify: pre-attack error — {_pre_e}")

            target_url = base_url + endpoint
            headers = {}
            if cookie:
                headers["Cookie"] = cookie
            if csrf_token:
                headers["X-CSRF-Token"] = csrf_token

            # Build request body/params from parameters (dict or list)
            body = None
            if isinstance(parameters, dict) and parameters:
                if http_method.upper() == "POST":
                    if json_body:
                        import json as _jb
                        body = _jb.dumps(parameters)
                        headers["Content-Type"] = "application/json"
                    else:
                        from urllib.parse import urlencode as _urlencode
                        body = _urlencode(parameters)
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    from urllib.parse import urlencode as _urlencode
                    target_url += "?" + _urlencode(parameters)
            else:
                param = (parameters or [None])[0] if parameters else None
                if http_method.upper() == "POST" and param:
                    body = f"{param}={payload}"
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                elif param and payload:
                    target_url += f"?{param}={payload}"

            step(f"  craftverify: {http_method} {target_url}")
            r = _http_request(http_method.upper(), target_url,
                              data=body, headers=headers, timeout=15)
            res.evidence["status"] = r.status_code
            res.evidence["body_snippet"] = (r.text or "")[:300]

            body_text = r.text or ""
            _effective_confirm = confirm_string or _nonce_confirm
            if r.status_code in (200, 201, 500):
                if _effective_confirm and _effective_confirm in body_text:
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = f"VERIFICADO: '{_effective_confirm}' en respuesta Craft"
                    step("  craftverify: VERIFICADO")
                elif not _effective_confirm and payload and payload in body_text:
                    res.verified = True
                    res.ok = True
                    res.confidence = "probable"
                    res.detail = "VERIFICADO (probable): payload reflejado"
                elif _had_nonce and "mkdir" in body_text.lower():
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = "VERIFICADO: mkdir() en respuesta Craft (register_argc_argv)"
                    step("  craftverify: VERIFICADO (mkdir fallback)")
                else:
                    res.ok = True
                    res.detail = "HTTP %d — confirm_string no encontrado" % r.status_code
            else:
                res.detail = f"HTTP {r.status_code}"
    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    return res
