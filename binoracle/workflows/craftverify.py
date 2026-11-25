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


def _craft_dockerfile(port: int = _CRAFT_PORT) -> str:
    """Generate a minimal Craft CMS 4 Dockerfile with SQLite."""
    return f"""FROM php:8.2-apache
RUN apt-get update -qq && apt-get install -y -qq \\
    libzip-dev libpng-dev libjpeg-dev libwebp-dev libfreetype6-dev \\
    libicu-dev unzip curl git libsqlite3-dev \\
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \\
    && docker-php-ext-install -j4 pdo pdo_sqlite zip gd intl bcmath opcache \\
    && a2enmod rewrite \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
RUN composer create-project craftcms/craft craft --no-interaction --prefer-dist \\
    || (echo "craft download failed" && exit 1)
WORKDIR /var/www/html/craft
RUN composer require craftcms/cms --no-interaction 2>/dev/null || true
# Configure SQLite
ENV CRAFT_DB_DRIVER=sqlite \\
    CRAFT_DB_DATABASE=/var/www/html/craft/storage/craft.db \\
    CRAFT_SECURITY_KEY=binoracle-test-key-32chars-00000 \\
    CRAFT_ENVIRONMENT=dev \\
    CRAFT_ALLOW_ADMIN_CHANGES=true \\
    PHP_PORT={port}
COPY . /var/www/html/craft/
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
        m = re.search(r'name="CRAFT_CSRF_TOKEN"\s+value="([^"]+)"', r.body or "")
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
) -> WpVerifyResult:
    """Verify a Craft CMS CVE dynamically.

    Spins up Craft CMS in Docker, fires PoC, checks confirm_string.
    Falls back to genericverify lab when Craft-specific Docker fails.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    # Prefer generic lab: Craft's Docker setup takes >3min; for most CVEs
    # (path traversal, XSS, SQLi) the generic PHP lab is faster and sufficient.
    try:
        from .genericverify import _bootstrap_generic_lab
        boot = _bootstrap_generic_lab(source_path, step, res, budget_s)
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
            res.evidence["status"] = r.status
            res.evidence["body_snippet"] = (r.body or "")[:300]
            res.evidence["endpoint"] = target_url

            if r.status in (200, 201):
                if confirm_string and confirm_string in (r.body or ""):
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Craft"
                    step("  craftverify: VERIFICADO")
                elif not confirm_string and payload and payload in (r.body or ""):
                    res.verified = True
                    res.ok = True
                    res.confidence = "probable"
                    res.detail = "VERIFICADO (probable): payload reflejado"
                else:
                    res.ok = True
                    res.detail = "HTTP 200 — confirm_string no encontrado"
            else:
                res.detail = f"HTTP {r.status} — endpoint no accesible"
            return res
    except Exception as e:
        step(f"  craftverify: generic lab error — {e}, trying Craft-specific lab")

    # Fallback: Craft-specific Docker (slow but accurate for Craft-specific auth flows)
    container = f"bo_craft_{os.urandom(4).hex()}"
    try:
        dockerfile_content = _craft_dockerfile(_CRAFT_PORT)
        import tempfile, pathlib
        with tempfile.TemporaryDirectory(prefix="bo_craft_") as tmpdir:
            pathlib.Path(tmpdir, "Dockerfile").write_text(dockerfile_content)
            step("  craftverify: construyendo imagen Craft CMS…")
            _run(["docker", "build", "-t", container, tmpdir], timeout=240)
            _run(["docker", "run", "-d", "--rm", "--name", container,
                  "-p", f"{_CRAFT_PORT}:{_CRAFT_PORT}", container], timeout=30)

            import socket as _sock
            host = _lab_host()
            for _ in range(60):
                try:
                    with _sock.create_connection((host, _CRAFT_PORT), timeout=1):
                        break
                except OSError:
                    time.sleep(1)

            base_url = f"http://{host}:{_CRAFT_PORT}"
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
            res.evidence["status"] = r.status
            res.evidence["body_snippet"] = (r.body or "")[:300]

            if r.status in (200, 201):
                if confirm_string and confirm_string in (r.body or ""):
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Craft"
                    step("  craftverify: VERIFICADO")
                elif not confirm_string and payload and payload in (r.body or ""):
                    res.verified = True
                    res.ok = True
                    res.confidence = "probable"
                    res.detail = "VERIFICADO (probable): payload reflejado"
                else:
                    res.ok = True
                    res.detail = "HTTP 200 — confirm_string no encontrado"
            else:
                res.detail = f"HTTP {r.status}"
    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    return res
