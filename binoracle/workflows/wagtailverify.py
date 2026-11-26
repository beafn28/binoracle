"""Dynamic verifier for Wagtail CMS CVEs.

Wagtail is a Django-based CMS. This verifier:
  1. Spins up an ephemeral Wagtail + SQLite Docker lab
  2. Creates a superuser non-interactively
  3. Authenticates via POST /admin/login/ (CSRF + sessionid)
  4. Fires the PoC, checks confirm_string

Supported vuln classes: xss, sqli, ssrf, missing-authorization, path-traversal.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host

_WAGTAIL_PORT = 8000
_WAGTAIL_USER = "binoracle_admin"
_WAGTAIL_PASS = "Binoracle123!"
_WAGTAIL_EMAIL = "admin@binoracle.dev"


def detect_wagtail(source_dir: str) -> bool:
    """Return True if source looks like a Wagtail project."""
    _dep_files = ["requirements.txt", "pyproject.toml", "setup.cfg", "Pipfile"]
    for fname in _dep_files:
        fpath = os.path.join(source_dir, fname)
        if os.path.isfile(fpath):
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read().lower()
                if "wagtail" in content:
                    return True
            except Exception:
                continue
    return False


def _wagtail_dockerfile(port: int = _WAGTAIL_PORT) -> str:
    return f"""FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir wagtail==5.2.3 gunicorn
WORKDIR /app
RUN wagtail start mysite . && \\
    python manage.py migrate --run-syncdb && \\
    echo "from django.contrib.auth import get_user_model; U=get_user_model(); \\
U.objects.create_superuser('{_WAGTAIL_USER}', '{_WAGTAIL_EMAIL}', '{_WAGTAIL_PASS}')" | \\
    python manage.py shell
EXPOSE {port}
CMD ["python", "manage.py", "runserver", "0.0.0.0:{port}"]
"""


def _get_wagtail_session(base_url: str, step) -> Optional[str]:
    """Get Wagtail admin session cookie via CSRF + login."""
    login_url = base_url + "/admin/login/"
    try:
        # Step 1: GET to get csrftoken
        r_get = _http_request("GET", login_url, timeout=10)
        csrf = ""
        m = re.search(r"csrftoken=([^;]+)", r_get.headers.get("set-cookie", ""))
        if m:
            csrf = m.group(1)
        if not csrf:
            m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
                          r_get.body or "")
            if m:
                csrf = m.group(1)
        if not csrf:
            step("  wagtail: no csrftoken en GET /admin/login/")
            return None

        # Step 2: POST login
        r_post = _http_request(
            "POST", login_url,
            data=(f"username={_WAGTAIL_USER}&password={_WAGTAIL_PASS}"
                  f"&csrfmiddlewaretoken={csrf}&next=/admin/"),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Cookie": f"csrftoken={csrf}",
                     "Referer": login_url},
            timeout=10,
        )
        cookies = r_post.headers.get("set-cookie", "")
        session_m = re.search(r"sessionid=([^;]+)", cookies)
        if session_m:
            step("  wagtail: session obtenida")
            return f"csrftoken={csrf}; sessionid={session_m.group(1)}"
        step("  wagtail: login falló (no sessionid en Set-Cookie)")
    except Exception as e:
        step(f"  wagtail: login error — {e}")
    return None


def verify_wagtail_web_cve(
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
    """Verify a Wagtail CMS CVE dynamically in an ephemeral Docker lab."""
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    container = f"bo_wagtail_{os.urandom(4).hex()}"
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="bo_wagtail_")
    dockerfile_path = os.path.join(tmpdir, "Dockerfile")

    try:
        with open(dockerfile_path, "w") as fh:
            fh.write(_wagtail_dockerfile(_WAGTAIL_PORT))

        step("  wagtail: construyendo imagen (puede tardar ~2min)…")
        _run(["docker", "build", "-t", container, tmpdir], timeout=180)
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "-p", f"{_WAGTAIL_PORT}:{_WAGTAIL_PORT}", container], timeout=30)

        # Poll until port is open
        import socket as _sock
        host = _lab_host()
        for _i in range(60):
            try:
                with _sock.create_connection((host, _WAGTAIL_PORT), timeout=1):
                    break
            except OSError:
                time.sleep(1)
        else:
            res.detail = f"Timeout esperando puerto {_WAGTAIL_PORT}"
            return res

        base_url = f"http://{host}:{_WAGTAIL_PORT}"
        time.sleep(2)

        # Auth
        cookie = None
        if auth_required:
            cookie = _get_wagtail_session(base_url, step)

        # Fire PoC
        target_url = base_url + endpoint
        headers = {}
        if cookie:
            headers["Cookie"] = cookie

        body, target_url, headers = _build_http_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  wagtail: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status_code
        res.evidence["body_snippet"] = (r.text or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status_code == 200:
            if confirm_string and confirm_string in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Wagtail"
                step("  wagtail: VERIFICADO")
            elif not confirm_string and payload and payload in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
            else:
                res.ok = True
                res.detail = "HTTP 200 — confirm_string no encontrado"
        else:
            res.detail = f"HTTP {r.status_code} — endpoint no accesible"

    except subprocess.CalledProcessError as e:
        res.detail = f"Docker error: {e}"
    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
            subprocess.run(["docker", "rmi", "-f", container],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        import shutil
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    return res
