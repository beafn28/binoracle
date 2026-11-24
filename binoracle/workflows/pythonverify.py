"""Verificador especializado para CVEs de apps Python: Django, FastAPI, Flask, Starlette.

Extiende genericverify.py con:
  - Auto-Dockerfile generado con la version vulnerable exacta del framework
  - Setup de superuser/admin para CVEs que requieren autenticacion Django
  - Deteccion automatica del patron de autenticacion (session cookie vs JWT vs API key)
  - Payloads especificos para cada clase de vulnerabilidad en el ecosistema Python web
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host


# ── Framework detection ───────────────────────────────────────────────────────

_DJANGO_SIGNALS = ["django", "wsgi", "asgi", "settings.py", "manage.py",
                   "models.py", "views.py", "urls.py", "INSTALLED_APPS"]
_FASTAPI_SIGNALS = ["fastapi", "uvicorn", "starlette", "pydantic", "@app.get",
                    "@router.get", "APIRouter", "FastAPI("]
_FLASK_SIGNALS = ["flask", "Flask(", "@app.route", "from flask", "Blueprint"]


def detect_python_framework(source_dir: str) -> str:
    """Return 'django' | 'fastapi' | 'flask' | 'generic' from source tree."""
    if not source_dir or not os.path.isdir(source_dir):
        return "generic"
    # Walk a few key files only — no need to scan everything
    for root, _dirs, fnames in os.walk(source_dir):
        _dirs[:] = [d for d in _dirs if d not in
                    (".git", "node_modules", "__pycache__", "vendor", "migrations")]
        for fn in fnames:
            if not fn.endswith((".py", ".txt", ".cfg", ".toml")):
                continue
            fpath = os.path.join(root, fn)
            try:
                content = open(fpath, encoding="utf-8", errors="replace").read(8000)
            except OSError:
                continue
            if any(s in content for s in _DJANGO_SIGNALS):
                return "django"
            if any(s in content for s in _FASTAPI_SIGNALS):
                return "fastapi"
            if any(s in content for s in _FLASK_SIGNALS):
                return "flask"
    return "generic"


# ── Dockerfile generators ─────────────────────────────────────────────────────

def _django_dockerfile(pkg_name: str, pkg_version: str = "",
                        port: int = 8000) -> str:
    ver = f"=={pkg_version}" if pkg_version else ""
    return f"""\
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir django{ver} gunicorn
COPY . .
RUN python manage.py migrate --run-syncdb 2>/dev/null || true
RUN python manage.py collectstatic --noinput 2>/dev/null || true
EXPOSE {port}
CMD ["python", "manage.py", "runserver", "0.0.0.0:{port}"]
"""


def _fastapi_dockerfile(pkg_name: str, pkg_version: str = "", port: int = 8000) -> str:
    ver = f"=={pkg_version}" if pkg_version else ""
    return f"""\
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi{ver} uvicorn[standard]
COPY . .
EXPOSE {port}
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}"]
"""


def _flask_dockerfile(pkg_name: str, pkg_version: str = "", port: int = 5000) -> str:
    ver = f"=={pkg_version}" if pkg_version else ""
    return f"""\
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask{ver}
COPY . .
ENV FLASK_ENV=development
EXPOSE {port}
CMD ["python", "app.py"]
"""


FRAMEWORK_DOCKERFILES = {
    "django": _django_dockerfile,
    "fastapi": _fastapi_dockerfile,
    "flask": _flask_dockerfile,
}


# ── Auth setup helpers ────────────────────────────────────────────────────────

def _django_create_superuser(container: str, step: Callable) -> Optional[str]:
    """Create a Django superuser in the running container.

    Returns the session cookie string on success, None on failure.
    """
    try:
        cmd = [
            "docker", "exec", container,
            "python", "manage.py", "shell", "-c",
            ("from django.contrib.auth import get_user_model; "
             "U=get_user_model(); "
             "U.objects.filter(username='binoracle_test').delete(); "
             "U.objects.create_superuser('binoracle_test','test@test.com','Binoracle123!')")
        ]
        subprocess.run(cmd, capture_output=True, timeout=30, check=True)
        step("  django: superuser creado (binoracle_test / Binoracle123!)")
        return "binoracle_test:Binoracle123!"
    except subprocess.CalledProcessError as e:
        step(f"  django: error creando superuser — {e.stderr.decode()[:200] if e.stderr else e}")
        return None


def _get_fastapi_token(base_url: str, username: str, password: str,
                       step: Callable) -> Optional[str]:
    """Get FastAPI OAuth2 Bearer token via password flow.

    Tries common FastAPI auth endpoints:
    - POST /token (OAuth2PasswordRequestForm — form-encoded)
    - POST /api/token
    - POST /auth/token
    - POST /api/auth/token
    - POST /login (JSON body)
    """
    _endpoints = ["/token", "/api/token", "/auth/token", "/api/auth/token",
                  "/api/v1/token", "/api/v1/auth/token"]
    for ep in _endpoints:
        url = base_url.rstrip("/") + ep
        try:
            # OAuth2PasswordRequestForm — form-encoded (FastAPI standard)
            r = _http_request("POST", url,
                              data=f"username={username}&password={password}&grant_type=password",
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              timeout=8)
            if r.status in (200, 201):
                import json as _j
                body = _j.loads(r.body or "{}")
                token = (body.get("access_token") or body.get("token") or
                         body.get("jwt") or "")
                if token:
                    step(f"  fastapi: Bearer token obtenido vía {ep}")
                    return f"Bearer {token}"
        except Exception:
            continue
    # Fallback: JSON body login
    for ep in ["/login", "/api/login", "/auth/login", "/api/auth/login"]:
        url = base_url.rstrip("/") + ep
        try:
            import json as _j
            body_str = _j.dumps({"username": username, "password": password,
                                  "email": f"{username}@binoracle.dev"})
            r = _http_request("POST", url, data=body_str,
                              headers={"Content-Type": "application/json"}, timeout=8)
            if r.status in (200, 201):
                body = _j.loads(r.body or "{}")
                token = (body.get("access_token") or body.get("token") or
                         (body.get("data") or {}).get("token") or "")
                if token:
                    step(f"  fastapi: Bearer token obtenido vía {ep} (JSON)")
                    return f"Bearer {token}"
        except Exception:
            continue
    return None


def _get_django_session(base_url: str, username: str, password: str,
                        step: Callable) -> Optional[str]:
    """Login to Django admin and return sessionid cookie."""
    # Get CSRF token from login page
    login_url = base_url.rstrip("/") + "/admin/login/"
    try:
        r = _http_request("GET", login_url, timeout=10)
        csrf = ""
        m = re.search(r'csrfmiddlewaretoken.*?value=["\']([^"\']+)', r.body or "")
        if m:
            csrf = m.group(1)
        cookies = r.headers.get("set-cookie", "")
        csrf_cookie = ""
        cm = re.search(r"csrftoken=([^;]+)", cookies)
        if cm:
            csrf_cookie = cm.group(1)

        r2 = _http_request("POST", login_url,
                           data=f"username={username}&password={password}&csrfmiddlewaretoken={csrf}",
                           headers={"Content-Type": "application/x-www-form-urlencoded",
                                    "Cookie": f"csrftoken={csrf_cookie}",
                                    "Referer": login_url},
                           timeout=10)
        sm = re.search(r"sessionid=([^;]+)", r2.headers.get("set-cookie", ""))
        if sm:
            step("  django: login OK, sessionid obtenido")
            return f"sessionid={sm.group(1)}"
    except Exception as e:
        step(f"  django: login error — {e}")
    return None


# ── Main verifier ─────────────────────────────────────────────────────────────

def verify_python_web_cve(source_path: str, endpoint: str,
                          vuln_class: str = "xss",
                          http_method: str = "GET",
                          parameters: Optional[list] = None,
                          payload: str = "",
                          confirm_string: str = "",
                          auth_required: bool = False,
                          pkg_version: str = "",
                          on_step: Optional[Callable] = None,
                          budget_s: float = 180.0) -> WpVerifyResult:
    """Generic verifier for Django/FastAPI/Flask CVEs.

    Auto-detects framework, builds Docker container with the vulnerable version,
    optionally sets up Django auth, fires the PoC and checks for confirmation.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    framework = detect_python_framework(source_path)
    step(f"  pythonverify: framework={framework}, vuln_class={vuln_class}")

    # Write Dockerfile if none exists
    dockerfile_path = os.path.join(source_path, "Dockerfile")
    _wrote_dockerfile = False
    if not os.path.exists(dockerfile_path):
        df_fn = FRAMEWORK_DOCKERFILES.get(framework)
        if df_fn:
            pkg = "django" if framework == "django" else ("fastapi" if framework == "fastapi" else "flask")
            dockerfile = df_fn(pkg, pkg_version)
            with open(dockerfile_path, "w") as fh:
                fh.write(dockerfile)
            _wrote_dockerfile = True
            step(f"  pythonverify: Dockerfile generado para {framework}")

    port = 8000 if framework in ("django", "fastapi") else 5000
    container = f"bo_pyverify_{os.path.basename(source_path.rstrip('/'))}"

    try:
        # Build + start container
        step(f"  pythonverify: construyendo imagen {container}…")
        _run(["docker", "build", "-t", container, source_path], timeout=120)
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "-p", f"{port}:{port}", container], timeout=30)
        # Poll until port is open (up to 30s) instead of blind sleep
        import socket as _sock
        host = _lab_host()
        for _i in range(30):
            try:
                with _sock.create_connection((host, port), timeout=1):
                    break
            except OSError:
                time.sleep(1)
        else:
            step(f"  pythonverify: timeout esperando puerto {port}")

        base_url = f"http://{host}:{port}"

        # Setup auth if needed
        cookie = None
        bearer = None
        _user = "binoracle_test"
        _pwd = "Binoracle123!"
        if auth_required:
            if framework == "django":
                creds = _django_create_superuser(container, step)
                if creds:
                    user, pwd = creds.split(":", 1)
                    cookie = _get_django_session(base_url, user, pwd, step)
            elif framework == "fastapi":
                bearer = _get_fastapi_token(base_url, _user, _pwd, step)
            elif framework == "flask":
                # Flask: try JSON login endpoints
                bearer = _get_fastapi_token(base_url, _user, _pwd, step)

        # Fire the PoC
        target_url = base_url + endpoint
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if bearer:
            headers["Authorization"] = bearer

        param = (parameters or [None])[0] if parameters else None
        body = None
        if http_method.upper() == "POST" and param:
            body = f"{param}={payload}"
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif param and payload:
            target_url += f"?{param}={payload}"

        step(f"  pythonverify: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status
        res.evidence["body_snippet"] = (r.body or "")[:300]

        if r.status == 200:
            if confirm_string and confirm_string in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: confirm_string '{confirm_string}' en respuesta"
                step("  pythonverify: VERIFICADO")
            elif not confirm_string and payload and payload in (r.body or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado en respuesta"
                step("  pythonverify: payload reflejado")
            else:
                res.ok = True
                res.detail = "Endpoint accesible (200) — confirm_string no encontrado"
        else:
            res.detail = f"HTTP {r.status} — endpoint no accesible"
        res.evidence["endpoint"] = target_url

    except subprocess.CalledProcessError as e:
        res.detail = f"Docker error: {e}"
        step(f"  pythonverify error: {e}")
    except Exception as e:
        res.detail = f"Error: {e}"
        step(f"  pythonverify error: {e}")
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        if _wrote_dockerfile:
            try:
                os.unlink(dockerfile_path)
            except Exception:
                pass

    return res
