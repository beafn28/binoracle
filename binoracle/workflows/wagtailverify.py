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

from .genericverify import _build_http_params
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
    request_chain: Optional[list] = None,
    bypass_header: str = "",
    bypass_value: str = "",
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
        auth_cookie = ""
        if auth_required or request_chain:
            auth_cookie = _get_wagtail_session(base_url, step) or ""

        # Multi-step request chain (generic)
        if request_chain:
            from .ghostverify import _ghost_run_request_chain
            verified, detail, evidence = _ghost_run_request_chain(
                base_url, request_chain, auth_cookie, step)
            res.verified = verified
            res.ok = True
            res.detail = detail
            res.evidence = {**evidence, "base_url": base_url, "vuln_class": vuln_class,
                            "tecnica": "request_chain"}
            return res

        _vc = (vuln_class or "").lower()

        # SSTI generic probe: Wagtail uses Django template engine
        if _vc == "ssti" and not payload:
            payload = "{{7*7}}"
            if not confirm_string:
                confirm_string = "49"
            step("  wagtail: SSTI: usando payload generico {{7*7}} (Django templates)")

        # Path traversal generic probe
        if _vc == "path-traversal" and not confirm_string:
            if not payload:
                payload = "../../../etc/passwd"
            confirm_string = "root:"
            step("  wagtail: path-traversal: buscando root: en la respuesta")

        # Fire PoC
        m = http_method.upper() or "GET"
        target_url = base_url + endpoint
        headers: dict = {}
        if auth_cookie:
            headers["Cookie"] = auth_cookie
        if bypass_header and bypass_value:
            headers[bypass_header] = bypass_value

        body, target_url, headers = _build_http_params(
            parameters, payload, m, target_url, headers)

        step(f"  wagtail: {m} {target_url}")
        r = _http_request(m, target_url, data=body, headers=headers, timeout=15)
        status = r.status_code
        body_text = r.text or ""

        # HTTP method rotation on 405
        if status == 405:
            m = "GET" if m != "GET" else "POST"
            step(f"  wagtail: 405 → reintentando con {m}")
            try:
                r2 = _http_request(m, target_url, data=body if m != "GET" else None,
                                   headers=headers, timeout=15)
                status = r2.status_code
                body_text = r2.text or ""
            except Exception:
                pass

        res.evidence.update({"status": status, "body_snippet": body_text[:300],
                             "endpoint": target_url, "vuln_class": vuln_class})

        string_ok = (not confirm_string) or (confirm_string in body_text)
        bypassed = status in range(200, 300)

        # Missing-auth comparison
        if _vc == "missing-authorization" and not auth_required and bypassed:
            try:
                _auth_sess = _get_wagtail_session(base_url, lambda _: None)
                if _auth_sess:
                    _auth_hdrs = {**headers, "Cookie": _auth_sess}
                    _r_auth = _http_request(m, target_url, data=body, headers=_auth_hdrs,
                                            timeout=15)
                    _auth_body = _r_auth.text or ""
                    _same_len = abs(len(_auth_body) - len(body_text)) < max(50, len(body_text) * 0.1)
                    res.evidence["auth_comparison"] = (
                        "no_auth_differentiation" if _same_len else "auth_changes_response")
                    step(f"  wagtail: auth comparison: {res.evidence['auth_comparison']}")
            except Exception:
                pass

        if bypassed and string_ok:
            res.verified = True
            res.ok = True
            res.confidence = "confirmed"
            res.detail = (
                f"VERIFICADO: {m} {endpoint} → HTTP {status}"
                + (f" — confirm_string '{confirm_string}' presente" if confirm_string else "")
            )
            step("  wagtail: VERIFICADO")
        elif bypassed and not confirm_string and payload and payload in body_text:
            res.ok = True
            res.confidence = "probable"
            res.evidence["not_verified_reason"] = (
                "payload reflejado en la respuesta no es prueba de ejecucion ni de explotacion -- muchos endpoints benignos reflejan el input del atacante (mensajes de error, formularios re-renderizados, busquedas, logs) sin que eso implique que el payload se ejecuto o que la vulnerabilidad es real")
            res.detail = "LEAD (no confirmado): payload reflejado en respuesta"
            step("  wagtail: payload reflejado (lead, no confirmado)")
        else:
            res.ok = True
            if bypassed and body_text:
                from .genericverify import _analyze_response_body
                _analysis = _analyze_response_body(
                    body_text, vuln_class, payload=payload,
                    confirm_string=confirm_string, status_code=status)
                if _analysis.get("interesting"):
                    res.evidence["response_analysis"] = _analysis
            res.detail = (
                f"no confirmado: {m} {endpoint} → HTTP {status}"
                + (f", confirm_string={string_ok}" if confirm_string else "")
            )
            step(f"  wagtail: no confirmado HTTP {status}")

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
