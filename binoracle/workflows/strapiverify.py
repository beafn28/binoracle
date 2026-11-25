"""Dynamic verifier for Strapi CMS CVEs. Structurally analogous to ghostverify.py /
pythonverify.py -- ephemeral Docker lab, no MySQL needed (uses SQLite in development mode),
Bearer JWT auth via the Strapi Admin API (/admin/register-admin then /admin/auth/local).

Covers XSS, SQLi (via REST/GraphQL), SSRF, missing-auth/IDOR, auth-bypass, SSTI and
command-injection classes. Auth-required CVEs are handled via the JWT flow: register the
first admin user, log in, attach the Bearer token to all requests.

Design decisions vs. joomlaverify.py:
  - No MySQL container: Strapi dev mode uses SQLite out of the box.
  - No separate extension install step: the vulnerable code is already in the source tree.
  - Admin setup is via the REST API, not a CLI wizard.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Callable, List, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _lab_host, _token


def detect_strapi(source_dir: str) -> bool:
    """Return True if source_dir looks like a Strapi project."""
    pkg = os.path.join(source_dir, "package.json")
    if not os.path.isfile(pkg):
        return False
    try:
        data = json.loads(open(pkg).read())
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        return any("strapi" in k for k in deps)
    except Exception:
        return False


def _strapi_dockerfile(port: int = 1337) -> str:
    return f"""\
FROM node:18-alpine
WORKDIR /app
ENV DATABASE_CLIENT=sqlite
ENV DATABASE_FILENAME=.tmp/data.db
ENV NODE_ENV=development
ENV HOST=0.0.0.0
ENV PORT={port}
COPY package*.json ./
RUN npm install --legacy-peer-deps 2>&1 | tail -5
COPY . .
EXPOSE {port}
CMD ["npx", "strapi", "develop", "--no-build"]
"""


def _run(cmd: List[str], timeout: float = 120.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _strapi_register_admin(base_url: str, username: str, firstname: str,
                            lastname: str, email: str, password: str,
                            step: Callable) -> Optional[str]:
    """Register first admin user via POST /admin/register-admin.

    Returns Bearer token or None. Only works on a fresh Strapi instance.
    """
    url = base_url.rstrip("/") + "/admin/register-admin"
    payload = json.dumps({
        "username": username, "firstname": firstname, "lastname": lastname,
        "email": email, "password": password, "registrationToken": "",
    })
    try:
        r = _http_request("POST", url, data=payload,
                          headers={"Content-Type": "application/json"}, timeout=15)
        body = json.loads(r.body or "{}")
        token = (body.get("data") or {}).get("token") or ""
        if token:
            step("  strapiverify: admin registrado — Bearer token obtenido")
            return f"Bearer {token}"
    except Exception:
        pass
    return None


def _strapi_login(base_url: str, email: str, password: str,
                  step: Callable) -> Optional[str]:
    """Login to Strapi Admin API via POST /admin/auth/local.

    Returns 'Bearer <token>' or None.
    """
    url = base_url.rstrip("/") + "/admin/auth/local"
    payload = json.dumps({"identifier": email, "password": password})
    try:
        r = _http_request("POST", url, data=payload,
                          headers={"Content-Type": "application/json"}, timeout=15)
        body = json.loads(r.body or "{}")
        token = (body.get("data") or {}).get("token") or ""
        if token:
            step("  strapiverify: login Admin API OK — Bearer token obtenido")
            return f"Bearer {token}"
    except Exception:
        pass
    return None


def _strapi_get_admin_jwt(base_url: str, step: Callable) -> Optional[str]:
    """Obtain a Strapi Admin JWT: register first admin then login.

    Returns 'Bearer <token>' or None if both fail.
    """
    _user = "binoracle"
    _email = "binoracle@binoracle-lab.dev"
    _pass = "Binoracle123!Admin"
    # Try register first (new instance)
    token = _strapi_register_admin(base_url, _user, "Binoracle", "Lab", _email, _pass, step)
    if token:
        return token
    # Fallback: login (instance already has an admin)
    return _strapi_login(base_url, _email, _pass, step)


def verify_strapi_web_cve(
    source_path: str,
    endpoint: str,
    vuln_class: str,
    http_method: str,
    parameters: List[str],
    payload: str,
    confirm_string: str,
    auth_required: bool,
    pkg_version: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 600.0,
) -> WpVerifyResult:
    """Build an ephemeral Strapi Docker lab and verify the CVE.

    Spin up Strapi in development mode (SQLite, no MySQL), wait for the
    admin API to be ready, optionally authenticate, fire the PoC, and
    check the response for confirm_string.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: Docker no disponible")
        return res

    if not os.path.isdir(source_path):
        res.detail = f"directorio de fuente no encontrado: {source_path}"
        return res

    port = 1337
    container = f"binoracle-strapi-{_token()}"

    try:
        # Write Dockerfile
        dockerfile_path = os.path.join(source_path, "Dockerfile.binoracle")
        with open(dockerfile_path, "w") as f:
            f.write(_strapi_dockerfile(port))

        step("  strapiverify: construyendo imagen Docker de Strapi (puede tardar)…")
        r = _run(["docker", "build", "-f", dockerfile_path, "-t", container, source_path],
                 timeout=300)
        if r.returncode != 0:
            res.detail = f"docker build fallido: {(r.stderr or '')[-500:]}"
            res.limitations.append("Strapi puede requerir Node 18+ — verifica la imagen base")
            return res

        step("  strapiverify: arrancando contenedor…")
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "-p", f"0.0.0.0::{port}", container], timeout=30)

        # Get actual mapped port
        rp = _run(["docker", "port", container, str(port)], timeout=10)
        m = re.search(r":(\d+)\s*$", (rp.stdout or "").strip())
        actual_port = int(m.group(1)) if m else port

        host = _lab_host()
        base_url = f"http://{host}:{actual_port}"

        step(f"  strapiverify: esperando que Strapi responda en {base_url}…")
        import socket as _sock
        for _i in range(90):  # Strapi takes time to start
            try:
                with _sock.create_connection((host, actual_port), timeout=1):
                    break
            except OSError:
                time.sleep(2)
        else:
            step("  strapiverify: timeout esperando Strapi (90s)")
            res.detail = "timeout esperando que Strapi arranque"
            return res

        # Wait a bit more for Strapi to fully initialize admin API
        time.sleep(5)

        # Auth
        bearer = None
        if auth_required:
            bearer = _strapi_get_admin_jwt(base_url, step)
            if not bearer:
                step("  strapiverify: auth fallida — intentando sin auth")

        # Build request
        target_url = base_url + endpoint
        headers: dict = {}
        if bearer:
            headers["Authorization"] = bearer

        body_data, target_url, headers = _build_json_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  strapiverify: {http_method.upper()} {target_url}")
        try:
            r2 = _http_request(http_method.upper(), target_url, data=body_data,
                               headers=headers, timeout=20)
        except Exception as e:
            res.detail = f"request fallida: {e}"
            return res

        res.evidence["status"] = r2.status
        res.evidence["body_snippet"] = (r2.body or "")[:400]
        res.evidence["endpoint"] = endpoint
        res.evidence["auth_used"] = bool(bearer)

        if r2.status < 500:
            if confirm_string and confirm_string in (r2.body or ""):
                res.verified = True
                res.ok = True
                res.detail = (f"VERIFICADO: '{confirm_string}' presente en la respuesta — "
                              f"CVE confirmado en Strapi (status {r2.status})")
                step("  strapiverify: VERIFICADO")
            elif r2.status in (200, 201) and not confirm_string:
                res.ok = True
                res.detail = f"endpoint respondio {r2.status} sin confirm_string — no concluyente"
            else:
                res.ok = True
                res.detail = (f"status {r2.status} — confirm_string no encontrado "
                              f"({confirm_string!r})" if confirm_string else
                              f"status {r2.status}")
        else:
            res.detail = f"server error {r2.status}"

        return res

    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("  strapiverify: desmontando contenedor…")
        try:
            subprocess.run(["docker", "rm", "-f", container],
                           capture_output=True, timeout=15)
        except Exception:
            pass
        try:
            os.remove(os.path.join(source_path, "Dockerfile.binoracle"))
        except Exception:
            pass
