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
from .genericverify import _build_json_params


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
        body = json.loads(r.text or "{}")
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
        body = json.loads(r.text or "{}")
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
    request_chain: Optional[list] = None,
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

        # Create isolated network with retry for Docker daemon race conditions
        network = f"binoracle-strapi-net-{_token()}"
        _net_err = ""
        for _att in range(3):
            r_net = subprocess.run(["docker", "network", "create", network],
                                   capture_output=True, timeout=15)
            if r_net.returncode == 0:
                break
            _net_err = (r_net.stderr or b"").decode(errors="replace").strip()
            if _att < 2:
                time.sleep(3)
        else:
            res.detail = f"docker network create failed: {_net_err}"
            return res

        step("  strapiverify: arrancando contenedor…")
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "--network", network,
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
        if auth_required or request_chain:
            bearer = _strapi_get_admin_jwt(base_url, step)
            if not bearer:
                step("  strapiverify: auth fallida — intentando sin auth")

        # Multi-step chain takes priority
        if request_chain:
            from .directusverify import _run_request_chain
            verified, detail, evidence = _run_request_chain(
                base_url, request_chain, bearer, step)
            res.verified = verified
            res.ok = verified
            res.confidence = "confirmed" if verified else "failed"
            res.detail = detail
            res.evidence.update(evidence)
            if verified:
                step("  strapiverify: VERIFICADO (chain)")
            return res

        # Build single request
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

        res.evidence["status"] = r2.status_code
        res.evidence["body_snippet"] = (r2.text or "")[:400]
        res.evidence["endpoint"] = endpoint
        res.evidence["auth_used"] = bool(bearer)

        if r2.status_code < 500:
            if confirm_string and confirm_string in (r2.text or ""):
                res.verified = True
                res.ok = True
                res.detail = (f"VERIFICADO: '{confirm_string}' presente en la respuesta — "
                              f"CVE confirmado en Strapi (status {r2.status_code})")
                step("  strapiverify: VERIFICADO")
            elif r2.status_code in (200, 201) and not confirm_string:
                res.ok = True
                res.detail = (f"endpoint respondio {r2.status_code} sin confirm_string "
                              f"— no concluyente")
            else:
                res.ok = True
                res.detail = (f"status {r2.status_code} — confirm_string no encontrado "
                              f"({confirm_string!r})" if confirm_string else
                              f"status {r2.status_code}")
        else:
            res.detail = f"server error {r2.status_code}"

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
            subprocess.run(["docker", "network", "rm", network],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            os.remove(os.path.join(source_path, "Dockerfile.binoracle"))
        except Exception:
            pass


def verify_strapi_unauth(
    source_path: str,
    endpoint: str,
    http_method: str = "GET",
    parameters: Optional[List[str]] = None,
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 600.0,
) -> WpVerifyResult:
    """Verify a missing-authorization CVE in Strapi by comparing unauth vs auth responses.

    After the lab is ready but BEFORE registering an admin, fires the request
    unauthenticated. If confirm_string appears unauthenticated, verified=True (hard evidence).
    Otherwise compares response body size with an authenticated request — if they match
    (within 10%), the endpoint skips auth checks.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        return res

    if not os.path.isdir(source_path):
        res.detail = f"directorio de fuente no encontrado: {source_path}"
        return res

    port = 1337
    container = f"binoracle-strapi-unauth-{_token()}"
    network = f"binoracle-strapi-unauth-net-{_token()}"

    try:
        dockerfile_path = os.path.join(source_path, "Dockerfile.binoracle")
        with open(dockerfile_path, "w") as f:
            f.write(_strapi_dockerfile(port))

        step("  strapi-unauth: construyendo imagen Docker…")
        r = _run(["docker", "build", "-f", dockerfile_path, "-t", container, source_path],
                 timeout=300)
        if r.returncode != 0:
            res.detail = f"docker build fallido: {(r.stderr or '')[-300:]}"
            return res

        _net_err = ""
        for _att in range(3):
            r_net = subprocess.run(["docker", "network", "create", network],
                                   capture_output=True, timeout=15)
            if r_net.returncode == 0:
                break
            _net_err = (r_net.stderr or b"").decode(errors="replace").strip()
            if _att < 2:
                time.sleep(3)
        else:
            res.detail = f"docker network create failed: {_net_err}"
            return res

        _run(["docker", "run", "-d", "--rm", "--name", container,
              "--network", network,
              "-p", f"0.0.0.0::{port}", container], timeout=30)

        rp = _run(["docker", "port", container, str(port)], timeout=10)
        m = re.search(r":(\d+)\s*$", (rp.stdout or "").strip())
        actual_port = int(m.group(1)) if m else port

        host = _lab_host()
        base_url = f"http://{host}:{actual_port}"

        step(f"  strapi-unauth: esperando que Strapi responda en {base_url}…")
        import socket as _sock
        for _i in range(90):
            try:
                with _sock.create_connection((host, actual_port), timeout=1):
                    break
            except OSError:
                time.sleep(2)
        else:
            res.detail = "timeout esperando que Strapi arranque"
            return res
        time.sleep(5)

        # Fire UNAUTHENTICATED request (before any admin setup)
        target_url = base_url + endpoint
        body_data, target_url, headers = _build_json_params(
            parameters, "", http_method, target_url, {})

        step(f"  strapi-unauth: {http_method.upper()} {target_url} (sin auth)")
        try:
            r_unauth = _http_request(http_method.upper(), target_url, data=body_data,
                                     headers=headers, timeout=15)
            unauth_status = r_unauth.status_code
            unauth_body = r_unauth.text or ""
        except Exception as e:
            res.detail = f"request sin auth fallida: {e}"
            return res

        res.evidence["status_unauth"] = unauth_status
        res.evidence["body_unauth_snippet"] = unauth_body[:300]
        res.evidence["endpoint"] = endpoint

        # Hard evidence: confirm_string in unauthenticated response
        if confirm_string and confirm_string in unauth_body:
            res.verified = True
            res.ok = True
            res.confidence = "confirmed"
            res.detail = (f"VERIFICADO: '{confirm_string}' en respuesta Strapi SIN autenticacion "
                          f"(HTTP {unauth_status}) — missing-authorization confirmado")
            step("  strapi-unauth: VERIFICADO (confirm_string)")
            return res

        # Soft evidence: compare with authenticated response
        bearer = _strapi_get_admin_jwt(base_url, step)
        if bearer:
            auth_hdrs = dict(headers)
            auth_hdrs["Authorization"] = bearer
            try:
                r_auth = _http_request(http_method.upper(), target_url, data=body_data,
                                       headers=auth_hdrs, timeout=15)
                auth_body = r_auth.text or ""
                res.evidence["status_auth"] = r_auth.status_code
                res.evidence["body_auth_snippet"] = auth_body[:200]

                # If sizes match within 10%, the endpoint doesn't differentiate auth
                if (unauth_status in (200, 201) and r_auth.status_code in (200, 201)
                        and abs(len(unauth_body) - len(auth_body)) < max(50, len(auth_body) * 0.1)):
                    res.ok = True
                    res.detail = (f"strapi-unauth: respuesta sin auth ({len(unauth_body)}B) ≈ "
                                  f"con auth ({len(auth_body)}B) — endpoint no diferencia usuarios")
                    res.evidence["privilege_comparison"] = "unauth==auth (no auth check)"
                elif unauth_status in (401, 403):
                    res.ok = True
                    res.detail = (f"strapi-unauth: endpoint rechazó acceso anónimo "
                                  f"(HTTP {unauth_status}) — comprobación activa")
                else:
                    res.ok = True
                    res.detail = (f"strapi-unauth: HTTP {unauth_status} sin auth, "
                                  f"HTTP {r_auth.status_code} con auth — revisar manualmente")
            except Exception:
                res.ok = True
                res.detail = f"strapi-unauth: HTTP {unauth_status} sin auth"
        else:
            res.ok = True
            res.detail = f"strapi-unauth: HTTP {unauth_status} sin auth (sin comparación auth)"

        return res

    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("  strapi-unauth: desmontando…")
        try:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=15)
        except Exception:
            pass
        try:
            subprocess.run(["docker", "network", "rm", network], capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            os.remove(os.path.join(source_path, "Dockerfile.binoracle"))
        except Exception:
            pass
