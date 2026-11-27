"""Dynamic verifier for Directus CMS CVEs.

Directus is a Node.js headless CMS. This verifier:
  1. Spins up directus/directus Docker with SQLite
  2. Authenticates via POST /auth/login -> data.access_token
  3. Fires the PoC against the REST or GraphQL API
  4. Checks confirm_string in response body

Supported vuln classes: xss, sqli, ssrf, missing-authorization, idor,
path-traversal, broken-access-control.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _docker_daemon_ok, _http_request, _run, _lab_host
from .genericverify import _build_json_params

_DIRECTUS_PORT = 8055
_DIRECTUS_ADMIN_EMAIL = "admin@binoracle.dev"
_DIRECTUS_ADMIN_PASSWORD = "Admin1234!Binoracle"
_DIRECTUS_KEY = "ffffffff-ffff-ffff-ffff-ffffffffffff"
_DIRECTUS_SECRET = "binoracle-directus-secret-32chars!"


def detect_directus(source_dir: str) -> bool:
    """Return True if source looks like a Directus project."""
    pkg_path = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg_path):
        try:
            content = open(pkg_path, encoding="utf-8", errors="ignore").read().lower()
            if '"directus"' in content or "@directus/" in content:
                return True
        except Exception:
            pass
    return False


def _get_directus_token(base_url: str, step) -> Optional[str]:
    """Login to Directus and return Bearer access token."""
    login_url = base_url + "/auth/login"
    try:
        r = _http_request(
            "POST", login_url,
            data=json.dumps({"email": _DIRECTUS_ADMIN_EMAIL,
                             "password": _DIRECTUS_ADMIN_PASSWORD}),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code in (200, 201):
            body = json.loads(r.text or "{}")
            token = ((body.get("data") or {}).get("access_token") or
                     body.get("access_token") or "")
            if token:
                step("  directus: Bearer token obtenido")
                return f"Bearer {token}"
        step(f"  directus: login falló — HTTP {r.status_code}")
    except Exception as e:
        step(f"  directus: login error — {e}")
    return None


def _run_request_chain(base_url: str, chain: list, bearer: Optional[str],
                        step) -> tuple:
    """Execute a request_chain, returning (verified, confirm_string_found, body_snippet).

    Each step dict has: method, endpoint, body (JSON string), headers, extract, confirm_string.
    'extract' maps var_name -> 'json:path.to.field' (dot-separated JSON path).
    '{{var}}' in endpoint/body is substituted with extracted values.
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
        if bearer and "Authorization" not in hdrs:
            hdrs["Authorization"] = bearer
        body_str = _substitute(step_def.get("body") or "{}")
        try:
            body_obj = json.loads(body_str)
            body_data = json.dumps(body_obj)
            hdrs.setdefault("Content-Type", "application/json")
        except Exception:
            body_data = body_str

        step(f"  directus chain[{idx}]: {method} {ep}")
        try:
            multipart_fields = step_def.get("multipart_fields")
            if multipart_fields:
                # Build requests-style multipart payload: {name: (filename, data, ctype) or (None, value)}
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
                r = _http_request(method, url, data=body_data if method in ("POST", "PUT", "PATCH")
                                  else None, headers=hdrs, timeout=20)
        except Exception as exc:
            return False, f"chain[{idx}] request error: {exc}", {}

        status = r.status_code
        body_text = r.text or ""

        # Extract variables from response — supports 'json:path.to.field' and regex patterns
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
                            step(f"  directus chain[{idx}]: extracted {var_name}={str(val)[:40]}")
                else:
                    # Treat as regex with one capture group
                    try:
                        m = _re.search(path_expr, body_text)
                        if m:
                            vars_[var_name] = m.group(1)
                            step(f"  directus chain[{idx}]: extracted {var_name}={vars_[var_name][:40]!r}")
                    except Exception:
                        pass

        expect_status = step_def.get("confirm_status")
        if expect_status and status != expect_status:
            step(f"  directus chain[{idx}]: HTTP {status} != {expect_status}")
            return False, f"chain[{idx}] HTTP {status} != expected {expect_status}", {}

        cs = step_def.get("confirm_string", "")
        is_final = step_def.get("is_final", idx == len(chain) - 1)
        if is_final:
            final_evidence = {"status": status, "body_snippet": body_text[:300],
                              "vars": vars_}
            if cs:
                if cs in body_text:
                    return True, f"VERIFICADO: '{cs}' en respuesta Directus (chain)", final_evidence
                return False, f"chain final: '{cs}' no encontrado — HTTP {status}", final_evidence
            return True, f"chain final: HTTP {status} OK (no confirm_string)", final_evidence

    return False, "request_chain vacío", {}


def verify_directus_web_cve(
    source_path: str,
    endpoint: str,
    vuln_class: str = "missing-authorization",
    http_method: str = "GET",
    parameters: Optional[list] = None,
    payload: str = "",
    confirm_string: str = "",
    auth_required: bool = False,
    pkg_version: str = "",
    request_chain: Optional[list] = None,
    on_step: Optional[Callable] = None,
    budget_s: float = 240.0,
) -> WpVerifyResult:
    """Verify a Directus CMS CVE dynamically in an ephemeral Docker lab."""
    step = on_step or print
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        return res

    container = f"bo_directus_{os.urandom(4).hex()}"
    # Use versioned image; fall back to latest if pkg_version not usable
    _image = f"directus/directus:{pkg_version}" if pkg_version else "directus/directus:latest"

    try:
        step(f"  directus: arrancando {_image} en puerto {_DIRECTUS_PORT}…")
        _run([
            "docker", "run", "-d", "--rm", "--name", container,
            "-p", f"{_DIRECTUS_PORT}:{_DIRECTUS_PORT}",
            "-e", f"KEY={_DIRECTUS_KEY}",
            "-e", f"SECRET={_DIRECTUS_SECRET}",
            "-e", f"ADMIN_EMAIL={_DIRECTUS_ADMIN_EMAIL}",
            "-e", f"ADMIN_PASSWORD={_DIRECTUS_ADMIN_PASSWORD}",
            "-e", "DB_CLIENT=sqlite3",
            "-e", "DB_FILENAME=/directus/database/data.db",
            "-e", f"PUBLIC_URL=http://localhost:{_DIRECTUS_PORT}",
            _image,
        ], timeout=30)

        # Poll until Directus HTTP is ready (up to 120s — it's slow to initialize DB)
        host = _lab_host()
        base_url = f"http://{host}:{_DIRECTUS_PORT}"
        _ready = False
        for _i in range(120):
            try:
                # Try a lightweight HTTP probe: ConnectionResetError means TCP open
                # but HTTP not ready yet — keep waiting.
                _probe = _http_request("GET", base_url + "/server/health", timeout=3)
                if _probe.status_code in (200, 204, 401, 403, 404):
                    _ready = True
                    break
            except Exception as _probe_exc:
                _exc_str = str(_probe_exc)
                if "Connection refused" in _exc_str:
                    pass  # container not up yet
                # else: ConnectionReset / other → not ready, keep waiting
            time.sleep(1)
        if not _ready:
            res.detail = f"Timeout esperando HTTP Directus en {_DIRECTUS_PORT}"
            return res
        # Extra grace period for DB migrations to complete
        time.sleep(3)

        # Auth (always needed for chain; also when auth_required=True)
        bearer = None
        if auth_required or request_chain:
            bearer = _get_directus_token(base_url, step)

        # Multi-step request chain takes priority over single request
        if request_chain:
            verified, detail, evidence = _run_request_chain(
                base_url, request_chain, bearer, step)
            res.verified = verified
            res.ok = verified
            res.confidence = "confirmed" if verified else "failed"
            res.detail = detail
            res.evidence.update(evidence)
            if verified:
                step("  directus: VERIFICADO (chain)")
            return res

        # Single-request PoC
        target_url = base_url + endpoint
        headers = {}
        if bearer:
            headers["Authorization"] = bearer

        body, target_url, headers = _build_json_params(
            parameters, payload, http_method, target_url, headers)

        step(f"  directus: {http_method} {target_url}")
        r = _http_request(http_method.upper(), target_url,
                          data=body, headers=headers, timeout=15)
        res.evidence["status"] = r.status_code
        res.evidence["body_snippet"] = (r.text or "")[:300]
        res.evidence["endpoint"] = target_url

        if r.status_code in (200, 201, 204):
            if confirm_string and confirm_string in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.detail = f"VERIFICADO: '{confirm_string}' en respuesta Directus"
                step("  directus: VERIFICADO")
            elif not confirm_string and payload and payload in (r.text or ""):
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.detail = "VERIFICADO (probable): payload reflejado"
            else:
                res.ok = True
                res.detail = f"HTTP {r.status_code} — confirm_string no encontrado"
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
        except Exception:
            pass

    return res
