"""
Deterministic static analysis of plugin source code before LLM RCA.
Inspired by binchomp's Binary Ninja headless deterministic step before Ghidra MCP.

Runs semgrep (if available) + fallback regex taint analysis over PHP/JS/Python source.
Output feeds directly into LLM context for more targeted RCA.

Gracefully degrades: semgrep not installed → regex fallback → empty results.
"""

import json
import os
import re
import shutil
import subprocess
from typing import List

__all__ = [
    "run_static_analysis",
    "format_for_llm_context",
]

# --- Regex patterns per vuln class ---

_REGEX_PATTERNS: dict = {
    "sqli": [
        # PHP/WordPress
        (r'\$wpdb->(query|get_results|get_row|get_var)\s*\(\s*["\']?.*\$_(GET|POST|REQUEST|COOKIE)',
         "wpdb_direct_input"),
        (r'\$wpdb->(query|get_results|get_row|get_var)\s*\(.*\.(.*\$_(GET|POST|REQUEST|COOKIE))',
         "wpdb_concat"),
        (r'(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY).*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
         "sql_concat"),
        # Python / SQLAlchemy / psycopg2
        (r'(cursor|conn|session)\.(execute|executemany)\s*\(.*%\s*\(',
         "py_cursor_format_injection"),
        (r'(cursor|conn|session)\.(execute|executemany)\s*\(.*\.format\(',
         "py_cursor_format_inject"),
        (r'db\.(session\.execute|execute|query)\s*\(.*f[\'"]\s*(SELECT|INSERT|UPDATE|DELETE)',
         "py_raw_sql_fstring"),
        # Node.js
        (r'(query|execute|raw)\s*\(\s*`[^`]*(SELECT|INSERT|UPDATE|DELETE).*\$\{(req\.|body\.|params\.)',
         "js_sql_template_literal"),
        (r'(query|execute)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE).*\+\s*(req\.|body\.|params\.)',
         "js_sql_concat"),
    ],
    "sql-injection": [
        (r'\$wpdb->(query|get_results|get_row|get_var)\s*\(\s*["\']?.*\$_(GET|POST|REQUEST|COOKIE)',
         "wpdb_direct_input"),
        (r'(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY).*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
         "sql_concat"),
        (r'(cursor|conn|session)\.(execute|executemany)\s*\(.*%\s*\(',
         "py_cursor_format_injection"),
        (r'(query|execute|raw)\s*\(\s*`[^`]*(SELECT|INSERT|UPDATE|DELETE).*\$\{(req\.|body\.|params\.)',
         "js_sql_template_literal"),
    ],
    "lfi": [
        (r'(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)',
         "include_user_input"),
        (r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)',
         "file_get_contents_input"),
        (r'(readfile|fopen|file)\s*\(.*\$_(GET|POST|REQUEST)',
         "file_read_input"),
    ],
    "local-file-inclusion": [
        (r'(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST)',
         "include_user_input"),
        (r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)',
         "file_get_contents_input"),
    ],
    "path-traversal": [
        # PHP
        (r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)',
         "file_read_input"),
        (r'(readfile|fopen|file|scandir|opendir|glob)\s*\(.*\$_(GET|POST|REQUEST)',
         "file_path_input"),
        # Python
        (r'open\s*\(.*request\.(args|form|json)',
         "py_open_request"),
        (r'os\.path\.(join|abspath)\s*\(.*request\.(args|form|json)',
         "py_path_join_request"),
        # Node.js
        (r'(readFile|readFileSync|createReadStream)\s*\(.*\+\s*(req\.|body\.|params\.)',
         "js_fs_concat"),
        (r'path\.join\s*\(.*\+\s*(req\.|body\.|params\.)',
         "js_path_join_request"),
    ],
    "arbitrary-file-read": [
        (r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)',
         "file_read_input"),
        (r'(readfile|fopen|file)\s*\(.*\$_(GET|POST|REQUEST)',
         "file_path_input"),
        (r'open\s*\(.*request\.(args|form|json)',
         "py_open_request"),
    ],
    "rce": [
        (r'(exec|shell_exec|system|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST)',
         "command_injection"),
        (r'eval\s*\(.*\$_(GET|POST|REQUEST)',
         "eval_input"),
        (r'`.*\$_(GET|POST|REQUEST).*`',
         "backtick_injection"),
        (r'subprocess\.(run|call|Popen|check_output)\s*\(.*request\.(args|form|json)',
         "py_subprocess_request"),
    ],
    "command-injection": [
        # PHP
        (r'(exec|shell_exec|system|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST)',
         "command_injection"),
        (r'`.*\$_(GET|POST|REQUEST).*`',
         "backtick_injection"),
        # Python
        (r'subprocess\.(run|call|Popen|check_output)\s*\(.*request\.(args|form|json)',
         "py_subprocess_request"),
        (r'os\.(system|popen)\s*\(.*request\.(args|form|json)',
         "py_os_system_request"),
        # Node.js
        (r'(exec|execSync|spawn|spawnSync)\s*\(.*\+\s*(req\.|body\.|params\.)',
         "js_exec_concat"),
        (r'(exec|execSync|spawn)\s*\(\s*`[^`]*\$\{(req\.|body\.|params\.)',
         "js_exec_template"),
    ],
    "remote-code-execution": [
        (r'(exec|shell_exec|system|passthru|proc_open)\s*\(.*\$_(GET|POST|REQUEST)',
         "command_injection"),
        (r'eval\s*\(.*\$_(GET|POST|REQUEST)',
         "eval_input"),
        (r'subprocess\.(run|call|Popen|check_output)\s*\(.*request\.(args|form|json)',
         "py_subprocess_request"),
    ],
    "xss": [
        (r'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)',
         "echo_unescaped"),
        (r'print\s+.*\$_(GET|POST|REQUEST)',
         "print_unescaped"),
        (r'printf\s*\(.*\$_(GET|POST|REQUEST)',
         "printf_unescaped"),
    ],
    "ssrf": [
        # PHP/WordPress
        (r'(wp_remote_get|wp_remote_post|wp_remote_request|curl_exec|file_get_contents)\s*\(.*\$_(GET|POST|REQUEST)',
         "ssrf_user_url"),
        # Python
        (r'requests\.(get|post|put|delete)\s*\(.*request\.(args|form|json)',
         "py_requests_user_url"),
        (r'urllib\.request\.urlopen\s*\(.*request\.(args|form|json)',
         "py_urllib_user_url"),
        (r'httpx\.(get|post)\s*\(.*request\.(args|form|json)',
         "py_httpx_user_url"),
        # Node.js
        (r'(axios|fetch|got)\s*\(\s*(req\.|body\.|params\.|query\.)',
         "js_fetch_user_url"),
    ],
    "ssti": [
        # PHP
        (r'(render|template|compile|eval)\s*\(.*\$_(GET|POST|REQUEST)',
         "template_user_input"),
        # Python / Jinja2 / Flask
        (r'Environment\s*\([^)]*\).*\.from_string\s*\(',
         "jinja2_from_string"),
        (r'Template\s*\(\s*request\.',
         "jinja2_template_request"),
        (r'render_template_string\s*\(.*request\.(args|form|json|data)',
         "flask_render_template_string"),
        (r'jinja2\.Template\s*\(\s*(request|user_input)',
         "jinja2_template_user"),
    ],
    "arbitrary-file-upload": [
        (r'move_uploaded_file\s*\(',
         "file_upload_sink"),
        (r'\$_FILES\[',
         "files_superglobal"),
        # Node.js / multer / busboy
        (r'(multer|busboy|formidable).*\.single\(',
         "js_multer_upload"),
        (r'req\.file\.(filename|path|originalname)',
         "js_req_file_access"),
    ],
    "deserialization": [
        (r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
         "php_unserialize_input"),
        (r'unserialize\s*\(\s*base64_decode\s*\(',
         "php_unserialize_b64"),
        (r'maybe_unserialize\s*\(\s*\$(?:option|value|meta)',
         "php_maybe_unserialize"),
        (r'pickle\.loads\s*\(',
         "py_pickle_loads"),
        (r'yaml\.load\s*\([^,)]+\)',
         "py_yaml_load_no_loader"),
        (r'Marshal\.load\s*\(',
         "ruby_marshal_load"),
    ],
    "php-object-injection": [
        (r'unserialize\s*\(',
         "php_unserialize"),
        (r'maybe_unserialize\s*\(',
         "php_maybe_unserialize"),
    ],
    "nosql-injection": [
        # MongoDB operators in user input
        (r'\[?["\']?\$(?:ne|gt|lt|gte|lte|in|nin|regex|where|exists)\b',
         "mongodb_operator"),
        (r'(find|findOne|update|delete)\s*\(\s*\{[^}]*req\.',
         "js_mongo_req_query"),
        (r'(find|findOne|update|delete)\s*\(\s*\{[^}]*request\.',
         "py_mongo_req_query"),
    ],
    "open-redirect": [
        (r'(wp_redirect|wp_safe_redirect|header\s*\(\s*["\']Location:)',
         "php_redirect_header"),
        (r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
         "php_location_input"),
        (r'wp_redirect\s*\(\s*\$_(GET|POST|REQUEST)',
         "wp_redirect_input"),
        (r'(res\.redirect|response\.redirect)\s*\(\s*(req\.|body\.|params\.)',
         "js_redirect_input"),
    ],
    "crlf-injection": [
        (r'header\s*\(\s*["\']?.*\$_(GET|POST|REQUEST|COOKIE)',
         "php_header_input"),
        (r'(setcookie|header)\s*\(.*\$_(GET|POST|REQUEST)',
         "php_set_header_input"),
        (r'(response\.setHeader|res\.set)\s*\(.*\+\s*(req\.|body\.)',
         "js_setheader_input"),
    ],
    "prototype-pollution": [
        (r'(mergeDeep|deepMerge|extend|assign)\s*\(.*req\.',
         "js_deep_merge_input"),
        (r'__proto__\s*\[',
         "js_proto_bracket"),
        (r'constructor\s*\[.*prototype\s*\[',
         "js_constructor_prototype"),
    ],
    "jwt-bypass": [
        (r'jwt\.verify\s*\([^,]+,\s*process\.env',
         "js_jwt_env_secret"),
        (r'alg\s*:\s*["\']none["\']',
         "js_jwt_alg_none"),
        (r'jwt_decode\s*\([^)]+,?\s*options',
         "py_jwt_decode_options"),
    ],
    "csrf": [
        (r'add_action\s*\(\s*["\']wp_ajax(?:_nopriv)?_[^"\']+["\']',
         "wp_ajax_handler"),
        (r'add_action\s*\(\s*["\']wp_ajax_[^"\']+["\']\s*,\s*\[',
         "wp_ajax_class_handler"),
    ],
    "missing-authorization": [
        # WordPress: handler without capability check
        (r'add_action\s*\(\s*["\']wp_ajax(?:_nopriv)?_[^"\']+["\']\s*,',
         "wp_ajax_no_cap_check"),
        # REST route without permission_callback
        (r'register_rest_route\s*\([^;]*(?!permission_callback)',
         "rest_route_no_permission"),
    ],
}

# Semgrep rule keyword filters per vuln class
_SEMGREP_FILTER: dict = {
    "sqli": ["sqli", "injection", "wpdb", "sql", "prepare"],
    "sql-injection": ["sqli", "injection", "wpdb", "sql", "prepare"],
    "lfi": ["lfi", "path", "traversal", "include", "require", "file"],
    "path-traversal": ["lfi", "path", "traversal", "include", "require", "file"],
    "arbitrary-file-read": ["lfi", "path", "file", "traversal"],
    "rce": ["rce", "exec", "shell", "eval", "system", "command"],
    "command-injection": ["rce", "exec", "shell", "eval", "command"],
    "remote-code-execution": ["rce", "exec", "shell", "eval"],
    "xss": ["xss", "cross-site", "injection", "escape"],
    "ssrf": ["ssrf", "request", "forgery", "url", "redirect"],
    "ssti": ["ssti", "template", "injection", "render"],
    "arbitrary-file-upload": ["upload", "file", "extension", "mime"],
    "deserialization": ["unserialize", "pickle", "deserializ", "marshal"],
    "php-object-injection": ["unserialize", "deserializ"],
    "nosql-injection": ["nosql", "mongodb", "operator", "injection"],
    "open-redirect": ["redirect", "location", "url"],
    "crlf-injection": ["crlf", "header", "injection", "response"],
    "prototype-pollution": ["prototype", "pollution", "merge", "__proto__"],
    "jwt-bypass": ["jwt", "token", "bypass", "alg"],
    "csrf": ["csrf", "nonce", "ajax", "referer"],
    "missing-authorization": ["authorization", "capability", "permission", "nonce"],
}


def _walk_source_files(source_dir: str, extensions: tuple = (".php", ".js", ".ts", ".py", ".rb", ".go", ".java")) -> List[str]:
    """Enumerate all source files under source_dir with given extensions."""
    files = []
    for root, dirs, fnames in os.walk(source_dir):
        # Skip vendor/node_modules/tests to stay focused
        dirs[:] = [d for d in dirs if d not in ("vendor", "node_modules", "test", "tests", ".git")]
        for fname in fnames:
            if fname.endswith(extensions):
                files.append(os.path.join(root, fname))
    return files


def _regex_taint_scan(source_dir: str, vuln_class: str) -> List[dict]:
    """Fast regex-based taint scan over PHP files. Returns list of findings."""
    findings = []
    patterns = _REGEX_PATTERNS.get(vuln_class.lower(), [])
    if not patterns:
        # Try partial match
        vc_lower = vuln_class.lower()
        for key, pats in _REGEX_PATTERNS.items():
            if key in vc_lower or vc_lower in key:
                patterns = pats
                break
    if not patterns:
        return findings

    files = _walk_source_files(source_dir)
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("//") or line_stripped.startswith("#"):
                continue
            for pattern, label in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    rel_path = os.path.relpath(fpath, source_dir)
                    # Try to extract function name from surrounding context
                    func_name = ""
                    for prev_line in reversed(lines[max(0, lineno - 15):lineno - 1]):
                        m = re.search(r'function\s+(\w+)\s*\(', prev_line)
                        if m:
                            func_name = m.group(1)
                            break
                    findings.append({
                        "file": rel_path,
                        "line": lineno,
                        "function": func_name,
                        "pattern": label,
                        "snippet": line_stripped[:200],
                        "confidence": "medium",
                    })
                    break  # one finding per line
    return findings


def _run_semgrep(source_dir: str, vuln_class: str) -> List[dict]:
    """Run semgrep and filter results by vuln class keywords. Returns parsed findings."""
    if not shutil.which("semgrep"):
        return []
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--lang=php", "--json", "--timeout=30",
             "--no-git-ignore", source_dir],
            capture_output=True, text=True, timeout=60,
        )
        if not result.stdout:
            return []
        data = json.loads(result.stdout)
        raw_results = data.get("results", [])
    except Exception:
        return []

    keywords = _SEMGREP_FILTER.get(vuln_class.lower(), [])
    if not keywords:
        # Partial match
        vc_lower = vuln_class.lower()
        for key, kws in _SEMGREP_FILTER.items():
            if key in vc_lower or vc_lower in key:
                keywords = kws
                break

    findings = []
    for r in raw_results:
        severity = (r.get("extra", {}).get("severity") or "").upper()
        if severity not in ("ERROR", "WARNING"):
            continue
        rule_id = (r.get("check_id") or "").lower()
        message = (r.get("extra", {}).get("message") or "").lower()
        combined = rule_id + " " + message
        # Include finding if any keyword matches, or if no keywords (include all)
        if not keywords or any(kw in combined for kw in keywords):
            path = r.get("path", "")
            start = r.get("start", {})
            matched = r.get("extra", {}).get("lines", "")
            findings.append({
                "file": os.path.relpath(path, source_dir) if path else path,
                "line": start.get("line", 0),
                "rule_id": r.get("check_id", ""),
                "message": r.get("extra", {}).get("message", ""),
                "matched_code": matched[:200] if matched else "",
                "severity": severity,
            })
    return findings


def _build_top_candidates(semgrep_findings: List[dict], regex_findings: List[dict]) -> List[dict]:
    """Merge and deduplicate findings into top candidates."""
    seen = set()
    candidates = []
    # Semgrep findings are higher confidence
    for f in semgrep_findings[:5]:
        key = (f.get("file", ""), f.get("line", 0))
        if key not in seen:
            seen.add(key)
            candidates.append({
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "function": "",
                "source": "semgrep",
                "confidence": "high",
                "detail": f.get("message", f.get("rule_id", "")),
            })
    # Regex findings are medium confidence
    for f in regex_findings[:5]:
        key = (f.get("file", ""), f.get("line", 0))
        if key not in seen:
            seen.add(key)
            candidates.append({
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "function": f.get("function", ""),
                "source": "regex",
                "confidence": f.get("confidence", "medium"),
                "detail": f.get("pattern", "") + ": " + f.get("snippet", "")[:100],
            })
    return candidates[:8]


def run_static_analysis(source_dir: str, vuln_class: str, slug: str = "") -> dict:
    """
    Run deterministic static analysis on plugin source before LLM RCA.

    Returns:
        {
            "semgrep_findings": [...],
            "regex_findings": [...],
            "summary": "Found N potential sinks",
            "top_candidates": [{file, line, function, confidence, detail}, ...]
        }
    """
    if not source_dir or not os.path.isdir(source_dir):
        return {"semgrep_findings": [], "regex_findings": [], "summary": "source_dir not found", "top_candidates": []}

    semgrep_findings = []
    regex_findings = []
    try:
        semgrep_findings = _run_semgrep(source_dir, vuln_class)
    except Exception:
        pass
    try:
        regex_findings = _regex_taint_scan(source_dir, vuln_class)
    except Exception:
        pass

    total = len(semgrep_findings) + len(regex_findings)
    slug_note = f" in {slug}" if slug else ""
    summary = (
        f"Found {total} potential {vuln_class} sink(s){slug_note}: "
        f"{len(semgrep_findings)} via semgrep, {len(regex_findings)} via regex taint"
    )

    top_candidates = _build_top_candidates(semgrep_findings, regex_findings)

    return {
        "semgrep_findings": semgrep_findings[:10],
        "regex_findings": regex_findings[:10],
        "summary": summary,
        "top_candidates": top_candidates,
    }


def format_for_llm_context(analysis: dict) -> str:
    """Format static analysis results as a compact LLM-readable block."""
    if not analysis or not analysis.get("top_candidates"):
        return ""
    lines = [f"[STATIC ANALYSIS] {analysis.get('summary', '')}"]
    for c in analysis.get("top_candidates", [])[:5]:
        func_part = f" in {c['function']}()" if c.get("function") else ""
        lines.append(
            f"  [{c.get('confidence','?').upper()}] {c.get('file','')}:{c.get('line','?')}"
            f"{func_part} — {c.get('detail','')[:120]}"
        )
    return "\n".join(lines)
