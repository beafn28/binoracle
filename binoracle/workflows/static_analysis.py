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
from typing import List, Optional

__all__ = [
    "run_static_analysis",
    "format_for_llm_context",
]

# --- Regex patterns per vuln class ---

_REGEX_PATTERNS: dict = {
    "sqli": [
        # Direct wpdb calls with user input
        (r'\$wpdb->(query|get_results|get_row|get_var)\s*\(\s*["\']?.*\$_(GET|POST|REQUEST|COOKIE)',
         "wpdb_direct_input"),
        # String concatenation into SQL
        (r'\$wpdb->(query|get_results|get_row|get_var)\s*\(.*\.(.*\$_(GET|POST|REQUEST|COOKIE))',
         "wpdb_concat"),
        # Raw SQL with concatenation (not just wpdb)
        (r'(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY).*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
         "sql_concat"),
    ],
    "sql-injection": [
        (r'\$wpdb->(query|get_results|get_row|get_var)\s*\(\s*["\']?.*\$_(GET|POST|REQUEST|COOKIE)',
         "wpdb_direct_input"),
        (r'(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY).*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
         "sql_concat"),
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
        (r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)',
         "file_read_input"),
        (r'(readfile|fopen|file|scandir|opendir|glob)\s*\(.*\$_(GET|POST|REQUEST)',
         "file_path_input"),
    ],
    "arbitrary-file-read": [
        (r'file_get_contents\s*\(.*\$_(GET|POST|REQUEST)',
         "file_read_input"),
        (r'(readfile|fopen|file)\s*\(.*\$_(GET|POST|REQUEST)',
         "file_path_input"),
    ],
    "rce": [
        (r'(exec|shell_exec|system|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST)',
         "command_injection"),
        (r'eval\s*\(.*\$_(GET|POST|REQUEST)',
         "eval_input"),
        (r'`.*\$_(GET|POST|REQUEST).*`',
         "backtick_injection"),
    ],
    "command-injection": [
        (r'(exec|shell_exec|system|passthru|popen|proc_open)\s*\(.*\$_(GET|POST|REQUEST)',
         "command_injection"),
        (r'`.*\$_(GET|POST|REQUEST).*`',
         "backtick_injection"),
    ],
    "remote-code-execution": [
        (r'(exec|shell_exec|system|passthru|proc_open)\s*\(.*\$_(GET|POST|REQUEST)',
         "command_injection"),
        (r'eval\s*\(.*\$_(GET|POST|REQUEST)',
         "eval_input"),
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
        (r'(wp_remote_get|wp_remote_post|wp_remote_request|curl_exec|file_get_contents)\s*\(.*\$_(GET|POST|REQUEST)',
         "ssrf_user_url"),
    ],
    "ssti": [
        (r'(render|template|compile|eval)\s*\(.*\$_(GET|POST|REQUEST)',
         "template_user_input"),
    ],
    "arbitrary-file-upload": [
        (r'move_uploaded_file\s*\(',
         "file_upload_sink"),
        (r'\$_FILES\[',
         "files_superglobal"),
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
}


def _walk_source_files(source_dir: str, extensions: tuple = (".php", ".js", ".py", ".rb")) -> List[str]:
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
