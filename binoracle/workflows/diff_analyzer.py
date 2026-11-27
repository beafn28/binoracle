"""Deterministic patch diff analyzer for exploit intelligence.

Parses git unified diffs from OSV.dev/GitHub security patches to extract:
- Which functions were patched
- What checks were added (the fix)
- What vulnerable code was removed
- What dangerous sinks are near the patch
- Input variable flow to the sink
"""
from __future__ import annotations

import glob
import os
import re

_AUTH_KEYWORDS = (
    "check_ajax_referer", "wp_verify_nonce", "current_user_can",
    "is_user_logged_in", "permission_callback", "auth_check",
    "sanitize_", "esc_attr", "esc_html", "esc_sql", "esc_url",
    "intval(", "absint(", "floatval(", "wp_die(", "rest_ensure_request",
)

_SINK_PATTERNS = (
    r"\$wpdb\s*->\s*query\s*\(",
    r"\$wpdb\s*->\s*get_results\s*\(",
    r"\$wpdb\s*->\s*get_row\s*\(",
    r"\$wpdb\s*->\s*get_var\s*\(",
    r"\beval\s*\(",
    r"\bsystem\s*\(",
    r"\bexec\s*\(",
    r"\bpassthru\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpopen\s*\(",
    r"\bproc_open\s*\(",
    r"\bfile_get_contents\s*\(",
    r"\bfile_put_contents\s*\(",
    r"\bfopen\s*\(",
    r"\binclude\s*[\(\s]",
    r"\brequire\s*[\(\s]",
    r"\binclude_once\s*[\(\s]",
    r"\brequire_once\s*[\(\s]",
    r"\bwp_remote_get\s*\(",
    r"\bwp_remote_post\s*\(",
    r"\bwp_remote_request\s*\(",
    r"\bcurl_exec\s*\(",
    r"\bpreg_replace\s*\(",
    r"\bcreate_function\s*\(",
    r"\bdo_shortcode\s*\(",
    r"\bwp_mail\s*\(",
)

_CAPABILITY_RE = re.compile(
    r"current_user_can\s*\(\s*['\"]([a-z_]+)['\"]", re.IGNORECASE
)
_FUNC_HUNK_RE = re.compile(r"@@[^@]*@@\s*(?:function\s+(\w+)|class\s+(\w+))")
_HUNK_HDR_RE = re.compile(r"^@@\s+-(\d+)", re.MULTILINE)
_SINK_RE = re.compile("|".join(_SINK_PATTERNS), re.IGNORECASE)
_USER_INPUT_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*['\"]?(\w+)['\"]?\s*\]",
    re.IGNORECASE,
)
_VAR_ASSIGN_RE = re.compile(
    r"(\$\w+)\s*=\s*(.+?)\s*;", re.DOTALL
)


def analyze_patch_diff(raw_diff: str) -> dict:
    """Parse a git unified diff and extract actionable exploit intelligence."""
    result: dict = {
        "patched_functions": [],
        "patched_files": [],
        "added_checks": [],
        "removed_code": [],
        "sink_candidates": [],
        "auth_checks_added": [],
        "nonce_checks_added": False,
        "capability_added": None,
        "fix_type": "other",
        "bypass_hints": [],
        "vulnerable_lines": [],
        "fix_completeness": "unknown",
    }
    if not raw_diff or not raw_diff.strip():
        return result

    current_file = ""
    current_line_no = 0
    added_lines: list[str] = []
    removed_lines: list[str] = []
    all_sink_hits: list[str] = []
    files_changed: set[str] = set()

    for raw_line in raw_diff.splitlines():
        # Track file being patched
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            files_changed.add(current_file)
            continue
        if raw_line.startswith("--- ") or raw_line.startswith("+++ "):
            continue

        # Hunk header — extract starting line number and function context
        if raw_line.startswith("@@"):
            m_hdr = _HUNK_HDR_RE.match(raw_line)
            if m_hdr:
                current_line_no = int(m_hdr.group(1))
            m_func = _FUNC_HUNK_RE.search(raw_line)
            if m_func:
                fname = m_func.group(1) or m_func.group(2)
                if fname and fname not in result["patched_functions"]:
                    result["patched_functions"].append(fname)
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            added_lines.append(content)
            if _SINK_RE.search(content):
                all_sink_hits.append(content.strip())
            current_line_no += 1

        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            content = raw_line[1:]
            removed_lines.append(content)
            if _SINK_RE.search(content):
                all_sink_hits.append(content.strip())
                result["vulnerable_lines"].append({
                    "file": current_file,
                    "line_no": current_line_no,
                    "content": content.strip(),
                })
        else:
            current_line_no += 1

    result["patched_files"] = list(files_changed)
    result["removed_code"] = [l.strip() for l in removed_lines if l.strip()]
    result["sink_candidates"] = list(dict.fromkeys(all_sink_hits))[:10]

    # Analyze added lines for security checks
    for line in added_lines:
        ls = line.strip()
        if not ls:
            continue
        # Nonce checks
        if "wp_verify_nonce" in ls or "check_ajax_referer" in ls:
            result["nonce_checks_added"] = True
            result["auth_checks_added"].append(ls[:120])
        # Auth / capability checks
        elif any(kw in ls for kw in ("current_user_can", "is_user_logged_in",
                                      "permission_callback", "auth_check")):
            result["auth_checks_added"].append(ls[:120])
            m_cap = _CAPABILITY_RE.search(ls)
            if m_cap and not result["capability_added"]:
                result["capability_added"] = m_cap.group(1)
        # Sanitization / escaping
        elif any(kw in ls for kw in _AUTH_KEYWORDS):
            result["added_checks"].append(ls[:120])

    # Deduplicate
    result["added_checks"] = list(dict.fromkeys(result["added_checks"]))[:20]
    result["auth_checks_added"] = list(dict.fromkeys(result["auth_checks_added"]))[:10]

    # Determine fix_type
    if result["nonce_checks_added"]:
        result["fix_type"] = "nonce"
    elif result["capability_added"] or any(
            "current_user_can" in l for l in result["auth_checks_added"]):
        result["fix_type"] = "capability"
    elif result["auth_checks_added"]:
        result["fix_type"] = "auth_check"
    elif any(
            any(kw in l for kw in ("sanitize_", "esc_", "intval(", "absint("))
            for l in result["added_checks"]):
        result["fix_type"] = "sanitization"

    # Bypass hints from removed code
    for line in result["removed_code"]:
        if _USER_INPUT_RE.search(line):
            result["bypass_hints"].append(
                f"Direct user input (no sanitization): {line.strip()[:100]}"
            )
        if _SINK_RE.search(line):
            result["bypass_hints"].append(
                f"Sink reached directly: {line.strip()[:100]}"
            )

    # Deeper bypass hints from the fix pattern itself
    _cap_added = result.get("capability_added")
    if _cap_added:
        # Suggest minimum role that might have this capability
        _high_caps = {"manage_options", "edit_theme_options", "install_plugins",
                      "update_plugins", "delete_plugins", "activate_plugins"}
        _mid_caps = {"edit_posts", "edit_pages", "publish_posts", "edit_others_posts",
                     "delete_posts", "upload_files"}
        _low_caps = {"read", "edit_comments", "moderate_comments"}
        if _cap_added in _high_caps:
            result["bypass_hints"].append(
                f"Fix adds '{_cap_added}' capability check — requires admin/editor role; "
                f"test if lower-privilege route (Subscriber, Contributor) still exposes the endpoint"
            )
        elif _cap_added in _mid_caps:
            result["bypass_hints"].append(
                f"Fix adds '{_cap_added}' capability check — Contributor/Author may have this; "
                f"try with unauthenticated request or Subscriber role first"
            )
        elif _cap_added in _low_caps:
            result["bypass_hints"].append(
                f"Fix adds '{_cap_added}' — this is a low-bar capability; "
                f"try unauthenticated access (wp_ajax_nopriv_) if handler also has nopriv hook"
            )
        else:
            result["bypass_hints"].append(
                f"Fix adds capability check '{_cap_added}' — verify if nopriv handler still exists"
            )
    if result.get("nonce_checks_added") and not _cap_added:
        # Nonce-only fix: nonces are obtainable if user is logged in
        result["bypass_hints"].append(
            "Fix adds nonce check only (no capability check) — nonce is obtainable by any logged-in "
            "user via wp_create_nonce(); Subscriber role may still be able to bypass"
        )
    if result.get("fix_completeness") == "partial":
        result["bypass_hints"].append(
            "Fix appears partial (single file, multiple sink patterns) — look for alternate "
            "code paths in other files that reach the same sink without the new check"
        )
    # Sanitization bypass hints
    for line in result.get("added_checks", []):
        if "intval(" in line or "absint(" in line:
            result["bypass_hints"].append(
                f"Fix uses intval()/absint() — only protects numeric parameters; "
                f"string params may still be unsanitized: {line[:80]}"
            )
            break
        if "sanitize_text_field" in line:
            result["bypass_hints"].append(
                "Fix uses sanitize_text_field() — strips HTML tags but does NOT protect against "
                "SQL injection; check if output goes into a query without prepare()"
            )
            break

    # Fix completeness: partial if only 1 file, same sink pattern in multiple hunks
    if len(files_changed) == 1 and len(result["sink_candidates"]) > 1:
        result["fix_completeness"] = "partial"
    elif files_changed:
        result["fix_completeness"] = "complete"

    # Deduplicate bypass hints
    result["bypass_hints"] = list(dict.fromkeys(result["bypass_hints"]))[:8]

    return result


def find_vulnerable_function(source_dir: str, function_names: list) -> list:
    """Scan plugin source for exact file:line of each function name."""
    if not source_dir or not function_names:
        return []
    results = []
    _fn_re = {
        fn: re.compile(
            rf"\bfunction\s+{re.escape(fn)}\s*\(", re.IGNORECASE
        )
        for fn in function_names
    }
    for php_file in glob.glob(os.path.join(source_dir, "**", "*.php"), recursive=True):
        try:
            with open(php_file, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    for fn, pattern in _fn_re.items():
                        if pattern.search(line):
                            rel = os.path.relpath(php_file, source_dir)
                            results.append({
                                "function": fn,
                                "file": rel,
                                "line": lineno,
                                "snippet": line.rstrip()[:120],
                            })
        except OSError:
            continue
    return results


def extract_input_path(raw_diff: str, sink_function: str) -> str:
    """Trace user input → sink from removed (vulnerable) diff lines."""
    if not raw_diff or not sink_function:
        return ""

    removed: list[str] = []
    for raw_line in raw_diff.splitlines():
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            removed.append(raw_line[1:])

    # Find removed lines that contain the sink
    sink_pat = re.compile(re.escape(sink_function), re.IGNORECASE)
    sink_lines = [l for l in removed if sink_pat.search(l)]
    if not sink_lines:
        return ""

    # Collect all variable assignments from removed code
    assignments: dict[str, str] = {}
    for line in removed:
        m = _VAR_ASSIGN_RE.search(line)
        if m:
            assignments[m.group(1)] = m.group(2).strip()[:80]

    # For each sink line, find variables and trace them back to user input
    chains: list[str] = []
    for sink_line in sink_lines[:3]:
        # Find variables used in the sink call
        var_hits = re.findall(r"\$\w+", sink_line)
        for var in var_hits:
            # Direct user input
            direct = _USER_INPUT_RE.search(assignments.get(var, ""))
            if direct:
                chains.append(
                    f"{direct.group(0)} -> {var} -> {sink_function}"
                )
                continue
            # One-hop indirection
            for src_var, src_val in assignments.items():
                if var in src_val:
                    ui = _USER_INPUT_RE.search(assignments.get(src_var, ""))
                    if ui:
                        chains.append(
                            f"{ui.group(0)} -> {src_var} -> {var} -> {sink_function}"
                        )

        # Also check direct user input in sink line itself
        direct_in_sink = _USER_INPUT_RE.search(sink_line)
        if direct_in_sink:
            chains.append(f"{direct_in_sink.group(0)} -> {sink_function}")

    return "; ".join(dict.fromkeys(chains))[:300]
