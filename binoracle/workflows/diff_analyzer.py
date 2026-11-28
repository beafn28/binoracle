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
    # WordPress / PHP
    "check_ajax_referer", "wp_verify_nonce", "current_user_can",
    "is_user_logged_in", "permission_callback", "auth_check",
    "sanitize_", "esc_attr", "esc_html", "esc_sql", "esc_url",
    "intval(", "absint(", "floatval(", "wp_die(", "rest_ensure_request",
    # Python
    "escape(", "bleach.clean(", "markupsafe.escape(", "html.escape(",
    "subprocess.run(", "shlex.quote(",
    # Node.js
    "validator.escape(", "DOMPurify.sanitize(", "helmet(", "xss(", "sanitizeHtml(",
    "req.isAuthenticated(", "passport.authenticate(",
    # Ruby
    "html_escape(", "sanitize(", "before_action :authenticate",
    # Java
    "StringEscapeUtils.escapeHtml", "ESAPI.encoder()", "@PreAuthorize",
)

_SINK_PATTERNS = (
    # PHP / WordPress
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
    # Python
    r"\bos\.system\s*\(",
    r"\bsubprocess\.(?:call|Popen|run|check_output)\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bpickle\.loads?\s*\(",
    r"\byaml\.load\s*\(",
    r"\bcursor\.execute\s*\(",
    r"\bengine\.execute\s*\(",
    r"\brender_template_string\s*\(",
    r"\bopen\s*\([^,)]+,\s*['\"]w",
    # Node.js / JavaScript
    r"\bchild_process\.exec\s*\(",
    r"\bexecSync\s*\(",
    r"\bspawnSync\s*\(",
    r"\beval\s*\(",
    r"\bFunction\s*\(",
    r"\bvm\.runInNewContext\s*\(",
    r"\bfs\.(?:readFile|writeFile|appendFile)\s*\(",
    r"\bres\.(?:send|json|end)\s*\(",
    r"\bDocument\.write\s*\(",
    r"\binnerHTML\s*=",
    r"\bdangerouslySetInnerHTML",
    # Ruby
    r"\bsystem\s*\(",
    r"\`[^`]+\`",
    r"\beval\s*\(",
    r"\bActiveRecord::Base\.connection\.execute\s*\(",
    r"\brender\s+:inline",
    # Java
    r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
    r"\bPreparedStatement\s*\(",
    r"\bStatement\.executeQuery\s*\(",
    r"\bObjectInputStream\s*\(",
    r"\bXMLDecoder\s*\(",
)

_CAPABILITY_RE = re.compile(
    r"current_user_can\s*\(\s*['\"]([a-z_]+)['\"]", re.IGNORECASE
)
_FUNC_HUNK_RE = re.compile(r"@@[^@]*@@\s*(?:function\s+(\w+)|class\s+(\w+))")
_HUNK_HDR_RE = re.compile(r"^@@\s+-(\d+)", re.MULTILINE)
_SINK_RE = re.compile("|".join(_SINK_PATTERNS), re.IGNORECASE)
_USER_INPUT_RE = re.compile(
    # PHP superglobals
    r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*['\"]?(\w+)['\"]?\s*\]"
    # Python: Flask/Django request objects
    r"|request\.(args|form|json|data|GET|POST|cookies|headers)\[?['\"]?(\w+)['\"]?\]?"
    r"|request\.(?:get_json|get_data)\s*\("
    # Node.js: Express req
    r"|req\.(?:query|body|params|headers|cookies)(?:\[.+?\]|\.\w+)"
    # Ruby: Rails params
    r"|params\[:(\w+)\]"
    r"|params\[\"(\w+)\"\]"
    # Java: HttpServletRequest
    r"|request\.getParameter\s*\(\s*[\"'](\w+)[\"']"
    r"|request\.getHeader\s*\(\s*[\"'](\w+)[\"']",
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
        # Nonce checks (WordPress)
        if "wp_verify_nonce" in ls or "check_ajax_referer" in ls:
            result["nonce_checks_added"] = True
            result["auth_checks_added"].append(ls[:120])
        # Auth / capability checks (WordPress)
        elif any(kw in ls for kw in ("current_user_can", "is_user_logged_in",
                                      "permission_callback", "auth_check")):
            result["auth_checks_added"].append(ls[:120])
            m_cap = _CAPABILITY_RE.search(ls)
            if m_cap and not result["capability_added"]:
                result["capability_added"] = m_cap.group(1)
        # Python/Django auth checks
        elif any(kw in ls for kw in ("@login_required", "@permission_required",
                                      "request.user.is_authenticated",
                                      "raise PermissionDenied", "raise Http404")):
            result["auth_checks_added"].append(ls[:120])
        # Node.js / Express auth checks
        elif any(kw in ls for kw in ("req.isAuthenticated()", "passport.authenticate(",
                                      "jwt.verify(", "verifyToken(", "checkAuth(",
                                      "middleware.auth", "ensureLoggedIn")):
            result["auth_checks_added"].append(ls[:120])
        # Ruby / Rails auth checks
        elif any(kw in ls for kw in ("before_action :authenticate", "authenticate_user!",
                                      "authorize!", "current_user.admin?")):
            result["auth_checks_added"].append(ls[:120])
        # Java auth checks
        elif any(kw in ls for kw in ("@PreAuthorize", "@Secured", "@RolesAllowed",
                                      "SecurityContextHolder", ".hasRole(", ".hasAuthority(")):
            result["auth_checks_added"].append(ls[:120])
        # Sanitization / escaping (all languages)
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
        # Detect framework from auth check text
        _auth_joined = " ".join(result["auth_checks_added"])
        if any(kw in _auth_joined for kw in ("@login_required", "is_authenticated",
                                               "PermissionDenied", "Http404")):
            result["fix_type"] = "auth_check_django"
        elif any(kw in _auth_joined for kw in ("isAuthenticated", "jwt.verify", "passport")):
            result["fix_type"] = "auth_check_express"
        elif any(kw in _auth_joined for kw in ("authenticate_user!", "before_action")):
            result["fix_type"] = "auth_check_rails"
        elif any(kw in _auth_joined for kw in ("@PreAuthorize", "@Secured", "hasRole")):
            result["fix_type"] = "auth_check_spring"
        else:
            result["fix_type"] = "auth_check"
    elif any(
            any(kw in l for kw in ("sanitize_", "esc_", "intval(", "absint("))
            for l in result["added_checks"]):
        result["fix_type"] = "sanitization"
    elif any(
            any(kw in l for kw in ("escape(", "bleach.clean", "html.escape", "DOMPurify"))
            for l in result["added_checks"]):
        result["fix_type"] = "sanitization_python_js"
    elif any("parameterized" in l.lower() or "prepared" in l.lower()
             for l in result["added_checks"]):
        result["fix_type"] = "parameterized_query"
    elif any(any(kw in l for kw in ("canonicalPath", "realpath", "normalize", "getCanonicalPath",
                                     "ZipEntry", "getZipSlip", "isWithinDirectory"))
             for l in added_lines):
        result["fix_type"] = "path_canonicalization"
    elif any(any(kw in l for kw in ("rateLimit", "rate_limit", "throttle", "RateLimiter",
                                     "express-rate-limit", "flask_limiter"))
             for l in added_lines):
        result["fix_type"] = "rate_limiting"
    elif any(any(kw in l for kw in ("cors(", "Access-Control-Allow-Origin", "CorsConfiguration",
                                     "AllowedOrigins", "cors.New"))
             for l in added_lines):
        result["fix_type"] = "cors_fix"
    elif any(any(kw in l for kw in ("Joi.", "z.object(", "yup.", "ajv.", "validate(",
                                     "schema.validate", "validator."))
             for l in added_lines):
        result["fix_type"] = "schema_validation"

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
    _fix_type = result.get("fix_type", "")
    if _fix_type == "auth_check_django":
        result["bypass_hints"].append(
            "Fix adds @login_required / is_authenticated — test with session fixation or "
            "unauthenticated access to the view if URL is guessable or not behind middleware"
        )
    elif _fix_type == "auth_check_express":
        result["bypass_hints"].append(
            "Fix adds JWT/passport auth — test with expired token (exp bypass), alg:none, "
            "or missing middleware on sub-routes; check if OPTIONS/HEAD bypass the middleware"
        )
    elif _fix_type == "auth_check_rails":
        result["bypass_hints"].append(
            "Fix adds before_action :authenticate — check if action is in :except or if "
            "skip_before_action exists in a subclass; try JSON format or non-HTML Accept header"
        )
    elif _fix_type in ("auth_check_spring", "auth_check_spring_security"):
        result["bypass_hints"].append(
            "Fix adds @PreAuthorize/@Secured — verify endpoint is mapped to Spring Security "
            "filter chain; test with trailing slash, different HTTP method, or case variation"
        )
    if result.get("fix_completeness") == "partial":
        result["bypass_hints"].append(
            "Fix appears partial (single file, multiple sink patterns) — look for alternate "
            "code paths in other files that reach the same sink without the new check"
        )
    if _fix_type == "path_canonicalization":
        result["bypass_hints"].append(
            "Fix adds path canonicalization for zip entries — check if canonicalization is "
            "applied before or after creating the destination path; double-dot encoded as ..%2f "
            "may survive one pass; also check Windows path separators (backslash)"
        )
    elif _fix_type == "rate_limiting":
        result["bypass_hints"].append(
            "Fix adds rate limiting — check if rate limit applies per-IP (bypassable with "
            "X-Forwarded-For spoofing), per-user (bypassable with new account creation), "
            "or uses Redis (check if bypass via IP rotation still works)"
        )
    elif _fix_type == "cors_fix":
        result["bypass_hints"].append(
            "Fix adds CORS restriction — check if null origin is allowed (file://, redirects), "
            "subdomain wildcard (*.example.com allows any subdomain), or if OPTIONS preflight "
            "is handled but actual request is not gated"
        )
    elif _fix_type == "schema_validation":
        result["bypass_hints"].append(
            "Fix adds schema validation (Joi/Zod/Yup) — check if validation is bypassed by "
            "sending extra properties (additionalProperties:true), type coercion "
            "(string '1' instead of int 1), or via nested objects that bypass flat validators"
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

    # Extract SQL injection context from vulnerable (removed) lines
    sqli_intel = extract_sqli_intel(removed_lines)
    if sqli_intel.get("injection_context"):
        result["sqli_intel"] = sqli_intel
        # Auto-add bypass hint for ORDER BY injection (no quoting, no WHERE close)
        if sqli_intel["injection_context"] == "order_by" and "order_by" not in " ".join(result["bypass_hints"]).lower():
            result["bypass_hints"].append(
                "SQL injection in ORDER BY context — no string quotes, payload is a bare "
                "expression (e.g. extractvalue(1,concat(0x7e,version())) or "
                "IF(1=1,SLEEP(5),0)); do NOT append AND/OR or use quotes"
            )
        elif sqli_intel["injection_context"] == "numeric" and "numeric" not in " ".join(result["bypass_hints"]).lower():
            result["bypass_hints"].append(
                "SQL injection in numeric context (no surrounding quotes) — inject as "
                "integer: e.g. '1 AND extractvalue(1,concat(0x7e,version()))'"
            )

    return result


# ---------------------------------------------------------------------------
# SQL injection context extraction from patch diff
# ---------------------------------------------------------------------------

_SQL_CTX_RE = re.compile(
    r"\b(ORDER\s+BY|WHERE|HAVING|LIMIT|GROUP\s+BY)\b", re.IGNORECASE
)
_SQL_CONCAT_RE = re.compile(
    # PHP string concat into SQL: '" . $var . "' or "'. $var .'"
    r"""['"][.\s]+\$\w+|"""
    # PHP heredoc/interpolation: "$var" or "{$var}"
    r"""\$\{?\w+\}?[^'"]*(?:['"]|$)|"""
    # Python f-string: f"...{var}..."
    r"""\{[\w.]+\}|"""
    # Node.js template literal: `...${var}...`
    r"""\$\{[\w.]+\}"""
)
_SQL_TABLE_RE = re.compile(
    r"""\b(?:FROM|JOIN|INTO|UPDATE)\s+[`'"]*(\w+)[`'"]*""", re.IGNORECASE
)
_SQL_COLUMN_RE = re.compile(
    r"""\b(?:WHERE|SET|ON)\s+[`'"]*(\w+)[`'"]*\s*[=<>!]""", re.IGNORECASE
)
_SQL_PREPARE_RE = re.compile(
    r"\b(?:prepare|wpdb->prepare|parameterize|bindParam|bindValue|placeholder)\b",
    re.IGNORECASE
)


def extract_sqli_intel(removed_lines: list) -> dict:
    """Extract SQL injection context from removed (vulnerable) patch diff lines.

    Looks for SQL query construction via string concatenation and identifies:
    - injection_context: "where", "order_by", "having", "limit", "numeric"
    - injection_quoting: "single", "double", "none"
    - table_names: tables in the query
    - column_names: columns near the injection
    - sql_template: the raw vulnerable SQL snippet (up to 200 chars)
    """
    result: dict = {
        "injection_context": None,
        "injection_quoting": None,
        "table_names": [],
        "column_names": [],
        "sql_template": "",
    }

    # Only look at lines that look like SQL query construction (not the fix)
    sql_lines = []
    for line in removed_lines:
        ls = line.strip()
        if not ls:
            continue
        # Must have SQL keyword AND string concatenation with a variable
        ctx_m = _SQL_CTX_RE.search(ls)
        concat_m = _SQL_CONCAT_RE.search(ls)
        # Also accept lines with wpdb->query/get_results with interpolation
        is_sink = bool(re.search(r"\$wpdb\s*->(?:query|get_results|get_row|get_var)\s*\(", ls))
        if (ctx_m or is_sink) and concat_m:
            sql_lines.append((ls, ctx_m))

    if not sql_lines:
        return result

    # Process the best matching line (prefer one with ORDER BY, then WHERE)
    order_by_lines = [(ln, m) for ln, m in sql_lines
                      if m and "ORDER" in m.group(1).upper()]
    best_lines = order_by_lines or sql_lines

    for ls, ctx_m in best_lines[:3]:  # noqa: E741
        ctx_keyword = (ctx_m.group(1).upper().replace(" ", "_")
                       if ctx_m else "")

        if "ORDER_BY" in ctx_keyword:
            result["injection_context"] = "order_by"
            result["injection_quoting"] = "none"
        elif ctx_keyword in ("WHERE", "HAVING"):
            result["injection_context"] = "where"
            # Determine quoting by looking at the character immediately before the
            # concat operator (". $var", ". $_POST", "${var}", "{var}")
            # Pattern: single-quote before concat: WHERE col = '" . $var
            #          double-quote before concat: WHERE col = "' . $var (unusual)
            # Simpler: scan the line for '" .' or "' ." or "= '" or '= "'
            if re.search(r"""[=\s]'\s*[."]\s*\.""", ls) or re.search(r"""'\s*\.\s*\$""", ls):
                result["injection_quoting"] = "single"
            elif re.search(r'''"[.\s]*\.\s*\$''', ls) and re.search(r"""WHERE\b""", ls, re.IGNORECASE):
                # e.g. WHERE col = "' . $var . '"  — double outer, single inner
                result["injection_quoting"] = "single"
            elif re.search(r'[=\s]"\s*[.]\s*\$', ls):
                result["injection_quoting"] = "double"
            else:
                result["injection_context"] = "numeric"
                result["injection_quoting"] = "none"
        elif "LIMIT" in ctx_keyword:
            result["injection_context"] = "limit"
            result["injection_quoting"] = "none"
        elif result["injection_context"] is None:
            # Sink line without explicit SQL keyword — numeric context
            result["injection_context"] = "numeric"
            result["injection_quoting"] = "none"

        # Extract table names
        for tbl in _SQL_TABLE_RE.findall(ls):
            if tbl and tbl not in result["table_names"] and not tbl.startswith("{"):
                result["table_names"].append(tbl)

        # Extract column names
        for col in _SQL_COLUMN_RE.findall(ls):
            if col and col not in result["column_names"] and not col.startswith("{"):
                result["column_names"].append(col)

        if not result["sql_template"]:
            result["sql_template"] = ls[:200]

        if result["injection_context"]:
            break

    # Strip empty lists
    if not result["table_names"]:
        del result["table_names"]
    if not result["column_names"]:
        del result["column_names"]
    if not result["sql_template"]:
        del result["sql_template"]

    return result


def find_vulnerable_function(source_dir: str, function_names: list) -> list:
    """Scan source for exact file:line of each function name, across all supported languages."""
    if not source_dir or not function_names:
        return []
    results = []
    # Language-specific function declaration patterns
    _lang_patterns = {
        ".php":  lambda fn: re.compile(rf"\bfunction\s+{re.escape(fn)}\s*\(", re.IGNORECASE),
        ".py":   lambda fn: re.compile(rf"\bdef\s+{re.escape(fn)}\s*\(", re.IGNORECASE),
        ".js":   lambda fn: re.compile(
            rf"(?:function\s+{re.escape(fn)}\s*\(|{re.escape(fn)}\s*[:=]\s*(?:async\s+)?function"
            rf"|\basync\s+function\s+{re.escape(fn)}\s*\()", re.IGNORECASE),
        ".ts":   lambda fn: re.compile(
            rf"(?:function\s+{re.escape(fn)}\s*\(|{re.escape(fn)}\s*[:=]\s*(?:async\s+)?function"
            rf"|\basync\s+function\s+{re.escape(fn)}\s*\()", re.IGNORECASE),
        ".rb":   lambda fn: re.compile(rf"\bdef\s+{re.escape(fn)}\b", re.IGNORECASE),
        ".java": lambda fn: re.compile(
            rf"(?:public|private|protected|static|\s)+\w[\w<>\[\]]*\s+{re.escape(fn)}\s*\(", re.IGNORECASE),
        ".go":   lambda fn: re.compile(rf"\bfunc\s+(?:\(\w+\s+\*?\w+\)\s+)?{re.escape(fn)}\s*\("),
        ".cs":   lambda fn: re.compile(
            rf"(?:public|private|protected|internal|static|\s)+\w[\w<>\[\]]*\s+{re.escape(fn)}\s*\(", re.IGNORECASE),
        ".rs":   lambda fn: re.compile(rf"\bfn\s+{re.escape(fn)}\s*[(<]"),
        ".kt":   lambda fn: re.compile(rf"\bfun\s+{re.escape(fn)}\s*\("),
        ".swift": lambda fn: re.compile(rf"\bfunc\s+{re.escape(fn)}\s*\("),
    }
    _exts = set(_lang_patterns.keys())
    # Pre-compile patterns per function per extension
    _compiled: dict[str, dict[str, re.Pattern]] = {ext: {} for ext in _exts}
    for ext, pat_fn in _lang_patterns.items():
        for fn in function_names:
            _compiled[ext][fn] = pat_fn(fn)

    for src_file in glob.glob(os.path.join(source_dir, "**", "*"), recursive=True):
        ext = os.path.splitext(src_file)[1].lower()
        if ext not in _exts:
            continue
        try:
            with open(src_file, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    for fn, pattern in _compiled[ext].items():
                        if pattern.search(line):
                            rel = os.path.relpath(src_file, source_dir)
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
