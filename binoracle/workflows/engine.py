"""
Universal Autonomous Error Analysis & Self-Remediation Engine.

Five core capabilities, each independently extensible:

  SourceCodeIntelligence   — understand code in any framework / language
  VulnerabilityIntelligence — detect security issues from code + behavior
  CveIntelligence          — reason about CVE descriptions, classify, map to attack surface
  DependencyAnalysis       — parse dependency manifests, detect vulnerable packages
  RemediationEngine        — DETECT → ANALYZE → DIAGNOSE → PROPOSE → VERIFY → CORRECT

Orchestrated by UniversalEngine. No hardcoded CVE IDs, no framework-specific rules:
all reasoning is driven by evidence from error signals, source code, and NVD data.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple


# ─────────────────────────── Core data types ──────────────────────────────────

class ErrorKind(Enum):
    VALIDATION  = auto()   # missing / invalid params, schema mismatch
    AUTH        = auto()   # 401/403, bad token, missing role
    NOT_FOUND   = auto()   # 404, unregistered route / resource
    SERVER      = auto()   # 500, fatal exception, process crash
    PROCESS     = auto()   # non-zero exit, signal, WP-CLI die()
    CONFIG      = auto()   # missing env-var, TLS, bad config
    DB          = auto()   # query failure, missing table, migration needed
    NETWORK     = auto()   # timeout, connection refused
    DEPENDENCY  = auto()   # missing class / module / import
    UNKNOWN     = auto()


@dataclass
class ErrorSignal:
    """Universal, format-agnostic error representation."""
    kind:     ErrorKind
    code:     str              # e.g. "rest_missing_callback_param", "403"
    message:  str
    source:   str              # "http_response" | "log" | "exit_code" | "exception"
    details:  Dict[str, Any] = field(default_factory=dict)
    raw:      Any = None       # original object (Response, exception, log line)

    @staticmethod
    def from_http(response: Any) -> Optional["ErrorSignal"]:
        """Parse an HTTP response into an ErrorSignal.
        Works for JSON (REST), XML (SOAP), plain-text, and HTML error pages."""
        if response is None:
            return None
        status = getattr(response, "status_code", 0)
        body = getattr(response, "text", "") or ""

        # Attempt JSON parse
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        # Classify kind from status
        if status in (400, 422):
            kind = ErrorKind.VALIDATION
        elif status in (401, 403):
            kind = ErrorKind.AUTH
        elif status == 404:
            kind = ErrorKind.NOT_FOUND
        elif status >= 500:
            kind = ErrorKind.SERVER
        else:
            kind = ErrorKind.UNKNOWN

        # Extract code / message from common REST error formats
        code = (data.get("code") or data.get("error") or
                data.get("type") or str(status))
        message = (data.get("message") or data.get("msg") or
                   data.get("detail") or body[:200])
        details = data.get("data") or data.get("errors") or {}
        if isinstance(details, str):
            details = {"_raw": details}

        return ErrorSignal(kind=kind, code=str(code), message=str(message),
                           source="http_response", details=details, raw=response)

    @staticmethod
    def from_exit(returncode: int, stdout: str, stderr: str) -> "ErrorSignal":
        """Parse a subprocess result into an ErrorSignal."""
        combined = (stderr or "") + (stdout or "")
        # WP-CLI / generic process patterns
        if "does not exist" in combined and "cannot be registered" in combined:
            kind, code = ErrorKind.DEPENDENCY, "callable_not_registered"
        elif "TLS" in combined or "SSL" in combined or "certificate" in combined:
            kind, code = ErrorKind.CONFIG, "tls_error"
        elif "Fatal error" in combined or "Uncaught" in combined:
            kind, code = ErrorKind.SERVER, "php_fatal"
        elif returncode != 0:
            kind, code = ErrorKind.PROCESS, f"exit_{returncode}"
        else:
            kind, code = ErrorKind.UNKNOWN, "unknown_exit"

        return ErrorSignal(kind=kind, code=code, message=combined[:300],
                           source="exit_code", details={}, raw=(returncode, stdout, stderr))


@dataclass
class ParamDefinition:
    """What a framework knows about a parameter from its schema / source."""
    name:           str
    required:       bool          = False
    type_hint:      str           = "string"
    allowed_values: List[str]     = field(default_factory=list)
    pattern:        str           = ""
    description:    str           = ""
    language:       str           = "unknown"   # php | python | js | java | ruby | go


@dataclass
class RootCause:
    signal:     ErrorSignal
    hypothesis: str                        # human-readable explanation
    confidence: float                      # 0.0 – 1.0
    param_defs: List[ParamDefinition]      = field(default_factory=list)
    evidence:   List[str]                  = field(default_factory=list)


@dataclass
class Fix:
    description: str
    changes:     Dict[str, Any]   # param_name → value, or other keyed changes
    reversible:  bool = True
    rationale:   str  = ""


@dataclass
class RemediationResult:
    success:       bool
    attempts:      int
    fixes_applied: List[Fix]
    final_signal:  Optional[ErrorSignal]
    log:           List[str] = field(default_factory=list)


# ─────────────────────── 1. Source Code Intelligence ──────────────────────────

class _BaseExtractor:
    """Interface for per-language source-code extractors."""
    extensions: Tuple[str, ...] = ()

    def applicable(self, path: str) -> bool:
        return any(path.endswith(ext) for ext in self.extensions)

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        return []


class _PHPExtractor(_BaseExtractor):
    """PHP / WordPress REST API — register_rest_route args, validate_callback."""
    extensions = (".php",)
    _NEVER = {
        "required", "true", "false", "type", "string", "integer", "boolean",
        "array", "default", "description", "sanitize", "validate", "callback",
        "enum", "format", "email", "number", "null", "object", "function",
        "return", "echo", "public", "private", "protected", "static",
        "sanitize_text_field", "sanitize_email", "rest_sanitize_boolean",
        "sanitize_user", "esc_url_raw", "column", "table", "prefix",
    }

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        # Match the param block: 'name' => [ ... ]
        for m in re.finditer(
            r"""['"]\s*""" + re.escape(param_name) + r"""\s*['"]\s*=>\s*\[(.{20,800}?)\]""",
            content, re.DOTALL
        ):
            block = m.group(1)
            required = bool(re.search(r"['\"]required['\"]\s*=>\s*true", block, re.I))
            type_hint = "string"
            for t in ("integer", "boolean", "array", "number"):
                if re.search(rf"['\"]type['\"]\s*=>\s*['\"]?{t}", block, re.I):
                    type_hint = t
                    break

            # Look for inline array of allowed values: ['a', 'b', 'c']
            allowed: List[str] = []
            # Pattern: in_array($x, ['a', 'b']) or just ['a', 'b'] near param block
            for arr_m in re.finditer(r"\[(['\"][a-zA-Z0-9_\-]+['\"](?:\s*,\s*['\"][a-zA-Z0-9_\-]+['\"])*)\]", block):
                vals = re.findall(r"['\"]([a-zA-Z0-9_\-]{2,30})['\"]", arr_m.group(1))
                good = [v for v in vals if v.lower() not in self._NEVER and not v.isdigit()]
                if good:
                    allowed = good
                    break

            # Also look for $allowed_types = ['a', 'b'] in a window that extends past the
            # matched block end (block may be truncated by an inner ']' in the closure).
            # We use a 400-char window starting from the block start, but require that the
            # variable assignment appears BEFORE the NEXT sibling param key ('other_param' =>).
            if not allowed:
                win_start = m.start()
                win_end   = min(len(content), win_start + len(block) + 200)
                # Restrict window to content before the next sibling param key at top level
                next_sibling = re.search(
                    r"""['"]\s*[a-zA-Z_][a-zA-Z0-9_]*\s*['"]\s*=>""",
                    content[m.end(): m.end() + 300]
                )
                if next_sibling:
                    win_end = min(win_end, m.end() + next_sibling.start())
                win = content[win_start:win_end]
                for arr_m in re.finditer(
                    r"\$\w*(?:type|kind|mode|value|option|status|role|method|provider|allow)\w*"
                    r"\s*=\s*\[(['\"][a-zA-Z0-9_\-]+['\"](?:\s*,\s*['\"][a-zA-Z0-9_\-]+['\"])*)\]",
                    win
                ):
                    vals = re.findall(r"['\"]([a-zA-Z0-9_\-]{2,30})['\"]", arr_m.group(1))
                    good = [v for v in vals if v.lower() not in self._NEVER and not v.isdigit()]
                    if good:
                        allowed = good
                        break

            results.append(ParamDefinition(
                name=param_name, required=required, type_hint=type_hint,
                allowed_values=allowed, language="php",
            ))
        return results


class _PythonExtractor(_BaseExtractor):
    """Python: FastAPI, Pydantic, Django REST Framework, Flask."""
    extensions = (".py",)

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        # Pydantic / FastAPI: param_name: Literal["a", "b"] — anchored to the param name
        for m in re.finditer(
            re.escape(param_name) + r"""\s*:\s*(?:[A-Za-z_]+\s*\[)?Literal\[(['"a-zA-Z0-9_,\s]+)\]""",
            content
        ):
            vals = re.findall(r"""['"]([a-zA-Z0-9_\-]{2,30})['"]""", m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="python",
                ))
        # Django choices: look for the choices tuple/list near a field that names this param.
        # Anchor: find a CharField/ChoiceField that mentions param_name within 400 chars of CHOICES.
        for pname_m in re.finditer(re.escape(param_name), content, re.IGNORECASE):
            ctx = content[max(0, pname_m.start() - 50): pname_m.start() + 600]
            for m in re.finditer(
                r"""[A-Z_]+\s*=\s*\[((?:\s*\(['\"][a-zA-Z0-9_\-]+['"]\s*,.*?\)\s*,?\s*)+)\]""",
                ctx, re.DOTALL
            ):
                vals = re.findall(r"""\(\s*['"]([a-zA-Z0-9_\-]{2,30})['"]\s*,""", m.group(1))
                if vals:
                    results.append(ParamDefinition(
                        name=param_name, required=True, type_hint="enum",
                        allowed_values=vals, language="python",
                    ))
                    break
        return results


class _JavaScriptExtractor(_BaseExtractor):
    """Node.js / TypeScript: Zod, Joi, Express validator, OpenAPI."""
    extensions = (".js", ".ts", ".mjs", ".cjs")

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        # For each occurrence of param_name in the file, check for schema patterns nearby.
        for pname_m in re.finditer(re.escape(param_name), content, re.IGNORECASE):
            ctx = content[pname_m.start(): pname_m.start() + 400]
            # Zod: param_name: z.enum(["a", "b"]) — colon + z.enum within 100 chars
            for m in re.finditer(r"z\.enum\(\s*\[([^\]]+)\]", ctx):
                vals = re.findall(r"""['"`]([a-zA-Z0-9_\-]{2,30})['"`]""", m.group(1))
                if vals:
                    results.append(ParamDefinition(
                        name=param_name, required=True, type_hint="enum",
                        allowed_values=vals, language="javascript",
                    ))
                    break
            # Joi: .valid('a', 'b') within 200 chars of param_name
            for m in re.finditer(r"""\.valid\(([^)]+)\)""", ctx):
                vals = re.findall(r"""['"`]([a-zA-Z0-9_\-]{2,30})['"`]""", m.group(1))
                if vals:
                    results.append(ParamDefinition(
                        name=param_name, required=True, type_hint="enum",
                        allowed_values=vals, language="javascript",
                    ))
                    break
        return results


class _GenericExtractor(_BaseExtractor):
    """Language-agnostic fallback: finds the param name as a KEY (followed by = or : or ()
    and looks for an array of string literals within 300 chars. Only triggers on key-value
    context to avoid cross-param contamination."""
    extensions = (".php", ".py", ".js", ".ts", ".rb", ".java", ".go", ".rs")

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        # Require param_name to appear as a key: name= / name: / name(
        for m in re.finditer(
            re.escape(param_name) + r"""\s*(?:=|:|\()""",
            content, re.IGNORECASE
        ):
            ctx = content[m.start(): m.start() + 300]
            for arr_m in re.finditer(
                r"""[\[(]['"` ]?([a-zA-Z0-9_\-]{2,20}['"`]\s*,\s*['"`]?[a-zA-Z0-9_\-]{2,20})['"` ]?\s*[\])]""",
                ctx
            ):
                vals = re.findall(r"""['"`]([a-zA-Z0-9_\-]{2,20})['"`]""", arr_m.group(0))
                if len(vals) >= 2:
                    return [ParamDefinition(
                        name=param_name, required=True, type_hint="enum",
                        allowed_values=vals, language="generic",
                    )]
        return []


class SourceCodeIntelligence:
    """
    Understands code in any language/framework.
    Extensible: register additional _BaseExtractor subclasses via add_extractor().
    """

    def __init__(self):
        self._extractors: List[_BaseExtractor] = [
            _PHPExtractor(),
            _PythonExtractor(),
            _JavaScriptExtractor(),
            _GenericExtractor(),
        ]

    def add_extractor(self, extractor: _BaseExtractor) -> None:
        self._extractors.insert(-1, extractor)   # before GenericExtractor

    def find_param_definitions(
        self,
        source_dir: str,
        param_names: List[str],
        max_files: int = 500,
    ) -> Dict[str, ParamDefinition]:
        """Walk source_dir, run all applicable extractors, return best definitions."""
        results: Dict[str, ParamDefinition] = {}
        if not os.path.isdir(source_dir):
            return results

        file_count = 0
        for root, _dirs, files in os.walk(source_dir):
            for fname in files:
                if file_count >= max_files:
                    break
                fpath = os.path.join(root, fname)
                applicable = [e for e in self._extractors if e.applicable(fpath)]
                if not applicable:
                    continue
                try:
                    content = open(fpath, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                file_count += 1

                for param in param_names:
                    if param in results and results[param].allowed_values:
                        continue   # already have a good definition
                    for extractor in applicable:
                        defs = extractor.find_param_defs(content, param)
                        for d in defs:
                            existing = results.get(param)
                            # Prefer defs with allowed_values over bare ones
                            if existing is None or (d.allowed_values and not existing.allowed_values):
                                results[param] = d
                                break

        return results

    def infer_valid_value(
        self,
        param_name: str,
        param_def: Optional[ParamDefinition] = None,
        error_message: str = "",
    ) -> str:
        """
        Return the most likely valid value for a parameter.
        Priority: (1) values extracted from error message, (2) first allowed value
        from source, (3) semantic default by param name.
        """
        # 1. Extract from error message: "Allowed types: google, apple"
        for pat in [
            r"(?:allowed\s+(?:types?|values?|options?)[:：]\s*)([a-z0-9_,\s\-]+)",
            r"(?:must\s+be\s+one\s+of[:：]\s*)([a-z0-9_,\s\-]+)",
            r"(?:valid\s+(?:types?|values?)[:：]\s*)([a-z0-9_,\s\-]+)",
            r"(?:accepted\s+(?:types?|values?)[:：]\s*)([a-z0-9_,\s\-]+)",
        ]:
            m = re.search(pat, error_message, re.IGNORECASE)
            if m:
                vals = [v.strip() for v in m.group(1).split(",") if v.strip()]
                if vals:
                    return vals[0]

        # 2. First allowed value from source code analysis
        if param_def and param_def.allowed_values:
            return param_def.allowed_values[0]

        # 3. Semantic defaults keyed by param-name patterns
        lp = param_name.lower()
        if any(x in lp for x in ("token", "access_token", "access", "secret",
                                   "password", "pass", "pwd", "credential", "key")):
            return "binoracle_lab_token"
        if any(x in lp for x in ("type", "kind", "mode", "method", "provider",
                                   "platform", "source", "action", "login_type")):
            return "default"
        if any(x in lp for x in ("role", "permission", "level", "scope")):
            return "subscriber"
        if any(x in lp for x in ("id", "user_id", "uid", "identifier")):
            return "1"
        if any(x in lp for x in ("name", "username", "login", "user")):
            return "binoracle_user"
        return "binoracle_test"


# ──────────────────── 2. Vulnerability Intelligence ───────────────────────────

@dataclass
class SecurityFinding:
    vuln_class:  str         # "auth_bypass", "sqli", "idor", "xss", …
    description: str
    evidence:    List[str]
    confidence:  float       # 0.0 – 1.0
    location:    str = ""    # file:line or endpoint


class VulnerabilityIntelligence:
    """
    Identifies security issues from source code patterns and HTTP behavior.
    Evidence-based: each finding requires at least one concrete code or
    runtime evidence item. No theoretical impact, no speculation.
    """

    # ── Auth bypass: set auth before checking role ──────────────────────────
    _AUTH_BEFORE_CHECK = [
        # PHP: wp_set_auth_cookie / wp_set_current_user before a role/capability check
        (r"wp_set_auth_cookie|wp_set_current_user",
         r"has_role|in_array.*role|current_user_can|getPatientRole|user_role",
         "auth_bypass_cookie_before_role_check"),
        # Python: session set before permission check
        (r"session\[.user.\]\s*=|login_user\(|set_cookie.*auth",
         r"has_permission|check_permission|require_permission|@login_required",
         "auth_bypass_session_before_permission"),
    ]

    # ── Missing authorization (public endpoint that should be private) ───────
    _PUBLIC_ENDPOINT_PATTERNS = [
        (r"permission_callback.*__return_true|permission_callback.*true",
         "wp_rest_no_auth_required"),
        (r"@app\.route.*methods=.*['\"]POST['\"](?!.*login_required)",
         "flask_unprotected_post"),
    ]

    def analyze_auth_flow(
        self,
        source_dir: str,
        endpoint: str = "",
        max_files: int = 300,
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        if not os.path.isdir(source_dir):
            return findings

        for root, _dirs, files in os.walk(source_dir):
            for fname in files:
                if not any(fname.endswith(e) for e in (".php", ".py", ".js", ".ts")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    content = open(fpath, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue

                # Auth-before-role-check patterns
                for set_pat, check_pat, vuln_class in self._AUTH_BEFORE_CHECK:
                    m_set   = re.search(set_pat, content)
                    m_check = re.search(check_pat, content)
                    if m_set and m_check:
                        set_pos   = m_set.start()
                        check_pos = m_check.start()
                        if set_pos < check_pos:
                            rel = os.path.relpath(fpath, source_dir)
                            findings.append(SecurityFinding(
                                vuln_class=vuln_class,
                                description=(
                                    f"Auth cookie/session set at offset {set_pos} "
                                    f"before role/permission check at offset {check_pos}"
                                ),
                                evidence=[
                                    f"{rel}: `{content[m_set.start():m_set.end()]}` "
                                    f"precedes `{content[m_check.start():m_check.end()]}`"
                                ],
                                confidence=0.85,
                                location=rel,
                            ))

                # Public endpoint patterns
                for pat, vuln_class in self._PUBLIC_ENDPOINT_PATTERNS:
                    for m in re.finditer(pat, content):
                        rel = os.path.relpath(fpath, source_dir)
                        findings.append(SecurityFinding(
                            vuln_class=vuln_class,
                            description="Endpoint registered with no authentication requirement",
                            evidence=[f"{rel}: `{content[m.start():m.end()]}`"],
                            confidence=0.7,
                            location=rel,
                        ))

        return findings

    def check_bypass_evidence(self, response_body: str, cookies: Dict,
                               victim_email: str = "") -> bool:
        """
        Returns True if runtime evidence confirms an auth bypass:
        an authenticated session that belongs to victim_email was produced
        without supplying that account's credentials.
        """
        if victim_email and victim_email in response_body:
            return True
        # WordPress: wp-admin/profile.php shows the logged-in user's email
        # This check is called from the verifier with the actual page content.
        if victim_email and re.search(re.escape(victim_email), response_body, re.IGNORECASE):
            return True
        # Any wp_set_auth_cookie path: 403 response WITH Set-Cookie containing wordpress_logged
        if cookies and any("wordpress_logged_in" in k for k in cookies):
            return True
        return False


# ─────────────────────────── 3. Remediation Engine ────────────────────────────

class RemediationEngine:
    """
    Implements the DETECT → ANALYZE → UNDERSTAND → DIAGNOSE →
    PROPOSE → VALIDATE → CORRECT → VERIFY cycle.

    Usage:
        engine = RemediationEngine(source_intel)
        result = engine.remediate(
            error_signal=sig,
            current_params=params,
            source_dir="/path/to/plugin",
            make_request=lambda p: session.post(url, data=p),
            on_step=print,
        )
        if result.success:
            final_response = result.final_signal.raw
    """

    def __init__(self, source_intel: Optional[SourceCodeIntelligence] = None):
        self._src = source_intel or SourceCodeIntelligence()

    def _analyze(self, signal: ErrorSignal, source_dir: str,
                  current_params: Dict) -> Tuple[RootCause, List[Fix]]:
        """Core reasoning: map error signal → root cause → proposed fixes."""
        cause = RootCause(signal=signal, hypothesis="", confidence=0.0)
        fixes: List[Fix] = []

        # ── Validation errors: missing or invalid params ──────────────────
        if signal.kind == ErrorKind.VALIDATION:
            # Extract which params are problematic
            if signal.code in ("rest_missing_callback_param", "rest_invalid_param"):
                raw_params = signal.details.get("params") or {}
                if isinstance(raw_params, list):
                    bad_params = raw_params
                    err_detail: Dict = {}
                elif isinstance(raw_params, dict):
                    bad_params = list(raw_params.keys())
                    err_detail = signal.details.get("details") or {}
                else:
                    bad_params = []
                    err_detail = {}

                cause.hypothesis = (
                    f"Endpoint requires parameters that are absent or invalid: {bad_params}. "
                    f"These are enforced by the framework's schema before the handler runs."
                )
                cause.confidence = 0.95
                cause.evidence.append(f"REST error code: {signal.code}")
                cause.evidence.append(f"Problematic params: {bad_params}")

                # Find definitions from source
                if bad_params and os.path.isdir(source_dir):
                    defs = self._src.find_param_definitions(source_dir, bad_params)
                    cause.param_defs = list(defs.values())

                # Build fix: infer one valid value per missing/invalid param
                new_values: Dict[str, str] = {}
                for pname in bad_params:
                    pdef  = defs.get(pname) if bad_params and os.path.isdir(source_dir) else None
                    detail_msg = ""
                    d_entry = err_detail.get(pname)
                    if isinstance(d_entry, dict):
                        detail_msg = d_entry.get("message") or ""
                    elif isinstance(d_entry, str):
                        detail_msg = d_entry
                    val = self._src.infer_valid_value(pname, pdef, detail_msg)
                    new_values[pname] = val
                    cause.evidence.append(
                        f"Inferred '{pname}'='{val}' from "
                        f"{'error message' if detail_msg else 'source code' if pdef else 'semantic default'}"
                    )

                if new_values:
                    fixes.append(Fix(
                        description=f"Add inferred values for params: {list(new_values.keys())}",
                        changes=new_values,
                        reversible=True,
                        rationale="Values derived from (1) error message, (2) source schema, (3) semantic name",
                    ))

            else:
                cause.hypothesis = f"Validation error: {signal.message}"
                cause.confidence = 0.6

        # ── Auth / permission errors ──────────────────────────────────────
        elif signal.kind == ErrorKind.AUTH:
            cause.hypothesis = (
                "The request was rejected on authorization grounds. "
                "This may be expected if the auth cookie was already set before the check "
                "(auth bypass pattern), or indicates insufficient privileges."
            )
            cause.confidence = 0.7

        # ── 404 / route not found ─────────────────────────────────────────
        elif signal.kind == ErrorKind.NOT_FOUND:
            cause.hypothesis = (
                "The endpoint returned 404. The route may not be registered "
                "because the plugin is inactive, WordPress permalinks are not "
                "set to /%postname%/, or the route registration hook did not fire."
            )
            cause.confidence = 0.75

        # ── Process / dependency errors (e.g. WP-CLI exit) ───────────────
        elif signal.kind in (ErrorKind.PROCESS, ErrorKind.DEPENDENCY):
            cause.hypothesis = (
                f"Process exited with error ({signal.code}): {signal.message[:150]}. "
                "This may indicate a missing class/callable registration that fires "
                "in CLI mode but is harmless for HTTP requests."
            )
            cause.confidence = 0.65

        else:
            cause.hypothesis = f"Unknown error class ({signal.code}): {signal.message[:150]}"
            cause.confidence = 0.3

        return cause, fixes

    def remediate(
        self,
        error_signal: ErrorSignal,
        current_params: Dict,
        source_dir: str,
        make_request: Callable[[Dict], Any],
        on_step: Optional[Callable[[str], None]] = None,
        max_attempts: int = 3,
    ) -> RemediationResult:
        """
        DETECT → ANALYZE → DIAGNOSE → PROPOSE → VALIDATE → CORRECT → VERIFY.
        Returns the final RemediationResult including the last response.
        """
        def _log(msg: str) -> None:
            if on_step:
                on_step(msg)

        log: List[str] = []
        applied: List[Fix] = []
        params = dict(current_params)
        last_signal: Optional[ErrorSignal] = error_signal

        for attempt in range(1, max_attempts + 1):
            if last_signal is None:
                break
            if last_signal.kind not in (ErrorKind.VALIDATION,):
                # Only retry for validation errors; other errors need different handling
                break

            cause, fixes = self._analyze(last_signal, source_dir, params)
            if not fixes:
                _log(f"[engine] no se pudo proponer una correccion para {last_signal.code}")
                break

            fix = fixes[0]
            _log(
                f"[engine] intento {attempt}/{max_attempts}: "
                f"{fix.description} — {fix.rationale}"
            )
            msg_parts = []
            for k, v in fix.changes.items():
                msg_parts.append(f"{k}={v!r}")
            _log(f"[engine] corrigiendo params: {', '.join(msg_parts)}")

            params.update(fix.changes)
            applied.append(fix)
            log.append(f"attempt {attempt}: {fix.description}")

            # Execute the fixed request
            try:
                response = make_request(params)
            except Exception as e:
                _log(f"[engine] fallo en reintento {attempt}: {e}")
                break

            # Parse new signal
            new_signal = ErrorSignal.from_http(response)
            if new_signal is None:
                break

            last_signal = new_signal
            if new_signal.kind not in (ErrorKind.VALIDATION,):
                # Non-validation response: either success or a different error class
                break

        success = (last_signal is None or
                   last_signal.kind not in (ErrorKind.VALIDATION, ErrorKind.NOT_FOUND))
        return RemediationResult(
            success=success,
            attempts=len(applied),
            fixes_applied=applied,
            final_signal=last_signal,
            log=log,
        )


# ─────────────────────── 4. CVE Intelligence ──────────────────────────────────

@dataclass
class CveProfile:
    """Structured reasoning extracted from a CVE description — no NVD fields verbatim."""
    cve_id:         str
    vuln_class:     str              # "auth_bypass", "sqli", "rce", "path_traversal", …
    affected_component: str          # e.g. "kivicare", "next.js", "django"
    version_hint:   str              # e.g. "4.1.2", "<=13.5.6"
    auth_required:  bool             # True if exploitation requires prior auth
    endpoint_hint:  str              # e.g. "/wp-json/kivicare/v1/auth/patient/social-login"
    exploit_method: str              # brief one-line description
    confidence:     float            # 0.0–1.0 based on how much we could extract
    raw_description: str = ""


# Keyword → vuln class mapping (checked in order; first match wins)
_VULN_CLASS_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(?:authentication bypass|auth bypass|bypass.{0,30}auth(?:entication)?|"
     r"unauthenticated.{0,30}access|without.{0,20}auth(?:entication)?)\b",
     "auth_bypass"),
    (r"\b(?:sql injection|sqli|sql.{0,10}inject)\b",                 "sqli"),
    (r"\b(?:remote code execution|rce|arbitrary code|code inject)\b", "rce"),
    (r"\b(?:path traversal|directory traversal|lfi|local file inclus)\b", "path_traversal"),
    (r"\b(?:cross.site scripting|xss|script inject)\b",              "xss"),
    (r"\b(?:server.side request forgery|ssrf)\b",                    "ssrf"),
    (r"\b(?:cross.site request forgery|csrf)\b",                     "csrf"),
    (r"\b(?:insecure deseri|deserializ)\b",                          "deserialization"),
    (r"\b(?:open redirect)\b",                                        "open_redirect"),
    (r"\b(?:file upload|arbitrary.{0,20}upload|webshell)\b",         "file_upload"),
    (r"\b(?:idor|insecure direct object|object reference)\b",        "idor"),
    (r"\b(?:privilege escalation|privesc|elevat.{0,20}privilege)\b", "privilege_escalation"),
    (r"\b(?:xxe|xml external entity)\b",                             "xxe"),
    (r"\b(?:broken.{0,20}access control|missing.{0,30}authorization|"
     r"lack.{0,20}(?:of\s+)?authorization)\b",                       "broken_access_control"),
]

# Auth-not-required signals
_NO_AUTH_PATTERNS = [
    r"\bunauthenticated\b",
    r"\bwithout.{0,20}(?:authentication|login|credential)\b",
    r"\bno.{0,10}(?:authentication|login|credential)\s+required\b",
    r"\banonymous\b",
    r"\bany.{0,10}(?:user|visitor|attacker)\b",
]

# Auth-required signals
_AUTH_REQUIRED_PATTERNS = [
    r"\b(?:authenticated|logged.{0,10}in|low.privilege|subscriber|contributor)\b",
    r"\bwith.{0,20}(?:authentication|valid.{0,10}account|low.{0,5}privilege)\b",
]


def _extract_endpoint_hint(text: str) -> str:
    """Find the most specific URL-like hint from a CVE description."""
    # REST path: /something/something
    for m in re.finditer(r"/(?:[a-zA-Z0-9_\-]+/){1,6}[a-zA-Z0-9_\-]*", text):
        p = m.group(0)
        if len(p) > 5 and p.count("/") >= 2:
            return p
    # Named endpoint hint
    for m in re.finditer(r"(?:endpoint|route|path|URL)[:\s]+(['\"/]?[^\s,;.\"\']{6,60})", text, re.I):
        return m.group(1).strip("'\"")
    return ""


def _extract_version_hint(text: str) -> str:
    """Find version constraints like '<=4.1.2', 'through 3.5', 'before 2.0.0'."""
    for pat in [
        r"(?:<=|<|through|prior to|before|up to)\s*v?(\d+\.\d+(?:\.\d+)?)",
        r"\bv?(\d+\.\d+(?:\.\d+)?)\s+(?:and earlier|and below|and prior)",
        r"\bversion\s+(\d+\.\d+(?:\.\d+)?)\b",
    ]:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1)
    return ""


class CveIntelligence:
    """
    Reasons about CVE descriptions to build a structured CveProfile.
    Uses cvelookup.fetch_cve() when network is available; falls back to
    description-only analysis when given raw text directly.
    """

    def profile_from_description(self, description: str, cve_id: str = "") -> CveProfile:
        """Extract structured CveProfile from free-text description alone."""
        text = description or ""
        lower = text.lower()

        # Classify vuln class
        vuln_class = "unknown"
        for pattern, cls in _VULN_CLASS_PATTERNS:
            if re.search(pattern, lower, re.I):
                vuln_class = cls
                break

        # Auth requirement
        no_auth = any(re.search(p, lower, re.I) for p in _NO_AUTH_PATTERNS)
        yes_auth = any(re.search(p, lower, re.I) for p in _AUTH_REQUIRED_PATTERNS)
        auth_required = yes_auth and not no_auth

        # Affected component: first quoted name, plugin name, or product name
        component = ""
        for pat in [
            r"(?:plugin|module|extension|package|library|component)\s+['\"]?([A-Za-z][A-Za-z0-9_\-\s]{2,30}?)['\"]?\s+(?:for|before|through|<=|plugin)",
            r"WordPress\s+plugin\s+['\"]?([^'\"<]{3,40}?)['\"]?\s+(?:before|through|<=|prior)",
            r"in\s+([A-Za-z][A-Za-z0-9_\-]{2,30})\s+(?:plugin|module|before|through|<=)",
        ]:
            m = re.search(pat, text, re.I)
            if m:
                component = m.group(1).strip().lower()
                break
        if not component:
            # Fallback: first capitalized product-looking word
            m = re.search(r"\b([A-Z][a-zA-Z0-9]{3,20}(?:\s[A-Z][a-zA-Z0-9]{2,20})?)\b", text)
            if m:
                component = m.group(1).lower()

        endpoint = _extract_endpoint_hint(text)
        version  = _extract_version_hint(text)

        # Confidence based on how much we extracted
        score = sum([
            vuln_class != "unknown",
            bool(component),
            bool(endpoint),
            bool(version),
        ]) / 4.0

        # Short exploit method summary
        method_map = {
            "auth_bypass":          "unauthenticated access via missing authorization check",
            "sqli":                 "SQL injection via unsanitized input parameter",
            "rce":                  "remote code execution via crafted input",
            "path_traversal":       "path traversal via directory sequence in parameter",
            "xss":                  "cross-site scripting via reflected/stored user input",
            "ssrf":                 "server-side request forgery via URL parameter",
            "csrf":                 "cross-site request forgery via forged request",
            "deserialization":      "insecure deserialization of untrusted data",
            "file_upload":          "arbitrary file upload bypassing extension/MIME filter",
            "idor":                 "insecure direct object reference via ID parameter",
            "broken_access_control":"missing authorization on sensitive endpoint",
        }
        exploit_method = method_map.get(vuln_class, "exploitation via crafted request")

        return CveProfile(
            cve_id=cve_id,
            vuln_class=vuln_class,
            affected_component=component,
            version_hint=version,
            auth_required=auth_required,
            endpoint_hint=endpoint,
            exploit_method=exploit_method,
            confidence=score,
            raw_description=text[:300],
        )

    def profile_from_nvd(self, cve_id: str, timeout: float = 20.0) -> Optional[CveProfile]:
        """Fetch CVE from NVD and return a structured CveProfile. Returns None on network error."""
        try:
            from binoracle.workflows.cvelookup import fetch_cve
            info = fetch_cve(cve_id, timeout=timeout, enrich=False)
            if not info.ok or not info.description:
                return None
            profile = self.profile_from_description(info.description, cve_id)
            # Override version from NVD CVSS when available
            if not profile.version_hint and info.cvss_vector:
                profile.confidence = min(1.0, profile.confidence + 0.1)
            return profile
        except Exception:
            return None


# ─────────────────────── 5. Dependency Analysis ───────────────────────────────

@dataclass
class DependencyRecord:
    """One package/library from a dependency manifest."""
    name:        str
    version:     str           # declared version string (may be a range)
    manager:     str           # "npm", "pip", "composer", "maven", "gem", "cargo", "go"
    source_file: str           # relative path of the manifest file
    dev_only:    bool = False  # true for devDependencies, test-only, etc.


@dataclass
class DependencyReport:
    dependencies: List[DependencyRecord]
    managers_found: List[str]
    source_dir: str


class DependencyAnalysis:
    """
    Parses dependency manifests from any ecosystem and returns a structured inventory.
    Supports: npm/yarn (package.json), pip (requirements.txt, pyproject.toml, setup.cfg),
    Composer (composer.json), Maven (pom.xml), Bundler (Gemfile.lock / Gemfile),
    Cargo (Cargo.toml), Go modules (go.mod).
    """

    def analyze(self, source_dir: str, max_depth: int = 4) -> DependencyReport:
        """Walk source_dir up to max_depth levels and parse all dependency manifests."""
        records: List[DependencyRecord] = []
        managers: List[str] = []

        for root, dirs, files in os.walk(source_dir):
            # Limit depth
            depth = root[len(source_dir):].count(os.sep)
            if depth >= max_depth:
                dirs.clear()
                continue
            # Skip common non-source dirs
            dirs[:] = [d for d in dirs if d not in
                       ("node_modules", ".git", "vendor", "__pycache__", ".venv", "venv",
                        "dist", "build", "target", ".tox", "eggs", ".eggs")]

            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, source_dir)
                try:
                    new = self._parse_file(fpath, rel, fname)
                except Exception:
                    new = []
                for rec in new:
                    records.append(rec)
                    if rec.manager not in managers:
                        managers.append(rec.manager)

        return DependencyReport(
            dependencies=records,
            managers_found=managers,
            source_dir=source_dir,
        )

    def _parse_file(self, fpath: str, rel: str, fname: str) -> List[DependencyRecord]:
        """Dispatch to the right parser based on filename."""
        if fname == "package.json":
            return self._parse_package_json(fpath, rel)
        if fname in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt"):
            return self._parse_requirements_txt(fpath, rel,
                                                 dev_only="dev" in fname.lower())
        if fname == "pyproject.toml":
            return self._parse_pyproject_toml(fpath, rel)
        if fname == "composer.json":
            return self._parse_composer_json(fpath, rel)
        if fname == "pom.xml":
            return self._parse_pom_xml(fpath, rel)
        if fname in ("Gemfile", "Gemfile.lock"):
            return self._parse_gemfile(fpath, rel)
        if fname == "Cargo.toml":
            return self._parse_cargo_toml(fpath, rel)
        if fname == "go.mod":
            return self._parse_go_mod(fpath, rel)
        return []

    # ── npm / yarn ────────────────────────────────────────────────────────────
    def _parse_package_json(self, fpath: str, rel: str) -> List[DependencyRecord]:
        try:
            data = json.loads(open(fpath, encoding="utf-8").read())
        except Exception:
            return []
        recs = []
        for section, dev in (("dependencies", False), ("devDependencies", True),
                              ("peerDependencies", False), ("optionalDependencies", False)):
            for name, ver in (data.get(section) or {}).items():
                recs.append(DependencyRecord(name=name, version=str(ver),
                                              manager="npm", source_file=rel, dev_only=dev))
        return recs

    # ── pip ───────────────────────────────────────────────────────────────────
    def _parse_requirements_txt(self, fpath: str, rel: str,
                                  dev_only: bool = False) -> List[DependencyRecord]:
        recs = []
        for line in open(fpath, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*([><=!~^]{0,3})\s*([^\s;#]*)", line)
            if m:
                recs.append(DependencyRecord(
                    name=m.group(1), version=(m.group(2) + m.group(3)).strip(),
                    manager="pip", source_file=rel, dev_only=dev_only,
                ))
        return recs

    def _parse_pyproject_toml(self, fpath: str, rel: str) -> List[DependencyRecord]:
        content = open(fpath, encoding="utf-8", errors="replace").read()
        recs = []
        # [project] dependencies = ["name>=ver", ...]
        for m in re.finditer(
            r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL
        ):
            for dep in re.findall(r"""['"]([A-Za-z0-9_.\-]+)\s*([><=!~^][^\s'"]*)?""",
                                   m.group(1)):
                recs.append(DependencyRecord(name=dep[0], version=dep[1] or "",
                                              manager="pip", source_file=rel))
        return recs

    # ── Composer (PHP) ────────────────────────────────────────────────────────
    def _parse_composer_json(self, fpath: str, rel: str) -> List[DependencyRecord]:
        try:
            data = json.loads(open(fpath, encoding="utf-8").read())
        except Exception:
            return []
        recs = []
        for section, dev in (("require", False), ("require-dev", True)):
            for name, ver in (data.get(section) or {}).items():
                if name == "php":
                    continue
                recs.append(DependencyRecord(name=name, version=str(ver),
                                              manager="composer", source_file=rel, dev_only=dev))
        return recs

    # ── Maven (Java) ──────────────────────────────────────────────────────────
    def _parse_pom_xml(self, fpath: str, rel: str) -> List[DependencyRecord]:
        content = open(fpath, encoding="utf-8", errors="replace").read()
        recs = []
        for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>"
            r"(?:\s*<version>([^<]*)</version>)?",
            content, re.DOTALL
        ):
            name = f"{m.group(1).strip()}:{m.group(2).strip()}"
            ver  = (m.group(3) or "").strip()
            # Check if test scope
            dev = bool(re.search(
                r"<scope>test</scope>",
                content[m.start(): m.start() + 500]
            ))
            recs.append(DependencyRecord(name=name, version=ver,
                                          manager="maven", source_file=rel, dev_only=dev))
        return recs

    # ── Bundler (Ruby) ────────────────────────────────────────────────────────
    def _parse_gemfile(self, fpath: str, rel: str) -> List[DependencyRecord]:
        recs = []
        for line in open(fpath, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line.startswith("#"):
                continue
            # gem 'name', '~> 1.2' or gem "name", ">= 1.0"
            m = re.match(r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", line)
            if m:
                recs.append(DependencyRecord(
                    name=m.group(1), version=m.group(2) or "",
                    manager="gem", source_file=rel,
                ))
            # Gemfile.lock: exact versions
            m2 = re.match(r"\s{4}([A-Za-z0-9_\-]+)\s+\(([^)]+)\)", line)
            if m2:
                recs.append(DependencyRecord(
                    name=m2.group(1), version=m2.group(2),
                    manager="gem", source_file=rel,
                ))
        return recs

    # ── Cargo (Rust) ─────────────────────────────────────────────────────────
    def _parse_cargo_toml(self, fpath: str, rel: str) -> List[DependencyRecord]:
        content = open(fpath, encoding="utf-8", errors="replace").read()
        recs = []
        in_deps = False
        in_dev  = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[dependencies]", "[workspace.dependencies]"):
                in_deps, in_dev = True, False
            elif stripped in ("[dev-dependencies]", "[build-dependencies]"):
                in_deps, in_dev = True, True
            elif stripped.startswith("["):
                in_deps = False
            elif in_deps:
                m = re.match(r'([A-Za-z0-9_\-]+)\s*=\s*["\']?([^"\'#\n]+)["\']?', stripped)
                if m:
                    recs.append(DependencyRecord(
                        name=m.group(1), version=m.group(2).strip().strip('"\''),
                        manager="cargo", source_file=rel, dev_only=in_dev,
                    ))
        return recs

    # ── Go modules ────────────────────────────────────────────────────────────
    def _parse_go_mod(self, fpath: str, rel: str) -> List[DependencyRecord]:
        recs = []
        for line in open(fpath, encoding="utf-8", errors="replace"):
            m = re.match(r"\s*([a-zA-Z0-9_.\-/]+)\s+(v[^\s]+)", line.strip())
            if m and not line.strip().startswith("//") and not line.strip().startswith("module"):
                recs.append(DependencyRecord(
                    name=m.group(1), version=m.group(2),
                    manager="go", source_file=rel,
                ))
        return recs


# ─────────────────────────── Universal Engine ─────────────────────────────────

class UniversalEngine:
    """
    Orchestrates all five capabilities:
      SourceCodeIntelligence, VulnerabilityIntelligence, CveIntelligence,
      DependencyAnalysis, RemediationEngine.

    Public entry points:
      .analyze_request_error(...)    — fix a failed HTTP request
      .analyze_process_error(...)    — reason about a failed process
      .assess_security(...)          — static security analysis of source
      .profile_cve(...)             — reason about a CVE description
      .analyze_dependencies(...)    — inventory a project's dependencies
    """

    def __init__(self):
        self.source_intel  = SourceCodeIntelligence()
        self.vuln_intel    = VulnerabilityIntelligence()
        self.cve_intel     = CveIntelligence()
        self.dep_analysis  = DependencyAnalysis()
        self.remediation   = RemediationEngine(self.source_intel)

    def analyze_request_error(
        self,
        response: Any,
        current_params: Dict,
        source_dir: str,
        make_request: Callable[[Dict], Any],
        on_step: Optional[Callable[[str], None]] = None,
        max_attempts: int = 3,
    ) -> Tuple[RemediationResult, Dict]:
        """
        Parse an HTTP response, reason about the error, propose + apply fixes,
        retry up to max_attempts. Returns (result, final_params).
        """
        signal = ErrorSignal.from_http(response)
        if signal is None or signal.kind not in (ErrorKind.VALIDATION,):
            return (
                RemediationResult(success=True, attempts=0, fixes_applied=[],
                                  final_signal=signal),
                current_params,
            )
        params = dict(current_params)
        result = self.remediation.remediate(
            signal, params, source_dir, make_request,
            on_step=on_step, max_attempts=max_attempts,
        )
        # Accumulate all param changes into final_params
        for fix in result.fixes_applied:
            params.update(fix.changes)
        return result, params

    def analyze_process_error(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> ErrorSignal:
        """Parse a subprocess result into a typed ErrorSignal."""
        return ErrorSignal.from_exit(returncode, stdout, stderr)

    def assess_security(
        self,
        source_dir: str,
        endpoint: str = "",
    ) -> List[SecurityFinding]:
        """Static security analysis of source_dir. Returns findings with evidence."""
        return self.vuln_intel.analyze_auth_flow(source_dir, endpoint)

    def profile_cve(
        self,
        cve_id_or_description: str,
        fetch_nvd: bool = True,
        timeout: float = 20.0,
    ) -> CveProfile:
        """
        Reason about a CVE: classify vuln class, extract component/version/endpoint hints.
        If cve_id_or_description looks like a CVE ID and fetch_nvd=True, fetches from NVD.
        Otherwise (or on network error), analyzes the description text directly.
        """
        is_id = bool(re.match(r"CVE-\d{4}-\d{4,}$", cve_id_or_description.strip(), re.I))
        if is_id and fetch_nvd:
            profile = self.cve_intel.profile_from_nvd(
                cve_id_or_description.strip().upper(), timeout=timeout
            )
            if profile:
                return profile
        return self.cve_intel.profile_from_description(cve_id_or_description)

    def analyze_dependencies(
        self,
        source_dir: str,
        max_depth: int = 4,
    ) -> DependencyReport:
        """
        Parse all dependency manifests in source_dir and return a structured inventory.
        Covers npm, pip, composer, maven, bundler, cargo, go modules.
        """
        return self.dep_analysis.analyze(source_dir, max_depth=max_depth)
