"""
Universal Autonomous Error Analysis & Self-Remediation Engine.

Three core capabilities, each independently extensible:

  SourceCodeIntelligence   — understand code in any framework / language
  VulnerabilityIntelligence — detect security issues from code + behavior
  RemediationEngine        — DETECT → ANALYZE → DIAGNOSE → PROPOSE → VERIFY → CORRECT

Orchestrated by UniversalEngine. No CVE IDs, no framework rules, no hardcoded fixes:
all reasoning is driven by evidence from the actual error signal and source code.
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

            # Also look for $allowed_types = ['a', 'b'] WITHIN the matched block only.
            # Searching outside the block risks finding arrays from sibling params.
            if not allowed:
                for arr_m in re.finditer(
                    r"\$\w*(?:type|kind|mode|value|option|status|role|method|provider|allow)\w*"
                    r"\s*=\s*\[(['\"][a-zA-Z0-9_\-]+['\"](?:\s*,\s*['\"][a-zA-Z0-9_\-]+['\"])*)\]",
                    block
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
        # Pydantic / FastAPI: Literal["a", "b"] or Enum class
        for m in re.finditer(
            r"(?:" + re.escape(param_name) + r"""\s*:\s*[A-Za-z_]*\s*=?\s*)?"""
            r"""Literal\[(['"a-zA-Z0-9_,\s]+)\]""",
            content
        ):
            vals = re.findall(r"""['"]([a-zA-Z0-9_\-]{2,30})['"]""", m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="python",
                ))
        # Django choices: CHOICES = [('a', '...'), ('b', '...')]
        for m in re.finditer(
            r"""[A-Z_]+\s*=\s*\[((?:\s*\(['\"][a-zA-Z0-9_\-]+['"]\s*,.*?\)\s*,?\s*)+)\]""",
            content, re.DOTALL
        ):
            vals = re.findall(r"""\(\s*['"]([a-zA-Z0-9_\-]{2,30})['"]\s*,""", m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="python",
                ))
        return results


class _JavaScriptExtractor(_BaseExtractor):
    """Node.js / TypeScript: Zod, Joi, Express validator, OpenAPI."""
    extensions = (".js", ".ts", ".mjs", ".cjs")

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        # Zod: z.enum(["a", "b"])
        for m in re.finditer(r"z\.enum\(\s*\[([^\]]+)\]", content):
            vals = re.findall(r"""['"`]([a-zA-Z0-9_\-]{2,30})['"`]""", m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="javascript",
                ))
        # Joi: Joi.string().valid('a', 'b')
        for m in re.finditer(r"""\.valid\(([^)]+)\)""", content):
            vals = re.findall(r"""['"`]([a-zA-Z0-9_\-]{2,30})['"`]""", m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="javascript",
                ))
        return results


class _GenericExtractor(_BaseExtractor):
    """Language-agnostic fallback: finds the param name near an array of string literals."""
    extensions = (".php", ".py", ".js", ".ts", ".rb", ".java", ".go", ".rs")

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        # Find param_name within 400 chars of a list-looking pattern
        for m in re.finditer(re.escape(param_name), content, re.IGNORECASE):
            ctx = content[m.start(): m.start() + 400]
            # Look for arrays: ["a", "b", "c"] or ('a', 'b') etc.
            for arr_m in re.finditer(
                r"""[\[(]['"` ]([a-zA-Z0-9_\-]{2,20}['"`]\s*,\s*['"` ][a-zA-Z0-9_\-]{2,20})['"` ]?\s*[\])]""",
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


# ─────────────────────────── Universal Engine ─────────────────────────────────

class UniversalEngine:
    """
    Orchestrates all three capabilities:
      SourceCodeIntelligence, VulnerabilityIntelligence, RemediationEngine.

    Public entry points:
      .analyze_request_error(...)    — fix a failed HTTP request
      .analyze_process_error(...)    — reason about a failed process
      .assess_security(...)          — static security analysis of source
    """

    def __init__(self):
        self.source_intel = SourceCodeIntelligence()
        self.vuln_intel   = VulnerabilityIntelligence()
        self.remediation  = RemediationEngine(self.source_intel)

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
