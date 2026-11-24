"""
Error Analyzer — structured error fingerprinting, classification, and root-cause diagnosis.

Every error in the pipeline goes through this module. It produces a machine-readable
ErrorRecord that the RepairMemory stores and the Controller uses to pick a repair strategy.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ErrorCategory(str, Enum):
    DEPENDENCY        = "dependency_conflict"
    BUILD             = "build_error"
    CONTAINER         = "container_unhealthy"
    TEST              = "test_failure"
    TIMEOUT           = "timeout"
    DISK_FULL         = "disk_full"
    PERMISSION        = "permission_denied"
    NETWORK           = "network_failure"
    CONFIG            = "malformed_configuration"
    MISSING_DEP       = "missing_dependency"
    NPM_INSTALL       = "npm_install_failure"
    PHP_FATAL         = "php_fatal_error"
    DB_CONN           = "db_connection_refused"
    PORT_CONFLICT     = "port_conflict"
    UNKNOWN           = "unknown"
    TRANSIENT         = "transient"
    SILENT_FAIL       = "silent_failure"


class ErrorSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class RepairStatus(str, Enum):
    PENDING    = "pending"
    DIAGNOSING = "diagnosing"
    REPAIRING  = "repairing"
    VALIDATED  = "validated"
    FAILED     = "failed"
    SKIPPED    = "skipped"


@dataclass
class ErrorRecord:
    error_id:        str
    stage:           str
    category:        ErrorCategory
    severity:        ErrorSeverity
    fingerprint:     str
    first_seen:      float
    last_seen:       float
    attempts:        int
    root_cause:      str
    hypothesis:      str
    proposed_fix:    str
    fix_applied:     bool
    validation:      str
    status:          RepairStatus
    command:         str = ""
    exit_code:       int = 0
    stdout:          str = ""
    stderr:          str = ""
    file_path:       str = ""
    line_number:     int = 0
    is_transient:    bool = False
    is_cascading:    bool = False
    caused_by:       Optional[str] = None   # error_id of parent error
    stack_trace:     str = ""
    context:         dict = field(default_factory=dict)


# ── Fingerprint ────────────────────────────────────────────────────────────────

def _error_fingerprint(stderr: str, stdout: str, exit_code: int) -> str:
    """Stable hash of the error — strips timestamps, line numbers, paths."""
    text = stderr or stdout or ""
    # Remove timestamps
    text = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,\d]*", "", text)
    # Remove absolute paths (keep relative)
    text = re.sub(r"/[/\w.\-]+/([^/\s]+)", r"\1", text)
    # Remove hex addresses
    text = re.sub(r"0x[0-9a-fA-F]{4,}", "0xADDR", text)
    # Remove specific port numbers
    text = re.sub(r":\d{4,5}(?!\d)", ":PORT", text)
    # Keep only first 1000 chars of normalized text
    text = text[:1000].strip()
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# ── Category classifier ────────────────────────────────────────────────────────

_CATEGORY_PATTERNS = [
    (ErrorCategory.DISK_FULL,      re.compile(r"no space left|disk quota|ENOSPC", re.I)),
    (ErrorCategory.PERMISSION,     re.compile(r"permission denied|EACCES|Operation not permitted", re.I)),
    (ErrorCategory.PORT_CONFLICT,  re.compile(r"address already in use|EADDRINUSE|port.*in use", re.I)),
    (ErrorCategory.TIMEOUT,        re.compile(r"timed? ?out|deadline exceeded|ETIMEDOUT", re.I)),
    (ErrorCategory.NETWORK,        re.compile(r"connection refused|ECONNREFUSED|name resolution|could not resolve", re.I)),
    (ErrorCategory.DB_CONN,        re.compile(r"can'?t connect.*mysql|SQLSTATE|could not connect.*database", re.I)),
    (ErrorCategory.PHP_FATAL,      re.compile(r"PHP Fatal error|Fatal error.*PHP|PHP Parse error", re.I)),
    (ErrorCategory.NPM_INSTALL,    re.compile(r"npm ERR!|yarn.*error|ERESOLVE|peer dep", re.I)),
    (ErrorCategory.MISSING_DEP,    re.compile(r"ModuleNotFoundError|No module named|command not found|not found.*executable", re.I)),
    (ErrorCategory.DEPENDENCY,     re.compile(r"conflict|incompatible.*version|requires.*but.*found|version mismatch", re.I)),
    (ErrorCategory.BUILD,          re.compile(r"error:.*compile|Build FAILED|make.*error|gcc.*error|SyntaxError", re.I)),
    (ErrorCategory.CONFIG,         re.compile(r"invalid config|parse error.*yaml|unexpected.*token.*json|malformed", re.I)),
    (ErrorCategory.CONTAINER,      re.compile(r"OOMKilled|container.*exited|unhealthy|exit code 137", re.I)),
    (ErrorCategory.TEST,           re.compile(r"FAILED.*test|AssertionError|test.*failed|FAIL.*pytest", re.I)),
]

_TRANSIENT_PATTERNS = re.compile(
    r"temporarily unavailable|EAGAIN|try again|503|502|connection reset|broken pipe|EOF", re.I
)

_SILENT_FAIL_INDICATORS = re.compile(
    r"^$|no output|completed successfully.*but no", re.I
)


def classify_error(stderr: str, stdout: str = "", exit_code: int = 1) -> ErrorCategory:
    text = (stderr or "") + " " + (stdout or "")
    for category, pattern in _CATEGORY_PATTERNS:
        if pattern.search(text):
            return category
    if exit_code == 0 and not stdout.strip():
        return ErrorCategory.SILENT_FAIL
    if _TRANSIENT_PATTERNS.search(text):
        return ErrorCategory.TRANSIENT
    return ErrorCategory.UNKNOWN


def _severity_from_category(cat: ErrorCategory) -> ErrorSeverity:
    if cat in (ErrorCategory.DISK_FULL, ErrorCategory.PERMISSION,
               ErrorCategory.PHP_FATAL, ErrorCategory.DB_CONN):
        return ErrorSeverity.CRITICAL
    if cat in (ErrorCategory.BUILD, ErrorCategory.CONTAINER,
               ErrorCategory.MISSING_DEP, ErrorCategory.NPM_INSTALL):
        return ErrorSeverity.HIGH
    if cat in (ErrorCategory.DEPENDENCY, ErrorCategory.CONFIG,
               ErrorCategory.NETWORK, ErrorCategory.TIMEOUT):
        return ErrorSeverity.MEDIUM
    return ErrorSeverity.LOW


# ── Root cause extraction ───────────────────────────────────────────────────────

def _extract_relevant_line(stderr: str, stdout: str = "") -> str:
    """Extract the most informative error line from output."""
    lines = (stderr or "").splitlines() + (stdout or "").splitlines()
    # Priority: lines with "error", "fatal", "exception", "failed", "traceback"
    priority = re.compile(r"error|fatal|exception|failed|traceback|abort|panic", re.I)
    # Skip generic noise
    skip = re.compile(r"^$|^\s*at |^\s*#|npm warn|WARN|DEBUG|INFO:|^\s*$", re.I)
    for line in lines:
        line = line.strip()
        if not line or skip.match(line):
            continue
        if priority.search(line):
            return line[:200]
    # Fallback: last non-empty line
    for line in reversed(lines):
        line = line.strip()
        if line and not skip.match(line):
            return line[:200]
    return ""


def _extract_file_and_line(stderr: str) -> tuple[str, int]:
    """Extract file path and line number from error output."""
    patterns = [
        re.compile(r'File "([^"]+)", line (\d+)'),       # Python
        re.compile(r'at ([^:]+):(\d+):\d+'),              # JS/Node
        re.compile(r'([^\s]+\.php) on line (\d+)'),       # PHP
        re.compile(r'([^\s]+\.[a-z]+):(\d+):'),           # generic
    ]
    for pat in patterns:
        m = pat.search(stderr or "")
        if m:
            return m.group(1), int(m.group(2))
    return "", 0


def _extract_stack_trace(stderr: str) -> str:
    """Extract the stack trace section from stderr."""
    lines = (stderr or "").splitlines()
    in_trace = False
    trace_lines = []
    for line in lines:
        if re.match(r"Traceback|  File |    at |Exception in thread", line):
            in_trace = True
        if in_trace:
            trace_lines.append(line)
            if len(trace_lines) > 30:
                break
    return "\n".join(trace_lines)


# ── Hypothesis generation ───────────────────────────────────────────────────────

_HYPOTHESES: dict[ErrorCategory, list[str]] = {
    ErrorCategory.DEPENDENCY:   [
        "Pin dependency to a known-compatible version",
        "Remove conflicting transitive dependency",
        "Use a virtual environment to isolate versions",
    ],
    ErrorCategory.BUILD:        [
        "Syntax error in recently modified file — review diff",
        "Missing import or undefined symbol",
        "Incompatible compiler/interpreter version",
    ],
    ErrorCategory.CONTAINER:    [
        "Container ran out of memory — increase --memory limit",
        "Container crashed on startup — check CMD / ENTRYPOINT",
        "Port not exposed — verify EXPOSE and -p mapping",
    ],
    ErrorCategory.TEST:         [
        "Regression introduced by recent change — review diff",
        "Test environment state not reset between runs",
        "Assertion expects stale value — data changed",
    ],
    ErrorCategory.TIMEOUT:      [
        "Blocking I/O or deadlock — check for hanging subprocess",
        "Network request to unavailable host",
        "Resource contention — reduce concurrency",
    ],
    ErrorCategory.MISSING_DEP:  [
        "Package not installed in current environment",
        "PATH does not include the binary's directory",
        "Wrong Python/Node environment active",
    ],
    ErrorCategory.NPM_INSTALL:  [
        "Delete node_modules and package-lock.json, reinstall",
        "Switch to npm legacy-peer-deps flag",
        "Use specific npm version matching lock file",
    ],
    ErrorCategory.NETWORK:      [
        "Target service not yet started — wait and retry",
        "DNS resolution failing — check /etc/hosts or VPN",
        "Firewall blocking outbound connection",
    ],
    ErrorCategory.DB_CONN:      [
        "Database container not healthy yet — increase wait time",
        "Wrong host/port in connection string",
        "Missing database initialization step",
    ],
    ErrorCategory.CONFIG:       [
        "YAML/JSON syntax error — validate with linter",
        "Missing required configuration field",
        "Environment variable not set",
    ],
    ErrorCategory.SILENT_FAIL:  [
        "Command exited 0 but produced no output — check stderr",
        "Output redirect suppressed expected content",
        "Process forked and left detached",
    ],
}

_PROPOSED_FIXES: dict[ErrorCategory, str] = {
    ErrorCategory.DEPENDENCY:  "Adjust pinned version in requirements/package.json and reinstall",
    ErrorCategory.BUILD:       "Review the error line, fix syntax or missing import",
    ErrorCategory.CONTAINER:   "Inspect container logs (docker logs), adjust resource limits if OOMKilled",
    ErrorCategory.TEST:        "Review the failing assertion and the diff since last green run",
    ErrorCategory.TIMEOUT:     "Increase timeout threshold or diagnose blocking subprocess",
    ErrorCategory.MISSING_DEP: "Install missing package in the active environment",
    ErrorCategory.NPM_INSTALL: "rm -rf node_modules package-lock.json && npm install --legacy-peer-deps",
    ErrorCategory.NETWORK:     "Wait for service readiness, then retry with exponential backoff",
    ErrorCategory.DB_CONN:     "Wait for DB healthcheck, then retry connection",
    ErrorCategory.CONFIG:      "Validate config file schema and fix malformed field",
    ErrorCategory.SILENT_FAIL: "Re-run with verbose flag and inspect both stdout and stderr",
    ErrorCategory.PHP_FATAL:   "Check PHP version compatibility and syntax of the offending file",
    ErrorCategory.DISK_FULL:   "Free disk space: docker system prune, rm old artifacts",
    ErrorCategory.PERMISSION:  "Check file ownership and chmod/chown as needed",
    ErrorCategory.PORT_CONFLICT: "Kill the process using the port or change the bind port",
    ErrorCategory.TRANSIENT:   "Retry with exponential backoff; transient condition likely resolved",
    ErrorCategory.UNKNOWN:     "Inspect full stderr/stdout and classify manually",
}


# ── Main entry point ────────────────────────────────────────────────────────────

_error_counter = 0


def analyze_error(
    stage: str,
    stderr: str,
    stdout: str = "",
    exit_code: int = 1,
    command: str = "",
    attempts: int = 1,
    caused_by: Optional[str] = None,
    context: Optional[dict] = None,
) -> ErrorRecord:
    global _error_counter
    _error_counter += 1

    stderr_trunc = (stderr or "")[-8000:]
    stdout_trunc = (stdout or "")[-4000:]

    category  = classify_error(stderr_trunc, stdout_trunc, exit_code)
    severity  = _severity_from_category(category)
    fp        = _error_fingerprint(stderr_trunc, stdout_trunc, exit_code)
    root_line = _extract_relevant_line(stderr_trunc, stdout_trunc)
    file_path, line_no = _extract_file_and_line(stderr_trunc)
    stack     = _extract_stack_trace(stderr_trunc)
    hyps      = _HYPOTHESES.get(category, ["Inspect full error output"])
    hypothesis = "; ".join(hyps[:2])
    proposed  = _PROPOSED_FIXES.get(category, "Inspect full error output")
    is_transient = category == ErrorCategory.TRANSIENT or bool(
        _TRANSIENT_PATTERNS.search(stderr_trunc)
    )

    now = time.time()
    return ErrorRecord(
        error_id      = f"ERR-{_error_counter:04d}-{fp[:8]}",
        stage         = stage,
        category      = category,
        severity      = severity,
        fingerprint   = fp,
        first_seen    = now,
        last_seen     = now,
        attempts      = attempts,
        root_cause    = root_line or category.value,
        hypothesis    = hypothesis,
        proposed_fix  = proposed,
        fix_applied   = False,
        validation    = RepairStatus.PENDING.value,
        status        = RepairStatus.DIAGNOSING,
        command       = command[:300],
        exit_code     = exit_code,
        stdout        = stdout_trunc[:2000],
        stderr        = stderr_trunc[:4000],
        file_path     = file_path,
        line_number   = line_no,
        is_transient  = is_transient,
        is_cascading  = caused_by is not None,
        caused_by     = caused_by,
        stack_trace   = stack,
        context       = context or {},
    )


def error_to_dict(r: ErrorRecord) -> dict:
    return {
        "error_id":    r.error_id,
        "stage":       r.stage,
        "category":    r.category.value,
        "severity":    r.severity.value,
        "fingerprint": r.fingerprint,
        "first_seen":  r.first_seen,
        "last_seen":   r.last_seen,
        "attempts":    r.attempts,
        "root_cause":  r.root_cause,
        "hypothesis":  r.hypothesis,
        "proposed_fix":r.proposed_fix,
        "fix_applied": r.fix_applied,
        "validation":  r.validation,
        "status":      r.status.value,
        "command":     r.command,
        "exit_code":   r.exit_code,
        "stdout":      r.stdout,
        "stderr":      r.stderr,
        "file_path":   r.file_path,
        "line_number": r.line_number,
        "is_transient":r.is_transient,
        "is_cascading":r.is_cascading,
        "caused_by":   r.caused_by,
        "stack_trace": r.stack_trace,
        "context":     r.context,
    }


def render_error_summary(r: ErrorRecord) -> str:
    lines = [
        f"[{r.severity.value.upper()}] {r.error_id} — {r.stage}",
        f"  category:   {r.category.value}",
        f"  root_cause: {r.root_cause}",
        f"  hypothesis: {r.hypothesis}",
        f"  fix:        {r.proposed_fix}",
    ]
    if r.file_path:
        lines.append(f"  location:   {r.file_path}:{r.line_number}")
    if r.is_transient:
        lines.append("  [transient — safe to retry]")
    if r.is_cascading:
        lines.append(f"  [cascading from {r.caused_by}]")
    return "\n".join(lines)
