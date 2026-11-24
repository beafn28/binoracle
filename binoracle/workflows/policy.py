"""
Policy — runtime permissions and limits for the autonomous agent.

The controller checks this before every action. The LLM can PROPOSE an action,
but the controller only EXECUTES actions that pass policy checks.

Nothing in this file communicates with the LLM. It is a pure rule engine.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ── Action types the agent can propose ─────────────────────────────────────────

ALLOWED_ACTIONS = {
    "edit_file",         # modify a file inside the workspace
    "run_command",       # run a shell command from the allowlist
    "docker_restart",    # restart a container
    "docker_stop",       # stop and remove a container
    "pip_install",       # install a Python package
    "npm_install",       # run npm install
    "git_stash",         # git stash (save state before repair)
    "git_checkout",      # git checkout a specific file (rollback one file)
    "wait",              # pause and retry
}

FORBIDDEN_ACTIONS = {
    "delete_project",    # never delete the whole project
    "git_reset_hard",    # never force-reset without explicit user request
    "git_push_force",    # never force-push
    "disable_tests",     # never disable test suite
    "modify_gitconfig",  # never touch git config
    "access_secrets",    # never read .env / credentials
    "rm_rf",             # never rm -rf outside tmp dirs
    "curl_external",     # no arbitrary outbound HTTP from repair actions
}

# Commands that the repair agent is explicitly allowed to run
_ALLOWED_COMMANDS = re.compile(
    r"^("
    r"python[23]? -m pytest|"
    r"python[23]? -m pip install|"
    r"npm (install|test|run)|"
    r"yarn (install|test)|"
    r"composer install|"
    r"phpunit|"
    r"docker (logs|restart|stop|rm|ps|inspect)|"
    r"git (status|diff|stash|log|show|checkout -- )|"
    r"pip[23]? install|"
    r"which |"
    r"ls |cat |head |tail |grep |find \."
    r")",
    re.I,
)

# Commands that are always blocked regardless of context
_FORBIDDEN_COMMAND_PATTERNS = re.compile(
    r"rm\s+-rf\s+[^/]|"           # rm -rf on project dirs
    r"git\s+reset\s+--hard|"
    r"git\s+push\s+--force|"
    r"git\s+config|"
    r"curl\s+https?://|"           # no outbound HTTP from repair
    r"wget\s+https?://|"
    r"sudo\s+(rm|chmod|chown)|"
    r"DROP\s+(TABLE|DATABASE)|"
    r"TRUNCATE\s+TABLE",
    re.I,
)


@dataclass
class PolicyResult:
    allowed:  bool
    action:   str
    reason:   str = ""
    warnings: List[str] = field(default_factory=list)


def check_action(action: str, params: Optional[dict] = None) -> PolicyResult:
    """
    Check whether an action proposed by the agent is permitted.
    Returns a PolicyResult with allowed=True/False and reasoning.
    """
    params = params or {}

    if action in FORBIDDEN_ACTIONS:
        return PolicyResult(
            allowed=False, action=action,
            reason=f"Action '{action}' is in the FORBIDDEN_ACTIONS list.",
        )

    if action not in ALLOWED_ACTIONS:
        return PolicyResult(
            allowed=False, action=action,
            reason=f"Action '{action}' is not in ALLOWED_ACTIONS.",
        )

    # Extra checks per action type
    if action == "run_command":
        cmd = params.get("command", "")
        return _check_command(cmd, action)

    if action == "edit_file":
        return _check_file_edit(params, action)

    if action in ("git_reset_hard", "rm_rf"):
        return PolicyResult(
            allowed=False, action=action,
            reason="Destructive git/fs operations require explicit user approval.",
        )

    return PolicyResult(allowed=True, action=action, reason="OK")


def _check_command(cmd: str, action: str) -> PolicyResult:
    if _FORBIDDEN_COMMAND_PATTERNS.search(cmd):
        return PolicyResult(
            allowed=False, action=action,
            reason=f"Command matches a forbidden pattern: {cmd[:80]}",
        )
    if not _ALLOWED_COMMANDS.match(cmd.strip()):
        return PolicyResult(
            allowed=False, action=action,
            reason=f"Command not in allowlist: {cmd[:80]}",
            warnings=["Only explicitly allowed commands may be executed autonomously."],
        )
    return PolicyResult(allowed=True, action=action, reason="command allowed")


def _check_file_edit(params: dict, action: str) -> PolicyResult:
    path = params.get("path", "")
    # Block editing sensitive files
    blocked_patterns = [
        r"\.env$", r"\.env\.", r"credentials", r"secrets?",
        r"\.gitconfig", r"id_rsa", r"\.ssh/", r"\.gnupg/",
        r"\.netrc",
    ]
    for pat in blocked_patterns:
        if re.search(pat, path, re.I):
            return PolicyResult(
                allowed=False, action=action,
                reason=f"Editing sensitive file blocked: {path}",
            )
    # Warn if editing outside src/tests
    warnings = []
    if not re.search(r"(src|tests?|lib|app|binoracle)/", path):
        warnings.append(f"File {path} is outside typical source directories — verify intent.")
    return PolicyResult(allowed=True, action=action, reason="file edit allowed", warnings=warnings)


def validate_llm_proposal(proposal: dict) -> PolicyResult:
    """
    Validate a structured JSON proposal from the LLM before execution.

    Expected proposal format:
    {
        "diagnosis": str,
        "confidence": float (0-1),
        "error_category": str,
        "proposed_action": str,
        "files_to_modify": [str],
        "validation_required": bool,
        "expected_result": str
    }
    """
    # Required fields
    for field_name in ("diagnosis", "proposed_action"):
        if not proposal.get(field_name):
            return PolicyResult(
                allowed=False, action=proposal.get("proposed_action", "unknown"),
                reason=f"Missing required field: {field_name}",
            )

    confidence = proposal.get("confidence", 0)
    if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
        return PolicyResult(
            allowed=False, action=proposal.get("proposed_action", "unknown"),
            reason="Invalid confidence value (must be 0–1)",
        )

    # Files must be listed and within workspace
    files = proposal.get("files_to_modify", [])
    if not isinstance(files, list):
        return PolicyResult(
            allowed=False, action=proposal.get("proposed_action", "unknown"),
            reason="files_to_modify must be a list",
        )

    # Check each file edit
    for f in files:
        pr = _check_file_edit({"path": f}, "edit_file")
        if not pr.allowed:
            return pr

    # Check the action itself
    return check_action(proposal["proposed_action"], proposal)


def resource_limits() -> dict:
    """Return configured resource limits from environment."""
    return {
        "max_total_iterations":  int(os.environ.get("BINORACLE_MAX_ITERS",    "10")),
        "max_attempts_per_error":int(os.environ.get("BINORACLE_MAX_ATTEMPTS", "3")),
        "max_strategy_switches": int(os.environ.get("BINORACLE_MAX_STRAT",    "4")),
        "phase_timeout_s":       int(os.environ.get("BINORACLE_PHASE_TIMEOUT","300")),
        "max_containers":        int(os.environ.get("BINORACLE_MAX_CONTAINERS","3")),
        "max_log_bytes":         int(os.environ.get("BINORACLE_MAX_LOG_BYTES","1048576")),  # 1 MB
        "workspace_max_files":   int(os.environ.get("BINORACLE_MAX_FILES",    "2000")),
    }
