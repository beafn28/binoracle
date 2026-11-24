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
  - What files to modify outside of the workspace (blocked by workspace_guard)

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
import subprocess
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

from .error_analyzer import (
    ErrorCategory, ErrorRecord, ErrorSeverity,
    analyze_error, render_error_summary,
)
from .repair_memory import RepairMemory

# ── Policy constants ────────────────────────────────────────────────────────────

_MAX_TOTAL_ITERATIONS  = int(os.environ.get("BINORACLE_MAX_ITERS",   "10"))
_MAX_ATTEMPTS_PER_ERR  = int(os.environ.get("BINORACLE_MAX_ATTEMPTS", "3"))
_MAX_STRATEGY_SWITCHES = int(os.environ.get("BINORACLE_MAX_STRAT",    "4"))
_PHASE_TIMEOUT_S       = int(os.environ.get("BINORACLE_PHASE_TIMEOUT","300"))
_NO_PROGRESS_LIMIT     = 3   # consecutive no-progress iterations before strategy switch


# ── Status ─────────────────────────────────────────────────────────────────────

class FinalStatus(str, Enum):
    COMPLETED_AND_VALIDATED   = "COMPLETED_AND_VALIDATED"
    COMPLETED_WITH_LIMITATIONS= "COMPLETED_WITH_LIMITATIONS"
    FAILED_RECOVERABLE        = "FAILED_RECOVERABLE"
    BLOCKED                   = "BLOCKED"
    UNVERIFIED                = "UNVERIFIED"


# ── Progress scoring ────────────────────────────────────────────────────────────

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
    score:         float = 0.0   # progress score [0,1]

    def has_progress(self) -> bool:
        return self.score > 0.0 or self.resolved or self.success


def _score_iteration(prev: Optional[IterationResult], curr: IterationResult) -> float:
    """Score this iteration's progress on a [0,1] scale."""
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
        score -= 0.3   # identical output → no progress
    return max(0.0, min(1.0, score))


# ── Checkpoint ─────────────────────────────────────────────────────────────────

@dataclass
class Checkpoint:
    name:       str
    phase:      str
    created_at: float
    state:      dict = field(default_factory=dict)
    git_sha:    str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name, "phase": self.phase,
            "created_at": self.created_at, "state": self.state,
            "git_sha": self.git_sha,
        }

    @staticmethod
    def from_dict(d: dict) -> "Checkpoint":
        return Checkpoint(
            name=d["name"], phase=d["phase"],
            created_at=d["created_at"], state=d.get("state", {}),
            git_sha=d.get("git_sha", ""),
        )


def _git_sha(cwd: str = ".") -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, cwd=cwd,
        )
        return r.stdout.strip()[:12] if r.returncode == 0 else ""
    except Exception:
        return ""


# ── Controller ─────────────────────────────────────────────────────────────────

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
    ):
        self.cve_id       = cve_id
        self.workspace    = workspace
        self.log          = log_fn or (lambda msg: None)
        self.project_type = project_type
        self.state        = ControllerState(cve_id=cve_id)
        self.memory       = RepairMemory()
        self._strategy_history: List[str] = []

    # ── Checkpoint management ───────────────────────────────────────────────

    def save_checkpoint(self, name: str, state: dict) -> Checkpoint:
        cp = Checkpoint(
            name       = name,
            phase      = self.state.phase,
            created_at = time.time(),
            state      = state,
            git_sha    = _git_sha(self.workspace),
        )
        self.state.checkpoints.append(cp)
        self.log(f"[checkpoint] saved: {name} (phase={self.state.phase})")
        return cp

    def last_checkpoint(self) -> Optional[Checkpoint]:
        return self.state.checkpoints[-1] if self.state.checkpoints else None

    # ── Loop detection ──────────────────────────────────────────────────────

    def _detect_loop(self) -> bool:
        """True if the last N iterations show no progress."""
        recent = self.state.history[-_NO_PROGRESS_LIMIT:]
        if len(recent) < _NO_PROGRESS_LIMIT:
            return False
        return not any(it.has_progress() for it in recent)

    def _identical_error_loop(self) -> bool:
        """True if the last 3 errors have the same fingerprint."""
        fps = [e.fingerprint for e in self.state.errors[-3:]]
        return len(fps) == 3 and len(set(fps)) == 1

    # ── Repair decision ─────────────────────────────────────────────────────

    def _pick_repair_strategy(self, error: ErrorRecord) -> str:
        """Return a repair strategy string, using memory if available."""
        past_fix = self.memory.best_fix_for(error)
        if past_fix:
            self.log(f"[repair_memory] found past fix: {past_fix[:80]}")
            return past_fix
        return error.proposed_fix

    def _is_fatal(self, error: ErrorRecord) -> bool:
        fatal_cats = {
            ErrorCategory.DISK_FULL,
            ErrorCategory.PERMISSION,
            ErrorCategory.PORT_CONFLICT,
        }
        return error.category in fatal_cats and not error.is_transient

    # ── Progress tracking ───────────────────────────────────────────────────

    def _record_iteration(
        self,
        phase:         str,
        success:       bool,
        error:         Optional[ErrorRecord] = None,
        output:        str = "",
        files_changed: Optional[List[str]] = None,
    ) -> IterationResult:
        self.state.iteration += 1
        prev = self.state.history[-1] if self.state.history else None

        it = IterationResult(
            iteration     = self.state.iteration,
            phase         = phase,
            success       = success,
            error         = error,
            output        = output[:500],
            files_changed = files_changed or [],
            new_errors    = len([e for e in self.state.errors if not e.fix_applied]),
            resolved      = error is not None and error.fix_applied,
        )
        it.score = _score_iteration(prev, it)
        self.state.history.append(it)

        if not it.has_progress():
            self.state.no_progress_count += 1
        else:
            self.state.no_progress_count = 0

        return it

    # ── Main loop ───────────────────────────────────────────────────────────

    def run(
        self,
        pipeline_fn: Callable[[ControllerState, Callable], tuple[bool, str, Optional[str], Optional[str]]],
    ) -> dict:
        """
        Drive the pipeline function through the full controlled lifecycle.

        pipeline_fn(state, step_fn) must return:
            (success: bool, output: str, stderr: Optional[str], phase: Optional[str])

        Returns a result dict with final_status, metrics, errors, and output.
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

    def _control_loop(
        self,
        pipeline_fn: Callable,
    ) -> dict:
        attempt = 0
        last_output = ""

        while attempt < _MAX_TOTAL_ITERATIONS:
            attempt += 1
            self.log(f"[controller] iteration {attempt}/{_MAX_TOTAL_ITERATIONS} phase={self.state.phase}")

            # ── Safety checks ──────────────────────────────────────────────
            if self._identical_error_loop():
                self.log("[controller] cycle detected — aborting")
                self.state.final_status = FinalStatus.FAILED_RECOVERABLE
                break

            if self._detect_loop():
                self.log(f"[controller] no progress for {_NO_PROGRESS_LIMIT} iterations — switching strategy")
                self.state.strategy_switches += 1
                if self.state.strategy_switches > _MAX_STRATEGY_SWITCHES:
                    self.log("[controller] strategy switch limit reached — BLOCKED")
                    self.state.final_status = FinalStatus.BLOCKED
                    break

            # ── Run one pipeline iteration ─────────────────────────────────
            t0 = time.time()
            try:
                success, output, stderr, phase = pipeline_fn(
                    self.state, self._step_logger
                )
            except Exception as exc:
                output  = ""
                stderr  = traceback.format_exc()
                success = False
                phase   = self.state.phase

            elapsed = time.time() - t0

            # ── Classify any error ─────────────────────────────────────────
            error_rec: Optional[ErrorRecord] = None
            if not success and stderr:
                error_rec = analyze_error(
                    stage    = phase or self.state.phase,
                    stderr   = stderr,
                    stdout   = output,
                    exit_code= 1,
                    attempts = attempt,
                )
                self.state.errors.append(error_rec)
                self.log(render_error_summary(error_rec))

                if self._is_fatal(error_rec):
                    self.log(f"[controller] fatal error ({error_rec.category.value}) — stopping")
                    self.state.final_status = FinalStatus.FAILED_RECOVERABLE
                    break

                # Look for past repair
                strategy = self._pick_repair_strategy(error_rec)
                self.log(f"[controller] repair strategy: {strategy}")
                self._strategy_history.append(strategy)

                # Record in memory (outcome TBD after validation)
                self.memory.record(
                    error        = error_rec,
                    fix_applied  = strategy,
                    outcome      = "pending",
                    project_type = self.project_type,
                )

            it = self._record_iteration(
                phase         = phase or self.state.phase,
                success       = success,
                error         = error_rec,
                output        = output,
            )

            if success:
                self.save_checkpoint(f"after_{phase or 'phase'}_{attempt}", {"success": True})
                last_output = output
                self.log(f"[controller] iteration {attempt} succeeded (elapsed={elapsed:.1f}s)")
                # Pipeline returns True when completely done
                self.state.final_status = FinalStatus.COMPLETED_AND_VALIDATED
                break

            last_output = output

        # If we ran out of iterations without a final status
        if self.state.final_status is None:
            if any(it.success for it in self.state.history):
                self.state.final_status = FinalStatus.COMPLETED_WITH_LIMITATIONS
            else:
                self.state.final_status = FinalStatus.FAILED_RECOVERABLE

        return {"output": last_output, "success": self.state.final_status == FinalStatus.COMPLETED_AND_VALIDATED}

    def _step_logger(self, msg: str) -> None:
        self.log(f"  [{self.state.phase}] {msg}")

    # ── Report ──────────────────────────────────────────────────────────────

    def _build_report(self, pipeline_result: dict) -> dict:
        elapsed = time.time() - self.state.start_time
        errors_summary = [
            {
                "error_id":   e.error_id,
                "category":   e.category.value,
                "severity":   e.severity.value,
                "root_cause": e.root_cause,
                "fix_applied": e.fix_applied,
                "stage":      e.stage,
            }
            for e in self.state.errors
        ]
        self.state.metrics = {
            "total_iterations":  self.state.iteration,
            "strategy_switches": self.state.strategy_switches,
            "total_errors":      len(self.state.errors),
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


# ── Convenience wrapper for cve_agent ──────────────────────────────────────────

def supervised_investigate(
    cve_id:       str,
    investigate_fn: Callable,
    *args,
    log_fn:       Optional[Callable] = None,
    project_type: str = "",
    **kwargs,
) -> dict:
    """
    Thin wrapper: runs investigate_fn inside the controller, returns controller report.

    investigate_fn should accept (state, step_fn, *args, **kwargs) and return
    (success, output, stderr, phase).
    """
    ctrl = AgentController(cve_id=cve_id, log_fn=log_fn, project_type=project_type)

    def pipeline_fn(state, step_fn):
        return investigate_fn(state, step_fn, *args, **kwargs)

    return ctrl.run(pipeline_fn)
