"""
CVE investigation state machine with SQLite persistence.

Provides resumable job tracking so investigations survive crashes, process kills,
and container restarts. Each CVE goes through these states:

  queued → research → setup → reproduce → analyze → patch → validate → report → done
                                                                              ↓
                                                                           failed (terminal)

Usage:
    from .cve_state import CveStateDB, JobState, JobRecord

    db = CveStateDB()
    db.enqueue("CVE-2026-1234", priority=10)

    # pick next job
    job = db.next_job()
    if job:
        db.transition(job.cve_id, JobState.RESEARCH)
        # ... do work ...
        db.set_evidence(job.cve_id, {"technique": "sqli", "confidence": "confirmed"})
        db.transition(job.cve_id, JobState.DONE)
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_DB_PATH = os.environ.get(
    "BINORACLE_STATE_DB",
    os.path.join(os.path.expanduser("~"), ".binoracle", "cve_state.db"),
)


class JobState(str, Enum):
    QUEUED      = "queued"
    RESEARCH    = "research"
    SETUP       = "setup"
    REPRODUCE   = "reproduce"
    ANALYZE     = "analyze"
    PATCH       = "patch"
    VALIDATE    = "validate"
    REPORT      = "report"
    DONE        = "done"
    FAILED      = "failed"
    BLOCKED     = "blocked"


# Valid forward transitions (backward via backtrack_to only)
_TRANSITIONS = {
    JobState.QUEUED:    {JobState.RESEARCH},
    JobState.RESEARCH:  {JobState.SETUP, JobState.FAILED, JobState.BLOCKED},
    JobState.SETUP:     {JobState.REPRODUCE, JobState.FAILED, JobState.BLOCKED},
    JobState.REPRODUCE: {JobState.ANALYZE, JobState.FAILED, JobState.BLOCKED},
    JobState.ANALYZE:   {JobState.PATCH, JobState.REPORT, JobState.FAILED, JobState.BLOCKED},
    JobState.PATCH:     {JobState.VALIDATE, JobState.FAILED},
    JobState.VALIDATE:  {JobState.REPORT, JobState.PATCH, JobState.FAILED},
    JobState.REPORT:    {JobState.DONE, JobState.FAILED},
    JobState.DONE:      set(),
    JobState.FAILED:    {JobState.QUEUED},  # allow re-queue
    JobState.BLOCKED:   {JobState.QUEUED},
}

_MAX_RETRIES_PER_PHASE = 5
_RETRY_BACKOFF_BASE    = 30.0   # seconds


@dataclass
class JobRecord:
    cve_id:        str
    state:         str = JobState.QUEUED
    priority:      int = 5
    attempts:      int = 0
    retry_after:   float = 0.0
    created_at:    float = field(default_factory=time.time)
    updated_at:    float = field(default_factory=time.time)
    evidence:      dict  = field(default_factory=dict)
    error_history: list  = field(default_factory=list)
    checkpoints:   dict  = field(default_factory=dict)
    phase_attempts: dict = field(default_factory=dict)


class CveStateDB:
    """Thread-safe SQLite-backed state store for CVE investigations."""

    def __init__(self, path: str = _DB_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    cve_id        TEXT PRIMARY KEY,
                    state         TEXT NOT NULL DEFAULT 'queued',
                    priority      INTEGER NOT NULL DEFAULT 5,
                    attempts      INTEGER NOT NULL DEFAULT 0,
                    retry_after   REAL NOT NULL DEFAULT 0,
                    created_at    REAL NOT NULL,
                    updated_at    REAL NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    error_history_json TEXT NOT NULL DEFAULT '[]',
                    checkpoints_json   TEXT NOT NULL DEFAULT '{}',
                    phase_attempts_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_jobs_state_priority
                ON jobs(state, priority DESC, retry_after)
            """)

    # ── CRUD ────────────────────────────────────────────────────────────────

    def enqueue(self, cve_id: str, priority: int = 5, force: bool = False) -> bool:
        """Add a CVE to the queue. Returns False if it already exists (unless force=True)."""
        now = time.time()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT state FROM jobs WHERE cve_id=?", (cve_id,)).fetchone()
            if existing and not force:
                return False
            conn.execute("""
                INSERT OR REPLACE INTO jobs
                  (cve_id, state, priority, attempts, retry_after, created_at, updated_at,
                   evidence_json, error_history_json, checkpoints_json, phase_attempts_json)
                VALUES (?, 'queued', ?, 0, 0, ?, ?, '{}', '[]', '{}', '{}')
            """, (cve_id, priority, now, now))
        return True

    def next_job(self) -> Optional[JobRecord]:
        """Return the highest-priority queued job that is ready to run."""
        now = time.time()
        with self._connect() as conn:
            row = conn.execute("""
                SELECT * FROM jobs
                WHERE state='queued' AND retry_after <= ?
                ORDER BY priority DESC, created_at ASC
                LIMIT 1
            """, (now,)).fetchone()
            return self._row_to_record(row) if row else None

    def get(self, cve_id: str) -> Optional[JobRecord]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE cve_id=?", (cve_id,)).fetchone()
            return self._row_to_record(row) if row else None

    def list_jobs(self, state: Optional[str] = None, limit: int = 100) -> list:
        with self._connect() as conn:
            if state:
                rows = conn.execute(
                    "SELECT * FROM jobs WHERE state=? ORDER BY priority DESC LIMIT ?",
                    (state, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM jobs ORDER BY priority DESC, updated_at DESC LIMIT ?",
                    (limit,)).fetchall()
            return [self._row_to_record(r) for r in rows]

    # ── State transitions ───────────────────────────────────────────────────

    def transition(self, cve_id: str, new_state: JobState, detail: str = "") -> bool:
        """Move a job to new_state. Returns False if the transition is invalid."""
        job = self.get(cve_id)
        if not job:
            return False
        cur = JobState(job.state)
        if new_state not in _TRANSITIONS.get(cur, set()):
            return False
        now = time.time()
        phase_attempts = dict(job.phase_attempts)
        phase_attempts[new_state] = phase_attempts.get(new_state, 0) + 1
        with self._connect() as conn:
            conn.execute("""
                UPDATE jobs SET state=?, updated_at=?, phase_attempts_json=?
                WHERE cve_id=?
            """, (new_state, now, json.dumps(phase_attempts), cve_id))
        return True

    def backtrack_to(self, cve_id: str, checkpoint_phase: str) -> bool:
        """Roll back to a previous checkpoint phase (e.g., after patch validation fails)."""
        job = self.get(cve_id)
        if not job:
            return False
        checkpoint = job.checkpoints.get(checkpoint_phase)
        if checkpoint is None:
            return False
        now = time.time()
        with self._connect() as conn:
            conn.execute("""
                UPDATE jobs SET state=?, evidence_json=?, updated_at=?
                WHERE cve_id=?
            """, (checkpoint_phase, json.dumps(checkpoint), now, cve_id))
        return True

    def fail_with_retry(self, cve_id: str, error: str, phase: str = "") -> bool:
        """Record an error; re-queue with backoff if under retry limit, else mark FAILED."""
        job = self.get(cve_id)
        if not job:
            return False
        now = time.time()
        history = list(job.error_history)
        history.append({"t": now, "phase": phase, "error": error[:500]})
        # Cycle detection: if the last 3 errors are identical, treat as stuck
        recent = [h["error"] for h in history[-3:]]
        is_cycle = len(recent) == 3 and len(set(recent)) == 1
        pa = dict(job.phase_attempts)
        phase_count = pa.get(phase, 0)
        if is_cycle or phase_count >= _MAX_RETRIES_PER_PHASE:
            new_state = "failed"
            retry_after = 0.0
        else:
            new_state = "queued"
            backoff = _RETRY_BACKOFF_BASE * (2 ** min(job.attempts, 5))
            retry_after = now + backoff
        with self._connect() as conn:
            conn.execute("""
                UPDATE jobs
                SET state=?, attempts=attempts+1, retry_after=?,
                    error_history_json=?, updated_at=?
                WHERE cve_id=?
            """, (new_state, retry_after, json.dumps(history), now, cve_id))
        return new_state == "queued"

    # ── Evidence & checkpoints ──────────────────────────────────────────────

    def set_evidence(self, cve_id: str, evidence: dict) -> None:
        """Merge evidence dict into the job's evidence store."""
        job = self.get(cve_id)
        if not job:
            return
        merged = {**job.evidence, **evidence}
        now = time.time()
        with self._connect() as conn:
            conn.execute("""
                UPDATE jobs SET evidence_json=?, updated_at=? WHERE cve_id=?
            """, (json.dumps(merged), now, cve_id))

    def save_checkpoint(self, cve_id: str, phase: str, snapshot: dict) -> None:
        """Snapshot the current evidence so backtrack_to(phase) can restore it."""
        job = self.get(cve_id)
        if not job:
            return
        checkpoints = {**job.checkpoints, phase: snapshot}
        now = time.time()
        with self._connect() as conn:
            conn.execute("""
                UPDATE jobs SET checkpoints_json=?, updated_at=? WHERE cve_id=?
            """, (json.dumps(checkpoints), now, cve_id))

    def duplicate_check(self, cve_id: str) -> Optional[str]:
        """Return existing state if CVE was already processed, else None."""
        job = self.get(cve_id)
        if job and job.state in (JobState.DONE, JobState.REPORT):
            return job.state
        return None

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> JobRecord:
        return JobRecord(
            cve_id=row["cve_id"],
            state=row["state"],
            priority=row["priority"],
            attempts=row["attempts"],
            retry_after=row["retry_after"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            evidence=json.loads(row["evidence_json"] or "{}"),
            error_history=json.loads(row["error_history_json"] or "[]"),
            checkpoints=json.loads(row["checkpoints_json"] or "{}"),
            phase_attempts=json.loads(row["phase_attempts_json"] or "{}"),
        )

    # ── Stats ────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT state, COUNT(*) as n FROM jobs GROUP BY state
            """).fetchall()
            return {r["state"]: r["n"] for r in rows}
