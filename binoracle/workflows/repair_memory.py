"""
Repair Memory — persistent SQLite store of error patterns and their outcomes.

Before investigating any new error the controller queries this DB for similar past
cases. Solutions that worked are promoted as first-hypothesis; failed solutions are
deprioritized so the system does not loop on a known-bad strategy.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import List, Optional

from .error_analyzer import ErrorCategory, ErrorRecord, error_to_dict

_DEFAULT_DB = os.environ.get(
    "BINORACLE_REPAIR_DB",
    os.path.expanduser("~/.binoracle/repair_memory.db"),
)

_SIMILARITY_THRESHOLD = 0.60   # min score to consider a past case relevant


@dataclass
class RepairCase:
    case_id:        str
    fingerprint:    str
    category:       str
    stage:          str
    root_cause:     str
    stack_excerpt:  str
    fix_applied:    str    # text description of what was done
    fix_diff:       str    # unified diff if available
    outcome:        str    # "success" | "failure" | "partial"
    attempts:       int
    project_type:   str
    language:       str
    os_name:        str
    created_at:     float
    validated_at:   float = 0.0
    times_used:     int = 0
    times_succeeded: int = 0
    tags:           List[str] = field(default_factory=list)
    context:        dict = field(default_factory=dict)


class RepairMemory:
    """Thread-safe SQLite-backed store for repair cases."""

    def __init__(self, db_path: str = _DEFAULT_DB):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS repair_cases (
                    case_id         TEXT PRIMARY KEY,
                    fingerprint     TEXT NOT NULL,
                    category        TEXT NOT NULL,
                    stage           TEXT NOT NULL,
                    root_cause      TEXT NOT NULL,
                    stack_excerpt   TEXT DEFAULT '',
                    fix_applied     TEXT NOT NULL,
                    fix_diff        TEXT DEFAULT '',
                    outcome         TEXT NOT NULL,
                    attempts        INTEGER DEFAULT 1,
                    project_type    TEXT DEFAULT '',
                    language        TEXT DEFAULT '',
                    os_name         TEXT DEFAULT '',
                    created_at      REAL NOT NULL,
                    validated_at    REAL DEFAULT 0.0,
                    times_used      INTEGER DEFAULT 0,
                    times_succeeded INTEGER DEFAULT 0,
                    tags            TEXT DEFAULT '[]',
                    context         TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_fp   ON repair_cases(fingerprint);
                CREATE INDEX IF NOT EXISTS idx_cat  ON repair_cases(category, outcome);
                CREATE INDEX IF NOT EXISTS idx_succ ON repair_cases(times_succeeded DESC);
            """)

    # ── Write ────────────────────────────────────────────────────────────────

    def record(
        self,
        error:        ErrorRecord,
        fix_applied:  str,
        outcome:      str,
        fix_diff:     str = "",
        project_type: str = "",
        language:     str = "",
        tags:         Optional[List[str]] = None,
    ) -> str:
        import uuid
        case_id = f"RC-{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO repair_cases
                    (case_id, fingerprint, category, stage, root_cause, stack_excerpt,
                     fix_applied, fix_diff, outcome, attempts, project_type, language,
                     os_name, created_at, tags, context)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                case_id,
                error.fingerprint,
                error.category.value,
                error.stage,
                error.root_cause[:300],
                error.stack_trace[:800],
                fix_applied[:500],
                fix_diff[:4000],
                outcome,
                error.attempts,
                project_type,
                language,
                os.uname().sysname if hasattr(os, "uname") else "",
                now,
                json.dumps(tags or []),
                json.dumps(error.context),
            ))
        return case_id

    def mark_validated(self, case_id: str, outcome: str) -> None:
        with self._conn() as conn:
            conn.execute("""
                UPDATE repair_cases
                   SET outcome = ?, validated_at = ?, times_used = times_used + 1,
                       times_succeeded = times_succeeded + ?
                 WHERE case_id = ?
            """, (outcome, time.time(), 1 if outcome == "success" else 0, case_id))

    # ── Query ────────────────────────────────────────────────────────────────

    def _similarity(self, fp_a: str, fp_b: str, cat_a: str, cat_b: str) -> float:
        """Simple similarity: exact fingerprint = 1.0, same category = 0.6."""
        if fp_a == fp_b:
            return 1.0
        if cat_a == cat_b:
            return 0.6
        return 0.0

    def find_similar(
        self,
        error:         ErrorRecord,
        project_type:  str = "",
        limit:         int = 5,
    ) -> List[RepairCase]:
        """Return past repair cases relevant to this error, best first."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM repair_cases
                 WHERE category = ?
                 ORDER BY times_succeeded DESC, created_at DESC
                 LIMIT 30
            """, (error.category.value,)).fetchall()

        cases = []
        for row in rows:
            score = self._similarity(
                error.fingerprint, row["fingerprint"],
                error.category.value, row["category"],
            )
            # Boost by success rate
            if row["times_used"] > 0:
                score += 0.2 * (row["times_succeeded"] / row["times_used"])
            # Boost for same project type
            if project_type and row["project_type"] == project_type:
                score += 0.1
            if score >= _SIMILARITY_THRESHOLD:
                cases.append((score, RepairCase(
                    case_id        = row["case_id"],
                    fingerprint    = row["fingerprint"],
                    category       = row["category"],
                    stage          = row["stage"],
                    root_cause     = row["root_cause"],
                    stack_excerpt  = row["stack_excerpt"],
                    fix_applied    = row["fix_applied"],
                    fix_diff       = row["fix_diff"],
                    outcome        = row["outcome"],
                    attempts       = row["attempts"],
                    project_type   = row["project_type"],
                    language       = row["language"],
                    os_name        = row["os_name"],
                    created_at     = row["created_at"],
                    validated_at   = row["validated_at"],
                    times_used     = row["times_used"],
                    times_succeeded= row["times_succeeded"],
                    tags           = json.loads(row["tags"] or "[]"),
                    context        = json.loads(row["context"] or "{}"),
                )))

        cases.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in cases[:limit]]

    def best_fix_for(self, error: ErrorRecord) -> Optional[str]:
        """Return the fix text with the highest success rate for this error category."""
        cases = self.find_similar(error, limit=3)
        successful = [c for c in cases if c.outcome == "success"]
        if successful:
            return successful[0].fix_applied
        if cases:
            return cases[0].fix_applied
        return None

    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM repair_cases").fetchone()[0]
            succ  = conn.execute("SELECT COUNT(*) FROM repair_cases WHERE outcome='success'").fetchone()[0]
            by_cat = conn.execute("""
                SELECT category, COUNT(*) as n, SUM(times_succeeded) as wins
                  FROM repair_cases GROUP BY category ORDER BY n DESC
            """).fetchall()
        return {
            "total_cases": total,
            "successful":  succ,
            "success_rate": round(succ / max(total, 1) * 100, 1),
            "by_category": [{"category": r["category"], "n": r["n"], "wins": r["wins"] or 0}
                            for r in by_cat],
        }
