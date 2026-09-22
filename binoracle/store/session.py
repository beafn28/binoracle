"""SQLite-backed per-binary session store.

Keeps grounded facts (tool results already gathered), verified findings, and free-form
annotations so re-running binoracle on the same target is incremental."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


def binary_id(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


@dataclass
class Finding:
    title: str
    severity: str            # info | low | medium | high | critical
    verdict: str             # unverified | grounded | verified
    evidence: str            # the oracle output(s) backing it, with provenance
    location: str = ""       # function / address
    rationale: str = ""
    recommendation: str = ""
    id: Optional[int] = None
    created_at: float = 0.0


SCHEMA = """
CREATE TABLE IF NOT EXISTS binaries (
    bin_id TEXT PRIMARY KEY,
    path TEXT,
    first_seen REAL
);
CREATE TABLE IF NOT EXISTS facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id TEXT,
    source TEXT,
    tool TEXT,
    data TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id TEXT,
    title TEXT,
    severity TEXT,
    verdict TEXT,
    evidence TEXT,
    location TEXT,
    rationale TEXT,
    recommendation TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id TEXT,
    key TEXT,
    value TEXT,
    created_at REAL
);
"""


class SessionStore:
    def __init__(self, db_path: Path, binary: str):
        self.db_path = Path(db_path)
        self.binary = binary
        self.bin_id = binary_id(binary)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO binaries(bin_id, path, first_seen) VALUES (?,?,?)",
            (self.bin_id, str(Path(binary).resolve()), time.time()),
        )
        self._conn.commit()

    def add_fact(self, tool: str, source: str, data: str) -> None:
        self._conn.execute(
            "INSERT INTO facts(bin_id, source, tool, data, created_at) VALUES (?,?,?,?,?)",
            (self.bin_id, source, tool, data, time.time()),
        )
        self._conn.commit()

    def add_finding(self, f: Finding) -> int:
        cur = self._conn.execute(
            """INSERT INTO findings(bin_id, title, severity, verdict, evidence, location,
                                    rationale, recommendation, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (self.bin_id, f.title, f.severity, f.verdict, f.evidence, f.location,
             f.rationale, f.recommendation, time.time()),
        )
        self._conn.commit()
        return cur.lastrowid

    def findings(self) -> List[Finding]:
        rows = self._conn.execute(
            """SELECT id, title, severity, verdict, evidence, location, rationale,
                      recommendation, created_at
               FROM findings WHERE bin_id=? ORDER BY id""",
            (self.bin_id,),
        ).fetchall()
        out = []
        for r in rows:
            out.append(Finding(
                id=r[0], title=r[1], severity=r[2], verdict=r[3], evidence=r[4],
                location=r[5], rationale=r[6], recommendation=r[7], created_at=r[8],
            ))
        return out

    def set_annotation(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO annotations(bin_id, key, value, created_at) VALUES (?,?,?,?)",
            (self.bin_id, key, value, time.time()),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
