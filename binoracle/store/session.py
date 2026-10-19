"""SQLite-backed per-binary session store.

Keeps grounded facts (tool results already gathered), verified findings, and free-form
annotations so re-running binoracle on the same target is incremental."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
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
    # Version en el otro idioma (opcional, solo para el informe; NO se persiste). rationale/
    # recommendation son el idioma primario; estos, el ingles si el primario es ES (o viceversa).
    rationale_en: str = ""
    recommendation_en: str = ""
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
CREATE TABLE IF NOT EXISTS knowledge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id TEXT,
    kind TEXT,
    content TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id TEXT,
    kind TEXT,
    data TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS global_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arch TEXT, bits TEXT, sink TEXT, mitig TEXT,
    fact TEXT, verdict TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS exploit_skill (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    arch TEXT, cls TEXT, strategy TEXT,
    attempts INTEGER DEFAULT 0, successes INTEGER DEFAULT 0,
    last_offset INTEGER, updated_at REAL,
    UNIQUE(arch, cls, strategy)
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
        # de-dup: one row per (bin_id, title, location). Re-analysis updates in place so a
        # promotion (grounded -> verified) persists without inflating counts.
        row = self._conn.execute(
            "SELECT id FROM findings WHERE bin_id=? AND title=? AND location=? LIMIT 1",
            (self.bin_id, f.title, f.location),
        ).fetchone()
        if row:
            self._conn.execute(
                """UPDATE findings SET severity=?, verdict=?, evidence=?, rationale=?,
                       recommendation=? WHERE id=?""",
                (f.severity, f.verdict, f.evidence, f.rationale, f.recommendation, row[0]),
            )
            self._conn.commit()
            return row[0]
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

    def add_knowledge(self, kind: str, content: str) -> None:
        if not content or not content.strip():
            return
        self._conn.execute(
            "INSERT INTO knowledge(bin_id, kind, content, created_at) VALUES (?,?,?,?)",
            (self.bin_id, kind, content, time.time()),
        )
        self._conn.commit()

    def get_knowledge(self, limit: int = 5):
        rows = self._conn.execute(
            "SELECT kind, content, created_at FROM knowledge WHERE bin_id=? ORDER BY id DESC LIMIT ?",
            (self.bin_id, limit),
        ).fetchall()
        return [{"kind": r[0], "content": r[1], "created_at": r[2]} for r in rows]

    def list_binaries(self):
        rows = self._conn.execute(
            """SELECT b.bin_id, b.path, b.first_seen,
                      (SELECT COUNT(*) FROM findings f WHERE f.bin_id=b.bin_id) AS nf,
                      (SELECT COUNT(*) FROM knowledge k WHERE k.bin_id=b.bin_id) AS nk
               FROM binaries b ORDER BY b.first_seen DESC"""
        ).fetchall()
        import os
        return [{"bin_id": r[0], "path": r[1], "name": os.path.basename(r[1]),
                 "first_seen": r[2], "findings": r[3], "knowledge": r[4]} for r in rows]

    def add_global_fact(self, arch, bits, sink, mitig, fact, verdict):
        # de-dup: same (arch, sink, fact) is stored once
        exists = self._conn.execute(
            "SELECT 1 FROM global_facts WHERE arch=? AND sink=? AND fact=? LIMIT 1",
            (arch, sink, fact),
        ).fetchone()
        if exists:
            return
        self._conn.execute(
            "INSERT INTO global_facts(arch,bits,sink,mitig,fact,verdict,created_at) VALUES (?,?,?,?,?,?,?)",
            (arch, bits, sink, mitig, fact, verdict, time.time()),
        )
        self._conn.commit()

    def record_exploit_attempt(self, arch, cls, strategy, ok: bool, offset=None) -> None:
        """El agente entrenador registra un intento de desarrollo de exploit por (arch, clase,
        estrategia): incrementa attempts y, si se verifico en sandbox, successes. Acumula entre
        ejecuciones para medir el progreso de la habilidad."""
        arch = arch or "?"; cls = cls or "?"; strategy = strategy or "?"
        self._conn.execute(
            """INSERT INTO exploit_skill(arch, cls, strategy, attempts, successes, last_offset, updated_at)
               VALUES (?,?,?,1,?,?,?)
               ON CONFLICT(arch, cls, strategy) DO UPDATE SET
                   attempts = attempts + 1,
                   successes = successes + ?,
                   last_offset = COALESCE(?, last_offset),
                   updated_at = ?""",
            (arch, cls, strategy, 1 if ok else 0, offset, time.time(),
             1 if ok else 0, offset, time.time()),
        )
        self._conn.commit()

    def exploit_skill(self):
        """Estado de la habilidad de explotacion aprendida: filas (arch, clase, estrategia) con
        intentos/exitos y tasa. Es lo que hace medible que el agente 'entrena' la habilidad."""
        rows = self._conn.execute(
            """SELECT arch, cls, strategy, attempts, successes, last_offset, updated_at
               FROM exploit_skill ORDER BY successes DESC, attempts DESC"""
        ).fetchall()
        return [{"arch": r[0], "cls": r[1], "strategy": r[2], "attempts": r[3],
                 "successes": r[4], "last_offset": r[5], "updated_at": r[6],
                 "rate": (r[4] / r[3]) if r[3] else 0.0} for r in rows]

    def relevant_facts(self, arch, sinks, limit: int = 8):
        """Cross-binary knowledge for a SIMILAR target: same arch and overlapping sinks.
        Anonymized (no paths). This is what makes the system improve as the corpus grows."""
        sinks = list(sinks or [])
        if sinks:
            q = ",".join("?" for _ in sinks)
            rows = self._conn.execute(
                f"SELECT DISTINCT fact FROM global_facts WHERE arch=? AND sink IN ({q}) "
                f"ORDER BY id DESC LIMIT ?", (arch, *sinks, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT DISTINCT fact FROM global_facts WHERE arch=? ORDER BY id DESC LIMIT ?",
                (arch, limit),
            ).fetchall()
        return [r[0] for r in rows]

    def save_verified_facts(self, findings, arch, bits, mitig):
        """Curation: only VERIFIED findings become durable facts (per-binary + global,
        anonymized). Feeding these back beats reinjecting the model's own prose."""
        import re as _re
        mit_short = _re.sub(r"\s+", " ", " ".join(l.strip() for l in (mitig or "").splitlines() if ":" in l)).strip()[:200]
        n = 0
        for f in findings:
            if f.verdict != "verified":
                continue
            m = _re.search(r"'([^']+)'", f.title or "")
            sink = m.group(1) if m else (f.location or "?")
            fact = f"{sink}: {f.title} @ {f.location} [verified]"
            self.add_knowledge("fact", fact)
            gfact = f"'{sink}' verificado alcanzable ({arch} {bits}-bit; {mit_short})"
            self.add_global_fact(arch, bits, sink, mit_short, gfact, "verified")
            n += 1
        return n

    def save_report(self, kind: str, data: dict) -> None:
        """Guarda el informe COMPLETO ya analizado (el dict que consume la vista, no solo los
        hallazgos sueltos) para que volver a abrirlo desde el historial lo muestre tal cual fue
        generado, sin re-analizar nada. Un solo informe guardado por (bin_id, kind): cada
        analisis nuevo reemplaza al anterior."""
        payload = json.dumps(data)
        self._conn.execute("DELETE FROM reports WHERE bin_id=? AND kind=?", (self.bin_id, kind))
        self._conn.execute(
            "INSERT INTO reports(bin_id, kind, data, created_at) VALUES (?,?,?,?)",
            (self.bin_id, kind, payload, time.time()),
        )
        self._conn.commit()

    def load_report(self, kind: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT data FROM reports WHERE bin_id=? AND kind=? ORDER BY id DESC LIMIT 1",
            (self.bin_id, kind),
        ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except (TypeError, ValueError):
            return None

    def close(self) -> None:
        self._conn.close()


def delete_binary(db_path, bin_id: str) -> dict:
    """Borra del historial un binario analizado y TODO lo asociado (facts, findings, annotations,
    knowledge por-binario). Los global_facts son conocimiento agregado/anonimo entre binarios y NO
    se tocan. Devuelve el recuento de filas eliminadas por tabla."""
    import os, sqlite3
    if not bin_id or not os.path.exists(str(db_path)):
        return {"ok": False, "error": "no db o bin_id vacio"}
    conn = sqlite3.connect(str(db_path))
    deleted = {}
    try:
        exists = conn.execute("SELECT 1 FROM binaries WHERE bin_id=? LIMIT 1", (bin_id,)).fetchone()
        if not exists:
            return {"ok": False, "error": "bin_id no encontrado"}
        for table in ("facts", "findings", "annotations", "knowledge", "reports", "binaries"):
            try:
                cur = conn.execute(f"DELETE FROM {table} WHERE bin_id=?", (bin_id,))
                deleted[table] = cur.rowcount
            except sqlite3.OperationalError:
                deleted[table] = 0
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "bin_id": bin_id, "deleted": deleted}


def read_exploit_skill(db_path):
    """Lee el estado de la habilidad de explotacion entrenada, sin necesitar un binario. Para el
    panel de progreso (web/CLI). Devuelve filas (arch, clase, estrategia, intentos, exitos, tasa)."""
    import os, sqlite3
    if not os.path.exists(str(db_path)):
        return []
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """SELECT arch, cls, strategy, attempts, successes, last_offset, updated_at
               FROM exploit_skill ORDER BY successes DESC, attempts DESC"""
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    return [{"arch": r[0], "cls": r[1], "strategy": r[2], "attempts": r[3],
             "successes": r[4], "last_offset": r[5], "updated_at": r[6],
             "rate": (r[4] / r[3]) if r[3] else 0.0} for r in rows]


def list_all_binaries(db_path):
    """List every analyzed binary in the DB (for history), without needing a target."""
    import os, sqlite3
    if not os.path.exists(str(db_path)):
        return []
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """SELECT b.bin_id, b.path, b.first_seen,
                      (SELECT COUNT(*) FROM findings f WHERE f.bin_id=b.bin_id),
                      (SELECT COUNT(*) FROM knowledge k WHERE k.bin_id=b.bin_id)
               FROM binaries b ORDER BY b.first_seen DESC"""
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    return [{"bin_id": r[0], "path": r[1], "name": os.path.basename(r[1]),
             "first_seen": r[2], "findings": r[3], "knowledge": r[4],
             "exists": os.path.exists(r[1])} for r in rows]
