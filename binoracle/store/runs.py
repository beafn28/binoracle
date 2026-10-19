"""Persistent regression dashboard: per-target run history + diff-between-runs.

ROADMAP v0.5 "[M] Regression dashboard" -- "Persistent multi-target web UI beyond the single
HTML report, with a diff-between-runs view (which findings are new / fixed / reintroduced)."
Audited first: `store/session.py`'s `SessionStore` already tracks the CURRENT state of a
binary's findings persistently (keyed by content-hash `bin_id`, upserted in place on re-run),
and `web.py` already has a multi-target history list (the "H" sidebar button) -- so "persistent
multi-target web UI" already existed. What was missing is the "diff-between-runs" half: there is
no history of PAST states to diff against (upsert overwrites in place), and content-hash is the
wrong key for it anyway -- a patch changes the hash, so re-scanning the same logical target after
a fix lands on a *different* `bin_id` row instead of accumulating history on the same one. This
module tracks runs keyed by a TARGET LABEL (the path handed to `audit`, same string across builds)
instead of content hash, so repeated scans of the same logical target -- even as the underlying
binary changes across builds -- accumulate a real, diffable run history."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS run_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    title TEXT,
    severity TEXT,
    verdict TEXT,
    location TEXT
);
"""


def _conn(db_path) -> sqlite3.Connection:
    c = sqlite3.connect(Path(db_path))
    c.executescript(SCHEMA)
    return c


def record_run(db_path, target: str, findings) -> int:
    """Snapshotea el estado actual de `findings` (lista de `store.session.Finding`, o cualquier
    objeto/dict con .title/.severity/.verdict/.location) como una run NUEVA para `target`. No
    reemplaza ninguna run anterior -- cada llamada agrega una fila a la historia."""
    c = _conn(db_path)
    try:
        cur = c.execute("INSERT INTO runs(target, ts) VALUES (?,?)", (target, time.time()))
        run_id = cur.lastrowid
        for f in findings or []:
            title = f.title if hasattr(f, "title") else f.get("title", "")
            severity = f.severity if hasattr(f, "severity") else f.get("severity", "")
            verdict = f.verdict if hasattr(f, "verdict") else f.get("verdict", "")
            location = f.location if hasattr(f, "location") else f.get("location", "")
            c.execute(
                "INSERT INTO run_findings(run_id, title, severity, verdict, location) VALUES (?,?,?,?,?)",
                (run_id, title, severity, verdict, location),
            )
        c.commit()
        return run_id
    finally:
        c.close()


def list_targets(db_path) -> List[dict]:
    c = _conn(db_path)
    try:
        rows = c.execute(
            """SELECT target, COUNT(*) AS n, MAX(ts) AS last FROM runs
               GROUP BY target ORDER BY last DESC"""
        ).fetchall()
        return [{"target": r[0], "n_runs": r[1], "last_run": r[2]} for r in rows]
    finally:
        c.close()


def list_runs(db_path, target: str) -> List[dict]:
    c = _conn(db_path)
    try:
        rows = c.execute(
            """SELECT id, ts, (SELECT COUNT(*) FROM run_findings WHERE run_id=runs.id)
               FROM runs WHERE target=? ORDER BY ts""",
            (target,),
        ).fetchall()
        return [{"run_id": r[0], "ts": r[1], "n_findings": r[2]} for r in rows]
    finally:
        c.close()


def _run_findings_keys(c: sqlite3.Connection, run_id: int) -> Dict[tuple, dict]:
    rows = c.execute(
        "SELECT title, location, severity, verdict FROM run_findings WHERE run_id=?", (run_id,)
    ).fetchall()
    return {(r[0], r[1]): {"title": r[0], "location": r[1], "severity": r[2], "verdict": r[3]}
            for r in rows}


def diff_latest_two(db_path, target: str) -> dict:
    """Diffea las DOS ultimas runs de `target`. Categorias (grounded en lo que de verdad se
    persistio, nunca inferidas): `new` -- aparece en la ultima run y NUNCA aparecio en ninguna
    run anterior a la penultima; `reintroduced` -- aparece en la ultima, no estaba en la
    penultima, pero SI aparecio en alguna run mas vieja (se arreglo una vez y volvio);
    `fixed` -- estaba en la penultima y ya no esta en la ultima; `persisted` -- en ambas."""
    c = _conn(db_path)
    try:
        run_ids = [r[0] for r in c.execute(
            "SELECT id FROM runs WHERE target=? ORDER BY ts", (target,)).fetchall()]
        if len(run_ids) < 2:
            return {"ok": False, "note": f"se necesitan al menos 2 runs para este target "
                                         f"({len(run_ids)} encontrada(s))"}
        prev_id, latest_id = run_ids[-2], run_ids[-1]
        older_ids = run_ids[:-2]

        latest = _run_findings_keys(c, latest_id)
        prev = _run_findings_keys(c, prev_id)
        ever_before = set()
        for rid in older_ids:
            ever_before |= set(_run_findings_keys(c, rid).keys())

        new_, reintroduced, persisted = [], [], []
        for k, v in latest.items():
            if k in prev:
                persisted.append(v)
            elif k in ever_before:
                reintroduced.append(v)
            else:
                new_.append(v)
        fixed = [v for k, v in prev.items() if k not in latest]
        return {"ok": True, "target": target, "prev_run_id": prev_id, "latest_run_id": latest_id,
                "new": new_, "reintroduced": reintroduced, "fixed": fixed, "persisted": persisted}
    finally:
        c.close()


def render_run_diff(d: dict) -> str:
    out = ["## Regresion: diff entre runs\n"]
    if not d.get("ok"):
        return "\n".join(out + ["No disponible: " + d.get("note", "")])
    out.append(f"- target: `{d['target']}`")
    out.append(f"- comparando run #{d['prev_run_id']} -> run #{d['latest_run_id']}\n")

    def sect(title: str, items: List[dict]) -> List[str]:
        s = [f"\n### {title} ({len(items)})\n"]
        if not items:
            s.append("_(ninguno)_")
        for it in items:
            loc = f" @ `{it['location']}`" if it.get("location") else ""
            s.append(f"- **{it['title']}** [{it.get('severity','?')}/{it.get('verdict','?')}]{loc}")
        return s

    out += sect("NUEVOS", d["new"])
    out += sect("REINTRODUCIDOS", d["reintroduced"])
    out += sect("CORREGIDOS (fixed)", d["fixed"])
    out += sect("Sin cambio (persisten)", d["persisted"])
    return "\n".join(out)


def render_targets(targets: List[dict]) -> str:
    out = ["## Regresion: targets con historial de runs\n"]
    if not targets:
        return "\n".join(out + ["Sin runs registradas todavia (corre `audit` para empezar a acumular historial)."])
    out.append("| target | runs | ultima run |")
    out.append("|---|---|---|")
    for t in targets:
        out.append(f"| `{t['target']}` | {t['n_runs']} | {time.strftime('%Y-%m-%d %H:%M', time.localtime(t['last_run']))} |")
    return "\n".join(out)
