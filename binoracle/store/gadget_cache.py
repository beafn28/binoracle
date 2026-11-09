"""Cross-engagement gadget cache: reuse discovered ROP gadgets across targets by content hash.

ROADMAP v0.5 "[L] Cross-engagement knowledge base" -- "Reuse discovered gadgets and attack
patterns across targets, anonymized, so each run makes the next one better." Audited first:
most of this already existed and is already CONSUMED (not just written): `store/session.py`'s
`global_facts` (anonymized verified findings, cross-binary, read via `relevant_facts()` and fed
back into the agent's prompt in `workflows/audit.py`) and `exploit_skill` (per arch/class/strategy
attempts+successes, read and updated by `workflows/exploit_trainer.py`) already cover "attack
PATTERNS". What was genuinely missing is literal GADGET reuse: `chainanalyzer.py`'s
`_enum_gadgets` runs a full ROP scan of `.text` via radare2 (`/Rj` per pattern) that its own
comment already flags as expensive -- "~6s EACH... ~17 patterns = ~110s" on an 800KB static
binary, explicitly budget-limited (`BINORACLE_GADGET_BUDGET`) because of this cost.

This cache is keyed by the exact SHA256 of the scanned binary's content (reusing
`store.session.binary_id`'s same hashing, truncated the same way) -- NOT a heuristic
similarity match. Two different "targets" (a second pwn challenge built from the same base
image, or more commonly a statically-linked binary that embeds the same libc/musl `.text` an
earlier target also embedded) that happen to share byte-identical code will have byte-identical
gadgets; caching is 100% safe because the key IS the content, so a false hit is impossible. The
stored record itself is anonymized by construction: it never stores the original path or
filename, only the content hash and the gadget list (addresses + instruction text, which are
already not sensitive -- just offsets into a scanned byte blob)."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS gadget_cache (
    content_hash TEXT PRIMARY KEY,
    bits INTEGER,
    gadgets_json TEXT,
    created_at REAL
);
"""


def _conn(db_path) -> sqlite3.Connection:
    c = sqlite3.connect(Path(db_path))
    c.executescript(SCHEMA)
    return c


def content_hash(path: str) -> str:
    """Mismo hashing que `store.session.binary_id` (sha256 truncado a 16 hex) -- clave de
    cache por CONTENIDO, nunca por ruta/nombre."""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def load_gadgets(db_path, chash: str) -> Optional[List[dict]]:
    """Devuelve la lista de gadgets cacheada (como dicts serializables, un `asdict(Gadget)` por
    entrada) para este hash de contenido, o None si nunca se cacheo."""
    c = _conn(db_path)
    try:
        row = c.execute(
            "SELECT gadgets_json FROM gadget_cache WHERE content_hash=?", (chash,)
        ).fetchone()
        if not row:
            return None
        import json
        return json.loads(row[0])
    finally:
        c.close()


def save_gadgets(db_path, chash: str, bits: int, gadgets: List[dict]) -> None:
    import json
    import time
    c = _conn(db_path)
    try:
        c.execute(
            "INSERT OR REPLACE INTO gadget_cache(content_hash, bits, gadgets_json, created_at) "
            "VALUES (?,?,?,?)",
            (chash, bits, json.dumps(gadgets), time.time()),
        )
        c.commit()
    finally:
        c.close()


def cache_stats(db_path) -> dict:
    c = _conn(db_path)
    try:
        n = c.execute("SELECT COUNT(*) FROM gadget_cache").fetchone()[0]
        return {"n_cached_binaries": n}
    finally:
        c.close()
