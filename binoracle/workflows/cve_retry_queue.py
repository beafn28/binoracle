"""CVE retry queue — tracks failed CVE investigations and retries transient failures.

Persists state in ~/.cache/binoracle/retry_queue.json. Max 50 entries.
Transient errors: Docker timeout, network unreachable, build failure, port not ready.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone, timedelta
from typing import List

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle")
_QUEUE_FILE = os.path.join(_STATE_DIR, "retry_queue.json")
_MAX_ENTRIES = 50

_TRANSIENT_PATTERNS = [
    r"timeout",
    r"timed out",
    r"network.*unreachable",
    r"connection refused",
    r"build.*fail",
    r"docker.*error",
    r"port.*not.*ready",
    r"server.*not.*start",
    r"container.*exit",
    r"no.*such.*host",
    r"pull.*fail",
    r"image.*not.*found",
    r"go.*build.*error",
    r"npm.*install.*fail",
    r"pip.*install.*fail",
]


def is_transient_error(error: str) -> bool:
    """Return True if the error is transient and worth retrying."""
    if not error:
        return False
    low = error.lower()
    return any(re.search(p, low) for p in _TRANSIENT_PATTERNS)


def _load() -> List[dict]:
    try:
        with open(_QUEUE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save(queue: List[dict]) -> None:
    try:
        os.makedirs(os.path.dirname(_QUEUE_FILE), exist_ok=True)
        tmp = _QUEUE_FILE + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)
        os.replace(tmp, _QUEUE_FILE)
    except Exception:
        pass


def add_to_retry(cve_id: str, error: str, stack: str = "") -> None:
    """Add a CVE to the retry queue. Skips duplicates. Caps at _MAX_ENTRIES."""
    queue = _load()
    cve_id = cve_id.upper()
    # skip if already present
    for entry in queue:
        if entry.get("cve_id") == cve_id:
            return
    queue.append({
        "cve_id": cve_id,
        "attempts": 1,
        "last_error": (error or "")[:300],
        "added": datetime.now(timezone.utc).isoformat(),
        "stack": stack,
    })
    # keep newest _MAX_ENTRIES
    if len(queue) > _MAX_ENTRIES:
        queue = queue[-_MAX_ENTRIES:]
    _save(queue)


def get_pending(max_age_hours: int = 24, max_attempts: int = 3) -> List[str]:
    """Return CVE IDs pending retry (not too old, not too many attempts)."""
    queue = _load()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    result = []
    for entry in queue:
        if entry.get("attempts", 0) >= max_attempts:
            continue
        try:
            added = datetime.fromisoformat(entry["added"])
            if added < cutoff:
                continue
        except Exception:
            pass
        result.append(entry["cve_id"])
    return result


def mark_done(cve_id: str) -> None:
    """Remove a CVE from the retry queue after successful processing."""
    cve_id = cve_id.upper()
    queue = [e for e in _load() if e.get("cve_id") != cve_id]
    _save(queue)


def mark_attempt(cve_id: str, error: str) -> None:
    """Increment attempt count and update last error for a CVE."""
    cve_id = cve_id.upper()
    queue = _load()
    for entry in queue:
        if entry.get("cve_id") == cve_id:
            entry["attempts"] = entry.get("attempts", 1) + 1
            entry["last_error"] = (error or "")[:300]
            break
    _save(queue)


def queue_summary() -> dict:
    """Return a summary of the retry queue state."""
    queue = _load()
    return {
        "total": len(queue),
        "pending": len(get_pending()),
        "entries": [{"cve_id": e["cve_id"], "attempts": e["attempts"],
                     "stack": e.get("stack", "")} for e in queue],
    }
