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
    # Source code availability (GitHub rate limit, temp unavailability)
    r"rate.?limit",
    r"github.*403",
    r"github.*429",
    r"source.*not.*found",
    r"clone.*fail",
    r"repository.*not.*found",
    r"checkout.*error",
    r"download.*fail",
    r"http.*503",
    r"http.*502",
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


_BACKOFF_HOURS = [0.5, 2, 8, 24, 72]  # backoff per attempt: 30min, 2h, 8h, 24h, 72h


def _next_retry_at(attempts: int) -> str:
    """Return ISO timestamp for next allowed retry, using exponential backoff."""
    idx = min(attempts, len(_BACKOFF_HOURS) - 1)
    delay_h = _BACKOFF_HOURS[idx]
    return (datetime.now(timezone.utc) + timedelta(hours=delay_h)).isoformat()


def add_to_retry(cve_id: str, error: str, stack: str = "") -> None:
    """Add a CVE to the retry queue. If already present, increment attempts.
    Caps at _MAX_ENTRIES."""
    queue = _load()
    cve_id = cve_id.upper()
    # update if already present
    for entry in queue:
        if entry.get("cve_id") == cve_id:
            new_attempts = entry.get("attempts", 1) + 1
            entry["attempts"] = new_attempts
            entry["last_error"] = (error or "")[:300]
            entry["next_retry_at"] = _next_retry_at(new_attempts)
            _save(queue)
            return
    next_retry = _next_retry_at(1)
    queue.append({
        "cve_id": cve_id,
        "attempts": 1,
        "last_error": (error or "")[:300],
        "added": datetime.now(timezone.utc).isoformat(),
        "next_retry_at": next_retry,
        "stack": stack,
    })
    # keep newest _MAX_ENTRIES
    if len(queue) > _MAX_ENTRIES:
        queue = queue[-_MAX_ENTRIES:]
    _save(queue)


def get_pending(max_age_hours: int = 24, max_attempts: int = 3) -> List[str]:
    """Return CVE IDs pending retry that are ready to be retried NOW.

    An entry is ready when:
    - attempts < max_attempts
    - not older than max_age_hours since first added
    - next_retry_at is in the past (backoff elapsed)
    """
    return [e["cve_id"] for e in get_pending_entries(max_age_hours, max_attempts)]


def get_pending_entries(max_age_hours: int = 24, max_attempts: int = 3) -> List[dict]:
    """Return full retry entries pending retry (with failure context).

    Each entry dict has: cve_id, attempts, last_error, stack, added.
    Use this when the caller needs the failure context to adjust the retry strategy
    (e.g., skip Docker lab if failure was 'source not found').
    """
    queue = _load()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=max_age_hours)
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
        # Check backoff: skip if next_retry_at is in the future
        next_retry_str = entry.get("next_retry_at")
        if next_retry_str:
            try:
                next_retry = datetime.fromisoformat(next_retry_str)
                if next_retry > now:
                    continue  # backoff not elapsed yet
            except Exception:
                pass
        result.append(entry)
    return result


def mark_done(cve_id: str) -> None:
    """Remove a CVE from the retry queue after successful processing."""
    cve_id = cve_id.upper()
    queue = [e for e in _load() if e.get("cve_id") != cve_id]
    _save(queue)


def mark_attempt(cve_id: str, error: str) -> None:
    """Increment attempt count, update last error, and set next backoff window."""
    cve_id = cve_id.upper()
    queue = _load()
    for entry in queue:
        if entry.get("cve_id") == cve_id:
            new_attempts = entry.get("attempts", 1) + 1
            entry["attempts"] = new_attempts
            entry["last_error"] = (error or "")[:300]
            entry["next_retry_at"] = _next_retry_at(new_attempts)
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
