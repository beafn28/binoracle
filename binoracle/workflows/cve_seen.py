"""cve_seen.py — Deduplication registry for processed CVEs in auto_queue_nvd.

Prevents re-processing the same CVE across consecutive nvd-watch cycles.
State persisted in ~/.cache/binoracle/cve_seen.json with per-CVE TTL.

A CVE is "seen" when auto_queue_nvd starts investigating it. It stays
seen for `default_ttl_hours` (default 48h). After the TTL expires, the
CVE can be re-investigated (useful for CVEs that failed and may now have
improved source availability).

Verified CVEs get a longer TTL (7 days by default) since there's no value
in re-running them unless the source code changes.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from typing import List

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle"
)
_SEEN_FILE = os.path.join(_STATE_DIR, "cve_seen.json")

_TTL_DEFAULT_H = 48      # unverified/failed: re-eligible after 48h
_TTL_VERIFIED_H = 168    # verified: re-eligible after 7 days
_MAX_ENTRIES = 500       # cap to avoid unbounded growth


def _load() -> dict:
    try:
        with open(_SEEN_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = _SEEN_FILE + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, _SEEN_FILE)
    except Exception:
        pass


def mark_seen(cve_id: str, verified: bool = False) -> None:
    """Record that a CVE was processed. TTL depends on whether it was verified."""
    data = _load()
    cve_id = cve_id.upper()
    ttl_h = _TTL_VERIFIED_H if verified else _TTL_DEFAULT_H
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_h)).isoformat()
    data[cve_id] = {
        "seen_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "verified": verified,
    }
    # Prune expired entries + cap at max
    now = datetime.now(timezone.utc)
    data = {
        k: v for k, v in data.items()
        if _parse_dt(v.get("expires_at", "")) > now
    }
    if len(data) > _MAX_ENTRIES:
        # Keep most recently seen entries
        data = dict(sorted(
            data.items(),
            key=lambda kv: kv[1].get("seen_at", ""),
            reverse=True,
        )[:_MAX_ENTRIES])
    _save(data)


def is_seen(cve_id: str) -> bool:
    """Return True if the CVE was recently processed and is still within its TTL."""
    data = _load()
    entry = data.get(cve_id.upper())
    if not entry:
        return False
    return _parse_dt(entry.get("expires_at", "")) > datetime.now(timezone.utc)


def filter_unseen(cve_ids: List[str]) -> List[str]:
    """Return only the CVE IDs that have NOT been seen recently."""
    data = _load()
    now = datetime.now(timezone.utc)
    result = []
    for cid in cve_ids:
        entry = data.get(cid.upper())
        if not entry or _parse_dt(entry.get("expires_at", "")) <= now:
            result.append(cid)
    return result


def seen_summary() -> dict:
    """Return a summary of the seen registry."""
    data = _load()
    now = datetime.now(timezone.utc)
    active = {k: v for k, v in data.items()
              if _parse_dt(v.get("expires_at", "")) > now}
    return {
        "total_active": len(active),
        "verified": sum(1 for v in active.values() if v.get("verified")),
        "unverified": sum(1 for v in active.values() if not v.get("verified")),
    }


def _parse_dt(s: str) -> datetime:
    """Parse ISO timestamp, return epoch on failure."""
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
