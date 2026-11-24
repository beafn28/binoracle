"""Cross-CVE learning: persists lessons learned from each investigation so future
runs of the same stack benefit from prior results.

State stored in ~/.cache/binoracle/cve_lessons.json. Thread-safe via atomic rename.
No external dependencies — stdlib only."""
from __future__ import annotations

import json
import os
from collections import Counter
from typing import Dict, List, Tuple

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle"
)
_LESSONS_FILE = os.path.join(_STATE_DIR, "cve_lessons.json")

# Keywords to detect stack from CVE description or source path
_STACK_KEYWORDS: Dict[str, List[str]] = {
    "django":      ["django"],
    "fastapi":     ["fastapi", "starlette"],
    "flask":       ["flask"],
    "express":     ["express", "node.js", "nodejs"],
    "nextjs":      ["next.js", "nextjs"],
    "gin":         ["gin-gonic", " gin ", "gin framework"],
    "echo":        [" echo ", "labstack/echo"],
    "fiber":       ["gofiber", "fiber framework"],
    "spring":      ["spring boot", "spring mvc", "springframework"],
    "rails":       ["ruby on rails", "rails"],
    "laravel":     ["laravel"],
    "wordpress":   ["wordpress", "wp-"],
    "drupal":      ["drupal"],
    "joomla":      ["joomla"],
    "strapi":      ["strapi"],
    "ghost":       ["ghost cms", "ghost blog"],
    "mattermost":  ["mattermost"],
    "grafana":     ["grafana"],
    "nextcloud":   ["nextcloud"],
    "gitea":       ["gitea"],
    "keycloak":    ["keycloak"],
    "authentik":   ["authentik"],
    "jellyfin":    ["jellyfin"],
    "audiobookshelf": ["audiobookshelf"],
}


def detect_stack(text: str) -> str:
    """Return the best-matching stack name from free text (description, path, etc.)."""
    lower = (text or "").lower()
    for stack, keywords in _STACK_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return stack
    return "generic"


def _load() -> dict:
    try:
        with open(_LESSONS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = _LESSONS_FILE + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, _LESSONS_FILE)
    except Exception:
        pass


def record_cve_result(
    stack: str,
    cve_id: str,
    endpoint: str = "",
    verified: bool = False,
    bypass_header: str = "",
    bypass_value: str = "",
    vuln_class: str = "",
) -> None:
    """Record the outcome of one CVE investigation for future learning."""
    if not stack:
        return
    data = _load()
    entry = data.setdefault(stack, {
        "runs": [],
        "verified_count": 0,
        "total_count": 0,
    })
    entry.setdefault("runs", [])
    entry.setdefault("verified_count", 0)
    entry.setdefault("total_count", 0)

    # Avoid duplicate entries for the same CVE
    existing_ids = {r.get("cve_id") for r in entry["runs"]}
    if cve_id in existing_ids:
        return

    entry["runs"].append({
        "cve_id": cve_id,
        "endpoint": endpoint,
        "verified": verified,
        "bypass_header": bypass_header,
        "bypass_value": bypass_value,
        "vuln_class": vuln_class,
    })
    entry["total_count"] += 1
    if verified:
        entry["verified_count"] += 1

    # Keep only last 100 runs per stack to avoid unbounded growth
    if len(entry["runs"]) > 100:
        entry["runs"] = entry["runs"][-100:]
        entry["total_count"] = len(entry["runs"])
        entry["verified_count"] = sum(1 for r in entry["runs"] if r.get("verified"))

    _save(data)


def get_lessons(stack: str) -> dict:
    """Return aggregated lessons for a stack: top endpoints, bypass headers, success rate."""
    data = _load()
    entry = data.get(stack) or {}
    runs = entry.get("runs") or []
    if not runs:
        return {}

    total = entry.get("total_count", len(runs))
    verified = entry.get("verified_count", sum(1 for r in runs if r.get("verified")))

    ep_counter: Counter = Counter()
    bp_counter: Counter = Counter()
    class_counter: Counter = Counter()
    for r in runs:
        ep = (r.get("endpoint") or "").strip()
        if ep and ep not in ("?", "", "unknown", "n/a"):
            ep_counter[ep] += 1 + (2 if r.get("verified") else 0)
        bh = (r.get("bypass_header") or "").strip()
        bv = (r.get("bypass_value") or "").strip()
        if bh and r.get("verified"):
            bp_counter[(bh, bv)] += 1
        vc = (r.get("vuln_class") or "").strip()
        if vc:
            class_counter[vc] += 1

    return {
        "stack": stack,
        "total_runs": total,
        "verified_rate": verified / total if total else 0.0,
        "top_endpoints": [ep for ep, _ in ep_counter.most_common(5)],
        "working_bypass_headers": [
            {"header": h, "value": v} for (h, v), _ in bp_counter.most_common(3)
        ],
        "top_vuln_classes": [vc for vc, _ in class_counter.most_common(3)],
    }


def suggest_endpoints(stack: str, vuln_class: str = "") -> List[str]:
    """Return up to 3 endpoints that worked for this stack+class before."""
    data = _load()
    entry = data.get(stack) or {}
    runs = entry.get("runs") or []
    if not runs:
        return []

    ep_scores: Counter = Counter()
    for r in runs:
        ep = (r.get("endpoint") or "").strip()
        if not ep or ep in ("?", "", "unknown", "n/a"):
            continue
        # Prioritize: verified + matching vuln_class scores highest
        score = 1
        if r.get("verified"):
            score += 3
        if vuln_class and (r.get("vuln_class") or "") == vuln_class:
            score += 2
        ep_scores[ep] += score

    return [ep for ep, _ in ep_scores.most_common(3)]


def suggest_bypass_headers(stack: str) -> List[Tuple[str, str]]:
    """Return bypass (header, value) pairs that worked before for this stack."""
    data = _load()
    entry = data.get(stack) or {}
    runs = entry.get("runs") or []
    bp_counter: Counter = Counter()
    for r in runs:
        if not r.get("verified"):
            continue
        bh = (r.get("bypass_header") or "").strip()
        bv = (r.get("bypass_value") or "").strip()
        if bh:
            bp_counter[(bh, bv)] += 1
    return [(h, v) for (h, v), _ in bp_counter.most_common(5)]


def all_stacks_summary() -> List[dict]:
    """Return a summary row per stack, sorted by total_runs desc."""
    data = _load()
    rows = []
    for stack in sorted(data, key=lambda s: data[s].get("total_count", 0), reverse=True):
        lessons = get_lessons(stack)
        if lessons:
            rows.append(lessons)
    return rows
