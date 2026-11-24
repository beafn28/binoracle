"""D18: CVE similarity index — detects when a new CVE resembles a previously verified one.

Similarity is computed from:
  - same patch function name (vuln_function from patch diff)
  - same parameter name
  - same CWE / vuln class
  - same affected package + major version

State stored in ~/.cache/binoracle/cve_similarity.json.
Thread-safe via atomic rename. No external dependencies — stdlib only.

Usage:
    from .cve_similarity import find_similar, record_verified_cve

    # Before launching a new investigation:
    hits = find_similar(cve_id="CVE-2026-99999", vuln_function="process_upload",
                        param="file", vuln_class="file-upload", package="ghost")
    if hits:
        # Use hits[0]['poc_endpoint'] as first-attempt endpoint

    # After successful verification:
    record_verified_cve(cve_id=..., vuln_function=..., param=..., ...)
"""
from __future__ import annotations

import json
import os
from typing import Optional

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle"
)
_SIM_FILE = os.path.join(_STATE_DIR, "cve_similarity.json")


def _load() -> list:
    try:
        with open(_SIM_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except Exception:
        return []


def _save(data: list) -> None:
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = _SIM_FILE + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, _SIM_FILE)
    except Exception:
        pass


def _score(entry: dict, vuln_function: str, param: str,
           vuln_class: str, package: str, cwe: str) -> float:
    """Return similarity score 0.0–1.0 for one index entry vs query."""
    score = 0.0
    if vuln_function and entry.get("vuln_function") == vuln_function:
        score += 0.40
    if param and entry.get("param") == param:
        score += 0.25
    if vuln_class and entry.get("vuln_class") == vuln_class:
        score += 0.20
    if package and entry.get("package") and (
            package.lower() in entry["package"].lower() or
            entry["package"].lower() in package.lower()):
        score += 0.10
    if cwe and entry.get("cwe") == cwe:
        score += 0.05
    return score


def find_similar(
    cve_id: str,
    vuln_function: str = "",
    param: str = "",
    vuln_class: str = "",
    package: str = "",
    cwe: str = "",
    min_score: float = 0.40,
    max_results: int = 3,
) -> list[dict]:
    """D18: Find similar previously-verified CVEs.

    Returns list of dicts with keys: cve_id, score, poc_endpoint, http_method,
    confirm_string, stack, vuln_function, param, vuln_class.
    Sorted by score descending. Empty if nothing reaches min_score.
    """
    index = _load()
    results = []
    for entry in index:
        if entry.get("cve_id") == cve_id:
            continue  # don't match self
        score = _score(entry, vuln_function, param, vuln_class, package, cwe)
        if score >= min_score:
            results.append(dict(entry, score=round(score, 3)))
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:max_results]


def record_verified_cve(
    cve_id: str,
    stack: str = "",
    vuln_function: str = "",
    param: str = "",
    vuln_class: str = "",
    package: str = "",
    cwe: str = "",
    poc_endpoint: str = "",
    http_method: str = "",
    confirm_string: str = "",
) -> None:
    """D18: Add a verified CVE to the similarity index."""
    if not cve_id:
        return
    index = _load()
    # Dedup by cve_id
    if any(e.get("cve_id") == cve_id for e in index):
        return
    index.append({
        "cve_id": cve_id,
        "stack": stack,
        "vuln_function": vuln_function,
        "param": param,
        "vuln_class": vuln_class,
        "package": package,
        "cwe": cwe,
        "poc_endpoint": poc_endpoint,
        "http_method": http_method,
        "confirm_string": confirm_string[:120],
    })
    # Cap at 500 entries — keep most recent
    if len(index) > 500:
        index = index[-500:]
    _save(index)
