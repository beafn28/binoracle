"""cve_correlation.py — Cross-CVE pattern correlation engine.

When investigating a CVE for project Foo, this module scans previously
verified CVEs in the same project to extract reusable attack patterns:
- Bypass headers that confirmed access
- Endpoints that responded
- Confirm strings that matched

This reduces false negatives: if CVE-Y verified via /api/admin with
X-Role: admin, CVE-Z targeting the same project should try that bypass
first rather than starting from zero.

Data sources:
1. ~/.cache/binoracle/cve_lessons.json (from cve_lessons.py)
2. ~/.binoracle/reports/*.md (report frontmatter + evidence sections)
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional


_CACHE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle"
)
_REPORTS_DIR = os.environ.get("BINORACLE_REPORTS_DIR") or os.path.join(
    os.path.expanduser("~"), ".binoracle", "reports"
)
_LESSONS_FILE = os.path.join(_CACHE_DIR, "cve_lessons.json")


# Vuln class groupings for adjacency scoring
_CLASS_GROUPS = {
    "auth": {
        "missing-authorization", "auth-bypass", "broken-access-control",
        "idor", "privilege-escalation", "authentication-bypass",
    },
    "injection": {
        "sqli", "sql-injection", "nosql-injection", "command-injection",
        "rce", "ssti", "template-injection", "ldap-injection",
    },
    "xss": {"xss", "reflected-xss", "stored-xss", "dom-xss"},
    "traversal": {"lfi", "path-traversal", "directory-traversal", "rfi"},
    "ssrf": {"ssrf", "open-redirect", "request-forgery"},
    "disclosure": {"information-disclosure", "sensitive-data-exposure", "exposure"},
}


def _class_group(cls: str) -> Optional[str]:
    """Return the class group name, or None if not grouped."""
    cls_low = cls.lower().replace(" ", "-")
    for group, members in _CLASS_GROUPS.items():
        if cls_low in members:
            return group
    return None


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class CorrelationHint:
    source_cve: str
    endpoint_pattern: str
    bypass_header: str
    bypass_value: str
    vuln_class: str
    confirm_string: str
    relevance: float
    project: str = ""


@dataclass
class CorrelationResult:
    hints: List[CorrelationHint] = field(default_factory=list)
    best_hint: Optional[CorrelationHint] = None
    reasoning: str = ""


# ── Project name fuzzy matching ───────────────────────────────────────────────

_VERSION_RE = re.compile(
    r"[-_]?(v?\d+\.\d+[\.\d]*|v\d+)$", re.I
)
_SUFFIX_RE = re.compile(
    r"[-_]?(api|core|sdk|lib|server|client|plugin|extension|addon|module)$", re.I
)


def _normalize_project(name: str) -> str:
    """Strip version + common suffixes, lowercase."""
    n = (name or "").lower().strip()
    n = _VERSION_RE.sub("", n)
    n = _SUFFIX_RE.sub("", n)
    return n.strip("-_ ")


def _levenshtein(a: str, b: str) -> int:
    """O(len(a)*len(b)) Levenshtein — only used on short strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,          # delete
                curr[j - 1] + 1,      # insert
                prev[j - 1] + (ca != cb),  # replace
            ))
        prev = curr
    return prev[-1]


def _project_match_score(a: str, b: str) -> float:
    """Return 0–1 similarity for two project names."""
    if not a or not b:
        return 0.0
    na, nb = _normalize_project(a), _normalize_project(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    # Prefix: one starts with the other
    short, long_ = (na, nb) if len(na) <= len(nb) else (nb, na)
    if long_.startswith(short) and len(short) >= 3:
        return 0.80
    # Same root after stripping both
    if na in nb or nb in na:
        return 0.70
    # Edit distance on short strings only (avoid quadratic on long garbage)
    if len(na) <= 20 and len(nb) <= 20:
        dist = _levenshtein(na, nb)
        max_len = max(len(na), len(nb))
        if dist <= 2 and max_len >= 4:
            return 0.60
        if dist <= 3 and max_len >= 8:
            return 0.55
    return 0.0


# ── Data loading ──────────────────────────────────────────────────────────────

def _load_from_lessons() -> List[dict]:
    """Load past CVE records from cve_lessons.json."""
    try:
        with open(_LESSONS_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    records = []
    for stack, entry in (data or {}).items():
        for run in (entry.get("runs") or []):
            if not run.get("verified"):
                continue
            records.append({
                "cve_id": run.get("cve_id", ""),
                "project": stack,
                "endpoint": run.get("endpoint", ""),
                "bypass_header": run.get("bypass_header", ""),
                "bypass_value": run.get("bypass_value", ""),
                "confirm_string": "",
                "vuln_class": run.get("vuln_class", ""),
                "verified": True,
            })
    return records


_EVIDENCE_ENDPOINT_RE = re.compile(r'"endpoint"\s*:\s*"([^"]+)"')
_EVIDENCE_BYPASS_HDR_RE = re.compile(r'"bypass_header"\s*:\s*"([^"]+)"')
_EVIDENCE_BYPASS_VAL_RE = re.compile(r'"bypass_value"\s*:\s*"([^"]+)"')
_EVIDENCE_CONFIRM_RE = re.compile(r'"confirm_string"\s*:\s*"([^"]+)"')
_EVIDENCE_VULN_CLASS_RE = re.compile(r'"vuln_class"\s*:\s*"([^"]+)"')
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.S)
_CVELINK_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def _load_from_reports() -> List[dict]:
    """Scan ~/.binoracle/reports/*.md for verified CVE evidence."""
    records = []
    if not os.path.isdir(_REPORTS_DIR):
        return records

    for fname in os.listdir(_REPORTS_DIR):
        if not fname.endswith(".md"):
            continue
        fpath = os.path.join(_REPORTS_DIR, fname)
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                text = f.read(8192)
        except Exception:
            continue

        # Only include confirmed reports
        if "verified: true" not in text.lower() and "verificado: sí" not in text.lower():
            continue

        cve_id = ""
        m = _CVELINK_RE.search(fname)
        if m:
            cve_id = m.group(0).upper()
        if not cve_id:
            m = _CVELINK_RE.search(text)
            if m:
                cve_id = m.group(0).upper()

        # Extract project from filename: CVE-2024-12345-projectname.md
        project = ""
        parts = os.path.splitext(fname)[0].split("-")
        if len(parts) > 3:
            project = "-".join(parts[3:])
        if not project and cve_id:
            project = cve_id

        endpoint = ((_EVIDENCE_ENDPOINT_RE.search(text) or {}).group(1)
                    if _EVIDENCE_ENDPOINT_RE.search(text) else "")
        bypass_hdr = ((_EVIDENCE_BYPASS_HDR_RE.search(text) or {}).group(1)
                      if _EVIDENCE_BYPASS_HDR_RE.search(text) else "")
        bypass_val = ((_EVIDENCE_BYPASS_VAL_RE.search(text) or {}).group(1)
                      if _EVIDENCE_BYPASS_VAL_RE.search(text) else "")
        confirm_str = ((_EVIDENCE_CONFIRM_RE.search(text) or {}).group(1)
                       if _EVIDENCE_CONFIRM_RE.search(text) else "")
        vuln_class = ((_EVIDENCE_VULN_CLASS_RE.search(text) or {}).group(1)
                      if _EVIDENCE_VULN_CLASS_RE.search(text) else "")

        records.append({
            "cve_id": cve_id,
            "project": project,
            "endpoint": endpoint,
            "bypass_header": bypass_hdr,
            "bypass_value": bypass_val,
            "confirm_string": confirm_str,
            "vuln_class": vuln_class,
            "verified": True,
        })
    return records


def _load_past_results(cache_dir: Optional[str] = None) -> List[dict]:
    """Load all verified past CVE records from lessons + reports."""
    if cache_dir:
        global _LESSONS_FILE, _REPORTS_DIR
        _LESSONS_FILE = os.path.join(cache_dir, "cve_lessons.json")
    return _load_from_lessons() + _load_from_reports()


# ── Scoring ───────────────────────────────────────────────────────────────────

def _vuln_class_score(target_class: str, source_class: str) -> float:
    """Score vuln class overlap: 1.0 exact, 0.70 same group, 0.0 unrelated."""
    if not target_class or not source_class:
        return 0.0
    t = target_class.lower().replace(" ", "-")
    s = source_class.lower().replace(" ", "-")
    if t == s:
        return 1.0
    tg, sg = _class_group(t), _class_group(s)
    if tg and sg and tg == sg:
        return 0.70
    return 0.0


def _score_record(record: dict, project_name: str, vuln_class: str) -> float:
    """Return 0–1 relevance for a past CVE record."""
    proj_score = _project_match_score(project_name, record.get("project", ""))
    if proj_score == 0.0:
        return 0.0
    class_s = _vuln_class_score(vuln_class, record.get("vuln_class", ""))
    # Weights: project match dominates, class boosts
    # Same project + exact class → 0.90
    # Same project + adjacent class → 0.70
    # Same project + any class → 0.50
    if proj_score >= 0.90:
        base = 0.50
        if class_s >= 1.0:
            return 0.90
        elif class_s >= 0.70:
            return 0.70
        else:
            return base
    elif proj_score >= 0.70:
        base = 0.40
        if class_s >= 1.0:
            return 0.70
        elif class_s >= 0.70:
            return 0.55
        else:
            return base
    else:
        # Fuzzy match (0.55–0.69): only worth returning if class also matches
        if class_s >= 0.70:
            return 0.50
        return 0.0


# ── Public API ────────────────────────────────────────────────────────────────

def find_correlated_cves(
    cve_id: str,
    project_name: str,
    pkg_version: str = "",
    endpoint: str = "",
    vuln_class: str = "",
    cache_dir: Optional[str] = None,
) -> CorrelationResult:
    """Find CVEs of the same project that may share attack patterns.

    Args:
        cve_id:       the CVE being investigated (excluded from results)
        project_name: project/package name to match against
        pkg_version:  version being investigated (not used for scoring yet)
        endpoint:     LLM-suggested endpoint (for future endpoint similarity)
        vuln_class:   LLM-inferred vulnerability class
        cache_dir:    override for the cache directory

    Returns CorrelationResult with up to 3 hints sorted by relevance desc.
    """
    if not project_name:
        return CorrelationResult(reasoning="no project_name provided")

    past = _load_past_results(cache_dir)
    if not past:
        return CorrelationResult(reasoning="no past CVE records found")

    scored: List[tuple[float, dict]] = []
    for rec in past:
        if (rec.get("cve_id") or "").upper() == (cve_id or "").upper():
            continue  # skip self
        score = _score_record(rec, project_name, vuln_class)
        if score >= 0.50:
            scored.append((score, rec))

    if not scored:
        return CorrelationResult(
            reasoning=f"no CVEs found for project '{project_name}' (class={vuln_class})"
        )

    scored.sort(key=lambda t: t[0], reverse=True)
    hints = []
    for relevance, rec in scored[:3]:
        hints.append(CorrelationHint(
            source_cve=rec.get("cve_id", ""),
            endpoint_pattern=rec.get("endpoint", ""),
            bypass_header=rec.get("bypass_header", ""),
            bypass_value=rec.get("bypass_value", ""),
            vuln_class=rec.get("vuln_class", ""),
            confirm_string=rec.get("confirm_string", ""),
            relevance=relevance,
            project=rec.get("project", ""),
        ))

    best = hints[0] if hints else None
    reasoning = (
        f"{len(hints)} hint(s) encontrado(s) para '{project_name}' "
        f"(mejor: {best.source_cve} relevancia={best.relevance:.2f})" if best
        else f"sin hints útiles para '{project_name}'"
    )

    return CorrelationResult(hints=hints, best_hint=best, reasoning=reasoning)


def _endpoint_similarity(ep_a: str, ep_b: str) -> float:
    """Score two API endpoints for structural similarity (0–1).

    Uses path segment overlap rather than string edit distance because
    /api/admin/users and /api/v2/admin/users are more similar than
    their edit distance suggests.
    """
    if not ep_a or not ep_b:
        return 0.0
    # Normalize: lowercase, strip query string and trailing slash
    def _norm(ep: str) -> list:
        ep = ep.lower().split("?")[0].rstrip("/")
        return [seg for seg in ep.split("/") if seg]

    segs_a = _norm(ep_a)
    segs_b = _norm(ep_b)
    if not segs_a or not segs_b:
        return 0.0

    # Exact match
    if segs_a == segs_b:
        return 1.0

    # Count overlapping segments (with position weighting: later segments = less weight)
    _set_a = set(segs_a)
    _set_b = set(segs_b)
    _common = _set_a & _set_b
    if not _common:
        return 0.0

    # Jaccard coefficient weighted by segment count
    _union = _set_a | _set_b
    jaccard = len(_common) / len(_union)

    # Boost if prefix matches (the first segments align)
    _prefix_match = 0
    for sa, sb in zip(segs_a, segs_b, strict=False):
        if sa == sb:
            _prefix_match += 1
        else:
            break
    _prefix_boost = min(0.20, _prefix_match * 0.08)

    return min(1.0, jaccard + _prefix_boost)


def rank_alt_endpoints_by_history(
    alt_endpoints: list,
    project_name: str,
    vuln_class: str = "",
    cache_dir: Optional[str] = None,
) -> list:
    """Re-rank a list of alternative endpoint candidates using historical evidence.

    Takes the LLM-generated alt_endpoints list (from llm_notes['alt_endpoints'])
    and boosts entries whose endpoint path matches previously-verified endpoints
    for the same project/stack.

    Returns the same list with an added 'history_boost' field, sorted by
    (original_score + history_boost) descending.

    Args:
        alt_endpoints:  list of {endpoint, param, score, reason} dicts
        project_name:   project/stack to look up in history
        vuln_class:     CVE class for filtering relevant history
        cache_dir:      override for cache directory
    """
    if not alt_endpoints:
        return []

    past = _load_past_results(cache_dir)
    # Filter to records for this project
    relevant_pasts = []
    for rec in past:
        if not rec.get("endpoint"):
            continue
        proj_score = _project_match_score(project_name, rec.get("project", ""))
        if proj_score < 0.50:
            continue
        class_s = _vuln_class_score(vuln_class, rec.get("vuln_class", ""))
        relevant_pasts.append({
            "endpoint": rec["endpoint"],
            "proj_score": proj_score,
            "class_score": class_s,
        })

    if not relevant_pasts:
        return alt_endpoints  # no history → return unchanged

    # Score each alt endpoint against history
    result = []
    for alt in alt_endpoints:
        ep = alt.get("endpoint", "")
        if not ep:
            continue
        # Find best matching historical endpoint
        best_hist_score = 0.0
        for hist in relevant_pasts:
            ep_sim = _endpoint_similarity(ep, hist["endpoint"])
            # Combined: ep_sim * (proj_score + class_score/2)
            combined = ep_sim * (hist["proj_score"] + hist["class_score"] * 0.5)
            best_hist_score = max(best_hist_score, combined)

        alt_copy = dict(alt)
        alt_copy["history_boost"] = round(best_hist_score * 0.30, 3)  # up to +0.30
        alt_copy["_total"] = alt.get("score", 0.5) + alt_copy["history_boost"]
        result.append(alt_copy)

    # Sort by combined score descending
    result.sort(key=lambda a: a.get("_total", 0.0), reverse=True)
    return result
