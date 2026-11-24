"""
CVE correlation — group and cluster related vulnerabilities.

Given a CVE (or a list), finds:
  - CVEs affecting the same component/vendor/product (from NVD CPE)
  - CVEs with overlapping fix commits (from OSV GIT ranges)
  - CVEs sharing the same CWE class
  - Exploitability score ranking within the cluster
  - Suggested investigation priority order

No hardcoded tables — everything derived live from NVD and OSV APIs.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_API  = "https://api.osv.dev/v1"
_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "binoracle", "correlate")

_CPE_PRODUCT_RE = re.compile(r"cpe:2\.3:[ao]:[^:]+:([^:]+):", re.I)
_CPE_VENDOR_RE  = re.compile(r"cpe:2\.3:[ao]:([^:]+):", re.I)


@dataclass
class CorrelatedCve:
    cve_id:        str
    description:   str = ""
    cvss_score:    float = 0.0
    cvss_severity: str = ""
    published:     str = ""
    cwe_ids:       List[str] = field(default_factory=list)
    cpe_products:  List[str] = field(default_factory=list)
    has_exploit:   bool = False
    shared_repo:   str = ""
    relation:      str = ""  # "same_component" | "same_cwe" | "shared_repo" | "sibling"


@dataclass
class CorrelationResult:
    cve_id:         str
    ok:             bool = False
    component:      str = ""
    vendor:         str = ""
    related:        List[CorrelatedCve] = field(default_factory=list)
    same_component: List[CorrelatedCve] = field(default_factory=list)
    same_cwe:       List[CorrelatedCve] = field(default_factory=list)
    shared_repo:    List[CorrelatedCve] = field(default_factory=list)
    priority_order: List[str]           = field(default_factory=list)
    note:           str = ""
    fetched_at:     float = field(default_factory=time.time)


def _get(url: str, timeout: int = 20) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _post(url: str, body: dict, timeout: int = 20) -> Optional[dict]:
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _cache_path(key: str) -> str:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    safe = re.sub(r"[^\w\-]", "_", key)
    return os.path.join(_CACHE_DIR, safe + ".json")


def _cache_load(key: str, max_age_s: int = 86400) -> Optional[dict]:
    p = _cache_path(key)
    try:
        if os.path.exists(p) and time.time() - os.path.getmtime(p) < max_age_s:
            return json.loads(open(p).read())
    except Exception:
        pass
    return None


def _cache_save(key: str, data: dict) -> None:
    try:
        open(_cache_path(key), "w").write(json.dumps(data))
    except Exception:
        pass


def _extract_cpes(nvd_item: dict) -> List[str]:
    """Extract CPE strings from an NVD CVE item."""
    cpes = []
    try:
        for cfg in nvd_item.get("cve", {}).get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        cpes.append(m.get("criteria", ""))
    except Exception:
        pass
    return cpes


def _extract_cwes(nvd_item: dict) -> List[str]:
    try:
        cwes = []
        for w in (nvd_item.get("cve", {}).get("weaknesses") or []):
            for d in w.get("description", []):
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])
        return cwes
    except Exception:
        return []


def _fetch_nvd_cve(cve_id: str) -> Optional[dict]:
    cached = _cache_load(f"nvd_{cve_id}")
    if cached:
        return cached
    data = _get(f"{_NVD_API}?cveId={cve_id}")
    if data and data.get("vulnerabilities"):
        item = data["vulnerabilities"][0]
        _cache_save(f"nvd_{cve_id}", item)
        return item
    return None


def _nvd_search_by_cpe(keyword: str, limit: int = 20) -> List[dict]:
    """Search NVD for CVEs mentioning a keyword in keywordSearch."""
    cached = _cache_load(f"nvd_kw_{keyword}_{limit}")
    if cached:
        return cached
    data = _get(f"{_NVD_API}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={limit}")
    items = []
    if data:
        items = data.get("vulnerabilities", [])
    _cache_save(f"nvd_kw_{keyword}_{limit}", items)
    return items


def _osv_query_package(ecosystem: str, package: str, limit: int = 20) -> List[dict]:
    """Query OSV for vulnerabilities affecting a package."""
    body = {"query": {"package": {"ecosystem": ecosystem, "name": package}}}
    cached = _cache_load(f"osv_{ecosystem}_{package}")
    if cached:
        return cached
    data = _post(f"{_OSV_API}/query", body)
    vulns = []
    if data:
        vulns = data.get("vulns", [])[:limit]
    _cache_save(f"osv_{ecosystem}_{package}", vulns)
    return vulns


def _osv_get(cve_id: str) -> Optional[dict]:
    cached = _cache_load(f"osv_vuln_{cve_id}")
    if cached:
        return cached
    data = _get(f"{_OSV_API}/vulns/{cve_id}")
    if data:
        _cache_save(f"osv_vuln_{cve_id}", data)
    return data


def _nvd_item_to_correlated(item: dict, relation: str, shared_repo: str = "") -> CorrelatedCve:
    cve   = item.get("cve", {})
    cve_id = cve.get("id", "")
    desc  = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score = 0.0
    sev   = ""
    try:
        m = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in m and m[key]:
                score = float(m[key][0].get("cvssData", {}).get("baseScore", 0) or 0)
                sev   = m[key][0].get("cvssData", {}).get("baseSeverity", "") or ""
                break
    except Exception:
        pass
    cpes = _extract_cpes(item)
    return CorrelatedCve(
        cve_id=cve_id, description=desc[:200], cvss_score=score,
        cvss_severity=sev, published=cve.get("published", "")[:10],
        cwe_ids=_extract_cwes(item), cpe_products=cpes[:5],
        relation=relation, shared_repo=shared_repo,
    )


def _rank_by_exploitability(cvs: List[CorrelatedCve]) -> List[str]:
    """Sort CVE IDs by exploitability: high CVSS + has_exploit first."""
    scored = []
    for c in cvs:
        priority = c.cvss_score * 10
        if c.has_exploit:
            priority += 30
        if c.relation == "same_component":
            priority += 5
        if c.relation == "shared_repo":
            priority += 3
        scored.append((c.cve_id, priority))
    scored.sort(key=lambda x: x[1], reverse=True)
    return [cve_id for cve_id, _ in scored]


def correlate_cve(cve_id: str, max_related: int = 15) -> CorrelationResult:
    """
    Main entry point. Given a CVE ID:
      1. Fetch the CVE from NVD → extract CPE product/vendor + CWE IDs
      2. Search NVD for recent CVEs in the same product/keyword
      3. Query OSV for the same affected component (across ecosystems)
      4. Find CVEs sharing fix commits in the same repo (OSV GIT ranges)
      5. Rank by exploitability and return a CorrelationResult

    All network calls are disk-cached for 24 hours.
    """
    result = CorrelationResult(cve_id=cve_id)

    # 1. Fetch base CVE
    item = _fetch_nvd_cve(cve_id)
    if not item:
        result.note = f"CVE {cve_id} not found in NVD"
        return result

    cpes = _extract_cpes(item)
    cwes = _extract_cwes(item)

    # Extract primary product/vendor from first CPE
    product = vendor = ""
    for cpe in cpes:
        vm = _CPE_VENDOR_RE.search(cpe)
        pm = _CPE_PRODUCT_RE.search(cpe)
        if vm:
            vendor = vm.group(1)
        if pm:
            product = pm.group(1)
        if product and vendor:
            break

    result.component = product or cve_id
    result.vendor    = vendor

    seen_ids: set = {cve_id}

    # 2. NVD keyword search on product name
    if product:
        kw_items = _nvd_search_by_cpe(product, limit=max_related)
        for kw_item in kw_items:
            kid = (kw_item.get("cve") or {}).get("id", "")
            if kid and kid not in seen_ids:
                seen_ids.add(kid)
                cc = _nvd_item_to_correlated(kw_item, "same_component")
                result.same_component.append(cc)
                result.related.append(cc)

    # 3. CWE-based correlation — find CVEs with same CWE in NVD (using keywordSearch fallback)
    if cwes and not result.same_component:
        for cwe in cwes[:2]:
            cw_items = _nvd_search_by_cpe(cwe, limit=10)
            for cw_item in cw_items:
                kid = (cw_item.get("cve") or {}).get("id", "")
                if kid and kid not in seen_ids:
                    seen_ids.add(kid)
                    cc = _nvd_item_to_correlated(cw_item, "same_cwe")
                    result.same_cwe.append(cc)
                    result.related.append(cc)

    # 4. OSV — find shared Git repo fix commits
    osv_base = _osv_get(cve_id)
    if osv_base:
        for affected in (osv_base.get("affected") or []):
            for rng in (affected.get("ranges") or []):
                if rng.get("type") == "GIT":
                    repo_url = rng.get("repo", "")
                    if not repo_url:
                        continue
                    # Find other OSV vulns in same repo via related alias search
                    aliases = osv_base.get("aliases", [])
                    for alias in aliases[:5]:
                        if alias != cve_id and alias not in seen_ids:
                            seen_ids.add(alias)
                            alias_data = _osv_get(alias)
                            if alias_data:
                                # Build a minimal CorrelatedCve from OSV data
                                desc = next(
                                    (d.get("detail", "") for d in [alias_data]),
                                    alias_data.get("summary", "")
                                )[:200]
                                cc = CorrelatedCve(
                                    cve_id=alias, description=desc,
                                    shared_repo=repo_url, relation="shared_repo",
                                )
                                result.shared_repo.append(cc)
                                result.related.append(cc)

    # 5. Rank
    result.priority_order = _rank_by_exploitability(result.related)
    result.ok = True
    result.note = (
        f"{len(result.related)} related CVEs found "
        f"({len(result.same_component)} same_component, "
        f"{len(result.same_cwe)} same_cwe, "
        f"{len(result.shared_repo)} shared_repo)"
    )
    return result


def render_correlation(r: CorrelationResult, lang: str = "es") -> str:
    es = lang == "es"
    hdr = "## Correlación CVE" if es else "## CVE Correlation"
    out = [f"{hdr} — `{r.cve_id}`\n"]
    if not r.ok:
        out.append(f"_{r.note}_")
        return "\n".join(out)

    out.append(f"**Componente:** `{r.component}`  |  **Vendor:** `{r.vendor}`")
    out.append(f"**CVEs relacionados:** {len(r.related)} · {r.note}\n")

    if r.priority_order:
        label = "Orden de investigación recomendado" if es else "Recommended investigation order"
        out.append(f"### {label}")
        for i, cid in enumerate(r.priority_order[:10], 1):
            cc = next((c for c in r.related if c.cve_id == cid), None)
            if cc:
                score_str = f"CVSS {cc.cvss_score:.1f}" if cc.cvss_score else "n/a"
                out.append(f"{i}. `{cc.cve_id}` — {score_str} · {cc.relation} · {cc.description[:80]}")
        out.append("")

    for section, items, label_es, label_en in [
        (r.same_component, r.same_component, "Mismo componente", "Same component"),
        (r.same_cwe,       r.same_cwe,       "Mismo CWE",        "Same CWE"),
        (r.shared_repo,    r.shared_repo,     "Mismo repositorio","Shared repo"),
    ]:
        if not items:
            continue
        label = label_es if es else label_en
        out.append(f"### {label} ({len(items)})")
        out.append("| CVE | CVSS | Publicado | Descripción |")
        out.append("|-----|------|-----------|-------------|")
        for cc in sorted(items, key=lambda x: x.cvss_score, reverse=True)[:8]:
            score_str = f"{cc.cvss_score:.1f}" if cc.cvss_score else "—"
            out.append(f"| `{cc.cve_id}` | {score_str} | {cc.published or '—'} | {cc.description[:70]} |")
        out.append("")

    return "\n".join(out)
