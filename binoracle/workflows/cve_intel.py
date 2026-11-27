"""
CVE intelligence enrichment from public free sources.

Sources:
  OSV.dev            — patch commit, aliases (GHSA / PYSEC), affected version ranges
  Nuclei Templates   — endpoint, http_method, confirm_string, payload, CVSS, EPSS, CWE
  PoC-in-GitHub      — public PoC repositories (nomi-sec index)
  GitHub Patch Diff  — unified diff of the fixing commit (patch_diff_analysis)

The enrichment is **additive and conservative**:
  - Only fills empty / missing fields in llm_notes (never overwrites analyst data)
  - All enriched fields are prefixed with ``_intel_`` so they're auditable
  - ``force=True`` overwrites even existing values

CLI:
  python -m binoracle.workflows.cve_intel CVE-2024-56201
  python -m binoracle.workflows.cve_intel --all --batch-dir binoracle_batch_reports/
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import requests

# Rate-limit: be polite to free public APIs
_RATE_SLEEP = 0.4  # seconds between requests


# ---------------------------------------------------------------------------
# 1. OSV.dev
# ---------------------------------------------------------------------------

def query_osv(cve_id: str) -> dict:
    """Return OSV data: aliases, patch_commit_urls, severity, affected_versions."""
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return {}
        d = r.json()
    except Exception:
        return {}

    # Extract patch commit URLs
    patch_commits = []
    for ref in d.get("references", []):
        ref_url = ref.get("url", "")
        if re.search(r"/commit/[0-9a-f]{7,40}", ref_url):
            patch_commits.append(ref_url)
        elif "/compare/" in ref_url or "/pull/" in ref_url:
            patch_commits.append(ref_url)

    # Extract GHSA advisory URL
    ghsa_url = ""
    aliases = d.get("aliases", [])
    for alias in aliases:
        if alias.startswith("GHSA-"):
            ghsa_url = f"https://github.com/advisories/{alias}"
            break

    # Affected version ranges
    versions: list[str] = []
    for aff in d.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                v = ev.get("introduced") or ev.get("fixed") or ev.get("last_affected")
                if v and v not in ("0", ""):
                    versions.append(v)

    return {
        "aliases": aliases,
        "patch_commits": patch_commits,
        "ghsa_url": ghsa_url,
        "affected_versions": versions[:10],
        "published": d.get("published", ""),
        "modified": d.get("modified", ""),
        "severity": _extract_osv_severity(d),
        "summary": d.get("summary", "") or d.get("details", "")[:300],
    }


def _extract_osv_severity(d: dict) -> str:
    for sev in d.get("severity", []):
        score = sev.get("score", "")
        if score:
            return str(score)
    return ""


# ---------------------------------------------------------------------------
# 2. GitHub Patch Diff
# ---------------------------------------------------------------------------

def fetch_github_patch_diff(commit_url: str) -> str:
    """Fetch unified diff for a GitHub commit URL.

    Converts:
      https://github.com/owner/repo/commit/SHA
    to:
      https://github.com/owner/repo/commit/SHA.diff
    """
    if not commit_url or "github.com" not in commit_url:
        return ""
    # Normalize to .diff URL
    diff_url = re.sub(r"(github\.com/.+/commit/[0-9a-f]{7,40})(\.diff)?$",
                      r"\1.diff", commit_url)
    if not diff_url.endswith(".diff"):
        diff_url += ".diff"
    try:
        r = requests.get(diff_url, timeout=20, headers={"Accept": "text/plain"})
        if r.status_code != 200:
            return ""
        # Trim to reasonable size
        return r.text[:8000]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 3. Nuclei Templates
# ---------------------------------------------------------------------------

_NUCLEI_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
_NUCLEI_PATHS = [
    "http/cves/{year}/{cve_id}.yaml",
    "http/cves/{year}/{cve_id_lower}.yaml",
    "cves/{year}/{cve_id}.yaml",
    "vulnerabilities/{cve_id}.yaml",
]


def fetch_nuclei_template(cve_id: str) -> dict:
    """Download and parse the Nuclei template for a CVE, if one exists."""
    year_m = re.match(r"CVE-(\d{4})-", cve_id.upper())
    if not year_m:
        return {}
    year = year_m.group(1)
    cve_upper = cve_id.upper()
    cve_lower = cve_id.lower()

    yaml_text = ""
    for tmpl in _NUCLEI_PATHS:
        url = f"{_NUCLEI_BASE}/{tmpl.format(year=year, cve_id=cve_upper, cve_id_lower=cve_lower)}"
        try:
            r = requests.get(url, timeout=12)
            if r.status_code == 200 and r.text.strip().startswith("id:"):
                yaml_text = r.text
                break
        except Exception:
            continue

    if not yaml_text:
        return {}

    return _parse_nuclei_yaml(yaml_text)


def _parse_nuclei_yaml(text: str) -> dict:
    """Parse Nuclei YAML into enrichment fields without full YAML library overhead."""
    try:
        import yaml as _yaml
        d = _yaml.safe_load(text)
    except Exception:
        # Fallback to regex parsing
        return _parse_nuclei_yaml_regex(text)

    if not isinstance(d, dict):
        return {}

    info = d.get("info", {}) or {}
    result: dict = {}

    # Basic metadata
    result["nuclei_name"] = info.get("name", "")
    result["nuclei_severity"] = info.get("severity", "")
    result["nuclei_tags"] = info.get("tags", "")
    result["nuclei_verified"] = bool((info.get("metadata") or {}).get("verified"))
    result["nuclei_max_requests"] = int((info.get("metadata") or {}).get("max-request", 0) or 0)

    # CVSS / EPSS / CWE
    cls = info.get("classification") or {}
    result["cvss_metrics"] = cls.get("cvss-metrics", "")
    result["cvss_score"] = str(cls.get("cvss-score", ""))
    result["cwe_id"] = cls.get("cwe-id", "")
    result["epss_score"] = str(cls.get("epss-score", ""))
    result["cpe"] = cls.get("cpe", "")

    # Shodan query
    shodan = (info.get("metadata") or {}).get("shodan-query", "")
    if isinstance(shodan, list):
        shodan = shodan[0] if shodan else ""
    result["shodan_query"] = str(shodan)

    # HTTP requests
    http_blocks = d.get("http", []) or d.get("requests", []) or []
    if http_blocks:
        _extract_http_block(http_blocks[0], result)

    # Variables (payload hints)
    variables = d.get("variables") or {}
    if isinstance(variables, dict):
        result["nuclei_variables"] = {k: str(v)[:200] for k, v in variables.items()}

    return result


def _extract_http_block(blk: dict, result: dict) -> None:
    """Populate result with endpoint, method, confirm_string from one HTTP block."""
    # Method
    method = blk.get("method", "")
    if method:
        result["http_method"] = method.upper()

    # Path/endpoint
    paths = blk.get("path", []) or []
    if paths:
        ep = str(paths[0]).replace("{{BaseURL}}", "").replace("{{Hostname}}", "")
        ep = ep.strip().split("?")[0]  # strip querystring for clean endpoint
        if ep:
            result["endpoint"] = ep

    # Raw requests (some templates use raw: instead of path:)
    raws = blk.get("raw", []) or []
    for raw in raws[:1]:
        lines = str(raw).strip().splitlines()
        if lines:
            m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", lines[0])
            if m:
                result.setdefault("http_method", m.group(1))
                ep = m.group(2).strip()
                if ep and ep != "HTTP/1.1":
                    result.setdefault("endpoint", ep.split("?")[0])
        # Body (POST data)
        if "\n\n" in str(raw):
            body = str(raw).split("\n\n", 1)[1].strip()
            if body:
                result.setdefault("nuclei_body", body[:500])

    # Matchers → confirm_string
    matchers = blk.get("matchers", []) or []
    confirm_candidates: list[str] = []
    for m in matchers:
        if isinstance(m, dict):
            words = m.get("words", [])
            regexes = m.get("regex", [])
            if words and isinstance(words, list):
                confirm_candidates.extend([str(w)[:200] for w in words[:2]])
            elif regexes and isinstance(regexes, list):
                confirm_candidates.extend([str(rx)[:200] for rx in regexes[:1]])
    if confirm_candidates:
        result["confirm_string"] = confirm_candidates[0]
        result["confirm_string_all"] = confirm_candidates[:5]

    # Headers
    hdrs = blk.get("headers", {}) or {}
    if hdrs:
        result["nuclei_headers"] = {k: str(v)[:200] for k, v in hdrs.items()}


def _parse_nuclei_yaml_regex(text: str) -> dict:
    """Regex-based fallback for Nuclei YAML parsing (no PyYAML)."""
    result: dict = {}
    # method
    for line in text.splitlines():
        m = re.match(r"^\s+method:\s+(\w+)", line)
        if m:
            result["http_method"] = m.group(1).upper()
            break
    # path
    m = re.search(r'path:\s*\n\s+-\s+"?\{\{BaseURL\}\}(/[^\s"]+)', text)
    if m:
        result["endpoint"] = m.group(1)
    # matchers word
    m = re.search(r"words:\s*\n\s+-\s+['\"](.+?)['\"]", text)
    if m:
        result["confirm_string"] = m.group(1)
    # severity
    m = re.search(r"severity:\s+(\w+)", text)
    if m:
        result["nuclei_severity"] = m.group(1)
    # cvss score
    m = re.search(r"cvss-score:\s+([\d.]+)", text)
    if m:
        result["cvss_score"] = m.group(1)
    # cwe
    m = re.search(r"cwe-id:\s+(CWE-\d+)", text)
    if m:
        result["cwe_id"] = m.group(1)
    # epss
    m = re.search(r"epss-score:\s+([\d.]+)", text)
    if m:
        result["epss_score"] = m.group(1)
    return result


# ---------------------------------------------------------------------------
# 4. PoC-in-GitHub index
# ---------------------------------------------------------------------------

_POC_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"


def query_poc_github(cve_id: str) -> list[dict]:
    """Return up to 10 PoC repositories for a CVE from nomi-sec index."""
    year_m = re.match(r"CVE-(\d{4})-", cve_id.upper())
    if not year_m:
        return []
    year = year_m.group(1)
    url = f"{_POC_BASE}/{year}/{cve_id.upper()}.json"
    try:
        r = requests.get(url, timeout=12)
        if r.status_code != 200:
            return []
        pocs = r.json()
        if not isinstance(pocs, list):
            return []
        return [
            {
                "repo": p.get("full_name", ""),
                "url": p.get("html_url", ""),
                "description": str(p.get("description", ""))[:200],
                "stars": p.get("stargazers_count", 0),
                "language": p.get("language", ""),
            }
            for p in pocs[:10]
            if p.get("html_url")
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 5. GHSA advisory (GitHub)
# ---------------------------------------------------------------------------

def fetch_ghsa_advisory(ghsa_id: str) -> dict:
    """Fetch a GitHub Security Advisory by GHSA-ID via public API."""
    if not ghsa_id.startswith("GHSA-"):
        return {}
    url = f"https://api.github.com/advisories/{ghsa_id}"
    try:
        r = requests.get(url, timeout=12,
                         headers={"Accept": "application/vnd.github+json"})
        if r.status_code != 200:
            return {}
        d = r.json()
        return {
            "ghsa_severity": d.get("severity", ""),
            "ghsa_cvss": (d.get("cvss") or {}).get("vector_string", ""),
            "ghsa_cwes": [(c.get("cwe_id", ""), c.get("name", ""))
                          for c in (d.get("cwes") or [])[:3]],
            "ghsa_description": (d.get("description") or "")[:500],
            "ghsa_vulnerabilities": [
                {
                    "package": (v.get("package") or {}).get("name", ""),
                    "ecosystem": (v.get("package") or {}).get("ecosystem", ""),
                    "vulnerable_range": v.get("vulnerable_version_range", ""),
                    "patched_version": v.get("first_patched_version", ""),
                }
                for v in (d.get("vulnerabilities") or [])[:3]
            ],
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 6. Main enrichment entry point
# ---------------------------------------------------------------------------

def enrich_cve(cve_id: str, notes: dict, force: bool = False,
               on_step=None) -> dict:
    """
    Enrich ``notes`` dict with data from OSV, Nuclei, PoC-in-GitHub, GHSA.

    Returns a NEW dict with enriched fields merged in.
    Does NOT mutate the input.
    By default only fills fields that are empty / missing (use force=True to override).
    All new fields are prefixed with ``_intel_``.
    """
    step = on_step or (lambda _m: None)
    out = dict(notes)

    # --- OSV ---
    step(f"[intel] querying OSV.dev for {cve_id}...")
    osv = query_osv(cve_id)
    time.sleep(_RATE_SLEEP)
    if osv:
        _set(out, "_intel_osv_aliases", osv.get("aliases"), force)
        _set(out, "_intel_patch_commits", osv.get("patch_commits"), force)
        _set(out, "_intel_ghsa_url", osv.get("ghsa_url"), force)
        _set(out, "_intel_affected_versions", osv.get("affected_versions"), force)
        _set(out, "_intel_osv_severity", osv.get("severity"), force)
        _set(out, "_intel_summary", osv.get("summary"), force)

        # Patch diff from first commit
        patch_commits = osv.get("patch_commits") or []
        if patch_commits and (force or not out.get("patch_diff_analysis")):
            step(f"[intel] fetching patch diff from {patch_commits[0][:60]}...")
            diff = fetch_github_patch_diff(patch_commits[0])
            time.sleep(_RATE_SLEEP)
            if diff:
                _set(out, "patch_diff_analysis", diff[:6000], force)
                # Structural analysis via diff_analyzer (fix_type, bypass_hints, sinks)
                if force or not out.get("patch_diff_structured"):
                    try:
                        from .diff_analyzer import analyze_patch_diff as _apd
                        _structured = _apd(diff)
                        # Strip empty lists/None to keep the stored dict lean
                        _lean = {k: v for k, v in _structured.items()
                                 if v not in (None, [], "", False, "unknown", "other")}
                        if _lean:
                            _set(out, "patch_diff_structured", _lean, force)
                            if _lean.get("fix_type"):
                                step(f"[intel] patch fix_type={_lean['fix_type']!r}, "
                                     f"bypass_hints={_lean.get('bypass_hints', [])}")
                    except Exception as _da_err:
                        step(f"[intel] diff_analyzer warning: {_da_err}")

        # GHSA details
        ghsa_ids = [a for a in (osv.get("aliases") or []) if a.startswith("GHSA-")]
        if ghsa_ids:
            step(f"[intel] fetching GHSA advisory {ghsa_ids[0]}...")
            ghsa = fetch_ghsa_advisory(ghsa_ids[0])
            time.sleep(_RATE_SLEEP)
            if ghsa:
                for k, v in ghsa.items():
                    _set(out, f"_intel_{k}", v, force)
                # Backfill empty llm_notes fields from GHSA
                if ghsa.get("ghsa_vulnerabilities"):
                    vv = ghsa["ghsa_vulnerabilities"][0]
                    if vv.get("patched_version"):
                        _set(out, "patched_version", vv["patched_version"], False)
                    if vv.get("vulnerable_range"):
                        _set(out, "affected_version", vv["vulnerable_range"], False)

    # --- Nuclei Template ---
    step(f"[intel] fetching Nuclei template for {cve_id}...")
    nuclei = fetch_nuclei_template(cve_id)
    time.sleep(_RATE_SLEEP)
    if nuclei:
        for k, v in nuclei.items():
            _set(out, f"_intel_nuclei_{k}", v, force)

        # Backfill core verification fields from Nuclei (only if empty)
        if nuclei.get("endpoint"):
            _set(out, "endpoint", nuclei["endpoint"], False)
        if nuclei.get("http_method"):
            _set(out, "http_method", nuclei["http_method"], False)
        if nuclei.get("confirm_string"):
            _set(out, "confirm_string", nuclei["confirm_string"], False)
        if nuclei.get("cvss_metrics"):
            _set(out, "_intel_cvss", nuclei["cvss_metrics"], force)
        if nuclei.get("cvss_score"):
            _set(out, "_intel_cvss_score", nuclei["cvss_score"], force)
        if nuclei.get("cwe_id"):
            _set(out, "_intel_cwe", nuclei["cwe_id"], force)
        if nuclei.get("epss_score"):
            _set(out, "_intel_epss", nuclei["epss_score"], force)
        if nuclei.get("nuclei_verified"):
            _set(out, "_intel_nuclei_human_verified", True, force)

    # --- PoC-in-GitHub ---
    step(f"[intel] querying PoC-in-GitHub index for {cve_id}...")
    pocs = query_poc_github(cve_id)
    time.sleep(_RATE_SLEEP)
    if pocs:
        _set(out, "_intel_poc_repos", pocs, force)
        step(f"[intel] found {len(pocs)} public PoC(s) for {cve_id}")
        # Sort by stars, pick top-starred
        top = sorted(pocs, key=lambda p: p.get("stars", 0), reverse=True)
        _set(out, "_intel_poc_top_url", top[0]["url"], force)

    return out


def _set(d: dict, key: str, value, force: bool) -> None:
    """Set d[key] = value only if the key is empty/missing, or force=True."""
    if value is None:
        return
    if isinstance(value, (list, dict)) and not value:
        return
    if isinstance(value, str) and not value.strip():
        return
    if force or not d.get(key):
        d[key] = value


# ---------------------------------------------------------------------------
# 7. Batch enrichment for all CVE JSONs
# ---------------------------------------------------------------------------

def enrich_batch_reports(batch_dir: str, force: bool = False,
                         on_step=None) -> dict[str, dict]:
    """
    Enrich all CVE JSONs in ``batch_dir``.

    For each file:
      1. Reads ``llm_notes``
      2. Calls ``enrich_cve``
      3. Writes updated ``llm_notes`` back to the file
      4. Returns a summary {cve_id: summary_dict}

    Does NOT overwrite ``attempt_evidence`` or ``dynamic_verify``.
    """
    step = on_step or (lambda _m: None)
    results: dict[str, dict] = {}
    batch_path = Path(batch_dir)
    files = sorted(batch_path.glob("CVE-*.json"))
    step(f"[intel] enriching {len(files)} CVE files in {batch_dir}")

    for path in files:
        cve_id = path.stem
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            step(f"[intel] SKIP {cve_id}: cannot read JSON ({e})")
            continue

        notes = data.get("llm_notes", {})
        step(f"\n[intel] --- {cve_id} ---")
        enriched = enrich_cve(cve_id, notes, force=force, on_step=step)

        # Count new fields added
        new_fields = [k for k in enriched if k not in notes and enriched[k]]
        updated_fields = [k for k in enriched
                          if k in notes and enriched[k] != notes.get(k)
                          and not k.startswith("_intel_")]

        data["llm_notes"] = enriched
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        summary = {
            "new_fields": new_fields,
            "updated_fields": updated_fields,
            "nuclei": bool(enriched.get("_intel_nuclei_name")),
            "poc_count": len(enriched.get("_intel_poc_repos") or []),
            "patch_diff": bool(enriched.get("patch_diff_analysis")),
            "confirm_string": enriched.get("confirm_string", ""),
        }
        results[cve_id] = summary

        step(f"[intel] {cve_id}: +{len(new_fields)} fields, "
             f"nuclei={'yes' if summary['nuclei'] else 'no'}, "
             f"pocs={summary['poc_count']}, "
             f"patch_diff={'yes' if summary['patch_diff'] else 'no'}, "
             f"confirm_string={summary['confirm_string'][:30] if summary['confirm_string'] else 'N/A'}")

    return results


# ---------------------------------------------------------------------------
# 8. Pipeline integration hook  (called from cve_agent.py before LLM analysis)
# ---------------------------------------------------------------------------

def auto_enrich_before_analysis(cve_id: str, notes: dict) -> dict:
    """
    Lightweight enrichment hook for the CVE agent pipeline.

    Only fetches OSV + Nuclei (skips PoC-in-GitHub to stay fast).
    Does NOT overwrite any existing analyst fields.
    Returns enriched notes.
    """
    out = dict(notes)

    # OSV: get patch commit for patch_diff_analysis
    osv = query_osv(cve_id)
    if osv:
        patch_commits = osv.get("patch_commits") or []
        if patch_commits and not out.get("patch_diff_analysis"):
            diff = fetch_github_patch_diff(patch_commits[0])
            if diff:
                out["patch_diff_analysis"] = diff[:6000]
                # Structured diff analysis (fix_type, bypass_hints) for exploit loop
                if not out.get("patch_diff_structured"):
                    try:
                        from .diff_analyzer import analyze_patch_diff as _apd
                        _lean = {k: v for k, v in _apd(diff).items()
                                 if v not in (None, [], "", False, "unknown", "other")}
                        if _lean:
                            out["patch_diff_structured"] = _lean
                    except Exception:
                        pass
        for alias in osv.get("aliases") or []:
            if alias.startswith("GHSA-") and not out.get("_intel_ghsa_url"):
                out["_intel_ghsa_url"] = f"https://github.com/advisories/{alias}"
                out["_intel_ghsa_id"] = alias

    # Nuclei: get endpoint / confirm_string
    nuclei = fetch_nuclei_template(cve_id)
    if nuclei:
        if nuclei.get("endpoint") and not out.get("endpoint"):
            out["endpoint"] = nuclei["endpoint"]
        if nuclei.get("http_method") and not out.get("http_method"):
            out["http_method"] = nuclei["http_method"]
        if nuclei.get("confirm_string") and not out.get("confirm_string"):
            out["confirm_string"] = nuclei["confirm_string"]
        if nuclei.get("cvss_score"):
            out.setdefault("_intel_cvss_score", nuclei["cvss_score"])
        if nuclei.get("epss_score"):
            out.setdefault("_intel_epss", nuclei["epss_score"])
        if nuclei.get("cwe_id"):
            out.setdefault("_intel_cwe", nuclei["cwe_id"])

    return out


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="CVE intelligence enrichment")
    ap.add_argument("cve_ids", nargs="*", metavar="CVE-ID",
                    help="CVE IDs to enrich (e.g. CVE-2024-56201)")
    ap.add_argument("--all", action="store_true",
                    help="Enrich all CVE JSONs in --batch-dir")
    ap.add_argument("--batch-dir", default="binoracle_batch_reports",
                    help="Directory with CVE JSON files (default: binoracle_batch_reports)")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite existing fields (default: only fill empty fields)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print enriched notes without writing files")
    args = ap.parse_args()

    if args.all:
        results = enrich_batch_reports(
            args.batch_dir, force=args.force,
            on_step=lambda m: print(m))
        print("\n=== ENRICHMENT SUMMARY ===")
        for cve_id, s in results.items():
            print(f"  {cve_id}: nuclei={s['nuclei']}, pocs={s['poc_count']}, "
                  f"patch_diff={s['patch_diff']}, "
                  f"confirm={s['confirm_string'][:30] if s['confirm_string'] else 'N/A'}, "
                  f"new_fields={len(s['new_fields'])}")
    elif args.cve_ids:
        for cve_id in args.cve_ids:
            print(f"\n=== Enriching {cve_id} ===")
            # Read existing JSON if available
            json_path = Path(args.batch_dir) / f"{cve_id}.json"
            notes: dict = {}
            if json_path.exists():
                with open(json_path) as f:
                    notes = json.load(f).get("llm_notes", {})
            enriched = enrich_cve(cve_id, notes, force=args.force,
                                  on_step=lambda m: print(m))
            if args.dry_run:
                # Print only the new/changed intel fields
                new = {k: v for k, v in enriched.items()
                       if k not in notes or (enriched[k] != notes.get(k)
                                             and k.startswith("_intel_"))}
                print(json.dumps(new, indent=2, ensure_ascii=False))
            else:
                if json_path.exists():
                    with open(json_path) as f:
                        data = json.load(f)
                    data["llm_notes"] = enriched
                    with open(json_path, "w") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    print(f"[OK] {json_path} updated")
                else:
                    print(json.dumps(enriched, indent=2, ensure_ascii=False))
    else:
        ap.print_help()
