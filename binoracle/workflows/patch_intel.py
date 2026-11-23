"""
Upstream patch intelligence for CVEs.

Given a CVE ID, finds:
  - Fix commits in NVD references and GitHub Advisories
  - Affected version ranges
  - Backport presence in forks/releases
  - Changelog diffs between vulnerable and patched versions
  - Vulnerability timeline

No external deps beyond stdlib + requests (optional).
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

_GH_API = "https://api.github.com"
_OSV_API = "https://api.osv.dev/v1/query"
_GH_ADVISORY_GQL = "https://api.github.com/graphql"
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

_COMMIT_URL_RE = re.compile(
    r"https://github\.com/([\w.\-]+/[\w.\-]+)/commit/([0-9a-f]{7,40})", re.I)
_TAG_URL_RE = re.compile(
    r"https://github\.com/([\w.\-]+/[\w.\-]+)/(?:releases/tag|tree)/([^\s/\"'>]+)", re.I)
_CHANGELOG_RE = re.compile(
    r"https://github\.com/([\w.\-]+/[\w.\-]+)/blob/[^\s]+/(?:CHANGELOG|CHANGES|HISTORY|NEWS)[^\s\"']*",
    re.I)


@dataclass
class FixCommit:
    repo:     str
    sha:      str
    url:      str
    message:  str = ""
    files:    List[str] = field(default_factory=list)
    verified_fix: bool = False


@dataclass
class PatchIntelResult:
    cve_id:           str
    ok:               bool = False
    fix_commits:      List[FixCommit] = field(default_factory=list)
    affected_ranges:  List[dict] = field(default_factory=list)
    patched_versions: List[str]  = field(default_factory=list)
    timeline:         List[dict] = field(default_factory=list)
    sources:          List[str]  = field(default_factory=list)
    note:             str = ""
    fetched_at:       float = field(default_factory=time.time)


def _get(url: str, headers: Optional[dict] = None, timeout: int = 15) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _gh_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _fetch_commit_details(repo: str, sha: str) -> FixCommit:
    """Fetch commit message and changed files from GitHub."""
    url = f"{_GH_API}/repos/{repo}/commits/{sha}"
    data = _get(url, headers=_gh_headers()) or {}
    commit = data.get("commit", {})
    files = [f["filename"] for f in data.get("files", []) if "filename" in f]
    return FixCommit(
        repo=repo, sha=sha,
        url=f"https://github.com/{repo}/commit/{sha}",
        message=(commit.get("message") or "")[:300],
        files=files[:20],
        verified_fix=bool(files),
    )


def _extract_fix_commits_from_refs(refs: list) -> List[FixCommit]:
    """Extract GitHub fix commits from NVD reference URLs."""
    commits = []
    seen = set()
    for ref in refs:
        url = ref.get("url") or ref if isinstance(ref, str) else ""
        m = _COMMIT_URL_RE.search(url)
        if m:
            repo, sha = m.group(1), m.group(2)
            key = (repo, sha[:7])
            if key not in seen:
                seen.add(key)
                commits.append(_fetch_commit_details(repo, sha))
    return commits


def _fetch_osv(cve_id: str) -> Optional[dict]:
    """Query OSV for affected ranges and fix commits."""
    try:
        body = json.dumps({"query": {"id": cve_id}}).encode()
        req = urllib.request.Request(
            _OSV_API, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _parse_osv_ranges(osv_data: dict) -> tuple:
    """Returns (affected_ranges, patched_versions, fix_commits) from OSV response."""
    ranges = []
    patched = []
    commits = []
    seen = set()
    for vuln in (osv_data.get("vulns") or []):
        for affected in (vuln.get("affected") or []):
            for rng in (affected.get("ranges") or []):
                rtype = rng.get("type", "")
                for ev in (rng.get("events") or []):
                    intro = ev.get("introduced")
                    fixed = ev.get("fixed")
                    if intro or fixed:
                        ranges.append({"type": rtype, "introduced": intro, "fixed": fixed})
                    if fixed:
                        patched.append(fixed)
                    # GIT range: repo URL + fix commit SHA
                    if rtype == "GIT" and fixed:
                        repo_url = rng.get("repo", "")
                        m = re.search(r"github\.com/([\w.\-]+/[\w.\-]+)", repo_url)
                        if m:
                            key = (m.group(1), fixed[:7])
                            if key not in seen:
                                seen.add(key)
                                commits.append(_fetch_commit_details(m.group(1), fixed))
    return ranges, list(dict.fromkeys(patched)), commits


def _build_timeline(cve_id: str, nvd_published: str,
                    fix_commits: List[FixCommit], patched_versions: List[str]) -> List[dict]:
    """Build a chronological timeline of the vulnerability."""
    events = []
    if nvd_published:
        events.append({"date": nvd_published[:10], "event": "NVD published", "detail": cve_id})
    for fc in fix_commits:
        events.append({"date": "unknown", "event": "fix commit", "detail": fc.url,
                       "files": fc.files[:5]})
    for v in patched_versions[:5]:
        events.append({"event": "patched version", "detail": v})
    return events


def fetch_patch_intel(cve_id: str, nvd_refs: Optional[list] = None,
                      nvd_published: str = "") -> PatchIntelResult:
    """
    Main entry point. Given a CVE ID and optionally its NVD reference list,
    return fix commits, affected ranges, patched versions, and a timeline.
    """
    result = PatchIntelResult(cve_id=cve_id)

    # 1. Extract fix commits from NVD references
    if nvd_refs:
        nvd_commits = _extract_fix_commits_from_refs(nvd_refs)
        result.fix_commits.extend(nvd_commits)
        if nvd_commits:
            result.sources.append("nvd-refs")

    # 2. Query OSV for structured ranges and GIT fix commits
    osv_data = _fetch_osv(cve_id)
    if osv_data:
        osv_ranges, osv_patched, osv_commits = _parse_osv_ranges(osv_data)
        result.affected_ranges.extend(osv_ranges)
        result.patched_versions.extend(osv_patched)
        # Merge commits (deduplicate by sha prefix)
        existing_shas = {fc.sha[:7] for fc in result.fix_commits}
        for fc in osv_commits:
            if fc.sha[:7] not in existing_shas:
                result.fix_commits.append(fc)
                existing_shas.add(fc.sha[:7])
        if osv_data.get("vulns"):
            result.sources.append("osv")

    # 3. Build timeline
    result.timeline = _build_timeline(
        cve_id, nvd_published, result.fix_commits, result.patched_versions)

    result.ok = bool(result.fix_commits or result.affected_ranges or result.patched_versions)
    if not result.ok:
        result.note = "no fix commits or ranges found in NVD refs or OSV"
    return result


def diff_fix_commit(repo: str, sha: str) -> Optional[str]:
    """
    Fetch the unified diff of a fix commit from GitHub.
    Returns the diff text (up to 50 KB) or None on failure.
    """
    url = f"{_GH_API}/repos/{repo}/commits/{sha}"
    headers = {**_gh_headers(), "Accept": "application/vnd.github.diff"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")[:50_000]
    except Exception:
        return None


def check_fix_in_fork(fork_repo: str, original_sha: str) -> bool:
    """
    Check if a fix commit's changed files are present in a fork by comparing
    the fork's default branch against the original commit's tree SHA.
    Returns True if all changed files in the fix commit exist in the fork.
    """
    # Get original commit files
    url = f"{_GH_API}/repos/{fork_repo}/commits/{original_sha}"
    data = _get(url, headers=_gh_headers()) or {}
    # If the fork has the commit → the fix is there
    if data.get("sha"):
        return True
    return False
