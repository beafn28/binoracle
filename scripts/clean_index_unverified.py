#!/usr/bin/env python3
"""Remove unverified CVE rows from index.html.

Reads JSON reports from binoracle_batch_reports/, identifies which CVEs
have dynamic_verify.ok=True (or legacy verified=True with verified_detail),
then removes any index.html table rows for CVEs that don't meet that bar.
"""
from __future__ import annotations
import json
import os
import re
import glob
import sys
import shutil
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "binoracle_batch_reports")
INDEX_PATH  = os.path.join(os.path.dirname(__file__), "..", "index.html")


def _is_dynamically_verified(d: dict) -> bool:
    """Return True only when the CVE was confirmed by a real Docker lab run."""
    if not d.get("verified"):
        return False
    dv = d.get("dynamic_verify") or {}
    if isinstance(dv, dict):
        if dv.get("ok") or dv.get("verified"):
            return True
    # Legacy: verified=True + has real evidence (verified_detail or non-empty verified_evidence)
    if d.get("verified_detail"):
        return True
    ve = d.get("verified_evidence") or {}
    if isinstance(ve, dict) and len(ve) > 0:
        return True
    return False


def load_verified_ids() -> set[str]:
    ids: set[str] = set()
    for f in glob.glob(os.path.join(REPORTS_DIR, "*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
            cve = d.get("cve_id") or os.path.basename(f).replace(".json", "")
            if _is_dynamically_verified(d):
                ids.add(cve)
        except Exception:
            pass
    return ids


def remove_unverified_rows(html: str, verified_ids: set[str]) -> tuple[str, list[str]]:
    """Remove <tr>…</tr> rows from index.html that contain a CVE-ID not in verified_ids."""
    removed: list[str] = []
    # Pattern: <tr data-cve="CVE-XXXX-NNNNN" ...>...</tr>  (may span multiple lines)
    # Also handle rows that just contain the CVE-ID somewhere inside
    row_pattern = re.compile(
        r'(<tr[^>]*>(?:(?!</tr>).)*?</tr>)',
        re.DOTALL | re.IGNORECASE
    )
    def _process_row(m: re.Match) -> str:
        row = m.group(0)
        # Find CVE-IDs in this row
        cve_ids_in_row = re.findall(r'CVE-\d{4}-\d+', row)
        for cid in cve_ids_in_row:
            if cid not in verified_ids:
                removed.append(cid)
                return ""   # remove this row
        return row
    new_html = row_pattern.sub(_process_row, html)
    return new_html, removed


def renumber_rows(html: str) -> str:
    """Renumber td-num cells sequentially starting from 1."""
    counter = [0]
    def _replace(m: re.Match) -> str:
        counter[0] += 1
        return f'class="td-num">{counter[0]}<'
    return re.sub(r'class="td-num">\d+<', _replace, html)


def main() -> None:
    if not os.path.exists(INDEX_PATH):
        print(f"index.html not found at {INDEX_PATH}")
        sys.exit(1)

    verified_ids = load_verified_ids()
    print(f"Dynamically verified CVEs: {len(verified_ids)}")
    for cid in sorted(verified_ids):
        print(f"  ✓ {cid}")

    with open(INDEX_PATH, encoding="utf-8") as fh:
        original = fh.read()

    new_html, removed = remove_unverified_rows(original, verified_ids)

    if not removed:
        print("\nindex.html already clean — no rows to remove.")
        return

    print(f"\nRemoving {len(removed)} unverified CVE rows:")
    for cid in sorted(set(removed)):
        print(f"  ✗ {cid}")

    # Also remove duplicate removals
    new_html = renumber_rows(new_html)

    # Backup
    backup = INDEX_PATH + f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(INDEX_PATH, backup)
    print(f"\nBackup saved: {backup}")

    with open(INDEX_PATH, "w", encoding="utf-8") as fh:
        fh.write(new_html)
    print(f"index.html updated — {len(verified_ids)} verified CVEs remain.")


if __name__ == "__main__":
    main()
