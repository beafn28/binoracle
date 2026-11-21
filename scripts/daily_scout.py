#!/usr/bin/env python3
"""Daily HUECO scout — finds new CVEs without public exploits across ALL tech stacks.

Runs automatically via cron agent. Writes new candidates to the HUECO queue file
at ~/.binoracle/hueco_queue.txt so the engine can pick them up.

Usage:
    python3 scripts/daily_scout.py [--days N] [--min-cvss X] [--techs t1,t2,...]
    python3 scripts/daily_scout.py --dry-run   # print candidates, do not save
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

# Allow running from project root without install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

QUEUE_PATH = os.path.expanduser("~/.binoracle/hueco_queue.txt")
LOG_PATH   = os.path.expanduser("~/.binoracle/scout_log.txt")

ALL_TECHS = [
    "wordpress",   # Patchstack RSS + NVD
    "nodejs",      # OSV npm + NVD
    "python",      # OSV PyPI + NVD
    "ruby",        # OSV RubyGems + NVD
    "java",        # OSV Maven + NVD
    "go",          # OSV Go + NVD
    "php",         # NVD
    "dotnet",      # OSV NuGet + NVD
]

SEV_ICON = {
    "CRITICAL": "[CRIT]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MED ]",
    "LOW":      "[LOW ]",
    "":         "[    ]",
}


def _log(msg: str, fp=None):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    line = f"[{ts}] {msg}"
    print(line)
    if fp:
        fp.write(line + "\n")
        fp.flush()


def main():
    ap = argparse.ArgumentParser(description="binoracle daily HUECO scout")
    ap.add_argument("--days",     type=int,   default=3,
                    help="Look-back window in days (default: 3)")
    ap.add_argument("--min-cvss", type=float, default=6.0,
                    help="Minimum CVSS score (default: 6.0)")
    ap.add_argument("--max-per-tech", type=int, default=10,
                    help="Max new CVEs per technology (default: 10)")
    ap.add_argument("--techs",    type=str,   default="",
                    help="Comma-separated tech list (default: all)")
    ap.add_argument("--dry-run",  action="store_true",
                    help="Print candidates, do not write to queue")
    args = ap.parse_args()

    techs = [t.strip() for t in args.techs.split(",") if t.strip()] or ALL_TECHS

    from binoracle.workflows.cvelookup import (
        scout_hueco_cves_generic,
        load_hueco_queue,
        append_hueco_queue,
    )

    os.makedirs(os.path.dirname(QUEUE_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    with open(LOG_PATH, "a", encoding="utf-8") as log_fp:
        _log(f"=== HUECO daily scout START | techs={techs} days={args.days} "
             f"min_cvss={args.min_cvss} ===", log_fp)

        # Load already-known CVEs so we don't add duplicates
        existing = set(load_hueco_queue(QUEUE_PATH))
        _log(f"Queue already contains {len(existing)} CVE(s)", log_fp)

        candidates = scout_hueco_cves_generic(
            techs=techs,
            min_cvss=args.min_cvss,
            days_back=args.days,
            max_per_tech=args.max_per_tech,
            skip_existing=existing,
        )

        if not candidates:
            _log("No new HUECO candidates found this run.", log_fp)
        else:
            _log(f"Found {len(candidates)} new HUECO candidate(s):", log_fp)
            for c in candidates:
                sev  = SEV_ICON.get(c.cvss_severity or "", "[    ]")
                cvss = f"{c.cvss_score:.1f}" if c.cvss_score else "?.?"
                desc = (c.description or "")[:100]
                _log(f"  {sev} {c.cve_id} | CVSS {cvss} | {c.plugin_name} | {desc}", log_fp)

            if not args.dry_run:
                added = append_hueco_queue(QUEUE_PATH, candidates)
                _log(f"Added {added} new CVE(s) to queue: {QUEUE_PATH}", log_fp)
                print(f"\nQueue updated: {QUEUE_PATH} (+{added} new)")
            else:
                _log("[DRY RUN] Queue not modified.", log_fp)

        _log("=== HUECO daily scout END ===\n", log_fp)

    return 0


if __name__ == "__main__":
    sys.exit(main())
