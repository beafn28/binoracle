#!/usr/bin/env python3
"""binoracle engine auto-expansion agent.

Reads successful HUECO verifications from ~/.binoracle/history/ and:
1. Extracts exact sink patterns found by the LLM (endpoint, function, parameter)
2. Suggests new regex patterns for the static scanners in websource.py
3. Saves them to ~/.binoracle/engine_expansions.jsonl for review
4. Optionally applies safe additions automatically (--auto-apply)

Run after the daily scout + verification cycle, or standalone.
Usage:
    python3 scripts/expand_engine.py [--days N] [--auto-apply]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HISTORY_DIR   = os.path.expanduser("~/.binoracle/history")
EXPANSIONS_DB = os.path.expanduser("~/.binoracle/engine_expansions.jsonl")
LOG_PATH      = os.path.expanduser("~/.binoracle/expand_log.txt")

# Map vuln_class → which scanner function it feeds, and which param key it uses
_CLASS_SCANNER = {
    "sqli":                    ("find_sqli_sinks_generic",        "sqli_param"),
    "sql-injection":           ("find_sqli_sinks_generic",        "sqli_param"),
    "xss":                     ("find_xss_sinks_generic",         "xss_param"),
    "cross-site-scripting":    ("find_xss_sinks_generic",         "xss_param"),
    "lfi":                     ("find_path_traversal_sinks",      "path_param"),
    "path-traversal":          ("find_path_traversal_sinks",      "path_param"),
    "ssrf":                    ("find_ssrf_sinks",                "ssrf_param"),
    "rce":                     ("find_rce_sinks",                 "cmd_param"),
    "command-injection":       ("find_rce_sinks",                 "cmd_param"),
    "deserialization":         ("find_deserialization_sinks",     "deser_param"),
    "xxe":                     ("find_xxe_sinks",                 "xml_param"),
    "open-redirect":           ("find_open_redirect_sinks",       "redirect_param"),
    "ssti":                    ("find_ssti_sinks",                "template_param"),
    "missing-authorization":   ("find_auth_bypass_generic",       "endpoint"),
    "auth-bypass":             ("find_auth_bypass_generic",       "endpoint"),
    "idor":                    ("find_auth_bypass_generic",       "endpoint"),
}

# Known sink functions already covered — only suggest NEW ones
_KNOWN_SINKS: dict = {
    "php":    {"sqli": ["$wpdb->query","$wpdb->get_results","mysqli_query","PDO::query"],
               "lfi":  ["file_get_contents","include","fopen","readfile"],
               "ssrf": ["file_get_contents","wp_remote_get","curl_init"],
               "rce":  ["exec","system","shell_exec","passthru","eval"],
               "xss":  ["echo","print"],
               "deser":["unserialize"]},
    "python": {"sqli": ["cursor.execute","raw(","objects.filter"],
               "lfi":  ["open(","Path(","os.path.join"],
               "ssrf": ["requests.get","requests.post","urllib.request.urlopen"],
               "rce":  ["os.system","subprocess.call","subprocess.run"],
               "xss":  ["render_template_string","mark_safe"],
               "deser":["pickle.loads","yaml.load","marshal.loads"]},
    "nodejs": {"sqli": [".query(`","knex.raw","Sequelize.literal"],
               "lfi":  ["fs.readFile","fs.createReadStream","path.join"],
               "ssrf": ["axios.get","fetch(","http.request"],
               "rce":  ["exec(","spawn(","execSync"],
               "xss":  ["res.send(","innerHTML","document.write"],
               "deser":["eval(","vm.runIn"]},
    "ruby":   {"sqli": [".where(\"","find_by_sql","connection.execute"],
               "lfi":  ["File.read","File.open","IO.read"],
               "ssrf": ["Net::HTTP","Faraday.get"],
               "rce":  ["system(","exec(","spawn("]},
    "java":   {"sqli": ["Statement.execute","createQuery","prepareStatement"],
               "lfi":  ["new FileInputStream","Files.readAllBytes"],
               "ssrf": ["new URL(","RestTemplate","HttpClient"],
               "rce":  ["Runtime.exec","ProcessBuilder"]},
    "go":     {"sqli": ["db.Query(fmt.Sprintf","db.Exec(fmt.Sprintf"],
               "lfi":  ["ioutil.ReadFile","os.Open","http.ServeFile"],
               "ssrf": ["http.Get(","http.Post(","client.Do"],
               "rce":  ["exec.Command("]},
}


def _load_recent_verified(days_back: int) -> list:
    """Load history entries verified=True within the last N days."""
    if not os.path.isdir(HISTORY_DIR):
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    records = []
    for fn in sorted(os.listdir(HISTORY_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(HISTORY_DIR, fn), encoding="utf-8") as fh:
                rec = json.load(fh)
        except Exception:
            continue
        if not rec.get("verified"):
            continue
        ts = rec.get("timestamp") or rec.get("result", {}).get("published") or ""
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt < cutoff:
                continue
        except Exception:
            pass
        records.append(rec)
    return records


def _extract_expansion(rec: dict) -> Optional[dict]:
    """Extract a potential scanner expansion from a verified result."""
    result    = rec.get("result", {})
    ve        = result.get("verified_evidence", {})
    notes     = result.get("llm_notes", {}) or {}
    cve_id    = rec.get("cve_id", "?")
    vc        = (result.get("vuln_class") or "").lower()
    tech      = (ve.get("tech") or notes.get("tech") or "php").lower()

    # Need at least: endpoint, sink function or param
    endpoint  = ve.get("endpoint") or notes.get("endpoint") or ""
    reasoning = notes.get("hueco_reasoning") or result.get("hueco_reasoning") or ""

    # Try to extract the specific sink function from reasoning or llm_notes
    deser_fn  = notes.get("deser_function") or ""
    ssrf_fn   = notes.get("ssrf_function") or ""
    rce_fn    = notes.get("rce_shell_operator") or ""
    ssti_eng  = notes.get("ssti_engine") or ""

    # Build sink hint from whatever we know
    sink_hint = deser_fn or ssrf_fn or ssti_eng or ""
    if not sink_hint and reasoning:
        import re as _re
        m = _re.search(r"\b([A-Za-z_][A-Za-z0-9_.>-]+\s*\()", reasoning)
        if m:
            sink_hint = m.group(1)

    scanner_fn, param_key = _CLASS_SCANNER.get(vc, ("", ""))
    if not scanner_fn:
        return None

    # Check if this sink is already known
    known = _KNOWN_SINKS.get(tech, {}).get(vc.split("-")[0], [])
    is_new = sink_hint and not any(s.lower() in sink_hint.lower() for s in known)

    return {
        "cve_id":      cve_id,
        "tech":        tech,
        "vuln_class":  vc,
        "endpoint":    endpoint,
        "scanner_fn":  scanner_fn,
        "param_key":   param_key,
        "sink_hint":   sink_hint,
        "is_new_sink": is_new,
        "reasoning":   reasoning[:200],
        "discovered":  datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }


def _load_existing_expansions() -> set:
    """Return set of CVE IDs already processed."""
    seen = set()
    if not os.path.exists(EXPANSIONS_DB):
        return seen
    with open(EXPANSIONS_DB, encoding="utf-8") as fh:
        for line in fh:
            try:
                seen.add(json.loads(line.strip()).get("cve_id", ""))
            except Exception:
                pass
    return seen


def main():
    ap = argparse.ArgumentParser(description="binoracle engine auto-expansion")
    ap.add_argument("--days",       type=int,  default=14,
                    help="Look-back window for verified CVEs (default: 14)")
    ap.add_argument("--auto-apply", action="store_true",
                    help="Auto-write new patterns to expansion DB (default: dry-run print)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(EXPANSIONS_DB), exist_ok=True)

    records  = _load_recent_verified(args.days)
    existing = _load_existing_expansions()

    new_expansions = []
    for rec in records:
        cve_id = rec.get("cve_id", "")
        if cve_id in existing:
            continue
        exp = _extract_expansion(rec)
        if exp:
            new_expansions.append(exp)

    if not new_expansions:
        print(f"No new engine expansions from {len(records)} verified CVE(s) in last {args.days} days.")
        return

    print(f"\n=== Engine expansion candidates from {len(records)} verified CVE(s) ===\n")
    new_sinks = [e for e in new_expansions if e["is_new_sink"]]
    known_sinks = [e for e in new_expansions if not e["is_new_sink"]]

    for e in new_sinks:
        print(f"  [NEW SINK] {e['cve_id']} | {e['tech']}/{e['vuln_class']}")
        print(f"    Scanner: {e['scanner_fn']}()")
        print(f"    Sink:    {e['sink_hint'] or '(unknown)'}")
        print(f"    Why:     {e['reasoning'][:120]}")
        print()

    if known_sinks:
        print(f"  [{len(known_sinks)} CVE(s) used already-known sinks — no scanner update needed]")

    if args.auto_apply:
        with open(EXPANSIONS_DB, "a", encoding="utf-8") as fh:
            for e in new_expansions:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"\nSaved {len(new_expansions)} expansion(s) → {EXPANSIONS_DB}")
        print("Review with: cat ~/.binoracle/engine_expansions.jsonl | python3 -m json.tool")
    else:
        print(f"[DRY RUN] Pass --auto-apply to save {len(new_expansions)} expansion(s).")

    with open(LOG_PATH, "a", encoding="utf-8") as lf:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lf.write(f"[{ts}] expand_engine: {len(new_expansions)} candidates "
                 f"({len(new_sinks)} new sinks) from {len(records)} verified CVEs\n")


if __name__ == "__main__":
    main()
