"""Cross-CVE learning: persists lessons learned from each investigation so future
runs of the same stack benefit from prior results.

State stored in ~/.cache/binoracle/cve_lessons.json. Thread-safe via atomic rename.
No external dependencies — stdlib only."""
from __future__ import annotations

import json
import os
import threading
from collections import Counter
from typing import Dict, List, Tuple

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle"
)
_LESSONS_FILE = os.path.join(_STATE_DIR, "cve_lessons.json")
_LESSONS_LOCK = threading.Lock()

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
    # Caller must hold _LESSONS_LOCK
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = _LESSONS_FILE + f".tmp-{os.getpid()}-{threading.get_ident()}"
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
    auth_method: str = "",
    http_method: str = "",
    confirm_string: str = "",
    pkg_version: str = "",
) -> None:
    """Record the outcome of one CVE investigation for future learning.

    Extended fields (all optional):
      auth_method   — e.g. "ghost-jwt", "drf-token", "django-session",
                       "fastapi-oauth2", "basic-auth", "none"
      http_method   — e.g. "GET", "POST", "PUT"
      confirm_string — snippet/keyword that confirmed the vuln
      pkg_version   — specific package version the lab ran on
    """
    if not stack:
        return
    with _LESSONS_LOCK:
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

        run: dict = {
            "cve_id": cve_id,
            "endpoint": endpoint,
            "verified": verified,
            "bypass_header": bypass_header,
            "bypass_value": bypass_value,
            "vuln_class": vuln_class,
        }
        if auth_method:
            run["auth_method"] = auth_method
        if http_method:
            run["http_method"] = http_method
        if confirm_string:
            run["confirm_string"] = confirm_string[:120]
        if pkg_version:
            run["pkg_version"] = pkg_version

        entry["runs"].append(run)
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
    auth_counter: Counter = Counter()
    method_counter: Counter = Counter()
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
        am = (r.get("auth_method") or "").strip()
        if am and r.get("verified"):
            auth_counter[am] += 1
        hm = (r.get("http_method") or "").strip()
        if hm and r.get("verified"):
            method_counter[hm] += 1

    result = {
        "stack": stack,
        "total_runs": total,
        "verified_rate": verified / total if total else 0.0,
        "top_endpoints": [ep for ep, _ in ep_counter.most_common(5)],
        "working_bypass_headers": [
            {"header": h, "value": v} for (h, v), _ in bp_counter.most_common(3)
        ],
        "top_vuln_classes": [vc for vc, _ in class_counter.most_common(3)],
    }
    if auth_counter:
        result["working_auth_methods"] = [am for am, _ in auth_counter.most_common(3)]
    if method_counter:
        result["top_http_methods"] = [hm for hm, _ in method_counter.most_common(2)]
    return result


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


def suggest_bypass_headers(stack: str, vuln_class: str = "") -> List[Tuple[str, str]]:
    """Return bypass (header, value) pairs that worked before for this stack.

    When vuln_class is provided, headers from verified runs of the same class
    are weighted 3x higher, since a header that bypassed auth for one IDOR
    is much more likely to work for another IDOR than for a SQLi.
    """
    data = _load()
    entry = data.get(stack) or {}
    runs = entry.get("runs") or []
    bp_counter: Counter = Counter()
    _vc_norm = (vuln_class or "").lower().replace("_", "-")
    for r in runs:
        if not r.get("verified"):
            continue
        bh = (r.get("bypass_header") or "").strip()
        bv = (r.get("bypass_value") or "").strip()
        if not bh:
            continue
        # Weight: class match counts 3x, unmatched counts 1x
        _run_vc = (r.get("vuln_class") or "").lower().replace("_", "-")
        _weight = 3 if (_vc_norm and _run_vc == _vc_norm) else 1
        bp_counter[(bh, bv)] += _weight
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


def stack_success_rate(stack: str) -> float:
    """Return the verified_rate for a stack (0.0–1.0). 0.0 when no history."""
    lessons = get_lessons(stack)
    if not lessons:
        return 0.0
    return float(lessons.get("verified_rate", 0.0))


def get_weakest_stacks(min_runs: int = 3, max_rate: float = 0.15) -> List[str]:
    """Return stacks with >= min_runs investigations but verified_rate <= max_rate.

    These are stacks where the engine consistently fails — good candidates for
    targeted improvements (new verifier, better auth flow, etc.).
    """
    summary = all_stacks_summary()
    return [
        row["stack"]
        for row in summary
        if row.get("total_runs", 0) >= min_runs
        and row.get("verified_rate", 1.0) <= max_rate
    ]


def get_top_performing_stacks(min_runs: int = 3, min_rate: float = 0.5) -> List[str]:
    """Return stacks with >= min_runs investigations and verified_rate >= min_rate.

    These are stacks where the engine is reliable — lessons from them are
    high-confidence inputs for the LLM context injection.
    """
    summary = all_stacks_summary()
    return [
        row["stack"]
        for row in summary
        if row.get("total_runs", 0) >= min_runs
        and row.get("verified_rate", 0.0) >= min_rate
    ]


def format_lessons_for_llm(stack: str, vuln_class: str = "",
                            max_tokens: int = 400) -> str:
    """Return a compact LLM-readable string of lessons for this stack.

    Injected into the investigation system prompt to bias the LLM toward
    endpoint patterns and auth methods that are known to work for this stack.
    Returns "" when no lessons exist (safe to pass as empty context).

    For stacks with >= 5 runs and < 10% verification rate, suppresses
    endpoint/bypass suggestions (not useful) and shows a LOW_SIGNAL warning
    instead — prevents the LLM from repeating known-failing strategies.
    """
    lessons = get_lessons(stack)
    if not lessons or lessons.get("total_runs", 0) < 1:
        return ""

    _total = lessons.get("total_runs", 0)
    _rate = lessons.get("verified_rate", 0.0)
    _low_signal = _total >= 5 and _rate < 0.10

    lines: list[str] = [
        f"[LECCIONES PREVIAS para stack={stack}]",
        f"- Tasa de verificacion: {_rate:.0%} ({_total} investigaciones previas)"
        + (" — SEÑAL BAJA: estrategias históricas poco efectivas en este stack" if _low_signal else ""),
    ]

    # For low-signal stacks, only show the warning and skip specific advice
    # (the specific advice comes from consistently failing runs — not useful)
    if _low_signal:
        lines.append("- NOTA: evitar repetir estrategias anteriores para este stack sin nueva información")
        return "\n".join(lines)

    # Suggest endpoints
    top_ep = suggest_endpoints(stack, vuln_class)
    if top_ep:
        lines.append(f"- Endpoints que funcionaron antes: {', '.join(top_ep[:3])}")

    # Auth methods
    working_auth = lessons.get("working_auth_methods", [])
    if working_auth:
        lines.append(f"- Metodos de auth que funcionaron: {', '.join(working_auth[:3])}")

    # Bypass headers
    bp_headers = suggest_bypass_headers(stack, vuln_class=vuln_class)
    if bp_headers:
        bph_strs = [f"{h}: {v[:40]}" for h, v in bp_headers[:2]]
        lines.append(f"- Headers de bypass que funcionaron: {'; '.join(bph_strs)}")

    # Vuln classes
    top_vc = lessons.get("top_vuln_classes", [])
    if top_vc:
        lines.append(f"- Clases de vulnerabilidad frecuentes: {', '.join(top_vc[:3])}")

    # HTTP methods
    top_hm = lessons.get("top_http_methods", [])
    if top_hm:
        lines.append(f"- Metodos HTTP mas usados: {', '.join(top_hm)}")

    # Recent verified examples (last 3) with impact_class
    data = _load()
    entry = data.get(stack) or {}
    runs = entry.get("runs") or []
    verified_runs = [r for r in runs if r.get("verified")][-3:]
    if verified_runs:
        lines.append("- Ejemplos verificados recientes:")
        for r in verified_runs:
            ep = r.get("endpoint", "?")
            vc = r.get("vuln_class", "?")
            am = r.get("auth_method", "")
            cve = r.get("cve_id", "?")
            ic = r.get("impact_class", "")
            am_str = f" auth={am}" if am else ""
            ic_str = f" impacto={ic}" if ic else ""
            lines.append(f"    {cve}: {r.get('http_method','GET')} {ep} [{vc}]{am_str}{ic_str}")

    # Patch fix_class distribution (from patchdiff analysis on verified runs)
    _fc_counter: Counter = Counter()
    for r in runs:
        if r.get("verified") and r.get("patch_fix_class"):
            _fc_counter[r["patch_fix_class"]] += 1
    if _fc_counter:
        _fc_top = [fc for fc, _ in _fc_counter.most_common(2)]
        lines.append(f"- Clases de fix mas frecuentes en diffs: {', '.join(_fc_top)}")

    # Impact class distribution across all verified runs
    _ic_counter: Counter = Counter()
    for r in runs:
        if r.get("verified") and r.get("impact_class"):
            _ic_counter[r["impact_class"]] += 1
    if _ic_counter:
        _ic_top = [f"{ic}({n})" for ic, n in _ic_counter.most_common(3)]
        lines.append(f"- Impactos observados en este stack: {', '.join(_ic_top)}")
        # If credential_exposure was common, signal it prominently
        if _ic_counter.get("credential_exposure", 0) >= 2:
            lines.append("  NOTA: credential_exposure frecuente — revisar respuesta para tokens/keys")

    # OSV package patterns seen on this stack (helps LLM know which npm/pypi packages to target)
    _osv_counter: Counter = Counter()
    for r in runs:
        for pkg in (r.get("osv_packages") or []):
            _pkg_name = pkg.split("@")[0].split("::")[-1] if pkg else ""
            if _pkg_name:
                _osv_counter[_pkg_name] += 1
    if _osv_counter:
        _osv_top = [p for p, _ in _osv_counter.most_common(3)]
        lines.append(f"- Paquetes OSV afectados en este stack: {', '.join(_osv_top)}")

    summary = "\n".join(lines)
    # Truncate to stay within token budget (approx 4 chars/token)
    if len(summary) > max_tokens * 4:
        summary = summary[:max_tokens * 4].rsplit("\n", 1)[0]
    return summary


def record_verified_lab(
    cve_id: str,
    stack: str,
    endpoint: str,
    vuln_class: str,
    http_method: str = "GET",
    auth_method: str = "",
    bypass_header: str = "",
    bypass_value: str = "",
    confirm_string: str = "",
    pkg_version: str = "",
) -> None:
    """Convenience wrapper: record a successful lab verification into lessons.

    Called from auto_chain.py's _notify_verified() path so that every
    confirmed CVE is automatically saved for future chain runs.
    """
    record_cve_result(
        stack=stack or detect_stack(cve_id),
        cve_id=cve_id,
        endpoint=endpoint,
        verified=True,
        bypass_header=bypass_header,
        bypass_value=bypass_value,
        vuln_class=vuln_class,
        auth_method=auth_method,
        http_method=http_method,
        confirm_string=confirm_string,
        pkg_version=pkg_version,
    )


def learn_from_chain_result(result: object) -> None:
    """Auto-learn from a completed ChainResult — called at end of run_full_chain().

    Extracts all the evidence fields needed to record lessons without the caller
    needing to know the internal lesson schema. Handles both verified and failed
    runs (failed runs help signal what NOT to try for a stack).

    For verified runs, extracts:
    - endpoint, http_method, bypass_header/value from evidence
    - confirm_string from the first body snippet in evidence
    - auth_method from evidence or cve_class heuristic
    - pkg_version from evidence or description

    For failed runs with enough evidence:
    - records the run as unverified so the success rate stays accurate
    """
    if not result or not result.cve_id:
        return

    ev = result.evidence or {}
    desc = result.description or ""
    _stack = detect_stack(desc) or detect_stack(result.cve_id) or "generic"

    # Extract fields from evidence
    _endpoint = (ev.get("endpoint") or ev.get("base_url") or "").strip()
    _method = (ev.get("metodo") or ev.get("method") or "GET").upper()
    _bypass_hdr = (ev.get("bypass_header") or ev.get("header") or "").strip()
    _bypass_val = (ev.get("bypass_value") or ev.get("header_value") or "").strip()
    _vuln_class = (ev.get("vuln_class") or result.cve_class or "")
    _confirm = ""
    for _bk in ("respuesta_cuerpo_recorte", "exploit_response", "confirm_string"):
        _candidate = ev.get(_bk, "")
        if isinstance(_candidate, str) and len(_candidate) > 5:
            _confirm = _candidate[:100]
            break

    # Auth method from evidence
    _auth = ""
    for _ak in ("auth_method", "auth_type", "auth_strategy"):
        _auth = (ev.get(_ak) or "").strip()
        if _auth:
            break
    if not _auth:
        # Heuristic from stack name
        _stack_auth = {
            "ghost": "ghost-jwt", "strapi": "strapi-jwt",
            "directus": "directus-bearer", "django": "django-session",
            "fastapi": "fastapi-oauth2", "wordpress": "wp-session",
        }
        _auth = _stack_auth.get(_stack, "")

    _pkg_ver = (ev.get("pkg_version") or ev.get("version") or "").strip()

    # Only record verified runs OR failed runs for well-known stacks (to track failure rate)
    if result.verified or _stack != "generic":
        record_cve_result(
            stack=_stack,
            cve_id=result.cve_id,
            endpoint=_endpoint,
            verified=result.verified,
            bypass_header=_bypass_hdr,
            bypass_value=_bypass_val,
            vuln_class=_vuln_class,
            auth_method=_auth,
            http_method=_method,
            confirm_string=_confirm,
            pkg_version=_pkg_ver,
        )

    # For verified runs: record impact_class from multiple evidence sources.
    # Priority: impact_escalation (most concrete) > response_body_analysis > direct impact_class key
    if result.verified:
        _impact = ""
        _confidence_bonus = 0.0
        # 1. impact_escalation (Stage 5c) — most specific: credential_exposure, admin_access, etc.
        _esc = ev.get("impact_escalation", {})
        if isinstance(_esc, dict):
            _impact = _esc.get("impact_class", "")
        # 2. response_body_analysis — from semantic response analysis
        if not _impact and ev.get("response_body_analysis"):
            _rba = ev["response_body_analysis"]
            _impact = _rba.get("impact_class", "")
            _confidence_bonus = _rba.get("confidence_bonus", 0.0)
        # 3. Direct impact_class key in evidence
        if not _impact:
            _impact = ev.get("impact_class", "")
        if _impact:
            with _LESSONS_LOCK:
                data = _load()
                _entry = data.get(_stack, {})
                if _entry and _entry.get("runs"):
                    for _run in reversed(_entry["runs"]):
                        if _run.get("cve_id") == result.cve_id:
                            _run["impact_class"] = _impact
                            if _confidence_bonus:
                                _run["confidence_bonus"] = _confidence_bonus
                            # Augment with patch diff fix_class and OSV package info
                            _pa = ev.get("patch_analysis", {})
                            if _pa.get("fix_class") and _pa["fix_class"] != "unknown":
                                _run["patch_fix_class"] = _pa["fix_class"]
                            _osv_pkgs = ev.get("osv_packages", [])
                            if _osv_pkgs:
                                _run["osv_packages"] = _osv_pkgs[:3]
                            break
                    _save(data)


def export_lessons_csv(out_path: str = "") -> str:
    """Export all CVE run records to a CSV file for external analysis.

    Columns: stack, cve_id, verified, vuln_class, endpoint, http_method,
             auth_method, bypass_header, impact_class, patch_fix_class,
             osv_packages, timestamp

    Returns the path where the CSV was saved (default: ~/.cache/binoracle/lessons.csv).
    """
    import csv as _csv
    _out = out_path or os.path.join(
        os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
            os.path.expanduser("~"), ".cache", "binoracle"),
        "lessons.csv",
    )
    data = _load()
    _COLS = [
        "stack", "cve_id", "verified", "vuln_class", "endpoint",
        "http_method", "auth_method", "bypass_header", "impact_class",
        "patch_fix_class", "osv_packages", "timestamp",
    ]
    rows: list[dict] = []
    for stack, entry in data.items():
        for run in (entry.get("runs") or []):
            rows.append({
                "stack": stack,
                "cve_id": run.get("cve_id", ""),
                "verified": "1" if run.get("verified") else "0",
                "vuln_class": run.get("vuln_class", ""),
                "endpoint": run.get("endpoint", ""),
                "http_method": run.get("http_method", ""),
                "auth_method": run.get("auth_method", ""),
                "bypass_header": run.get("bypass_header", ""),
                "impact_class": run.get("impact_class", ""),
                "patch_fix_class": run.get("patch_fix_class", ""),
                "osv_packages": "|".join(run.get("osv_packages") or []),
                "timestamp": run.get("timestamp", ""),
            })
    try:
        os.makedirs(os.path.dirname(_out), exist_ok=True)
        with open(_out, "w", newline="", encoding="utf-8") as f:
            w = _csv.DictWriter(f, fieldnames=_COLS)
            w.writeheader()
            w.writerows(rows)
    except Exception as e:
        return f"error: {e}"
    return _out


# ── D17: Transfer learning between similar stacks ─────────────────────────────

_STACK_FAMILY: dict[str, list[str]] = {
    "django":    ["fastapi", "flask"],
    "fastapi":   ["django", "flask"],
    "flask":     ["django", "fastapi"],
    "express":   ["nextjs", "nestjs"],
    "nextjs":    ["express", "nestjs"],
    "nestjs":    ["express", "nextjs"],
    "rails":     ["laravel", "django"],
    "laravel":   ["rails", "wordpress"],
    "wordpress": ["drupal", "joomla", "laravel"],
    "drupal":    ["wordpress", "joomla"],
    "joomla":    ["wordpress", "drupal"],
    "strapi":    ["ghost", "directus", "payload"],
    "ghost":     ["strapi", "directus"],
    "directus":  ["strapi", "ghost"],
    "gitea":     ["mattermost", "nextcloud"],
    "mattermost":["gitea", "nextcloud"],
    "nextcloud": ["gitea", "mattermost"],
}


def transfer_lessons(target_stack: str, max_transferred: int = 5) -> list[dict]:
    """D17: Seed lessons for target_stack from sibling stacks.

    Returns a list of run dicts (endpoint, vuln_class, http_method, etc.)
    sourced from related stacks, filtered to verified=True runs only,
    for use as seed hints when target_stack has few/no runs.
    """
    siblings = _STACK_FAMILY.get(target_stack, [])
    if not siblings:
        return []
    data = _load()
    # Only return transfer if target has few runs itself
    target_runs = len((data.get(target_stack) or {}).get("runs") or [])
    if target_runs >= 10:
        return []
    transferred: list[dict] = []
    for sib in siblings:
        entry = data.get(sib) or {}
        for run in (entry.get("runs") or []):
            if run.get("verified") and run not in transferred:
                transferred.append(dict(run, _from_stack=sib))
        if len(transferred) >= max_transferred:
            break
    return transferred[:max_transferred]


# ── D19: Lessons decay — mark stale runs ──────────────────────────────────────

_DECAY_DAYS = int(os.environ.get("BINORACLE_LESSONS_DECAY_DAYS", "90"))


def decay_stale_lessons(dry_run: bool = False) -> dict:
    """D19: Mark lessons older than BINORACLE_LESSONS_DECAY_DAYS as stale.

    Runs do NOT have timestamps by default; decay is based on cve_id year
    parsed from the CVE-YYYY-NNNNN pattern — a CVE from >2 years ago is
    considered stale. Returns {stacks_touched: N, runs_marked: N}.
    If dry_run=True, returns counts but writes nothing.
    """
    import re as _re
    import datetime as _dt

    cutoff_year = _dt.datetime.utcnow().year - 2
    data = _load()
    stacks_touched = 0
    runs_marked = 0
    for _stack, entry in data.items():
        changed = False
        for run in (entry.get("runs") or []):
            cve_id = run.get("cve_id", "")
            m = _re.match(r"CVE-(\d{4})-", cve_id)
            if m and int(m.group(1)) <= cutoff_year:
                if not run.get("stale"):
                    run["stale"] = True
                    runs_marked += 1
                    changed = True
        if changed:
            stacks_touched += 1
    if not dry_run and runs_marked:
        _save(data)
    return {"stacks_touched": stacks_touched, "runs_marked": runs_marked}
