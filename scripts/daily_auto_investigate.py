#!/usr/bin/env python3
"""Agente autónomo diario de binoracle.

Cada día:
1. Busca CVEs nuevos (CMSs + diversas techs) en GitHub Advisory DB / OSV / NVD.
2. Los filtra (no investigados antes, CVSS >= threshold, clases web).
3. Lanza verify dinámica para cada uno vía `binoracle cve`.
4. Regenera informes HTML y actualiza index.html.
5. Registra un resumen en ~/.binoracle/auto_investigate_log.txt.

Uso:
    python3 scripts/daily_auto_investigate.py [--dry-run] [--max N] [--days D]
    python3 scripts/daily_auto_investigate.py --cms-only      # solo CMSs
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LOG_PATH       = os.path.expanduser("~/.binoracle/auto_investigate_log.txt")
HISTORY_DIR    = os.path.expanduser("~/.binoracle/history")
PROJECT_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# CMSs de interés para mejorar el motor (prioridad alta)
CMS_TECHS = [
    "ghost", "strapi", "payload", "craft", "drupal", "wagtail",
    "djangocms", "directus", "typo3", "concrete5", "statamic",
    "kirby", "umbraco", "contao", "modx", "joomla",
]

# Stacks genéricos (segunda prioridad)
GENERIC_TECHS = [
    "nodejs", "python", "ruby", "php", "java", "go", "dotnet",
    "wordpress", "laravel", "symfony", "rails", "spring",
]

# Clases de vulnerabilidad que el motor puede verificar dinámicamente
VERIFIABLE_CLASSES = {
    "sqli", "auth-bypass", "missing-authorization", "idor",
    "path-traversal", "lfi", "rce", "code-injection",
    "file-upload", "arbitrary-file-upload", "xxe", "ssti",
    "open-redirect", "ssrf", "xss", "command-injection",
    "deserialization", "graphql-bypass", "boolean-oracle",
}

SEV_ICON = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _log(msg: str, fp=None):
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    if fp:
        fp.write(line + "\n")
        fp.flush()


def _already_investigated(cve_id: str) -> bool:
    """True si ya tenemos un resultado en history para este CVE."""
    path = os.path.join(HISTORY_DIR, f"{cve_id}.json")
    return os.path.isfile(path)


def _load_all_investigated() -> set:
    """Conjunto de CVE IDs ya en history."""
    seen = set()
    if not os.path.isdir(HISTORY_DIR):
        return seen
    for f in os.listdir(HISTORY_DIR):
        if f.endswith(".json"):
            seen.add(f[:-5])
    return seen


def _guess_vuln_class(description: str, keywords: list) -> str:
    """Deducción simple de clase desde descripción / keywords del aviso."""
    text = (description or "").lower() + " " + " ".join(keywords or []).lower()
    mapping = [
        ("sqli",             ["sql injection", "sqli", "sql query"]),
        ("auth-bypass",      ["authentication bypass", "auth bypass", "unauthenticated"]),
        ("missing-authorization", ["missing authorization", "broken access", "privilege escalation"]),
        ("path-traversal",   ["path traversal", "directory traversal", "../"]),
        ("lfi",              ["local file inclusion", "lfi", "file inclusion"]),
        ("rce",              ["remote code execution", "arbitrary code", "code execution"]),
        ("command-injection",["command injection", "os command", "shell injection"]),
        ("file-upload",      ["file upload", "arbitrary upload", "unrestricted upload"]),
        ("xxe",              ["xml external entity", "xxe"]),
        ("ssti",             ["server-side template", "ssti", "template injection"]),
        ("open-redirect",    ["open redirect", "unvalidated redirect"]),
        ("ssrf",             ["server-side request forgery", "ssrf"]),
        ("xss",              ["cross-site scripting", "xss", "reflected"]),
        ("deserialization",  ["deserialization", "object injection", "unsafe deserializ"]),
        ("graphql-bypass",   ["graphql", "introspection"]),
        ("boolean-oracle",   ["boolean oracle", "boolean injection", "data leak", "where clause"]),
        ("code-injection",   ["code injection", "eval injection", "php eval"]),
    ]
    for cls, kws in mapping:
        if any(k in text for k in kws):
            return cls
    return "auth-bypass"  # fallback seguro


def _run_investigate(cve_id: str, vuln_class: str, log_fp, dry_run: bool,
                     budget: int = 900) -> bool:
    """Lanza `binoracle cve <cve_id> --vuln-class <vc>` y espera resultado.
    Devuelve True si el CVE quedó verificado."""
    if dry_run:
        _log(f"  [DRY-RUN] binoracle cve {cve_id} --vuln-class {vuln_class}", log_fp)
        return False

    cmd = [sys.executable, "-u", "-m", "binoracle", "cve", cve_id,
           "--vuln-class", vuln_class]
    _log(f"  Lanzando: {' '.join(cmd)}", log_fp)
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    t0 = time.time()
    try:
        result = subprocess.run(
            cmd,
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=budget + 60,
            env=env,
        )
        elapsed = time.time() - t0
        combined = (result.stdout or "") + (result.stderr or "")
        verified = ("VERIFICADO" in combined or "CONFIRMED" in combined or
                    "verified=True" in combined)
        status = "VERIFICADO" if verified else ("ERROR" if result.returncode != 0 else "no-confirm")
        _log(f"  → {status} ({elapsed:.0f}s) rc={result.returncode}", log_fp)
        if result.returncode != 0 and not verified:
            # Log last few lines of stderr for debugging
            last = (combined)[-300:].strip().replace("\n", " | ")
            _log(f"    stderr: {last}", log_fp)
        return verified
    except subprocess.TimeoutExpired:
        _log(f"  → TIMEOUT ({budget + 60}s)", log_fp)
        return False
    except Exception as e:
        _log(f"  → excepcion: {e}", log_fp)
        return False


def _regenerate_reports_and_index(log_fp):
    """Regenera informes batch y el index.html."""
    _log("Regenerando informes batch...", log_fp)
    try:
        r = subprocess.run(
            [sys.executable, "scripts/gen_batch_informes.py"],
            cwd=PROJECT_DIR, capture_output=True, text=True, timeout=300)
        lines = (r.stdout or "").strip().splitlines()
        _log(f"  gen_batch_informes: {lines[-1] if lines else 'ok'}", log_fp)
    except Exception as e:
        _log(f"  gen_batch_informes error: {e}", log_fp)

    _log("Regenerando index.html...", log_fp)
    try:
        r = subprocess.run(
            [sys.executable, "scripts/gen_index.py"],
            cwd=PROJECT_DIR, capture_output=True, text=True, timeout=120)
        lines = (r.stdout or "").strip().splitlines()
        _log(f"  gen_index: {lines[-1] if lines else 'ok'}", log_fp)
    except Exception as e:
        _log(f"  gen_index error: {e}", log_fp)


def main():
    ap = argparse.ArgumentParser(description="binoracle autonomous daily investigator")
    ap.add_argument("--dry-run",   action="store_true", help="No lanzar verificaciones reales")
    ap.add_argument("--max",       type=int, default=5,
                    help="Max CVEs a investigar por ejecucion (default: 5)")
    ap.add_argument("--days",      type=int, default=7,
                    help="Ventana de busqueda en dias (default: 7)")
    ap.add_argument("--min-cvss",  type=float, default=7.0,
                    help="CVSS minimo (default: 7.0)")
    ap.add_argument("--cms-only",  action="store_true",
                    help="Solo investigar CVEs de CMSs")
    ap.add_argument("--budget",    type=int, default=900,
                    help="Presupuesto de tiempo por CVE en segundos (default: 900)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)

    techs = CMS_TECHS if args.cms_only else CMS_TECHS + GENERIC_TECHS
    already_done = _load_all_investigated()

    with open(LOG_PATH, "a", encoding="utf-8") as log_fp:
        _log(f"=== AUTO-INVESTIGATE START | max={args.max} days={args.days} "
             f"min_cvss={args.min_cvss} techs={'cms' if args.cms_only else 'all'} ===", log_fp)
        _log(f"CVEs ya investigados: {len(already_done)}", log_fp)

        # ── 1. Buscar CVEs nuevos ──────────────────────────────────────────────
        candidates = []
        try:
            from binoracle.workflows.cvelookup import scout_hueco_cves_generic
            raw = scout_hueco_cves_generic(
                techs=techs,
                min_cvss=args.min_cvss,
                days_back=args.days,
                max_per_tech=8,
                skip_existing=already_done,
            )
            candidates = [c for c in raw if c.cve_id not in already_done]
            _log(f"Candidatos nuevos encontrados: {len(candidates)}", log_fp)
        except Exception as e:
            _log(f"Error en scout: {e}", log_fp)

        # ── 2. Priorizar y filtrar ─────────────────────────────────────────────
        # Prioridad: CMSs > CVSS alto > web classes verificables
        def _priority(c):
            tech = (c.plugin_name or "").lower()
            is_cms = any(t in tech for t in CMS_TECHS)
            cvss = c.cvss_score or 0.0
            return (1 if is_cms else 0, cvss)

        candidates.sort(key=_priority, reverse=True)
        queue: List = []
        for c in candidates:
            desc = c.description or ""
            vc = _guess_vuln_class(desc, [])
            if vc not in VERIFIABLE_CLASSES:
                continue
            queue.append((c, vc))
            if len(queue) >= args.max:
                break

        _log(f"Cola de verificacion: {len(queue)} CVE(s)", log_fp)
        for c, vc in queue:
            sev = SEV_ICON.get(c.cvss_severity or "", "?")
            _log(f"  {sev} {c.cve_id} ({c.plugin_name}) CVSS={c.cvss_score} → {vc}", log_fp)

        # ── 3. Investigar cada CVE ─────────────────────────────────────────────
        verified_today = []
        for c, vc in queue:
            _log(f"Investigando {c.cve_id} ({vc})...", log_fp)
            ok = _run_investigate(c.cve_id, vc, log_fp, args.dry_run, args.budget)
            if ok:
                verified_today.append(c.cve_id)

        # ── 4. Regenerar si hubo resultados ───────────────────────────────────
        if verified_today and not args.dry_run:
            _log(f"Verificados hoy: {verified_today}", log_fp)
            _regenerate_reports_and_index(log_fp)
        elif not verified_today:
            _log("Ningún CVE nuevo verificado esta ejecucion.", log_fp)

        _log(f"=== AUTO-INVESTIGATE END | verificados={len(verified_today)} ===\n", log_fp)

    return 0


if __name__ == "__main__":
    sys.exit(main())
