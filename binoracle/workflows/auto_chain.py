"""auto_chain — Cadena autónoma completa desde solo el CVE ID.

Reproduce el flujo de un investigador senior de explotación:
  1. Gather ALL intelligence (NVD, EPSS, CISA KEV, correlación, patch)
  2. Classify: web / binary / cli / native
  3. Hypothesis generation (LLM + deterministic)
  4. Patch diff (auto-download del commit de fix)
  5. Lab setup + verification (Docker completo)
  6. Para HUECOs sin fuente: razonamiento desde descripción
  7. Enrich (CVSS auto, CWE, executive summary)
  8. Professional report (report_generator.py)
  9. Save + return structured result

USO:
    from binoracle.workflows.auto_chain import run_full_chain
    result = run_full_chain("CVE-2024-1234", on_step=print)
    print(result.report_md)

CLI:
    binoracle chain CVE-2024-1234
    binoracle chain CVE-2024-1234 --binary /path/to/bin --lang en

Para AUTHORIZED targets / CTF / investigación defensiva únicamente.
LLM: Qwen2.5-Coder:7b via Ollama ONLY. Zero hardcoded URLs/paths/values.
"""
from __future__ import annotations

import os
import re
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    name:    str
    status:  str   # "ok" | "skip" | "warn" | "error"
    detail:  str   = ""
    elapsed: float = 0.0


@dataclass
class ChainResult:
    cve_id:         str
    cve_class:      str             = ""   # "web" | "binary" | "cli" | "native" | "unknown"
    cvss_score:     Optional[float] = None
    cvss_severity:  str             = ""
    epss_score:     Optional[float] = None
    epss_pct:       Optional[float] = None
    in_cisa_kev:    bool            = False
    risk_label:     str             = ""
    description:    str             = ""
    verified:       bool            = False
    steps:          List[ChainStep] = field(default_factory=list)
    findings:       List[Any]       = field(default_factory=list)
    patch_summary:  str             = ""
    mitigation_report: str          = ""
    report_md:      str             = ""
    report_path:    str             = ""
    inv:            Any             = None   # raw Investigation object
    error:          str             = ""
    elapsed_s:      float           = 0.0
    engine_confidence: float        = 0.0   # 0–1: how confident the engine is in its own result
    evidence:       dict            = field(default_factory=dict)  # {endpoint, status, body_snippet, ...}

    def add_step(self, name: str, status: str, detail: str = "", elapsed: float = 0.0):
        self.steps.append(ChainStep(name, status, detail, elapsed))

    def banner(self) -> str:
        kev = " [CISA KEV — ACTIVELY EXPLOITED]" if self.in_cisa_kev else ""
        epss_str = f" | EPSS {self.epss_score:.0%} ({self.epss_pct:.0f}th pct)" if self.epss_score else ""
        return (f"{self.cve_id} | {self.risk_label or self.cvss_severity} "
                f"CVSS {self.cvss_score or '?'}{epss_str}{kev}")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _t():
    t = time.time()
    return lambda: time.time() - t


def _safe(fn, *a, default=None, **kw):
    try:
        return fn(*a, **kw)
    except Exception:
        return default


def _banner(step, msg: str):
    step(f"{'─'*60}")
    step(f"  {msg}")
    step(f"{'─'*60}")


# ── Intelligence gathering ────────────────────────────────────────────────────

def _gather_intelligence(cve_id: str, result: ChainResult, step: Callable) -> Optional[Any]:
    """Stage 1: collect everything known about this CVE from every source."""
    t = _t()
    _banner(step, f"[1/8] INTELLIGENCE GATHERING — {cve_id}")

    cve_info = None
    try:
        from .cvelookup import fetch_cve
        step("  NVD + GitHub PoC + ExploitDB + OSV.dev...")
        cve_info = fetch_cve(cve_id)
        if not cve_info.ok:
            step(f"  NVD: {cve_info.note}")
            result.add_step("nvd_lookup", "warn", cve_info.note, elapsed=t())
        else:
            result.description = cve_info.description or ""
            result.cvss_score   = cve_info.cvss_score
            result.cvss_severity = cve_info.cvss_severity or ""
            poc_count = len(getattr(cve_info, "exploit_refs", []))
            step(f"  NVD: CVSS={result.cvss_score} ({result.cvss_severity}), "
                 f"PoC={poc_count}, gap={getattr(cve_info,'is_gap',True)}")
    except Exception as e:
        step(f"  NVD error: {e}")
        result.add_step("nvd_lookup", "error", str(e)[:100])
        return cve_info

    # EPSS
    try:
        epss = getattr(cve_info, "epss_score", None)
        epss_pct = getattr(cve_info, "epss_percentile", None)
        if epss is None:
            from .cvelookup import _fetch_epss  # type: ignore
            epss_data = _fetch_epss(cve_id)
            if epss_data:
                epss = epss_data.get("epss")
                epss_pct = epss_data.get("percentile")
        if epss is not None:
            result.epss_score = float(epss)
            result.epss_pct   = float(epss_pct or 0) * 100
            step(f"  EPSS: {result.epss_score:.1%} probabilidad explotación (percentil {result.epss_pct:.0f})")
    except Exception:
        pass

    # CISA KEV
    try:
        kev = getattr(cve_info, "in_cisa_kev", False)
        if not kev:
            from .cvelookup import _fetch_cisa_kev  # type: ignore
            kev_set = _fetch_cisa_kev()
            kev = cve_id in kev_set
        if kev:
            result.in_cisa_kev = True
            step("  CISA KEV: SÍ — vulnerabilidad ACTIVAMENTE EXPLOTADA en la naturaleza")
        else:
            step("  CISA KEV: no")
    except Exception:
        pass

    # Risk label
    try:
        from .cvelookup import risk_label  # type: ignore
        result.risk_label = risk_label(cve_info)
    except Exception:
        cvss = result.cvss_score or 0
        result.risk_label = (
            "CRITICAL-WEAPONIZED" if result.in_cisa_kev else
            "CRITICAL" if cvss >= 9.0 else
            "HIGH"     if cvss >= 7.0 else
            "MEDIUM"   if cvss >= 4.0 else "LOW"
        )
    step(f"  Risk label: {result.risk_label}")

    # CVE correlation
    try:
        from .cve_correlate import correlate_cve
        corr = correlate_cve(cve_id, max_related=5)
        if corr.ok and corr.related:
            step(f"  Correlación: {len(corr.related)} CVEs relacionados con {corr.component}")
    except Exception:
        pass

    result.add_step("intelligence", "ok",
                    f"cvss={result.cvss_score} epss={result.epss_score or 0:.0%} "
                    f"kev={result.in_cisa_kev}", elapsed=t())
    return cve_info


# ── CVE classification ────────────────────────────────────────────────────────

_WEB_SIGNALS = [
    # ── Vulnerability classes (always web) ───────────────────────────────────
    "sqli", "xss", "ssrf", "csrf", "path traversal", "file upload",
    "auth bypass", "open redirect", "injection", "graphql", "oauth",
    "rest api", "api endpoint", "rest endpoint", "json api", "web application",
    "improper authorization", "access control", "broken access",
    "http", "web", "endpoint", "request handler", "authentication bypass",
    "unauthorized access", "privilege escalation via web", "idor",
    "insecure direct object", "missing authorization", "server-side",
    # ── Generic CMS ──────────────────────────────────────────────────────────
    "cms", "plugin", "theme", "wordpress", "drupal", "joomla",
    "magento", "typo3", "contao", "october cms", "craft cms", "statamic",
    "wagtail", "umbraco", "kentico", "sitecore", "prestashop", "opencart",
    "woocommerce", "spree", "solidus", "shopware", "sylius",
    # ── Headless CMS / BaaS / API platforms ──────────────────────────────────
    "headless cms", "baas", "backend as a service", "strapi", "ghost",
    "directus", "payload cms", "keystone", "pocketbase", "appwrite",
    "hasura", "daptin", "xano", "supabase", "nhost",
    # ── Node.js ecosystem ────────────────────────────────────────────────────
    "node.js", "nodejs", "express", "fastify", "koa", "hapi", "nestjs",
    "feathers", "loopback", "sails", "meteor", "adonis", "remix", "nuxt",
    "nextjs", "svelte", "astro", "vite", "socket.io",
    # ── Python web frameworks ────────────────────────────────────────────────
    "django", "flask", "fastapi", "starlette", "tornado", "sanic",
    "pyramid", "bottle", "cherrypy", "falcon", "aiohttp server",
    # ── PHP frameworks ───────────────────────────────────────────────────────
    "php", "laravel", "symfony", "codeigniter", "yii", "cakephp",
    "slim", "lumen", "phalcon", "fuelphp", "zend", "laminas",
    # ── Ruby / Java / Go / Rust ──────────────────────────────────────────────
    "rails", "sinatra", "grape", "hanami",
    "spring", "spring boot", "struts", "jersey", "quarkus", "micronaut",
    "play framework", "dropwizard", "vertx", "vert.x", "helidon",
    "gin", "echo", "fiber", "chi", "gorilla", "buffalo", "revel", "beego",
    "actix", "rocket", "axum", "warp", "tide",
    # ── .NET ─────────────────────────────────────────────────────────────────
    "asp.net", "aspnet", ".net core", "blazor", "razor pages",
    # ── Collaboration / communication ────────────────────────────────────────
    "mattermost", "rocket.chat", "matrix", "element", "zulip", "discourse",
    "wiki.js", "bookstack", "outline", "confluence", "xwiki", "dokuwiki",
    "mediawiki", "tiddlywiki",
    # ── File / cloud storage ─────────────────────────────────────────────────
    "nextcloud", "owncloud", "seafile", "pydio", "filebrowser",
    # ── DevOps / infra portals ───────────────────────────────────────────────
    "gitea", "gogs", "forgejo", "gitlab", "harbor", "portainer",
    "rancher", "argocd", "backstage", "drone", "woodpecker", "jenkins",
    "sonarqube", "nexus", "artifactory", "minio", "vault", "consul",
    # ── Auth / identity ───────────────────────────────────────────────────────
    "keycloak", "authentik", "authelia", "passbolt", "zitadel", "gluu",
    # ── Media / streaming ────────────────────────────────────────────────────
    "audiobookshelf", "media server", "jellyfin", "emby", "plex",
    "navidrome", "subsonic", "ampache", "airsonic", "funkwhale",
    "peertube", "owncast",
    # ── Monitoring / observability ───────────────────────────────────────────
    "grafana", "kibana", "prometheus", "opensearch dashboards",
    "zabbix", "nagios", "checkmk", "icinga", "librenms", "netdata",
    "graylog", "loki", "jaeger", "zipkin",
    # ── Database / search web UIs ────────────────────────────────────────────
    "phpmyadmin", "adminer", "pgadmin", "redisinsight", "mongo express",
    "elasticsearch", "opensearch", "typesense", "meilisearch",
    # ── IoT / home automation ────────────────────────────────────────────────
    "home assistant", "homeassistant", "openhab", "domoticz", "node-red",
    "mosquitto", "emqx",
    # ── eCommerce / SaaS extras ──────────────────────────────────────────────
    "odoo", "erpnext", "dolibarr", "invoiceninja", "snipe-it", "glpi",
    "netbox", "nautobot", "device42", "racktables",
]
_BIN_SIGNALS = [
    "buffer overflow", "heap overflow", "stack overflow", "heap corruption",
    "rop", "libc", "binary", "elf", "pe", "mach-o",
    "format string", "uaf", "use after free", "integer overflow",
    "memory corruption", "out-of-bounds", "oob", "null deref",
    "type confusion", "arbitrary code execution", "code execution",
]
_CLI_SIGNALS = ["cli", "command line", "npm package", "pip package", "gem ",
                "tool", "utility", "argument", "command injection via flag"]
_NATIVE_SIGNALS = ["sudo", "openssl", "curl", "bash", "zip", "gzip", "tar",
                   "kernel", "linux", "windows", "macos", "firmware"]

# Library-level CVEs: affect a package/library that needs a wrapper app to exploit via HTTP
_LIBRARY_PACKAGES = [
    "jinja2", "jinja", "pyyaml", "yaml", "pickle", "marshal", "shelve",
    "werkzeug", "markupsafe", "mako", "chameleon", "genshi",
    "cryptography", "paramiko", "twisted", "aiohttp", "httpx",
    "pillow", "pil", "imagemagick", "libmagick",
    "lxml", "defusedxml", "xmltodict", "pyexpat",
    "numpy", "pandas", "scipy", "scikit",
    "sqlalchemy", "peewee", "tortoise",
    "celery", "kombu", "redis-py", "pymongo",
]
# Signals that imply NO direct HTTP endpoint on the vulnerable component
_LIBRARY_SIGNALS = [
    "sandbox escape", "sandbox bypass", "template injection", "ssti",
    "arbitrary code via template", "template engine", "render_template_string",
    "unsafe deserialization", "deserialization of untrusted",
    "library", "python package", "pip install", "via crafted",
]


def _is_library_cve(cve_info, llm_notes: dict) -> bool:
    """Return True when the CVE targets a library that needs a wrapper app to exploit."""
    desc = ((getattr(cve_info, "description", "") or "") + " " + str(llm_notes)).lower()
    pkg_hit  = any(p in desc for p in _LIBRARY_PACKAGES)
    sig_hit  = any(s in desc for s in _LIBRARY_SIGNALS)
    no_endpoint = (llm_notes.get("endpoint", "") or "").strip() in ("", "?", "unknown", "n/a")
    return (pkg_hit or sig_hit) and no_endpoint


def _signal_match(signal: str, text: str) -> bool:
    """Match signal against text. Use word-boundary check for short signals (<=4 chars)
    to avoid false positives like 'rop' in 'improper' or 'pe' in 'permission'."""
    if len(signal) <= 4:
        return bool(re.search(r'\b' + re.escape(signal) + r'\b', text))
    return signal in text


def _classify(cve_info, llm_notes: dict) -> str:
    text = ((getattr(cve_info, "description", "") or "") + " " + str(llm_notes)).lower()
    scores = {
        "web":    sum(1 for s in _WEB_SIGNALS    if _signal_match(s, text)),
        "binary": sum(1 for s in _BIN_SIGNALS    if _signal_match(s, text)),
        "cli":    sum(1 for s in _CLI_SIGNALS    if _signal_match(s, text)),
        "native": sum(1 for s in _NATIVE_SIGNALS if _signal_match(s, text)),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


def _auto_learn_web_signal(cve_info, llm_notes: dict, llm, step) -> bool:
    """When CVE is classified as binary/native but description suggests a web app,
    ask the LLM to extract the key technology term, add it to _WEB_SIGNALS in memory
    AND patch auto_chain.py on disk so future runs benefit immediately.

    Returns True if a new signal was added and reclassification should happen.
    """
    if llm is None or not getattr(llm, "available", lambda: False)():
        return False
    desc = ((getattr(cve_info, "description", "") or "") + " " + str(llm_notes)).lower()
    # Quick heuristic: if any generic web indicator is present in the raw description
    # but _WEB_SIGNALS didn't score it, the specific product name is likely missing.
    _QUICK_WEB_HINTS = ["http", "web", "api", "rest", "endpoint", "request", "server",
                        "authentication", "authorization", "login", "admin", "dashboard"]
    if not any(h in desc for h in _QUICK_WEB_HINTS):
        return False  # genuinely not a web CVE

    from ..llm.base import Message
    prompt = (
        "CVE description: " + (getattr(cve_info, "description", "") or "") + "\n\n"
        "This CVE was misclassified as 'binary/native' by a keyword scorer. "
        "The description suggests it may be a web application vulnerability. "
        "Extract the SINGLE most specific technology keyword that identifies this as a web app "
        "(e.g. 'mattermost', 'nextcloud', 'grafana', 'keycloak', 'harbor'). "
        "Rules: lowercase, 1-3 words max, no version numbers, must appear in the description. "
        'Reply with ONLY valid JSON: {"signal": "keyword"} or {"signal": ""} if unsure.'
    )
    try:
        raw = llm.chat([Message("user", prompt)], json_mode=True)
        import json as _json
        data = _json.loads(raw)
        signal = (data.get("signal") or "").strip().lower()
    except Exception:
        return False

    if not signal or len(signal) > 40 or signal in _WEB_SIGNALS:
        return False

    # Verify the signal actually appears in the description (guard against hallucination)
    if signal not in desc:
        return False

    step(f"  AUTO-LEARN: añadiendo '{signal}' a _WEB_SIGNALS")

    # 1) Update in-memory list immediately (affects this run)
    _WEB_SIGNALS.append(signal)

    # 2) Patch auto_chain.py on disk (affects all future runs)
    try:
        _this_file = os.path.abspath(__file__)
        with open(_this_file, "r", encoding="utf-8") as fh:
            src = fh.read()
        # Find the last signal in _WEB_SIGNALS list and append after it
        old_tail = '"express", "fastify", "nextjs", "nuxt", "svelte", "astro",\n]'
        new_tail = f'"express", "fastify", "nextjs", "nuxt", "svelte", "astro",\n    "{signal}",\n]'
        if old_tail in src:
            src = src.replace(old_tail, new_tail, 1)
        else:
            # Fallback: append before the closing bracket of _WEB_SIGNALS
            old_last = '"astro",\n]'
            if old_last in src:
                src = src.replace(old_last, f'"astro",\n    "{signal}",\n]', 1)
        with open(_this_file, "w", encoding="utf-8") as fh:
            fh.write(src)
        step(f"  AUTO-LEARN: auto_chain.py actualizado en disco con '{signal}'")
    except Exception as exc:
        step(f"  AUTO-LEARN: fallo al parchear disco ({exc}) — solo en memoria")

    return True


# ── Patch diff stage ──────────────────────────────────────────────────────────

def _find_patch_urls(cve_info) -> List[str]:
    """Find ALL patch/diff URLs from CVE references, ordered by quality."""
    refs = getattr(cve_info, "references", []) or []
    urls = []
    for ref in refs:
        url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
        if not url:
            continue
        m = re.search(r"(https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40})", url)
        if m:
            urls.append(m.group(1) + ".diff")
        elif url.endswith(".diff") or url.endswith(".patch"):
            urls.append(url)
    # Also check patch_intel block
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        pi = ref.get("patch_intel")
        if pi:
            for fc in (pi.get("fix_commits") or []):
                fc_url = fc.get("url", "")
                if fc_url and "github.com" in fc_url:
                    urls.append(fc_url + ".diff")
    return list(dict.fromkeys(urls))  # deduplicate, preserve order


def _download(url: str, timeout: int = 20) -> Optional[str]:
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle-chain/0.4"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(512_000).decode(errors="replace")
    except Exception:
        return None


def _run_patch_stage(cve_id: str, cve_info, result: ChainResult,
                     step: Callable, tmpdir: str) -> str:
    t = _t()
    _banner(step, f"[4/8] PATCH DIFF — {cve_id}")
    urls = _find_patch_urls(cve_info)
    if not urls:
        step("  sin URL de parche en referencias NVD")
        result.add_step("patch_diff", "skip", "no patch URL")
        return ""

    for patch_url in urls[:3]:
        step(f"  descargando: {patch_url[:90]}...")
        patch_text = _download(patch_url)
        if not patch_text:
            continue
        lines = patch_text.splitlines()
        added   = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
        step(f"  parche: +{added} líneas añadidas, -{removed} eliminadas")

        # patchdiff v2
        old_path = os.path.join(tmpdir, "patch.diff")
        with open(old_path, "w") as f:
            f.write(patch_text)
        try:
            from .patchdiff import run_patchdiff, render_patchdiff
            dr = run_patchdiff(old_path, old_path)
            dr.cve_id = cve_id
            summary = render_patchdiff(dr)
            step(f"  patchdiff: tipo={dr.patch_type.value}, "
                 f"score_seguridad={dr.security_score:.1f}")
            result.add_step("patch_diff", "ok",
                            f"type={dr.patch_type.value} +{added}/-{removed}",
                            elapsed=t())
            return summary
        except Exception:
            summary = (f"## Patch diff — {cve_id}\n\n"
                       f"- **URL**: {patch_url}\n"
                       f"- **Cambios**: +{added} líneas / -{removed} líneas\n\n"
                       f"### Funciones modificadas\n")
            # Extract function names from diff
            for l in lines:
                if l.startswith("@@") and "def " in l or "function " in l or "++" in l:
                    summary += f"- `{l[2:].strip()}`\n"
            result.add_step("patch_diff", "ok", f"+{added}/-{removed}", elapsed=t())
            return summary
    result.add_step("patch_diff", "warn", "all patch downloads failed")
    return ""


# ── Binary analysis stage ─────────────────────────────────────────────────────

def _run_binary_stage(cve_id: str, binary_path: str,
                       result: ChainResult, step: Callable, llm=None) -> str:
    t = _t()
    _banner(step, f"[5/8] BINARY ANALYSIS — {os.path.basename(binary_path)}")
    parts = []

    # Quick triage
    try:
        from .triage import triage_cve, render_triage
        from ..oracles.base import ToolRegistry
        step("  triage: ELF header + mitigaciones + imports...")
        reg = ToolRegistry()
        tr  = triage_cve(cve_id=cve_id, binary=binary_path, registry=reg, on_step=step)
        tmd = render_triage(tr)
        parts.append(tmd)
        label = tr.score.label if tr.score else "?"
        step(f"  triage confidence: {label}")
        result.add_step("triage", "ok", f"confidence={label}", elapsed=t())
    except Exception as e:
        step(f"  triage error: {e}")
        result.add_step("triage", "error", str(e)[:100])

    # Mitigation fingerprint + bypass
    try:
        from .mitigation_bypass import analyze_mitigations, render_mitigation_report
        t2 = _t()
        step("  mitigaciones: NX, PIE, Canary, RELRO, CFI, ASan, SafeStack...")
        mr  = analyze_mitigations(binary_path, llm=llm)
        mmd = render_mitigation_report(mr)
        result.mitigation_report = mmd
        parts.append(mmd)
        present = [m.name for m in mr.mitigations if m.present]
        step(f"  mitigaciones presentes: {', '.join(present) or 'ninguna'}")
        result.add_step("mitigation_bypass", "ok",
                        f"{len(present)} mitigations", elapsed=t2())
    except Exception as e:
        step(f"  mitigation_bypass error: {e}")
        result.add_step("mitigation_bypass", "error", str(e)[:100])

    # ROP chain if relevant
    try:
        t3 = _t()
        step("  buscando gadgets ROP...")
        from .rop import build_rop_chain, render_rop
        rc  = build_rop_chain(binary_path)
        if rc.chains:
            step(f"  ROP: {len(rc.chains)} cadenas generadas")
            parts.append(render_rop(rc))
            result.add_step("rop_chain", "ok", f"{len(rc.chains)} chains", elapsed=t3())
        else:
            result.add_step("rop_chain", "skip", "no chains found")
    except Exception:
        pass

    return "\n\n".join(parts)


def _auto_binary_stage(cve_id: str, cve_info, llm_notes: dict,
                        result: "ChainResult", step: Callable, llm=None) -> str:
    """Auto-investigate a binary CVE when no --binary path was provided.

    Uses binaryverify.verify_binary_crash_via_dockerfile to build a Docker
    image with the vulnerable package version and run the LLM-generated PoC
    inside it. Covers OS packages (sudo, curl, openssl, glibc, bash, etc.)
    that can be installed via apt/apk at a specific version.

    Returns a markdown report section.
    """
    _banner(step, f"[5/8] BINARY AUTO-LAB — {cve_id}")
    parts: List[str] = []

    if not llm:
        step("  sin LLM: no se puede generar Dockerfile de lab automático")
        result.add_step("binary_auto_lab", "skip", "no LLM")
        return ""

    pkg_name = (llm_notes.get("package_name") or llm_notes.get("component") or
                llm_notes.get("affected_component") or "")
    pkg_version = (llm_notes.get("vulnerable_version") or
                   llm_notes.get("affected_version") or "")

    if not pkg_name:
        step("  sin nombre de paquete en llm_notes — infiriendo del CVE...")
        try:
            from ..llm.base import Message
            resp = llm.chat([Message("system",
                "Extract the vulnerable package name and version from this CVE. "
                "Reply JSON: {\"package\": \"<apt/apk name>\", \"version\": \"<version>\", "
                "\"os\": \"ubuntu|debian|alpine|centos|generic\", "
                "\"poc_cmd\": \"<shell command to trigger the bug>\", "
                "\"crash_pattern\": \"<string in stderr/stdout that confirms crash>\"}"),
                Message("user", str(cve_info)[:2000])],
                json_mode=True)
            import json as _j
            data = _j.loads(resp)
            pkg_name = data.get("package") or ""
            pkg_version = data.get("version") or pkg_version
            poc_cmd = data.get("poc_cmd") or ""
            crash_pattern = data.get("crash_pattern") or ""
            os_hint = data.get("os") or "ubuntu"
        except Exception as e:
            step(f"  LLM error extrayendo paquete: {e}")
            result.add_step("binary_auto_lab", "error", str(e)[:100])
            return ""
    else:
        poc_cmd = llm_notes.get("poc_cmd") or llm_notes.get("command") or ""
        crash_pattern = llm_notes.get("crash_pattern") or llm_notes.get("confirm_string") or ""
        os_hint = llm_notes.get("os") or "ubuntu"

    if not pkg_name:
        step("  no se pudo determinar el paquete — saltando lab de binario")
        result.add_step("binary_auto_lab", "skip", "unknown package")
        return ""

    step(f"  paquete: {pkg_name}=={pkg_version or '?'}, OS: {os_hint}")
    step(f"  PoC cmd: {poc_cmd[:80] if poc_cmd else '(LLM generará)'}")

    # Build Dockerfile content
    base_map = {"ubuntu": "ubuntu:22.04", "debian": "debian:bullseye",
                "alpine": "alpine:3.19", "centos": "centos:7", "generic": "ubuntu:22.04"}
    base_img = base_map.get(os_hint, "ubuntu:22.04")
    pkg_spec = f"{pkg_name}={pkg_version}" if pkg_version else pkg_name

    if "alpine" in base_img:
        install_cmd = f"RUN apk add --no-cache {pkg_spec} 2>/dev/null || apk add --no-cache {pkg_name}"
    else:
        install_cmd = (f"RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                       f"{pkg_spec} 2>/dev/null || apt-get install -y --no-install-recommends {pkg_name}")

    dockerfile_body = f"FROM {base_img}\n{install_cmd}\n"

    if not poc_cmd:
        step("  generando PoC shell con LLM...")
        try:
            from ..llm.base import Message
            resp2 = llm.chat([Message("system",
                "Write a minimal shell command to trigger this vulnerability in a Docker container. "
                "Reply with ONLY the shell command, no explanation."),
                Message("user", f"CVE: {cve_id}\n{str(cve_info)[:1500]}")], json_mode=False)
            poc_cmd = resp2.strip().split("\n")[0][:200]
        except Exception:
            poc_cmd = f"{pkg_name} --version"

    step(f"  levantando lab efímero Docker para {pkg_name}...")
    try:
        from .binaryverify import verify_binary_crash_via_dockerfile
        wr = verify_binary_crash_via_dockerfile(
            dockerfile_body=dockerfile_body,
            poc_command=poc_cmd,
            crash_patterns=[crash_pattern] if crash_pattern else [],
            on_step=step,
            timeout_s=30,
        )
        if wr.verified:
            step(f"  BINARIO VERIFICADO: {pkg_name} crash confirmado")
            result.verified = True
            result.add_step("binary_auto_lab", "verified",
                            f"{pkg_name} crash via Dockerfile lab")
            parts.append(f"## Lab Binario Auto-generado\n\n"
                         f"**Paquete**: `{pkg_name}=={pkg_version}`  \n"
                         f"**PoC**: `{poc_cmd}`  \n"
                         f"**Resultado**: VERIFICADO — crash confirmado en Docker\n\n"
                         f"```\n{wr.detail}\n```")
            # Try to extract the binary from the container and run full analysis
            # (triage + mitigations + ROP chain via _run_binary_stage)
            _container_id = getattr(wr, "container_id", "") or getattr(wr, "evidence", {}).get("container", "")
            if _container_id:
                import subprocess as _sp
                import tempfile as _tf
                _bin_common_paths = [
                    f"/usr/bin/{pkg_name}", f"/usr/sbin/{pkg_name}",
                    f"/bin/{pkg_name}", f"/usr/local/bin/{pkg_name}",
                ]
                _extracted = None
                _tmp_bin = _tf.mktemp(prefix=f"bo_bin_{pkg_name}_")
                for _bp in _bin_common_paths:
                    try:
                        _sp.run(["docker", "cp", f"{_container_id}:{_bp}", _tmp_bin],
                                capture_output=True, timeout=10, check=True)
                        _extracted = _tmp_bin
                        step(f"  binario extraído del container: {_bp} → {_tmp_bin}")
                        break
                    except Exception:
                        continue
                if _extracted and os.path.isfile(_extracted):
                    step("  ejecutando análisis estático completo (triage + mitigaciones + ROP)...")
                    try:
                        _bin_analysis = _run_binary_stage(cve_id, _extracted, result, step, llm=llm)
                        if _bin_analysis:
                            parts.append(_bin_analysis)
                    except Exception as _be:
                        step(f"  análisis estático error: {_be}")
                    finally:
                        try:
                            os.unlink(_extracted)
                        except Exception:
                            pass
        else:
            step(f"  lab no confirmó crash: {wr.detail[:100] if wr.detail else '?'}")
            result.add_step("binary_auto_lab", "unconfirmed", wr.detail[:100] if wr.detail else "")
            parts.append(f"## Lab Binario Auto-generado\n\n"
                         f"**Paquete**: `{pkg_name}=={pkg_version}`  \n"
                         f"**PoC**: `{poc_cmd}`  \n"
                         f"**Resultado**: no confirmado — {wr.detail[:200] if wr.detail else '?'}")
    except Exception as exc:
        step(f"  binary lab error: {exc}")
        result.add_step("binary_auto_lab", "error", str(exc)[:100])

    # Also run static binary analysis if we can find the binary inside Docker
    parts.append("\n*Auto-lab: paquete instalado en Docker efímero, "
                 "PoC ejecutado en entorno aislado*")
    return "\n\n".join(parts)


# ── Docker Compose multi-container lab ───────────────────────────────────────

_COMPOSE_NGINX_CONF = """\
events {}
http {{
  server {{
    listen 80;
    location / {{
      proxy_pass http://app:{app_port}/;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }}
  }}
}}
"""

_COMPOSE_SYSTEM_PROMPT = (
    "You are a security researcher building a Docker Compose lab for CVE testing. "
    "Given a CVE description, generate a docker-compose.yml with TWO services: "
    "'nginx' (reverse proxy on port 80) and 'app' (the vulnerable application). "
    "The app service must use the actual vulnerable software version. "
    "nginx must proxy ALL requests to app. "
    "Return ONLY the docker-compose.yml content, no markdown fences, no explanation."
)


def _needs_compose_lab(cve_info, llm_notes: dict) -> bool:
    """Return True when the CVE requires a multi-container lab (proxy + app)."""
    desc = ((getattr(cve_info, "description", "") or "") + " " + str(llm_notes)).lower()
    compose_signals = [
        "reverse proxy", "proxy misconfiguration", "proxy bypass",
        "trusted proxy", "x-forwarded-for", "hop-by-hop", "trusted header",
        "session cookie", "proxy_pass", "nginx", "apache proxy",
        "traefik", "caddy", "haproxy", "envoy", "istio",
    ]
    return any(s in desc for s in compose_signals)


def _generate_compose_lab(cve_id: str, cve_info, llm_notes: dict,
                           tmpdir: str, step, llm=None) -> str | None:
    """Generate a docker-compose.yml lab with nginx + vulnerable app.

    Returns the lab URL (http://localhost:<port>) or None on failure.
    """
    if llm is None:
        step("  compose: sin LLM — no se puede generar lab multi-contenedor")
        return None

    desc = getattr(cve_info, "description", "") or ""
    from ..llm.base import Message
    prompt = f"CVE: {cve_id}\nDescription: {desc[:800]}\nGenerate the docker-compose.yml."
    try:
        compose_yaml = llm.chat([
            Message("system", _COMPOSE_SYSTEM_PROMPT),
            Message("user", prompt),
        ]).strip()
    except Exception as e:
        step(f"  compose LLM error: {e}")
        return None

    if compose_yaml.startswith("```"):
        compose_yaml = "\n".join(
            ln for ln in compose_yaml.splitlines()
            if not ln.startswith("```")
        ).strip()

    lab_dir = os.path.join(tmpdir, "compose_lab")
    os.makedirs(lab_dir, exist_ok=True)

    with open(os.path.join(lab_dir, "docker-compose.yml"), "w") as fh:
        fh.write(compose_yaml)

    # Find free port for nginx
    import socket
    with socket.socket() as s:
        s.bind(("", 0))
        port = s.getsockname()[1]

    import subprocess
    try:
        step(f"  compose: levantando lab en puerto {port}...")
        subprocess.run(
            ["docker", "compose", "-f", os.path.join(lab_dir, "docker-compose.yml"),
             "up", "-d", "--build", "--wait"],
            timeout=180, capture_output=True, check=True
        )
        return f"http://localhost:{port}"
    except subprocess.CalledProcessError as e:
        step(f"  compose error: {e.stderr.decode()[:200] if e.stderr else e}")
        return None
    except FileNotFoundError:
        step("  compose: docker compose no disponible")
        return None


# ── Library wrapper app generator ────────────────────────────────────────────

_WRAPPER_PROMPTS = {
    "python": (
        "You are a security researcher building minimal vulnerable demo apps for CVE lab testing. "
        "Generate a self-contained Python Flask app (single file, app.py) that exposes the "
        "vulnerable library over HTTP. The app MUST: (1) import and use the vulnerable library, "
        "(2) accept attacker-controlled input via HTTP (GET/POST parameter), (3) pass that input "
        "to the vulnerable function without sanitization, (4) run on port 5000. "
        "Return ONLY Python code, no markdown fences."
    ),
    "node": (
        "You are a security researcher building minimal vulnerable demo apps for CVE lab testing. "
        "Generate a self-contained Node.js app (single file, app.js) using Express that exposes "
        "the vulnerable npm package over HTTP. The app MUST: (1) require and use the vulnerable "
        "package, (2) accept attacker-controlled input via HTTP query/body, (3) pass that input "
        "to the vulnerable function without sanitization, (4) listen on port 5000. "
        "Return ONLY JavaScript code, no markdown fences."
    ),
    "go": (
        "You are a security researcher building minimal vulnerable demo apps for CVE lab testing. "
        "Generate a self-contained Go HTTP server (single file, main.go) that exposes the "
        "vulnerable functionality over HTTP. The app MUST: (1) import and use the vulnerable "
        "package, (2) register at least one HTTP handler that accepts attacker input, "
        "(3) pass that input to the vulnerable code path, (4) listen on :5000. "
        "Return ONLY Go code (package main + imports + handlers), no markdown fences."
    ),
    "java": (
        "You are a security researcher building minimal vulnerable demo apps for CVE lab testing. "
        "Generate a minimal Spring Boot application (App.java, single file) that exposes the "
        "vulnerable library over HTTP. The app MUST: (1) use the vulnerable dependency, "
        "(2) expose a REST endpoint accepting attacker input, (3) pass that input to the "
        "vulnerable code path without sanitization, (4) listen on port 5000. "
        "Return ONLY Java code, no markdown fences."
    ),
}

_WRAPPER_DOCKERFILES = {
    "python": """\
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
ENV FLASK_ENV=development
EXPOSE 5000
CMD ["python", "app.py"]
""",
    "node": """\
FROM node:20-slim
WORKDIR /app
COPY package.json .
RUN npm install
COPY app.js .
EXPOSE 5000
CMD ["node", "app.js"]
""",
    "go": """\
FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY main.go .
RUN go build -o server .
FROM alpine:3.19
COPY --from=build /app/server /server
EXPOSE 5000
CMD ["/server"]
""",
    "java": """\
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -q 2>/dev/null || true
COPY src ./src
RUN mvn package -DskipTests -q
FROM eclipse-temurin:21-jre-alpine
COPY --from=build /app/target/*.jar /app.jar
EXPOSE 5000
CMD ["java","-jar","/app.jar"]
""",
}

_SPRING_POM_XML = """\
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId><version>3.2.0</version></parent>
  <groupId>com.binoracle</groupId><artifactId>wrapper</artifactId><version>0.0.1</version>
  <properties><java.version>21</java.version></properties>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId></dependency>
  </dependencies>
  <build><plugins><plugin><groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build>
</project>
"""

# Fallback legacy alias
_WRAPPER_SYSTEM_PROMPT = _WRAPPER_PROMPTS["python"]
_WRAPPER_DOCKERFILE = _WRAPPER_DOCKERFILES["python"]


def _detect_wrapper_stack(cve_info, llm_notes: dict) -> str:
    """Detect which tech stack to use for the wrapper app."""
    text = ((getattr(cve_info, "description", "") or "") + " " + str(llm_notes)).lower()
    if any(k in text for k in ("node", "npm", "javascript", "typescript", "express",
                                "nestjs", "fastify", "koa", "socket.io")):
        return "node"
    if any(k in text for k in ("golang", " go ", "go module", "go package",
                                "gin ", "echo ", "fiber ", "gorilla")):
        return "go"
    if any(k in text for k in ("java", "spring", "maven", "gradle", "quarkus",
                                "micronaut", "struts", "jersey")):
        return "java"
    return "python"


def _generate_wrapper_app(cve_id: str, cve_info, llm_notes: dict,
                           tmpdir: str, step: Callable, llm=None) -> str | None:
    """Generate a minimal Flask app that exposes the vulnerable library over HTTP.

    Returns the URL the target is reachable at (e.g. 'http://localhost:5001'),
    or None if generation/startup failed.
    """
    if llm is None:
        step("  wrapper: sin LLM — no se puede generar app demo")
        return None

    desc = getattr(cve_info, "description", "") or ""
    exploit_hint = llm_notes.get("exploitation_steps", "") or llm_notes.get("payload", "")
    stack = _detect_wrapper_stack(cve_info, llm_notes)
    sys_prompt = _WRAPPER_PROMPTS.get(stack, _WRAPPER_PROMPTS["python"])
    main_file = {"python": "app.py", "node": "app.js", "go": "main.go", "java": "App.java"}.get(stack, "app.py")
    step(f"  wrapper: stack={stack}, archivo={main_file}")

    from ..llm.base import Message
    prompt = (
        f"CVE: {cve_id}\n"
        f"Description: {desc[:800]}\n"
        f"Exploitation hint: {exploit_hint[:400]}\n\n"
        f"Generate the {main_file} code."
    )
    try:
        code = llm.chat([
            Message("system", sys_prompt),
            Message("user", prompt),
        ]).strip()
    except Exception as e:
        step(f"  wrapper LLM error: {e}")
        return None

    # Strip markdown fences if the LLM added them anyway
    if code.startswith("```"):
        code = "\n".join(
            ln for ln in code.splitlines()
            if not ln.startswith("```")
        ).strip()

    app_dir = os.path.join(tmpdir, "wrapper_app")
    os.makedirs(app_dir, exist_ok=True)

    with open(os.path.join(app_dir, main_file), "w") as fh:
        fh.write(code)

    # Write dependency manifest per stack
    desc_lower = (desc + " " + code).lower()
    if stack == "python":
        pkgs = ["flask"]
        for pkg in _LIBRARY_PACKAGES:
            if pkg in desc_lower:
                pkgs.append(pkg)
        with open(os.path.join(app_dir, "requirements.txt"), "w") as fh:
            fh.write("\n".join(dict.fromkeys(pkgs)))
    elif stack == "node":
        # Minimal package.json — LLM code determines actual deps
        import json as _json
        pkg_name = cve_id.lower().replace("-", "_")
        with open(os.path.join(app_dir, "package.json"), "w") as fh:
            _json.dump({"name": pkg_name, "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}, fh)
    elif stack == "go":
        # Minimal go.mod
        with open(os.path.join(app_dir, "go.mod"), "w") as fh:
            fh.write("module wrapper\n\ngo 1.22\n")
    elif stack == "java":
        # Minimal pom.xml with Spring Boot
        os.makedirs(os.path.join(app_dir, "src", "main", "java"), exist_ok=True)
        # Move App.java to correct path
        import shutil as _shutil
        _shutil.move(os.path.join(app_dir, main_file),
                     os.path.join(app_dir, "src", "main", "java", main_file))
        with open(os.path.join(app_dir, "pom.xml"), "w") as fh:
            fh.write(_SPRING_POM_XML)

    with open(os.path.join(app_dir, "Dockerfile"), "w") as fh:
        fh.write(_WRAPPER_DOCKERFILES.get(stack, _WRAPPER_DOCKERFILES["python"]))

    # Find a free port
    import socket
    with socket.socket() as s:
        s.bind(("", 0))
        port = s.getsockname()[1]

    container_name = f"bo_wrapper_{cve_id.replace('-', '_').lower()}"
    step(f"  wrapper: construyendo imagen Docker en puerto {port}…")
    try:
        import subprocess
        subprocess.run(
            ["docker", "build", "-t", container_name, "."],
            cwd=app_dir, capture_output=True, timeout=120, check=True,
        )
        subprocess.run(
            ["docker", "run", "-d", "--rm",
             "-p", f"{port}:5000",
             "--name", container_name, container_name],
            capture_output=True, timeout=30, check=True,
        )
        import time
        time.sleep(3)  # wait for Flask to start
        step(f"  wrapper: container arrancado → http://localhost:{port}")
        return f"http://localhost:{port}"
    except Exception as e:
        step(f"  wrapper: fallo Docker — {e}")
        return None


# ── Web investigation stage ───────────────────────────────────────────────────

def _run_web_stage(cve_id: str, cve_info, llm_notes: dict,
                   result: ChainResult, step: Callable,
                   budget_s: float, config=None, llm=None, lang: str = "es") -> Any:
    """Full web CVE investigation. Returns the Investigation object."""
    t = _t()
    _banner(step, f"[5/8] WEB INVESTIGATION — {cve_id}")

    is_gap = getattr(cve_info, "is_gap", True) if cve_info else True
    step(f"  modo: {'HUECO (sin PoC público)' if is_gap else 'PoC público encontrado'}")

    # ── Compose lab: multi-container (nginx + app) for proxy-class CVEs ─────────
    compose_lab_url = None
    _compose_tmpdir = tempfile.mkdtemp(prefix="bo_compose_")
    if _needs_compose_lab(cve_info, llm_notes):
        step("  COMPOSE LAB detectado — levantando nginx + app para CVE de proxy…")
        result.add_step("compose_detection", "ok", "multi-container lab needed")
        compose_lab_url = _generate_compose_lab(
            cve_id, cve_info, llm_notes, _compose_tmpdir, step, llm=llm)
        if compose_lab_url:
            if config is None:
                config = {}
            config = dict(config)
            config["target_url"] = compose_lab_url
            step(f"  compose lab listo: {compose_lab_url}")
            result.add_step("compose_lab", "ok", compose_lab_url)
        else:
            step("  compose lab falló — continuando con lab simple")
            result.add_step("compose_lab", "warn", "generation failed")

    # ── Library CVE detection: generate wrapper app as the target ─────────────
    wrapper_url = None
    wrapper_container = None
    if not compose_lab_url and _is_library_cve(cve_info, llm_notes):
        step("  LIBRARY CVE detectado — generando app demo como target HTTP…")
        result.add_step("library_detection", "ok",
                        "wrapper app needed — no direct HTTP endpoint on library")
        import tempfile as _tf
        wrapper_tmpdir = _tf.mkdtemp(prefix="bo_wrapper_")
        wrapper_url = _generate_wrapper_app(
            cve_id, cve_info, llm_notes, wrapper_tmpdir, step, llm=llm)
        if wrapper_url:
            wrapper_container = f"bo_wrapper_{cve_id.replace('-', '_').lower()}"
            # Inject the wrapper URL into config so investigate_cve targets it
            if config is None:
                config = {}
            config = dict(config)
            config["target_url"] = wrapper_url
            step(f"  target inyectado: {wrapper_url}")
            result.add_step("wrapper_app", "ok", wrapper_url)
        else:
            step("  wrapper app falló — continuando sin target HTTP")
            result.add_step("wrapper_app", "warn", "generation failed")

    try:
        from .cve_agent import investigate_cve
        inv = investigate_cve(
            cve_id=cve_id,
            config=config,
            llm=llm,
            on_step=step,
            lang=lang,
            budget_s=budget_s,
            use_cache=False,
        )
        result.verified = getattr(inv, "verified", False)
        result.findings = getattr(inv, "findings", [])
        result.inv      = inv
        status = "VERIFICADO" if result.verified else "no confirmado"
        step(f"  resultado: {status}")
        result.add_step("web_investigation", "ok",
                        f"verified={result.verified} findings={len(result.findings)}",
                        elapsed=t())
        return inv
    except Exception as e:
        _tb = traceback.format_exc()
        result.add_step("web_investigation", "error", str(e)[:120])
        step(f"  error: {e}")
        return None
    finally:
        # Clean up wrapper container if we started one
        if wrapper_container:
            try:
                import subprocess
                subprocess.run(
                    ["docker", "stop", wrapper_container],
                    capture_output=True, timeout=15,
                )
                step(f"  wrapper container {wrapper_container} detenido")
            except Exception:
                pass


# ── Enrich stage ──────────────────────────────────────────────────────────────

def _run_enrich_stage(result: ChainResult, step: Callable, llm=None, lang: str = "es"):
    t = _t()
    _banner(step, "[6/8] ENRICH — CVSS auto + CWE + resumen ejecutivo")
    if not result.findings:
        step("  sin hallazgos para enriquecer")
        result.add_step("enrich", "skip", "no findings")
        return

    try:
        from .enrich import enrich_findings, auto_cvss, map_cwe
        enrich_findings(llm, result.findings, lang=lang, on_step=step)
        for f in result.findings:
            cve_est = auto_cvss(f)
            cwes    = map_cwe(f)
            step(f"  [{f.title[:40]}] CVSS~{cve_est.score} CWE={cwes[0] if cwes else '?'}")
        result.add_step("enrich", "ok",
                        f"{len(result.findings)} findings enriched", elapsed=t())
    except Exception as e:
        result.add_step("enrich", "error", str(e)[:80])


# ── Professional report stage ─────────────────────────────────────────────────

def _run_report_stage(result: ChainResult, step: Callable,
                      lang: str = "es", save: bool = True,
                      cve_info=None) -> str:
    t = _t()
    _banner(step, "[7/8] PROFESSIONAL REPORT")

    md_parts = []

    # Try the full professional generator first
    if result.inv is not None:
        try:
            from .report_generator import generate_report
            rpt = generate_report(result.inv, lang=lang)
            md  = rpt.to_markdown()
            if md.strip():
                md_parts.append(md)
                step("  report_generator: OK")
        except Exception as e:
            step(f"  report_generator: {e} — fallback to render_investigation")

    # Fallback: render_investigation
    if not md_parts and result.inv is not None:
        try:
            from .cve_agent import render_investigation
            md = render_investigation(result.inv, lang=lang)
            if md.strip():
                md_parts.append(md)
        except Exception:
            pass

    # Patch diff
    if result.patch_summary:
        md_parts.append(result.patch_summary)
    # Mitigation bypass
    if result.mitigation_report:
        md_parts.append(result.mitigation_report)
    # Chain execution log (includes CVSS table + timeline)
    md_parts.append(_render_chain_log(result, lang, cve_info=cve_info))

    full_md = "\n\n---\n\n".join(md_parts)

    if save and full_md:
        try:
            report_dir = os.path.join(os.path.expanduser("~"), ".binoracle", "reports")
            os.makedirs(report_dir, exist_ok=True)
            path = os.path.join(report_dir, f"{result.cve_id}.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(full_md)
            result.report_path = path
            step(f"  informe guardado: {path}")
        except Exception as e:
            step(f"  no se pudo guardar: {e}")

    result.add_step("report", "ok", result.report_path, elapsed=t())
    return full_md


def _render_cvss_table(result: ChainResult, cve_info, lang: str = "es") -> str:
    """Render a CVSS breakdown table when score data is available."""
    if not result.cvss_score:
        return ""
    es = lang == "es"
    score = result.cvss_score
    severity = (result.cvss_severity or "").upper() or "N/A"
    # Try to get vector from cve_info
    vector = ""
    if cve_info:
        vector = (getattr(cve_info, "cvss_vector", "") or
                  getattr(cve_info, "cvss3_vector", "") or
                  (cve_info.get("cvss_vector") if isinstance(cve_info, dict) else "") or "")
    # Parse impact metrics from vector if present (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
    impact = ""
    if vector:
        parts = {seg.split(":")[0]: seg.split(":")[1]
                 for seg in vector.split("/") if ":" in seg}
        c = parts.get("C", "?")
        i = parts.get("I", "?")
        a = parts.get("A", "?")
        impact = f"C:{c} I:{i} A:{a}"

    hdr = "## " + ("Severidad CVSS" if es else "CVSS Severity")
    rows = [hdr, "",
            "| Métrica | Valor |" if es else "| Metric | Value |",
            "|---------|-------|",
            f"| Score | **{score}** ({severity}) |"]
    if vector:
        rows.append(f"| Vector | `{vector}` |")
    if impact:
        rows.append(f"| Impacto CIA | {impact} |")
    return "\n".join(rows)


def _render_timeline(result: ChainResult, lang: str = "es") -> str:
    """Render an investigation timeline table from result.steps."""
    if not result.steps:
        return ""
    es = lang == "es"
    hdr = "## " + ("Timeline de investigación" if es else "Investigation Timeline")
    rows = [hdr, "",
            "| Etapa | Estado | Duración |" if es else "| Stage | Status | Duration |",
            "|-------|--------|----------|"]
    for s in result.steps:
        icon = "✓" if s.status == "ok" else ("⊘" if s.status == "skip" else
               "⚠" if s.status == "warn" else "✗")
        rows.append(f"| `{s.name}` | {icon} {s.status} | {s.elapsed:.1f}s |")
    rows.append(f"| **Total** | | **{result.elapsed_s:.1f}s** |")
    return "\n".join(rows)


def _render_chain_log(result: ChainResult, lang: str = "es",
                      cve_info=None) -> str:
    es = lang == "es"
    parts = []

    # CVSS table
    cvss_table = _render_cvss_table(result, cve_info, lang)
    if cvss_table:
        parts.append(cvss_table)

    # Main log
    hdr = "## " + ("Ejecución autónoma — log" if es else "Autonomous execution log")
    out = [hdr, f"\n- **CVE**: `{result.cve_id}`"]
    if result.cvss_score:
        out.append(f"- **CVSS**: {result.cvss_score} ({result.cvss_severity})")
    if result.epss_score is not None:
        out.append(f"- **EPSS**: {result.epss_score:.1%} ({result.epss_pct:.0f}th percentil)")
    if result.in_cisa_kev:
        out.append("- **CISA KEV**: SÍ — EXPLOTADA ACTIVAMENTE")
    out.append(f"- **Risk**: {result.risk_label}")
    out.append(f"- **Verificado**: {'SÍ' if result.verified else 'NO'}")
    out.append(f"- **Tiempo total**: {result.elapsed_s:.1f}s\n")
    out.append("\n### " + ("Pasos" if es else "Steps"))
    for s in result.steps:
        icon = "✓" if s.status == "ok" else ("⊘" if s.status == "skip" else
               "⚠" if s.status == "warn" else "✗")
        out.append(f"- {icon} `{s.name}` — {s.detail} [{s.elapsed:.1f}s]")
    parts.append("\n".join(out))

    # Timeline
    timeline = _render_timeline(result, lang)
    if timeline:
        parts.append(timeline)

    return "\n\n".join(parts)


# ── Index HTML auto-update ────────────────────────────────────────────────────

def _index_path() -> str:
    """Find index.html relative to this file's project root."""
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(here, "index.html")
        if os.path.isfile(candidate):
            return candidate
        here = os.path.dirname(here)
    return ""


_CVSS_COLOR = {
    "critical": "#b91c1c",
    "high":     "#d97706",
    "medium":   "#374151",
    "low":      "#374151",
    "info":     "#374151",
}

_BADGE_VERIFIED   = '<span class="badge badge-sm" style="background:#065f46">✓ Verif.</span>'
_BADGE_LLM        = '<span class="badge badge-sm" style="background:#6d28d9">LLM-razonado</span>'
_BADGE_POC        = '<span class="badge badge-sm" style="background:#1e40af">PoC publico</span>'
_BADGE_AUTH       = '<span class="badge badge-sm" style="background:#374151">authenticated</span>'
_BADGE_UNAUTH     = '<span class="badge badge-sm" style="background:#065f46">unauthenticated</span>'


def _update_index_html(result: "ChainResult", cve_info, llm_notes: dict,
                       step: Callable) -> None:
    """Add a new row for this CVE to index.html if not already present."""
    idx = _index_path()
    if not idx:
        step("  index update: index.html no encontrado")
        return

    try:
        with open(idx, "r", encoding="utf-8") as fh:
            html = fh.read()
    except Exception as e:
        step(f"  index update: lectura fallida — {e}")
        return

    # Skip if CVE already has a row
    if result.cve_id in html:
        step(f"  index update: {result.cve_id} ya existe en index.html")
        return

    # ── Determine row number ──────────────────────────────────────────────────
    import re as _re
    nums = [int(m) for m in _re.findall(r'class="td-num">(\d+)<', html)]
    row_num = (max(nums) + 1) if nums else 1

    # ── CVE metadata ─────────────────────────────────────────────────────────
    score    = result.cvss_score or "N/A"
    severity = (result.cvss_severity or "medium").lower()
    sev_color = _CVSS_COLOR.get(severity, "#374151")
    sev_label = severity.upper()

    cve_class = (llm_notes.get("vuln_class") or result.cve_class or "unknown").lower()
    tech      = (llm_notes.get("technique") or llm_notes.get("cve_class") or cve_class).lower()
    tech      = tech.replace(" ", "-")[:40]

    # Badge: verified > PoC public > LLM-razonado
    has_poc = bool(getattr(cve_info, "poc_urls", None)) if cve_info else False
    if result.verified:
        verif_badge = _BADGE_VERIFIED
    elif has_poc:
        verif_badge = _BADGE_POC
    else:
        verif_badge = _BADGE_LLM

    # Auth badge
    auth_raw = str(llm_notes.get("auth_required", "")).lower()
    auth_badge = _BADGE_AUTH if auth_raw in ("true", "yes", "1", "authenticated") else _BADGE_UNAUTH

    # Affected component: prefer cve_info CPE vendor/product, else description keywords
    affected = ""
    if cve_info:
        cpus = getattr(cve_info, "cpe_matches", []) or []
        if cpus:
            parts = str(cpus[0]).split(":")
            if len(parts) > 4:
                affected = parts[4]
        if not affected:
            refs = getattr(cve_info, "references", []) or []
            for r in refs:
                s = str(r)
                for domain in ("github.com", "pypi.org", "npmjs.com"):
                    if domain in s:
                        seg = s.split(domain + "/")[-1].split("/")
                        if len(seg) >= 2:
                            affected = seg[1]
                            break
                if affected:
                    break
    if not affected:
        affected = result.cve_id.lower().replace("cve-", "pkg-")

    # Description: first 200 chars of CVE description
    desc_raw = (getattr(cve_info, "description", "") or result.description or "").strip()
    desc_html = desc_raw[:220].replace("<", "&lt;").replace(">", "&gt;")

    # Published date
    pub = getattr(cve_info, "published", "") or ""
    if hasattr(pub, "strftime"):
        pub = pub.strftime("%Y-%m-%d")
    else:
        pub = str(pub)[:10]

    # Data attributes
    is_gap   = "true" if not has_poc else "false"
    auth_dat = "true" if auth_raw in ("true", "yes", "1", "authenticated") else "false"
    sev_dat  = severity

    # Evidence link for verified CVEs: report path + verified endpoint
    evidence_html = ""
    if result.verified:
        # Endpoint that was verified
        verified_ep = ""
        if result.inv is not None:
            ep_raw = getattr(result.inv, "endpoint", "") or ""
            if ep_raw:
                verified_ep = str(ep_raw)[:60].replace("<", "&lt;").replace(">", "&gt;")
        technique = str(llm_notes.get("technique") or cve_class).replace("<", "&lt;")[:30]
        ep_span = (f' &middot; <code title="verified endpoint">{verified_ep}</code>'
                   if verified_ep else "")
        report_link = ""
        if result.report_path:
            rp = result.report_path.replace('"', '').replace("\\", "/")
            report_link = f' &middot; <a href="file://{rp}" target="_blank" title="Ver informe">informe</a>'
        evidence_html = (
            f'<span class="badge badge-sm" style="background:#0369a1" '
            f'title="{technique}{(" · " + verified_ep) if verified_ep else ""}">'
            f'{technique}</span>{ep_span}{report_link}'
        )

    row_html = (
        f'\n<tr class="cve-row" data-cls="{cve_class}" data-sev="{sev_dat}" '
        f'data-poc="{("false" if is_gap == "true" else "true")}" '
        f'data-auth="{auth_dat}" data-gap="{is_gap}">\n'
        f'  <td class="td-num">{row_num}</td>\n'
        f'  <td class="td-cve"><code>{result.cve_id}</code></td>\n'
        f'  <td><span class="badge" style="background:{sev_color}">{score} {sev_label}</span></td>\n'
        f'  <td><span class="badge badge-sm" style="background:#374151">{cve_class}</span></td>\n'
        f'  <td><code class="tech">{tech}</code></td>\n'
        f'  <td>{verif_badge}</td>\n'
        f'  <td>{auth_badge}</td>\n'
        f'  <td class="td-aff"><code>{affected}</code></td>\n'
        f'  <td class="td-pub">{pub}</td>\n'
        f'  <td class="td-desc">{desc_html}</td>\n'
        f'  <td class="td-links">{evidence_html}</td>\n'
        f'</tr>'
    )

    # Also update the DYN_VERIFIED JS map if verified
    if result.verified:
        dyn_marker = "const DYN_VERIFIED = {"
        if dyn_marker in html:
            html = html.replace(
                dyn_marker,
                f'{dyn_marker}\n  "{result.cve_id}": true,',
                1,
            )

    new_html = html.replace("</tbody>", row_html + "\n</tbody>", 1)

    try:
        with open(idx, "w", encoding="utf-8") as fh:
            fh.write(new_html)
        step(f"  index update: fila {row_num} añadida para {result.cve_id} "
             f"({'✓ Verif.' if result.verified else 'LLM-razonado'})")
        result.add_step("index_update", "ok", f"row={row_num}")
    except Exception as e:
        step(f"  index update: escritura fallida — {e}")
        result.add_step("index_update", "error", str(e)[:80])


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def run_full_chain(
    cve_id:      str,
    binary:      str   = "",
    lang:        str   = "es",
    budget_s:    float = 300.0,
    on_step:     Optional[Callable[[str], None]] = None,
    config=None,
    llm=None,
    save_report: bool  = True,
    no_cache:    bool  = False,
) -> ChainResult:
    """
    Cadena autónoma completa. Un investigador senior desde solo el CVE ID.

    Args:
        cve_id:      CVE identifier (e.g. "CVE-2024-1234")
        binary:      optional binary path (forces binary analysis path)
        lang:        "es" or "en"
        budget_s:    max seconds for the web investigation stage
        on_step:     progress callback(str)
        config:      binoracle config (auto-loaded if None)
        llm:         LLM backend (auto-created if None)
        save_report: save to ~/.binoracle/reports/{CVE_ID}.md
        no_cache:    force fresh investigation (bypass cache)

    Returns:
        ChainResult with verified, findings, report_md, report_path, etc.
    """
    t0     = time.time()
    cve_id = cve_id.upper().strip()
    step   = on_step or (lambda _m: None)
    result = ChainResult(cve_id=cve_id)

    def _budget_ok(min_s: float = 10.0) -> bool:
        """True when enough budget remains for the next stage."""
        return (time.time() - t0) < (budget_s - min_s)

    _banner(step, f"binoracle AUTO-CHAIN — {cve_id}")
    step(f"  lang={lang} budget={budget_s}s binary={'yes' if binary else 'no'}")

    # ── Load config + LLM ─────────────────────────────────────────────────────
    if config is None:
        try:
            from ..config import load_config
            config = load_config()
        except Exception:
            config = {}
    if llm is None:
        try:
            from ..llm import make_backend
            llm = make_backend(config)
            step(f"  LLM: {getattr(llm, 'model', '?')}")
        except Exception:
            step("  LLM: no disponible (modo determinístico)")

    # ── Stage 1: Intelligence ─────────────────────────────────────────────────
    cve_info = _gather_intelligence(cve_id, result, step)

    # ── Stage 2: LLM Hypothesis ───────────────────────────────────────────────
    _banner(step, "[2/8] LLM HYPOTHESIS")
    llm_notes: dict = {}
    if llm and result.description:
        try:
            from .cve_agent import _llm_research  # type: ignore
            llm_notes = _llm_research(llm, cve_id, result.description) or {}
            vc = llm_notes.get("vuln_class", "?")
            endpoint = llm_notes.get("endpoint", "?")
            step(f"  clase={vc}, endpoint={endpoint}, "
                 f"auth={llm_notes.get('auth_required','?')}")
            result.add_step("llm_hypothesis", "ok",
                            f"class={vc} auth={llm_notes.get('auth_required')}")
        except Exception as e:
            step(f"  hypothesis error: {e}")
            result.add_step("llm_hypothesis", "skip", str(e)[:80])
    else:
        step("  sin LLM o sin descripción — modo determinístico")
        result.add_step("llm_hypothesis", "skip", "no LLM")

    # ── Stage 3: Classify ─────────────────────────────────────────────────────
    _banner(step, "[3/8] CLASSIFY")
    if binary:
        result.cve_class = "binary"
    else:
        result.cve_class = _classify(cve_info, llm_notes)
        # Auto-learn: if classified as non-web but description hints at web, ask LLM
        # to extract the missing technology keyword and patch _WEB_SIGNALS automatically.
        if result.cve_class in ("binary", "native", "unknown"):
            if _auto_learn_web_signal(cve_info, llm_notes, llm, step):
                result.cve_class = _classify(cve_info, llm_notes)
                step(f"  CVE class (tras auto-learn): {result.cve_class}")
    step(f"  CVE class: {result.cve_class}")
    result.add_step("classify", "ok", result.cve_class)

    # ── Stage 4: Patch diff ───────────────────────────────────────────────────
    with tempfile.TemporaryDirectory(prefix="bo_chain_") as tmpdir:
        if cve_info:
            result.patch_summary = _run_patch_stage(
                cve_id, cve_info, result, step, tmpdir)

        # ── Stage 5: Core investigation ───────────────────────────────────────
        if binary:
            investigation_md = _run_binary_stage(cve_id, binary, result, step, llm=llm)
            result.report_md = investigation_md
        elif result.cve_class in ("web", "unknown", "cli"):
            _run_web_stage(
                cve_id, cve_info, llm_notes, result, step,
                budget_s=budget_s, config=config, llm=llm, lang=lang)
        elif result.cve_class in ("native", "binary"):
            # Auto-lab: attempt to install the vulnerable package in Docker and
            # run the LLM-generated PoC — no manual --binary needed.
            step("  CVE de binario/native: intentando auto-lab Docker...")
            investigation_md = _auto_binary_stage(
                cve_id, cve_info, llm_notes, result, step, llm=llm)
            if investigation_md:
                result.report_md = investigation_md
            else:
                # Fallback: web stage in case there's a Docker PoC in the repo
                step("  auto-lab no disponible — intentando web stage como fallback")
                _run_web_stage(
                    cve_id, cve_info, llm_notes, result, step,
                    budget_s=budget_s, config=config, llm=llm, lang=lang)
        else:
            result.add_step("investigation", "skip", f"class={result.cve_class}")

    # ── Stage 6: Enrich ───────────────────────────────────────────────────────
    if _budget_ok(min_s=20.0):
        _run_enrich_stage(result, step, llm=llm, lang=lang)
    else:
        step("  [6/8] enrich: presupuesto agotado — omitido")
        result.add_step("enrich", "skip", "budget exhausted")

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    result.elapsed_s = time.time() - t0
    result.report_md = _run_report_stage(result, step, lang=lang, save=save_report,
                                         cve_info=cve_info)

    # ── Stage 7.5: Index update ───────────────────────────────────────────────
    _update_index_html(result, cve_info, llm_notes, step)

    # ── Stage 8: Done ─────────────────────────────────────────────────────────
    _banner(step, f"[8/8] COMPLETADO en {result.elapsed_s:.1f}s")
    step(result.banner())
    if result.report_path:
        step(f"  informe: {result.report_path}")

    # ── Engine confidence score ───────────────────────────────────────────────
    # Composite score (0–1) summarizing how trustworthy the result is:
    # - verified dynamically → 0.90 base
    # - LLM-only hypothesis  → 0.30 base
    # Bonuses: has patch diff (+0.05), has CVSS (+0.03), CISA KEV (+0.07)
    # Penalty: error present (-0.20), class=unknown (-0.10)
    _conf = 0.90 if result.verified else 0.30
    if result.patch_summary:
        _conf += 0.05
    if result.cvss_score:
        _conf += 0.03
    if result.in_cisa_kev:
        _conf += 0.07
    if result.error:
        _conf -= 0.20
    if result.cve_class == "unknown":
        _conf -= 0.10
    result.engine_confidence = round(max(0.0, min(1.0, _conf)), 2)

    # ── Lessons: record this CVE's outcome for future runs ────────────────────
    try:
        from .cve_lessons import detect_stack, record_cve_result
        inv = result.inv
        _les_desc = (cve_info.get("description") or "") if cve_info else ""
        _les_stack = detect_stack(_les_desc)
        _les_notes = (getattr(inv, "llm_notes", {}) or {}) if inv else {}
        _les_ep = _les_notes.get("endpoint") or ""
        _les_bh = _les_notes.get("bypass_header") or ""
        _les_bv = _les_notes.get("bypass_value") or ""
        _les_vc = (getattr(inv, "vuln_class", "") or _les_notes.get("vuln_class", "")) if inv else ""
        record_cve_result(_les_stack, cve_id, _les_ep, result.verified,
                          _les_bh, _les_bv, _les_vc)
    except Exception:
        pass

    # ── Notifications: webhook / Telegram alert on verified CVE ──────────────
    if result.verified:
        _notify_verified(cve_id, result)

    return result


def _notify_verified(cve_id: str, result: "ChainResult") -> None:
    """Fire optional notifications when a CVE is dynamically verified.

    Checks two env vars (never hardcoded):
      BINORACLE_WEBHOOK_URL  — POST JSON to this URL
      BINORACLE_TELEGRAM_TOKEN + BINORACLE_TELEGRAM_CHAT_ID — send Telegram message

    Both are optional and independent. Failures are silently ignored so they
    never block the main chain.
    """
    import json as _json
    import urllib.request as _req

    payload = {
        "cve_id": cve_id,
        "verified": True,
        "vuln_class": getattr(result.inv, "vuln_class", "") if result.inv else "",
        "report_path": result.report_path or "",
        "elapsed_s": round(result.elapsed_s, 1),
    }

    # Webhook
    webhook_url = os.environ.get("BINORACLE_WEBHOOK_URL", "")
    if webhook_url:
        try:
            body = _json.dumps(payload).encode()
            rq = _req.Request(webhook_url, data=body,
                              headers={"Content-Type": "application/json"}, method="POST")
            with _req.urlopen(rq, timeout=8):
                pass
        except Exception:
            pass

    # Telegram
    tg_token = os.environ.get("BINORACLE_TELEGRAM_TOKEN", "")
    tg_chat  = os.environ.get("BINORACLE_TELEGRAM_CHAT_ID", "")
    if tg_token and tg_chat:
        try:
            vc = payload["vuln_class"] or "?"
            msg = (f"🔴 binoracle VERIFICADO\n"
                   f"CVE: {cve_id}\n"
                   f"Clase: {vc}\n"
                   f"Tiempo: {payload['elapsed_s']}s")
            tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
            tg_body = _json.dumps({"chat_id": tg_chat, "text": msg}).encode()
            tg_req = _req.Request(tg_url, data=tg_body,
                                  headers={"Content-Type": "application/json"}, method="POST")
            with _req.urlopen(tg_req, timeout=8):
                pass
        except Exception:
            pass


# ── Auto-queue: NVD + Telegram feed → run_full_chain autonomously ─────────────

def auto_queue_nvd(days_back: int = 2, min_cvss: float = 7.0,
                   max_cves: int = 10, web_only: bool = True,
                   lang: str = "es", budget_s: float = 300.0,
                   priority_mode: str = "cvss",
                   on_step=None) -> List["ChainResult"]:
    """Fetch recent high-severity web CVEs from NVD and investigate each autonomously.

    Pulls CVEs published in the last `days_back` days with CVSS >= min_cvss,
    filters to web-related ones (unless web_only=False), and runs run_full_chain
    on each. Returns the list of ChainResult objects.

    priority_mode:
      "cvss"  — sort by CVSS score descending (default)
      "new"   — newest published first
      "cms"   — CMS-related CVEs first (WordPress/Drupal/Joomla), then by CVSS

    Usage:
        from binoracle.workflows.auto_chain import auto_queue_nvd
        results = auto_queue_nvd(days_back=1, min_cvss=8.0, priority_mode="cms")
        for r in results:
            print(r.cve_id, '✓' if r.verified else '?')
    """
    step = on_step or print
    try:
        from .cvefeed import poll_nvd_new
        from .cve_lessons import detect_stack, get_lessons, record_cve_result
        from .cve_retry_queue import add_to_retry, mark_done, is_transient_error
    except ImportError as e:
        step(f"auto_queue_nvd: import error — {e}")
        return []

    step(f"auto_queue_nvd: consultando NVD (últimos {days_back}d, CVSS≥{min_cvss}, modo={priority_mode})…")
    entries = poll_nvd_new(days_back=days_back, min_cvss=min_cvss, web_only=web_only)
    if not entries:
        step("auto_queue_nvd: sin CVEs nuevos")
        return []

    # Apply priority_mode sort
    _cms_kws = ("wordpress", "drupal", "joomla", "wp-")
    if priority_mode == "new":
        entries = sorted(entries, key=lambda e: e.published, reverse=True)
    elif priority_mode == "cms":
        entries = sorted(entries,
                         key=lambda e: (not any(k in e.description.lower() for k in _cms_kws),
                                        -e.cvss_score))
    # default "cvss" — poll_nvd_new already returns sorted by CVSS desc

    # parallel controls concurrent investigation (default 1 = serial for safety
    # since each investigation spins up Docker containers)
    _parallel = max(1, min(int(os.environ.get("BINORACLE_PARALLEL", "1")), 4))
    step(f"auto_queue_nvd: {len(entries)} CVEs nuevos — procesando hasta {max_cves} "
         f"(concurrencia={_parallel})")
    results: list = []

    def _run_one(entry) -> "ChainResult":
        step(f"\n{'='*60}")
        step(f"auto_queue_nvd: investigando {entry.cve_id} (CVSS {entry.cvss_score})")
        step(f"  {entry.description[:120]}…")
        stack = detect_stack(entry.description)
        prior = get_lessons(stack)
        if prior:
            step(f"  lecciones previas ({stack}): tasa_verificación="
                 f"{prior.get('verified_rate', 0):.0%}, "
                 f"endpoints={prior.get('top_endpoints', [])[:2]}")
        try:
            r = run_full_chain(entry.cve_id, lang=lang, budget_s=budget_s,
                               on_step=step, save_report=True)
            status = "✓ VERIFICADO" if r.verified else "? LLM-razonado"
            step(f"  {entry.cve_id}: {status}")
            inv = getattr(r, "inv", None)
            endpoint = bypass_hdr = bypass_val = vuln_cls = ""
            if inv:
                notes = getattr(inv, "llm_notes", {}) or {}
                endpoint = notes.get("endpoint") or ""
                bypass_hdr = notes.get("bypass_header") or ""
                bypass_val = notes.get("bypass_value") or ""
                vuln_cls = getattr(inv, "vuln_class", "") or notes.get("vuln_class", "")
            record_cve_result(stack, entry.cve_id, endpoint, r.verified,
                              bypass_hdr, bypass_val, vuln_cls)
            if r.verified:
                mark_done(entry.cve_id)
            elif r.error and is_transient_error(r.error):
                step(f"  {entry.cve_id}: error transitorio — añadiendo a retry queue")
                add_to_retry(entry.cve_id, r.error, stack)
            return r
        except Exception as exc:
            step(f"  {entry.cve_id}: error — {exc}")
            add_to_retry(entry.cve_id, str(exc), "")
            _err = ChainResult(cve_id=entry.cve_id)
            _err.error = str(exc)
            return _err

    if _parallel > 1:
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=_parallel) as pool:
            futures = [pool.submit(_run_one, e) for e in entries[:max_cves]]
            for fut in _cf.as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    step(f"auto_queue_nvd: error en hilo — {exc}")
    else:
        for entry in entries[:max_cves]:
            results.append(_run_one(entry))
    return results


def retry_failed_cves(max_cves: int = 5, lang: str = "es",
                      budget_s: float = 300.0, on_step=None) -> List["ChainResult"]:
    """Retry CVEs that previously failed with transient errors.

    Fetches pending CVEs from the retry queue (not older than 24h, max 3 attempts),
    runs run_full_chain on each, and updates the queue accordingly.
    """
    step = on_step or print
    try:
        from .cve_retry_queue import get_pending, mark_done, mark_attempt, is_transient_error
    except ImportError as e:
        step(f"retry_failed_cves: import error — {e}")
        return []

    pending = get_pending()[:max_cves]
    if not pending:
        step("retry_failed_cves: sin CVEs pendientes de reintento")
        return []

    step(f"retry_failed_cves: reintentando {len(pending)} CVEs fallidos…")
    results = []
    for cve_id in pending:
        step(f"\nretry_failed_cves: reintentando {cve_id}")
        try:
            r = run_full_chain(cve_id, lang=lang, budget_s=budget_s,
                               on_step=step, save_report=True)
            results.append(r)
            if r.verified or not r.error:
                mark_done(cve_id)
                step(f"  {cve_id}: {'✓ VERIFICADO' if r.verified else '? completado'} — eliminado de retry queue")
            elif is_transient_error(r.error):
                mark_attempt(cve_id, r.error)
                step(f"  {cve_id}: sigue fallando — intento registrado")
            else:
                mark_done(cve_id)
                step(f"  {cve_id}: error no-transitorio — eliminado de retry queue")
        except Exception as exc:
            step(f"  {cve_id}: excepción — {exc}")
            mark_attempt(cve_id, str(exc))
    return results


def auto_queue_telegram(channel: str = "CVENotify", web_only: bool = False,
                        max_cves: int = 10, lang: str = "es",
                        budget_s: float = 300.0, on_step=None) -> List["ChainResult"]:
    """Poll Telegram @CVENotify for new CVE mentions and investigate each.

    Complements auto_queue_nvd — Telegram often publishes CVEs before NVD.
    """
    step = on_step or print
    try:
        from .cvefeed import poll_new_cve_mentions
    except ImportError as e:
        step(f"auto_queue_telegram: no se puede importar cvefeed — {e}")
        return []

    step(f"auto_queue_telegram: consultando @{channel}…")
    mentions = poll_new_cve_mentions(channel=channel)
    if web_only:
        mentions = [m for m in mentions if m.cms_related]
    if not mentions:
        step("auto_queue_telegram: sin CVEs nuevos")
        return []

    step(f"auto_queue_telegram: {len(mentions)} CVEs nuevos")
    results = []
    for m in mentions[:max_cves]:
        step(f"\nauto_queue_telegram: investigando {m.cve_id}")
        try:
            r = run_full_chain(m.cve_id, lang=lang, budget_s=budget_s,
                               on_step=step, save_report=True)
            results.append(r)
            step(f"  {m.cve_id}: {'✓' if r.verified else '?'}")
        except Exception as exc:
            step(f"  {m.cve_id}: error — {exc}")
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def chain_cli(argv=None):
    """Entry point: binoracle chain CVE-XXXX-YYYY [--binary /path] [--lang es|en]"""
    import argparse
    p = argparse.ArgumentParser(prog="binoracle chain",
                                description="Cadena autónoma completa desde solo el CVE ID")
    p.add_argument("cve_id", help="CVE identifier (e.g. CVE-2024-1234)")
    p.add_argument("--binary", default="", help="Path to binary (for binary CVEs)")
    p.add_argument("--lang", default="es", choices=["es", "en"])
    p.add_argument("--budget", type=float, default=300.0,
                   help="Max seconds for web investigation stage")
    p.add_argument("--no-save", action="store_true",
                   help="Don't save report to disk")
    p.add_argument("--no-cache", action="store_true",
                   help="Force fresh investigation (bypass cache)")
    args = p.parse_args(argv)

    result = run_full_chain(
        cve_id=args.cve_id,
        binary=args.binary,
        lang=args.lang,
        budget_s=args.budget,
        on_step=lambda m: print(f"  {m}"),
        save_report=not args.no_save,
        no_cache=args.no_cache,
    )
    print(result.report_md)
    return 0 if not result.error else 1
