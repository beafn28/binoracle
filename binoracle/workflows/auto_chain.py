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


# ── Chain checkpoint system ───────────────────────────────────────────────────

def _checkpoint_path(cve_id: str) -> str:
    """Return path to the checkpoint file for a CVE chain run."""
    _dir = os.path.join(os.path.expanduser("~"), ".binoracle", "checkpoints")
    os.makedirs(_dir, exist_ok=True)
    _slug = cve_id.replace("/", "_").replace("\\", "_")
    return os.path.join(_dir, f"{_slug}.json")


def _save_checkpoint(result: ChainResult, llm_notes: dict, stage: str) -> None:
    """Persist chain state after a completed stage.

    Serializes the parts of ChainResult that are JSON-safe and cheap to
    re-use: steps, evidence, scores, llm_notes. The inv object (raw
    Investigation) is NOT persisted — it holds Docker state.
    """
    import json as _json
    try:
        _data = {
            "cve_id": result.cve_id,
            "last_stage": stage,
            "cve_class": result.cve_class,
            "cvss_score": result.cvss_score,
            "cvss_severity": result.cvss_severity,
            "epss_score": result.epss_score,
            "risk_label": result.risk_label,
            "description": result.description,
            "verified": result.verified,
            "error": result.error,
            "patch_summary": result.patch_summary[:2000] if result.patch_summary else "",
            "evidence": {k: v for k, v in (result.evidence or {}).items()
                         if isinstance(v, (str, int, float, bool, list, dict, type(None)))},
            "llm_notes": llm_notes,
            "steps": [{"name": s.name, "status": s.status,
                        "detail": s.detail, "elapsed": s.elapsed}
                       for s in result.steps],
            "saved_at": time.time(),
        }
        with open(_checkpoint_path(result.cve_id), "w", encoding="utf-8") as f:
            _json.dump(_data, f, indent=2, default=str)
    except Exception:
        pass


def _load_checkpoint(cve_id: str) -> Optional[dict]:
    """Load a saved checkpoint for a CVE, if it exists and is recent (< 24h).

    Returns the dict or None if not found / too old.
    """
    import json as _json
    try:
        path = _checkpoint_path(cve_id)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as f:
            data = _json.load(f)
        # Discard checkpoints older than 24 hours
        age = time.time() - float(data.get("saved_at", 0))
        if age > 86400:
            os.unlink(path)
            return None
        return data
    except Exception:
        return None


def _clear_checkpoint(cve_id: str) -> None:
    """Remove a checkpoint once the chain completes successfully."""
    try:
        p = _checkpoint_path(cve_id)
        if os.path.isfile(p):
            os.unlink(p)
    except Exception:
        pass


# ── Semantic response body analysis ──────────────────────────────────────────

_RESPONSE_PATTERNS = {
    # Credentials / secrets exposed in body
    "aws_key": (re.compile(
        r'AKIA[0-9A-Z]{16}', re.IGNORECASE), "AWS Access Key ID in response body"),
    "jwt_token": (re.compile(
        r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'),
        "JWT token in response body"),
    "private_key": (re.compile(
        r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'), "Private key in response body"),
    "password_field": (re.compile(
        r'"password"\s*:\s*"[^"]{6,}"', re.IGNORECASE), "Password field in JSON response"),
    "api_key": (re.compile(
        r'"api[_-]?key"\s*:\s*"[^"]{8,}"', re.IGNORECASE), "API key in JSON response"),
    "secret_field": (re.compile(
        r'"secret"\s*:\s*"[^"]{8,}"', re.IGNORECASE), "Secret field in JSON response"),
    "auth_token": (re.compile(
        r'"(?:auth|access|refresh)[_-]?token"\s*:\s*"[^"]{20,}"', re.IGNORECASE),
        "Auth token in JSON response"),
    # Technical information disclosure
    "stack_trace_php": (re.compile(
        r'(?:Fatal error|Parse error|Warning).*on line \d+', re.IGNORECASE),
        "PHP error/stack trace in response"),
    "stack_trace_python": (re.compile(
        r'Traceback \(most recent call last\)', re.IGNORECASE),
        "Python traceback in response"),
    "stack_trace_java": (re.compile(
        r'(?:java\.|javax\.|org\.|com\.)[A-Za-z]+Exception:', re.IGNORECASE),
        "Java exception in response"),
    "stack_trace_node": (re.compile(
        r'(?:TypeError|ReferenceError|SyntaxError): .+\n\s+at .+:\d+:\d+', re.IGNORECASE),
        "Node.js stack trace in response"),
    "sql_error": (re.compile(
        r"(?:You have an error in your SQL syntax|SQLSTATE\[|pg::SyntaxError|"
        r"ORA-\d{5}|sqlite3\.OperationalError)", re.IGNORECASE),
        "SQL error in response — SQLi confirmed"),
    "etc_passwd": (re.compile(
        r'root:(?:x|\*|!):0:0:', re.IGNORECASE), "/etc/passwd content in response"),
    "db_credentials": (re.compile(
        r'"(?:db_|database_)?(?:user|pass|password|host)"\s*:\s*"[^"]{3,}"', re.IGNORECASE),
        "Database credentials in response"),
    "internal_path": (re.compile(
        r'(?:/var/www/|/usr/local/|/home/\w+/|C:\\\\Users\\\\)', re.IGNORECASE),
        "Internal server path disclosed in response"),
    "xss_reflection": (re.compile(
        r'<script[^>]*>.*?alert\s*\(|<img[^>]+onerror\s*=|<svg[^>]+onload\s*=',
        re.IGNORECASE | re.DOTALL),
        "XSS payload reflected unescaped in response"),
    # Admin / privileged data
    "user_enumeration": (re.compile(
        r'"(?:users?|accounts?)"\s*:\s*\[', re.IGNORECASE), "User list in response"),
    "admin_data": (re.compile(
        r'"(?:is_admin|is_staff|role)"\s*:\s*"?(?:true|admin|superuser|1)',
        re.IGNORECASE), "Admin/privileged field in response"),
}


def _analyze_response_body(body: str, vuln_class: str = "") -> dict:
    """Analyze an HTTP response body for security-significant patterns.

    Returns a dict with:
      findings: list of (pattern_name, description) tuples
      severity_upgrade: bool — finding implies higher impact than base vuln_class
      impact_class: str — 'credential_exposure' | 'data_disclosure' | 'code_execution' |
                          'information_disclosure' | ''
      confidence_bonus: float — additional engine_confidence to add (0-0.15)
    """
    if not body:
        return {"findings": [], "severity_upgrade": False,
                "impact_class": "", "confidence_bonus": 0.0}

    findings = []
    for name, (pattern, description) in _RESPONSE_PATTERNS.items():
        if pattern.search(body):
            findings.append((name, description))

    if not findings:
        return {"findings": [], "severity_upgrade": False,
                "impact_class": "", "confidence_bonus": 0.0}

    # Classify impact
    _cred_findings = {f[0] for f in findings} & {
        "aws_key", "jwt_token", "private_key", "password_field",
        "api_key", "secret_field", "auth_token", "db_credentials"}
    _code_findings = {f[0] for f in findings} & {"xss_reflection", "etc_passwd"}
    _disclosure_findings = {f[0] for f in findings} & {
        "stack_trace_php", "stack_trace_python", "stack_trace_java",
        "stack_trace_node", "sql_error", "internal_path",
        "user_enumeration", "admin_data"}

    if _cred_findings:
        impact_class = "credential_exposure"
        severity_upgrade = True
        confidence_bonus = 0.12
    elif _code_findings:
        impact_class = "code_execution" if "etc_passwd" in _code_findings else "xss_confirmed"
        severity_upgrade = True
        confidence_bonus = 0.10
    elif "sql_error" in {f[0] for f in findings}:
        impact_class = "sqli_confirmed"
        severity_upgrade = True
        confidence_bonus = 0.10
    elif _disclosure_findings:
        impact_class = "information_disclosure"
        severity_upgrade = False
        confidence_bonus = 0.05
    else:
        impact_class = "data_disclosure"
        severity_upgrade = True
        confidence_bonus = 0.08

    return {
        "findings": findings,
        "severity_upgrade": severity_upgrade,
        "impact_class": impact_class,
        "confidence_bonus": confidence_bonus,
    }


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

        # Store raw diff for source-level analysis in Stage 4b
        result.evidence["raw_patch_text"] = patch_text[:65536]  # cap at 64KB

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
        # apk version format: pkg=version or pkg=version-r0
        pkg_prefix = f"{pkg_spec}*" if pkg_version else pkg_name
        install_cmd = (f"RUN apk add --no-cache {pkg_spec} 2>/dev/null || "
                       f"apk add --no-cache '{pkg_prefix}' 2>/dev/null || "
                       f"apk add --no-cache {pkg_name}")
    else:
        # apt version format: pkg=version or pkg=version-1ubuntu1*
        # Try exact, then prefix wildcard (handles epoch/revision suffixes), then unversioned
        pkg_prefix = f"{pkg_name}={pkg_version}*" if pkg_version else pkg_name
        install_cmd = (
            f"RUN apt-get update -qq && apt-get install -y --no-install-recommends "
            f"{pkg_spec} 2>/dev/null || "
            f"apt-get install -y --no-install-recommends '{pkg_prefix}' 2>/dev/null || "
            f"apt-get install -y --no-install-recommends {pkg_name}"
        )

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

        # Semantic response body analysis — extract additional signals from
        # any response body captured in evidence (stack traces, credentials, etc.)
        _body_to_analyze = ""
        for _ev_key in ("respuesta_cuerpo_recorte", "exploit_response", "body_snippet",
                        "listener_log_recorte"):
            _ev_body = getattr(inv, "evidence", {}) or {}
            _ev_body = _ev_body if isinstance(_ev_body, dict) else {}
            _candidate = _ev_body.get(_ev_key, "")
            if isinstance(_candidate, str) and len(_candidate) > 20:
                _body_to_analyze = _candidate
                break
        if not _body_to_analyze:
            # Try result.evidence too
            for _ev_key in ("respuesta_cuerpo_recorte", "exploit_response"):
                _candidate = result.evidence.get(_ev_key, "")
                if isinstance(_candidate, str) and len(_candidate) > 20:
                    _body_to_analyze = _candidate
                    break

        if _body_to_analyze:
            _body_analysis = _analyze_response_body(
                _body_to_analyze, llm_notes.get("vuln_class", ""))
            if _body_analysis["findings"]:
                result.evidence["response_body_analysis"] = _body_analysis
                _found_names = [f[1] for f in _body_analysis["findings"]]
                step(f"  respuesta semántica: {', '.join(_found_names[:3])}")
                # Apply confidence bonus
                result.engine_confidence = min(
                    1.0, result.engine_confidence + _body_analysis["confidence_bonus"])
                # Tag impact class in evidence
                result.evidence["impact_class"] = _body_analysis["impact_class"]
                if _body_analysis["severity_upgrade"]:
                    step(f"  impacto actualizado: {_body_analysis['impact_class']}")

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
    # Deep patch analysis section (when available and confident)
    _pa = result.evidence.get("patch_analysis", {})
    if _pa and _pa.get("confidence", 0) >= 0.60:
        _pa_es = lang == "es"
        _pa_hdr = "## Análisis del parche" if _pa_es else "## Patch Analysis"
        _pa_rows = [
            (_pa_hdr, ""),
            ("| Campo | Valor |" if _pa_es else "| Field | Value |", ""),
            ("|-------|-------|", ""),
        ]
        if _pa.get("vuln_function"):
            _lbl = "Función vulnerable" if _pa_es else "Vulnerable function"
            _pa_rows.append((f"| {_lbl} | `{_pa['vuln_function']}` |", ""))
        if _pa.get("vuln_file"):
            _lbl = "Archivo" if _pa_es else "File"
            _pa_rows.append((f"| {_lbl} | `{_pa['vuln_file']}` |", ""))
        if _pa.get("vuln_pattern"):
            _lbl = "Patrón vulnerable" if _pa_es else "Vuln pattern"
            _pa_rows.append((f"| {_lbl} | {_pa['vuln_pattern']} |", ""))
        if _pa.get("patch_pattern"):
            _lbl = "Fix aplicado" if _pa_es else "Fix applied"
            _pa_rows.append((f"| {_lbl} | {_pa['patch_pattern']} |", ""))
        if _pa.get("suggested_param"):
            _lbl = "Parámetro sugerido" if _pa_es else "Suggested param"
            _pa_rows.append((f"| {_lbl} | `{_pa['suggested_param']}` |", ""))
        if _pa.get("suggested_value"):
            _lbl = "Payload sugerido" if _pa_es else "Suggested payload"
            _pa_rows.append((f"| {_lbl} | `{_pa['suggested_value']}` |", ""))
        _conf_pct = f"{_pa['confidence']:.0%}"
        _lbl = "Confianza" if _pa_es else "Confidence"
        _pa_rows.append((f"| {_lbl} | {_conf_pct} |", ""))
        md_parts.append("\n".join(r[0] for r in _pa_rows))
        # Include PoC HTTP block if generated
        if _pa.get("poc_http"):
            _poc_hdr = ("### PoC HTTP (generado del diff)\n\n"
                        if _pa_es else
                        "### PoC HTTP (generated from diff)\n\n")
            md_parts.append(_poc_hdr + "```http\n" + _pa["poc_http"] + "\n```")
    # Response body analysis — semantic signals found in HTTP responses
    _rba = result.evidence.get("response_body_analysis", {})
    if _rba and _rba.get("findings"):
        _rba_es = lang == "es"
        _rba_hdr = "## Análisis semántico del cuerpo de respuesta" if _rba_es else "## Response Body Semantic Analysis"
        _rba_lines = [_rba_hdr, ""]
        _rba_ic = _rba.get("impact_class", "")
        if _rba_ic:
            _lbl = "Clase de impacto observada" if _rba_es else "Observed impact class"
            _rba_lines.append(f"**{_lbl}:** `{_rba_ic}`")
        _rba_bonus = _rba.get("confidence_bonus", 0)
        if _rba_bonus:
            _lbl = "Bonus de confianza aplicado" if _rba_es else "Confidence bonus applied"
            _rba_lines.append(f"**{_lbl}:** +{_rba_bonus:.0%}")
        _rba_lines.append("")
        _fnd_hdr = "| Patrón | Descripción |" if _rba_es else "| Pattern | Description |"
        _rba_lines.append(_fnd_hdr)
        _rba_lines.append("|--------|-------------|")
        for _fname, _fdesc in _rba["findings"][:8]:
            _rba_lines.append(f"| `{_fname}` | {_fdesc} |")
        md_parts.append("\n".join(_rba_lines))

    # GraphQL schema probe results
    _gql = result.evidence.get("graphql_schema", {})
    if _gql and (_gql.get("queries") or _gql.get("mutations")):
        _gql_es = lang == "es"
        _gql_hdr = "## Esquema GraphQL descubierto" if _gql_es else "## GraphQL Schema Discovery"
        _gql_lines = [_gql_hdr, ""]
        if _gql.get("queries"):
            _lbl = "Queries" if not _gql_es else "Queries disponibles"
            _gql_lines.append(f"**{_lbl}:** {', '.join(_gql['queries'][:10])}")
        if _gql.get("mutations"):
            _lbl = "Mutations" if not _gql_es else "Mutations disponibles"
            _gql_lines.append(f"**{_lbl}:** {', '.join(_gql['mutations'][:10])}")
        if _gql.get("sensitive_fields"):
            _lbl = "Campos sensibles detectados" if _gql_es else "Sensitive fields detected"
            _gql_lines.append(f"**{_lbl}:** {', '.join(_gql['sensitive_fields'][:8])}")
        if _gql.get("lfi_ssrf_candidates"):
            _lbl = "Candidatos LFI/SSRF (args de ruta/URL)" if _gql_es else "LFI/SSRF candidates (path/url args)"
            _gql_lines.append(f"**{_lbl}:** {', '.join(_gql['lfi_ssrf_candidates'][:6])}")
        if _gql.get("auth_required_queries"):
            _lbl = "Queries con autenticación" if _gql_es else "Auth-gated queries"
            _gql_lines.append(f"**{_lbl}:** {', '.join(_gql['auth_required_queries'][:5])}")
        md_parts.append("\n".join(_gql_lines))

    # SSRF cloud metadata escalation results
    _ssrf_esc = result.evidence.get("ssrf_cloud_escalation", {})
    if _ssrf_esc and (_ssrf_esc.get("has_credentials") or _ssrf_esc.get("cloud_responses")):
        _ssrf_es = lang == "es"
        _ssrf_hdr = "## Escalado SSRF → Metadatos Cloud" if _ssrf_es else "## SSRF Cloud Metadata Escalation"
        _ssrf_lines = [_ssrf_hdr, ""]
        if _ssrf_esc.get("has_credentials"):
            _lbl = "CREDENCIALES EXPUESTAS" if _ssrf_es else "CREDENTIALS EXPOSED"
            _ssrf_lines.append(f"**{_lbl}** — el SSRF permitió acceder a metadatos de credenciales cloud")
        for _cloud_resp in (_ssrf_esc.get("cloud_responses") or [])[:5]:
            _ssrf_lines.append(f"- `{_cloud_resp.get('provider','?')}` {_cloud_resp.get('url','?')}: "
                               f"HTTP {_cloud_resp.get('status','?')} "
                               f"({_cloud_resp.get('type','?')})")
        md_parts.append("\n".join(_ssrf_lines))

    # YWH writeup reference (when auto-generated)
    _ywh = result.evidence.get("ywh_writeup", {})
    if _ywh and _ywh.get("title"):
        _ywh_es = lang == "es"
        _ywh_hdr = "## Borrador YesWeHack" if _ywh_es else "## YesWeHack Draft"
        _ywh_file = _ywh.get("file", "")
        _ywh_note = (f"Reporte estructurado generado en `{_ywh_file}`" if _ywh_file else
                     "Reporte estructurado disponible en `evidence['ywh_writeup']`")
        _ywh_note_en = (f"Structured report saved to `{_ywh_file}`" if _ywh_file else
                        "Structured report available in `evidence['ywh_writeup']`")
        _ywh_lines = [
            _ywh_hdr, "",
            f"**Título:** {_ywh['title']}" if _ywh_es else f"**Title:** {_ywh['title']}",
            f"**Severidad:** {_ywh.get('severity','?')}" if _ywh_es else f"**Severity:** {_ywh.get('severity','?')}",
            (_ywh_note if _ywh_es else _ywh_note_en),
        ]
        md_parts.append("\n".join(_ywh_lines))

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
    out.append(f"- **Verificado**: {'SÍ ✓' if result.verified else 'NO ✗'}")
    _conf_pct = int(result.engine_confidence * 100)
    _conf_level = ("ALTO" if result.engine_confidence >= 0.80 else
                   "MEDIO" if result.engine_confidence >= 0.50 else "BAJO")
    _conf_basis = ("verificado dinámicamente" if result.verified else "hipótesis LLM") if es else \
                  ("dynamically verified" if result.verified else "LLM hypothesis only")
    out.append(f"- **{'Confianza del motor' if es else 'Engine confidence'}**: "
               f"{_conf_pct}% ({_conf_level}) · {_conf_basis}")
    out.append(f"- **Tiempo total**: {result.elapsed_s:.1f}s\n")

    # Diagnosis block: when not verified, explain why and suggest next steps
    if not result.verified:
        _diag_items = []
        # Look at failed steps for clues
        _failed_steps = [s for s in result.steps if s.status in ("fail", "error")]
        for _fs in _failed_steps[:3]:
            if "403" in _fs.detail:
                _diag_items.append("endpoint responde 403 — el payload no eludió la autorización")
            elif "404" in _fs.detail:
                _diag_items.append("endpoint responde 404 — ruta no encontrada en esta versión")
            elif "timeout" in _fs.detail.lower():
                _diag_items.append("timeout del contenedor — el lab no arrancó correctamente")
            elif "container" in _fs.detail.lower() or "docker" in _fs.detail.lower():
                _diag_items.append("fallo de infraestructura Docker — revisar logs del contenedor")
            elif "confirm_string" in _fs.detail.lower() or "wrong_body" in _fs.detail.lower():
                _diag_items.append("endpoint accesible pero confirm_string no presente — "
                                   "revisar respuesta real del servidor")
        # Check if precheck blocked
        _prec = next((s for s in result.steps if "precheck" in s.name), None)
        if _prec and _prec.status == "fail":
            _diag_items.append(f"precheck bloqueó el lab: {_prec.detail[:80]}")
        # Check if autofuzz ran but found nothing
        _fuzz = next((s for s in result.steps if "autofuzz" in s.name), None)
        if _fuzz and _fuzz.status == "fail":
            _diag_items.append("fuzzing de parámetros no encontró injection point — "
                                "prueba BINORACLE_FUZZ=1 con más presupuesto")
        if result.cve_class == "unknown":
            _diag_items.append("clase de vulnerabilidad desconocida — el LLM no pudo clasificarla")
        if result.error:
            _diag_items.append(f"error: {result.error[:100]}")
        # Next steps
        _next = []
        if any("403" in d or "autorización" in d for d in _diag_items):
            _next.append("intentar bypass alternativo: `X-Forwarded-For: 127.0.0.1`, "
                         "`X-Real-IP: 127.0.0.1`, o `Authorization: Bearer <token>`")
        if any("404" in d or "ruta" in d for d in _diag_items):
            _next.append("verificar endpoint en el código fuente: `grep -r 'api/v' --include='*.py'`")
        if any("confirm_string" in d or "wrong_body" in d for d in _diag_items):
            _next.append("ajustar confirm_string o inspeccionar la respuesta real del lab")
        if any("docker" in d.lower() or "contenedor" in d.lower() for d in _diag_items):
            _next.append("revisar `docker ps` y `docker logs bo_lab_*` para diagnóstico")
        if _diag_items or _next:
            out.append("\n### " + ("Diagnóstico" if es else "Diagnosis"))
            for d in _diag_items:
                out.append(f"- ⚠ {d}")
            if _next:
                out.append("\n**Próximos pasos sugeridos:**")
                for n in _next:
                    out.append(f"  - {n}")

    out.append("\n### " + ("Pasos" if es else "Steps"))
    for s in result.steps:
        icon = "✓" if s.status == "ok" else ("⊘" if s.status == "skip" else
               "⚠" if s.status == "warn" else "✗")
        out.append(f"- {icon} `{s.name}` — {s.detail} [{s.elapsed:.1f}s]")
    parts.append("\n".join(out))

    # Impact escalation block (missing-auth CVEs with successful escalation probe)
    _esc_data = None
    if result.evidence:
        _esc_data = result.evidence.get("impact_escalation")
    if not _esc_data and result.inv:
        # Try to find impact_escalation nested inside the verifier's evidence dict
        _vr = getattr(result.inv, "verify_result", None)
        if _vr and isinstance(getattr(_vr, "evidence", None), dict):
            _esc_data = _vr.evidence.get("impact_escalation")
    if _esc_data and isinstance(_esc_data, dict):
        _esc_hdr = "## " + ("Impacto verificado" if es else "Verified Impact")
        _esc_lines = [_esc_hdr, ""]
        _cls = _esc_data.get("impact_class", "unknown")
        _max_imp = _esc_data.get("max_impact_found", "unknown").upper()
        _summary = _esc_data.get("escalation_summary", "")
        _snippets: list = _esc_data.get("evidence_snippets", [])
        _cls_labels = {
            "credential_exposure": "Exposición de credenciales/tokens",
            "user_enumeration": "Enumeración de usuarios/emails",
            "data_enumeration": "Enumeración de datos sin autenticación",
            "unauthorized_creation": "Creación no autorizada de recursos",
            "admin_access": "Acceso no autenticado a recursos de administración",
            "unknown": "Acceso sin autenticación (impacto no clasificado)",
        }
        _esc_lines.append(f"**Clase de impacto**: {_cls_labels.get(_cls, _cls)}")
        _esc_lines.append(f"**Impacto máximo**: {_max_imp}")
        if _summary:
            _esc_lines.append(f"\n> {_summary}")
        if _snippets:
            _esc_lines.append("")
            _esc_lines.append("| Endpoint | HTTP | Vista previa de datos |"
                               if es else "| Endpoint | HTTP | Data preview |")
            _esc_lines.append("|----------|------|-----------------------|")
            for sn in _snippets[:8]:
                _url = sn.get("url", "")
                _st = sn.get("status", "?")
                _prev = (sn.get("data_preview") or "")[:80].replace("|", "\\|").replace("\n", " ")
                _esc_lines.append(f"| `{_url}` | {_st} | `{_prev}` |")
        parts.append("\n".join(_esc_lines))

    # Autofuzz evidence block
    _fuzz_ev = result.evidence.get("autofuzz") if result.evidence else None
    if _fuzz_ev and isinstance(_fuzz_ev, dict) and _fuzz_ev.get("best_param"):
        _fuzz_hdr = "## " + ("Fuzzing de parámetros" if es else "Parameter Fuzzing")
        _fuzz_lines = [_fuzz_hdr, ""]
        _fuzz_lines.append(f"**Parámetro identificado**: `{_fuzz_ev['best_param']}`")
        _fuzz_lines.append(f"**Payload**: `{_fuzz_ev.get('best_payload', '')}`")
        _fuzz_lines.append(f"**Señal**: {_fuzz_ev.get('signal', '?')} "
                           f"(confianza {int((_fuzz_ev.get('confidence') or 0)*100)}%)")
        _fuzz_lines.append(f"**Requests enviados**: {_fuzz_ev.get('requests_sent', '?')}"
                           f" | **Hits**: {_fuzz_ev.get('hits', 0)}")
        parts.append("\n".join(_fuzz_lines))

    # Mass assignment evidence block
    _ma_ev = result.evidence.get("injected_fields") if result.evidence else None
    if _ma_ev and isinstance(_ma_ev, dict) and result.evidence.get("technique") in (
            "mass-assignment", "mass-assignment-profile-update"):
        _ma_hdr = "## " + ("Mass Assignment — Campos Inyectados" if es
                            else "Mass Assignment — Injected Fields")
        _ma_lines = [_ma_hdr, ""]
        _ma_lines.append("**Técnica**: Mass Assignment (inyección de campos privilegiados)")
        _ma_ep = result.evidence.get("register_endpoint") or result.evidence.get("update_endpoint", "")
        if _ma_ep:
            _ma_lines.append(f"**Endpoint vulnerable**: `{_ma_ep}`")
        _inj = {k: v for k, v in _ma_ev.items() if str(v).lower() not in ("false", "")}
        if _inj:
            _ma_lines.append("**Campos inyectados**:")
            for _k, _v in list(_inj.items())[:6]:
                _ma_lines.append(f"  - `{_k}`: `{_v}`")
        _ma_sigs = result.evidence.get("admin_signals_found", [])
        if _ma_sigs:
            _ma_lines.append(f"**Señales admin en respuesta**: {', '.join(_ma_sigs[:4])}")
        _ma_prof = result.evidence.get("profile_verification", {})
        if _ma_prof:
            _ma_lines.append(
                f"**Verificación de perfil (GET {_ma_prof.get('endpoint', '')})**:"
                f" HTTP {_ma_prof.get('status', '?')} — señales: "
                f"{', '.join(_ma_prof.get('admin_signals', [])[:3])}")
        parts.append("\n".join(_ma_lines))

    # Differential test evidence block
    _diff_ev = result.evidence.get("differential_test") if result.evidence else None
    if _diff_ev and isinstance(_diff_ev, dict) and result.evidence.get("diff_reason"):
        _diff_hdr = "## " + ("Test diferencial (vuln vs parchado)" if es
                              else "Differential Test (vuln vs patched)")
        _diff_lines = [_diff_hdr, ""]
        _diff_lines.append("**Resultado**: CONFIRMADO DIFERENCIALMENTE")
        _diff_lines.append(f"**Razón**: {result.evidence.get('diff_reason', '')}")
        _diff_lines.append(
            f"**Versión vulnerable**: HTTP {_diff_ev.get('vuln_status')} — "
            f"`{_diff_ev.get('vuln_url', '')}`")
        _diff_lines.append(
            f"**Versión parchada**: HTTP {_diff_ev.get('patched_status')} — "
            f"`{_diff_ev.get('patched_url', '')}`")
        parts.append("\n".join(_diff_lines))

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

    # Confidence badge
    _conf = result.engine_confidence
    if _conf >= 0.80:
        _conf_cls, _conf_lbl = "badge-conf-high", f"ALTO {int(_conf*100)}%"
    elif _conf >= 0.50:
        _conf_cls, _conf_lbl = "badge-conf-med", f"MEDIO {int(_conf*100)}%"
    else:
        _conf_cls, _conf_lbl = "badge-conf-low", f"BAJO {int(_conf*100)}%"
    conf_badge = f'<span class="badge {_conf_cls}" title="Confianza del motor">{_conf_lbl}</span>'

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
        f'  <td>{conf_badge}</td>\n'
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


# ── LLM RE-HYPOTHESIS HELPERS ─────────────────────────────────────────────────

def _extract_failure_context(result: "ChainResult", llm_notes: dict) -> dict:
    """Distil what went wrong in Stage 5 into a compact failure descriptor.

    Reads from result.evidence (populated by verifiers) and llm_notes
    (original LLM hypothesis) to decide the dominant failure reason so
    _llm_rehypothesis can build a targeted retry prompt.
    """
    status = result.evidence.get("status", 0)
    snippet = str(result.evidence.get("body_snippet", ""))[:200]

    # Map HTTP status to a symbolic failure reason
    if status == 403:
        reason = "403"
    elif status == 404:
        reason = "404"
    elif status == 0 or "timeout" in str(result.error).lower():
        reason = "timeout"
    elif "container" in str(result.error).lower() or "docker" in str(result.error).lower():
        reason = "container_crash"
    elif status and str(status).startswith("2"):
        # 2xx but nothing confirming the vuln in the body
        reason = "wrong_body"
    elif status and str(status).startswith("5"):
        reason = "server_error"
    else:
        reason = "unknown"

    # Was a precheck block the proximate cause?
    precheck_blocked = any(
        (getattr(s, "stage", "") or "").startswith("precheck")
        and getattr(s, "status", "") == "skip"
        for s in result.steps
    )

    return {
        "tried_endpoint": llm_notes.get("endpoint", ""),
        "tried_method":   llm_notes.get("http_method", "GET"),
        "tried_payload":  llm_notes.get("payload", ""),
        "response_status":  status,
        "response_snippet": snippet,
        "failure_reason":   reason,
        "precheck_blocked": precheck_blocked,
        "error_message":    result.error,
    }


def _llm_rehypothesis(
    cve_id: str,
    description: str,
    failure_ctx: dict,
    original_notes: dict,
    llm,
    step: "Callable",
) -> Optional[dict]:
    """Ask the LLM for a revised hypothesis given what failed in Stage 5.

    Returns a dict with the same schema as _llm_research, or None on failure.
    Only called when the LLM is available and there is budget left.
    """
    if llm is None or not getattr(llm, "available", lambda: False)():
        return None
    try:
        from ..llm.base import Message
    except Exception:
        return None

    tried_ep  = failure_ctx.get("tried_endpoint", "")
    tried_m   = failure_ctx.get("tried_method", "GET")
    tried_pl  = failure_ctx.get("tried_payload", "")
    http_st   = failure_ctx.get("response_status", 0)
    snippet   = failure_ctx.get("response_snippet", "")
    reason    = failure_ctx.get("failure_reason", "unknown")

    _vuln_cl  = original_notes.get("vuln_class", "?")
    _orig_ep  = original_notes.get("endpoint", tried_ep)
    _auth_req = original_notes.get("auth_required", "?")

    payload_line = f"\n- Payload enviado: {tried_pl}" if tried_pl else ""

    # Inject prior lessons for this stack into the prompt
    _les_hint = ""
    try:
        from .cve_lessons import detect_stack, format_lessons_for_llm
        _les_stack = detect_stack(description)
        _les_txt = format_lessons_for_llm(_les_stack, _vuln_cl, max_tokens=200)
        if _les_txt:
            _les_hint = f"\n\n{_les_txt}"
    except Exception:
        pass

    sys_prompt = (
        "Eres un investigador de explotacion para objetivos AUTORIZADOS (pentest/CTF/research). "
        "Se te da el contexto de un intento fallido de verificacion dinamica de una CVE. "
        "Tu tarea: proponer una hipotesis ALTERNATIVA con un endpoint, metodo y payload diferentes. "
        "Responde SOLO con JSON valido con las mismas claves que la hipotesis original: "
        "endpoint, http_method, parameters, payload, vuln_class, auth_required, "
        "bypass_header, bypass_value, confirm_string, custom_headers. "
        "IMPORTANTE: el endpoint DEBE ser distinto de '" + tried_ep + "'. "
        "No repitas la estrategia que ya fallo."
        + _les_hint
    )

    user_msg = (
        f"CVE: {cve_id}\n"
        f"Descripcion: {description}\n\n"
        f"Clase de vulnerabilidad: {_vuln_cl}\n"
        f"Auth requerida: {_auth_req}\n\n"
        f"PRIMER INTENTO FALLIDO:\n"
        f"- Metodo + endpoint: {tried_m} {_orig_ep}"
        f"{payload_line}\n"
        f"- Respuesta: HTTP {http_st} — {snippet!r}\n"
        f"- Razon del fallo: {reason}\n\n"
        "Proporciona una hipotesis REVISADA en JSON con la misma estructura. "
        f"Usa un endpoint DIFERENTE a: {tried_ep}"
    )

    step("  [5b] LLM re-hipotesis: consultando modelo…")
    try:
        raw = llm.chat(
            [Message("system", sys_prompt), Message("user", user_msg)],
            json_mode=True,
        )
        import json as _json
        data = _json.loads(raw)
        if isinstance(data, dict) and data.get("endpoint"):
            return data
    except Exception as exc:
        step(f"  [5b] LLM re-hipotesis: error al parsear — {exc}")
    return None


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

    # ── Checkpoint resume ─────────────────────────────────────────────────────
    # If a previous run was interrupted (timeout, crash) and a checkpoint was
    # saved within the last 24h, restore what we know and skip completed stages.
    llm_notes: dict = {}
    _ckpt = _load_checkpoint(cve_id) if not no_cache else None
    if _ckpt:
        step(f"  checkpoint encontrado (stage={_ckpt.get('last_stage', '?')}, "
             f"{int(time.time() - _ckpt.get('saved_at', 0))/60:.0f}min atrás) — reanudando")
        # Restore cheap state
        result.cve_class   = _ckpt.get("cve_class", "")
        result.cvss_score  = _ckpt.get("cvss_score")
        result.cvss_severity = _ckpt.get("cvss_severity", "")
        result.epss_score  = _ckpt.get("epss_score")
        result.risk_label  = _ckpt.get("risk_label", "")
        result.description = _ckpt.get("description", "")
        result.error       = _ckpt.get("error", "")
        result.patch_summary = _ckpt.get("patch_summary", "")
        result.evidence.update(_ckpt.get("evidence", {}))
        llm_notes = _ckpt.get("llm_notes", {})
        for _s in _ckpt.get("steps", []):
            result.add_step(_s["name"], _s["status"], _s.get("detail", ""),
                            _s.get("elapsed", 0.0))
        result.add_step("checkpoint_resume", "ok",
                        f"restored from stage={_ckpt.get('last_stage', '?')}")

    # ── Stage 1: Intelligence ─────────────────────────────────────────────────
    # Skip if already completed in checkpoint
    if _ckpt and _ckpt.get("last_stage", "") not in ("", "start"):
        step("  [1/8] intelligence: restaurado del checkpoint — omitido")
        # Still need cve_info for later stages
        try:
            from .cvelookup import fetch_cve
            cve_info = fetch_cve(cve_id)
        except Exception:
            cve_info = None
    else:
        cve_info = _gather_intelligence(cve_id, result, step)
        _save_checkpoint(result, llm_notes, "intelligence")

    # ── Stage 2: LLM Hypothesis ───────────────────────────────────────────────
    _banner(step, "[2/8] LLM HYPOTHESIS")
    # llm_notes may already be populated from checkpoint resume above.
    # Only regenerate if empty (checkpoint didn't have them).
    if not llm_notes:
        llm_notes = {}
    if llm and result.description and not llm_notes.get("vuln_class"):
        try:
            from .cve_agent import _llm_research  # type: ignore
            llm_notes = _llm_research(llm, cve_id, result.description) or {}
            vc = llm_notes.get("vuln_class", "?")
            endpoint = llm_notes.get("endpoint", "?")
            step(f"  clase={vc}, endpoint={endpoint}, "
                 f"auth={llm_notes.get('auth_required','?')}")

            # Multi-hypothesis: ask LLM for ranked alternative endpoints/params
            # Only when LLM gave us at least one hypothesis and there are budget seconds left
            _mh_prompt = (
                f"CVE: {cve_id}\nDescription: {result.description[:800]}\n"
                f"Primary hypothesis: class={vc}, endpoint={endpoint}, "
                f"param={llm_notes.get('param', 'unknown')}\n\n"
                f"List up to 3 ALTERNATIVE endpoint/parameter combinations that could also "
                f"be vulnerable, ranked by probability. Format as JSON array:\n"
                f'[{{"endpoint":"/api/foo","param":"id","reason":"...","score":0.7}}, ...]\n'
                f"Only include alternatives different from the primary. "
                f"Return empty array [] if no good alternatives."
            )
            try:
                _mh_response = llm.generate(prompt=_mh_prompt,
                                             max_tokens=300, temperature=0.3)
                _mh_text = (_mh_response or {}).get("response", "") or ""
                # Extract JSON array from response
                _mh_match = re.search(r'\[.*\]', _mh_text, re.DOTALL)
                if _mh_match:
                    import json as _json_mh
                    _alternatives = _json_mh.loads(_mh_match.group(0))
                    if isinstance(_alternatives, list) and _alternatives:
                        # Store as alt_endpoints — the verifier can try these after primary fails
                        llm_notes["alt_endpoints"] = [
                            {"endpoint": a.get("endpoint", ""),
                             "param": a.get("param", ""),
                             "score": float(a.get("score", 0.5)),
                             "reason": a.get("reason", "")}
                            for a in _alternatives[:3]
                            if isinstance(a, dict) and a.get("endpoint")
                        ]
                        step(f"  multi-hypothesis: {len(llm_notes['alt_endpoints'])} "
                             f"alternativas — "
                             f"{[a['endpoint'] for a in llm_notes['alt_endpoints']]}")
            except Exception:
                pass  # multi-hypothesis is best-effort

            result.add_step("llm_hypothesis", "ok",
                            f"class={vc} auth={llm_notes.get('auth_required')} "
                            f"alts={len(llm_notes.get('alt_endpoints', []))}")
        except Exception as e:
            step(f"  hypothesis error: {e}")
            result.add_step("llm_hypothesis", "skip", str(e)[:80])
    else:
        step("  sin LLM o sin descripción — modo determinístico")
        result.add_step("llm_hypothesis", "skip", "no LLM")

    # ── Stage 2.5: Correlation — seed llm_notes from adjacent CVEs ──────────
    # Runs after LLM hypothesis so we can boost/validate what the LLM said.
    # Only seeds fields the LLM left empty (never overwrites a confident LLM answer).
    _corr_project = ""
    if cve_info:
        # Try cpe_matches vendor, then package refs, then description keywords
        _cpus = getattr(cve_info, "cpe_matches", []) or []
        if _cpus:
            _parts = str(_cpus[0]).split(":")
            if len(_parts) > 4:
                _corr_project = _parts[4]
        if not _corr_project:
            _refs = getattr(cve_info, "references", []) or []
            for _r in _refs:
                _s = str(_r)
                for _dom in ("github.com", "pypi.org", "npmjs.com"):
                    if _dom in _s:
                        _seg = _s.split(_dom + "/")[-1].split("/")
                        if len(_seg) >= 2:
                            _corr_project = _seg[1]
                            break
                if _corr_project:
                    break
    # Also try package_name from llm_notes
    if not _corr_project:
        _corr_project = (llm_notes.get("package_name") or
                         llm_notes.get("component") or "")
    if _corr_project:
        try:
            from .cve_correlation import find_correlated_cves
            _corr = find_correlated_cves(
                cve_id=cve_id,
                project_name=_corr_project,
                pkg_version=llm_notes.get("vulnerable_version", ""),
                endpoint=llm_notes.get("endpoint", ""),
                vuln_class=llm_notes.get("vuln_class", ""),
            )
            if _corr.best_hint and _corr.best_hint.relevance >= 0.70:
                _bh = _corr.best_hint
                step(f"  [2.5] correlación: {_bh.source_cve} "
                     f"(rel={_bh.relevance:.2f}) → "
                     f"endpoint={_bh.endpoint_pattern!r} "
                     f"bypass={_bh.bypass_header!r}")
                result.evidence["correlation_hint"] = {
                    "source_cve": _bh.source_cve,
                    "endpoint_pattern": _bh.endpoint_pattern,
                    "bypass_header": _bh.bypass_header,
                    "bypass_value": _bh.bypass_value,
                    "relevance": _bh.relevance,
                }
                result.add_step("correlation", "ok",
                                 f"{_bh.source_cve} rel={_bh.relevance:.2f}")
                # Seed only empty fields — never overwrite a confident LLM answer
                if not llm_notes.get("bypass_header") and _bh.bypass_header:
                    llm_notes["bypass_header"] = _bh.bypass_header
                    llm_notes["bypass_value"] = _bh.bypass_value
                if not llm_notes.get("endpoint") and _bh.endpoint_pattern:
                    llm_notes["endpoint"] = _bh.endpoint_pattern
                if not llm_notes.get("confirm_string") and _bh.confirm_string:
                    llm_notes["confirm_string"] = _bh.confirm_string

                # Re-rank alt_endpoints using historical endpoint similarity
                if llm_notes.get("alt_endpoints"):
                    try:
                        from .cve_correlation import rank_alt_endpoints_by_history
                        _reranked = rank_alt_endpoints_by_history(
                            llm_notes["alt_endpoints"],
                            project_name=_corr_project,
                            vuln_class=llm_notes.get("vuln_class", ""),
                        )
                        if _reranked:
                            llm_notes["alt_endpoints"] = _reranked
                            step(f"  [2.5] alt endpoints re-rankeados: "
                                 f"{[a['endpoint'] for a in _reranked[:2]]}")
                    except Exception:
                        pass
            else:
                result.add_step("correlation", "skip", _corr.reasoning[:60])
        except Exception as _ce:
            step(f"  [2.5] correlación: error: {_ce}")
            result.add_step("correlation", "error", str(_ce)[:60])

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
    _save_checkpoint(result, llm_notes, "classify")

    # ── Stage 4: Patch diff ───────────────────────────────────────────────────
    with tempfile.TemporaryDirectory(prefix="bo_chain_") as tmpdir:
        if cve_info:
            result.patch_summary = _run_patch_stage(
                cve_id, cve_info, result, step, tmpdir)

        # Stage 4b: Deep source-level patch analysis — extract vuln pattern + PoC seeds
        # Uses raw_patch_text (the actual git diff) not the rendered markdown summary
        _raw_pt = result.evidence.get("raw_patch_text", "")
        if _raw_pt and len(_raw_pt) > 100:
            try:
                from .patchdiff import analyze_patch_diff
                _pdiff = analyze_patch_diff(_raw_pt)
                if _pdiff.confidence >= 0.60:
                    # Generate PoC HTTP request from diff analysis
                    _poc_http = ""
                    try:
                        from .patchdiff import generate_poc_from_analysis
                        _poc_http = generate_poc_from_analysis(
                            _pdiff,
                            base_url=llm_notes.get("base_url", "http://TARGET"),
                            http_method=llm_notes.get("method", "GET"),
                            auth_header="",
                        )
                    except Exception:
                        pass

                    result.evidence["patch_analysis"] = {
                        "vuln_function": _pdiff.vuln_function,
                        "vuln_file":     _pdiff.vuln_file,
                        "vuln_pattern":  _pdiff.vuln_pattern,
                        "patch_pattern": _pdiff.patch_pattern,
                        "suggested_param": _pdiff.suggested_param,
                        "suggested_value": _pdiff.suggested_value,
                        "fix_class":     _pdiff.fix_class,
                        "confidence":    _pdiff.confidence,
                        "poc_http":      _poc_http,
                    }
                    step(f"  patch-diff: clase={_pdiff.fix_class} "
                         f"func={_pdiff.vuln_function!r} "
                         f"conf={_pdiff.confidence:.0%}"
                         + (" PoC generado" if _poc_http else ""))
                    # Seed llm_notes if LLM didn't provide them yet
                    if not llm_notes.get("parameters") and _pdiff.suggested_param:
                        llm_notes["parameters"] = {
                            _pdiff.suggested_param: _pdiff.suggested_value}
                        step(f"  patch-diff: param extraído del diff: "
                             f"{_pdiff.suggested_param!r}")
                    if not llm_notes.get("payload") and _pdiff.suggested_value:
                        llm_notes["payload"] = _pdiff.suggested_value
                        step(f"  patch-diff: payload extraído del diff: "
                             f"{_pdiff.suggested_value!r}")
                    # Override cve_class if the diff analysis is more certain
                    if (_pdiff.fix_class in ("sqli", "sql-injection") and
                            result.cve_class not in ("native", "binary")):
                        result.cve_class = "web"
                else:
                    step(f"  patch-diff: confianza insuficiente ({_pdiff.confidence:.0%})")
            except Exception as _pde:
                step(f"  patch-diff: error en análisis: {_pde}")

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

    # ── Stage 5b: LLM re-hypothesis on actionable failure ────────────────────
    # Fires once when Stage 5 did not verify the CVE and the failure was
    # actionable (403/404/wrong_body) — not for binary/native paths where
    # Stage 5 did not run _run_web_stage at all.
    _actionable_failures = {"403", "404", "wrong_body", "server_error"}
    if (not result.verified
            and not binary
            and result.cve_class in ("web", "unknown", "cli")
            and llm is not None
            and not result.error
            and _budget_ok(min_s=60.0)):
        _banner(step, "[5b/8] LLM RE-HYPOTHESIS")
        _fail_ctx = _extract_failure_context(result, llm_notes)
        _fail_reason = _fail_ctx.get("failure_reason", "unknown")
        step(f"  fallo en Stage 5: {_fail_reason} — consultando LLM para hipotesis revisada")

        if _fail_reason in _actionable_failures:
            _tried_ep = _fail_ctx.get("tried_endpoint", "")

            # ── 5b-fast: try ranked alt_endpoints from Stage 2.5 first ──────────
            # This avoids a full LLM round-trip when we already have ranked
            # alternative hypotheses from multi-hypothesis generation.
            _alt_eps = llm_notes.get("alt_endpoints") or []
            _alt_tried = False
            if _alt_eps:
                # Pick the top-ranked alt that wasn't the one that just failed
                _next_alt = next(
                    (a for a in _alt_eps
                     if a.get("endpoint") and a.get("endpoint") != _tried_ep),
                    None,
                )
                if _next_alt:
                    step(f"  [5b-fast] probando alt_endpoint rankeado: "
                         f"{_next_alt.get('endpoint')} "
                         f"(motivo: {_next_alt.get('reason', '?')[:60]})")
                    _fast_notes = dict(llm_notes)
                    _fast_notes["endpoint"] = _next_alt["endpoint"]
                    if _next_alt.get("param"):
                        _fast_notes["param"] = _next_alt["param"]
                    _remaining_fast = max(0.0, budget_s - (time.time() - t0))
                    _fast_budget = min(_remaining_fast * 0.35, 100.0)
                    if _fast_budget >= 30.0:
                        _run_web_stage(
                            cve_id, cve_info, _fast_notes, result, step,
                            budget_s=_fast_budget, config=config, llm=llm, lang=lang)
                        _status_fast = "VERIFICADO" if result.verified else "no confirmado"
                        step(f"  [5b-fast] resultado: {_status_fast}")
                        result.add_step("rehypothesis_alt_ep", "ok" if result.verified else "fail",
                                        f"{_next_alt['endpoint']}: {_status_fast}")
                        # If alt verified, update main llm_notes with working endpoint
                        if result.verified:
                            llm_notes["endpoint"] = _next_alt["endpoint"]
                            if _next_alt.get("param"):
                                llm_notes["param"] = _next_alt["param"]
                        _alt_tried = True
                    else:
                        step("  [5b-fast] presupuesto insuficiente — omitido")

            # ── 5b-llm: full LLM re-hypothesis if alt_ep didn't verify ──────────
            if not result.verified and not _alt_tried or (not result.verified and not _alt_eps):
                _revised = _llm_rehypothesis(
                    cve_id=cve_id,
                    description=result.description,
                    failure_ctx=_fail_ctx,
                    original_notes=llm_notes,
                    llm=llm,
                    step=step,
                )
                if (_revised
                        and isinstance(_revised, dict)
                        and _revised.get("endpoint")
                        and _revised.get("endpoint") != _tried_ep):
                    # Merge revised notes — keep originals for fields LLM didn't revise
                    llm_notes.update(_revised)
                    result.add_step(
                        "rehypothesis", "ok",
                        f"revised endpoint: {_revised.get('endpoint')} "
                        f"(was: {_tried_ep})",
                    )
                    step(f"  hipotesis revisada: {_revised.get('http_method','GET')} "
                         f"{_revised.get('endpoint')} — relanzando Stage 5")

                    # Cap re-hypothesis budget at 40% of remaining or 120 s max
                    _remaining = max(0.0, budget_s - (time.time() - t0))
                    _rehyp_budget = min(_remaining * 0.40, 120.0)

                    if _rehyp_budget >= 30.0:
                        _run_web_stage(
                            cve_id, cve_info, llm_notes, result, step,
                            budget_s=_rehyp_budget, config=config, llm=llm, lang=lang)
                        _status = "VERIFICADO" if result.verified else "no confirmado"
                        step(f"  [5b] resultado: {_status}")
                        result.add_step("rehypothesis_run", "ok" if result.verified else "fail",
                                        _status)
                    else:
                        step("  [5b] presupuesto insuficiente para re-run — omitido")
                        result.add_step("rehypothesis_run", "skip", "budget < 30 s")
                elif _revised and _revised.get("endpoint") == _tried_ep:
                    step("  [5b] LLM propuso el mismo endpoint — descartado")
                    result.add_step("rehypothesis", "skip", "same endpoint as original")
                else:
                    step("  [5b] LLM no devolvió hipotesis revisada válida")
                    result.add_step("rehypothesis", "skip", "no valid hypothesis")
        else:
            step(f"  [5b] fallo no accionable ({_fail_reason}) — sin re-hipotesis")
            result.add_step("rehypothesis", "skip", f"non-actionable failure: {_fail_reason}")

    # ── Stage 5.5: Differential test (vuln vs patched) ───────────────────────
    # Fires only when:
    # - result is NOT yet verified (we want stronger proof or last resort)
    # - OR result IS verified but we want irrefutable differential evidence
    # - A patch URL exists (we have the patched version to compare against)
    # - Budget remaining ≥ 90s (needs to spin up 2 containers)
    # - BINORACLE_DIFFTEST=1 (opt-in, disabled by default — costly)
    if (os.environ.get("BINORACLE_DIFFTEST") == "1" and
            result.patch_summary and _budget_ok(min_s=90.0) and
            cve_info and llm_notes.get("endpoint")):
        _banner(step, "[5.5/8] DIFFERENTIAL TEST — vuln vs patched")
        step("  construyendo containers vulnerable y parchado para comparación…")
        try:
            from .difftest import differential_test
            # Extract patched version from cve_info if available
            _patched_ver = ""
            if isinstance(cve_info, dict):
                _patched_ver = (cve_info.get("patched_version") or
                                cve_info.get("fixed_version") or "")
            elif hasattr(cve_info, "patched_version"):
                _patched_ver = getattr(cve_info, "patched_version", "") or ""
            _fr_path = getattr(result.inv, "source_path", "") if result.inv else ""
            if not _fr_path:
                step("  difftest: sin ruta de fuente disponible — omitido")
            else:
                _diff_r = differential_test(
                    source_dir=str(_fr_path),
                    patched_source_dir=None,
                    endpoint=llm_notes.get("endpoint", "/"),
                    http_method=llm_notes.get("http_method", "GET"),
                    payload=llm_notes.get("payload", ""),
                    confirm_string=llm_notes.get("confirm_string", ""),
                    patched_version=_patched_ver,
                    on_step=step,
                    budget_s=min(120.0, budget_s * 0.4),
                )
                if _diff_r.confirmed:
                    result.verified = True
                    result.evidence["differential_test"] = _diff_r.evidence
                    result.evidence["diff_reason"] = _diff_r.diff_reason
                    result.add_step("differential_test", "ok",
                                    f"confirmed: {_diff_r.diff_reason[:60]}")
                    step(f"  difftest: VERIFICADO DIFERENCIALMENTE — {_diff_r.diff_reason}")
                else:
                    result.add_step("differential_test", "fail",
                                    _diff_r.error or _diff_r.diff_reason)
                    step(f"  difftest: sin diferencia — {_diff_r.diff_reason}")
        except Exception as _e:
            step(f"  difftest: error — {_e}")
            result.add_step("differential_test", "error", str(_e)[:80])

    # ── Stage 5.6: Parameter fuzzing ─────────────────────────────────────────
    # Fires when:
    # - NOT yet verified (looking for the specific injection param)
    # - Vuln class is fuzzable (sqli, xss, ssti, lfi, rce, command-injection)
    # - An endpoint was identified (need somewhere to fuzz)
    # - Budget remaining ≥ 45s
    # - BINORACLE_FUZZ=1 (opt-in, disabled by default to avoid noise)
    _FUZZABLE_CLASSES = {
        "sqli", "sql-injection", "xss", "reflected-xss", "stored-xss",
        "ssti", "template-injection", "lfi", "path-traversal",
        "rce", "command-injection", "open-redirect",
    }
    _cve_class_low = (result.cve_class or "").lower().replace(" ", "-")
    if (not result.verified and
            os.environ.get("BINORACLE_FUZZ") == "1" and
            _cve_class_low in _FUZZABLE_CLASSES and
            llm_notes.get("endpoint") and
            _budget_ok(min_s=45.0)):
        _banner(step, "[5.6/8] PARAMETER FUZZING")
        step(f"  autofuzz: clase={_cve_class_low} endpoint={llm_notes['endpoint']}")
        try:
            from .autofuzz import fuzz_parameters
            # Build auth headers from whatever the web stage established
            _fuzz_auth = {}
            if result.inv:
                _inv = result.inv
                if hasattr(_inv, "auth_headers") and _inv.auth_headers:
                    _fuzz_auth = dict(_inv.auth_headers)
                elif hasattr(_inv, "verify_result"):
                    _vr = _inv.verify_result
                    if hasattr(_vr, "evidence") and isinstance(_vr.evidence, dict):
                        _fuzz_auth = _vr.evidence.get("auth_headers", {}) or {}
            # Include any extra params the LLM suggested
            _extra_params = []
            if llm_notes.get("parameters"):
                _params_raw = llm_notes["parameters"]
                if isinstance(_params_raw, dict):
                    _extra_params = list(_params_raw.keys())
                elif isinstance(_params_raw, list):
                    _extra_params = [str(p) for p in _params_raw]
            # Need a live base_url — extract from evidence or build from source path
            _fuzz_base = ""
            if result.inv and hasattr(result.inv, "verify_result"):
                _fuzz_base = (result.inv.verify_result.evidence or {}).get("base_url", "")
            if not _fuzz_base and result.evidence.get("base_url"):
                _fuzz_base = result.evidence["base_url"]
            if _fuzz_base:
                _fuzz_res = fuzz_parameters(
                    base_url=_fuzz_base,
                    endpoint=llm_notes["endpoint"],
                    http_method=llm_notes.get("http_method", "GET"),
                    vuln_class=_cve_class_low,
                    auth_headers=_fuzz_auth or None,
                    extra_params=_extra_params or None,
                    on_step=step,
                    budget_s=min(60.0, budget_s * 0.3),
                    min_confidence=0.75,
                    requests_per_second=2.0,
                )
                if _fuzz_res.best_hit:
                    _bh = _fuzz_res.best_hit
                    result.evidence["autofuzz"] = {
                        "best_param": _bh.param,
                        "best_payload": _bh.payload,
                        "signal": _bh.signal,
                        "confidence": _bh.confidence,
                        "hits": len(_fuzz_res.hits),
                        "requests_sent": _fuzz_res.payloads_sent,
                    }
                    result.add_step("autofuzz", "ok",
                                    f"best={_bh.param!r} signal={_bh.signal} "
                                    f"conf={_bh.confidence:.0%}")
                    step(f"  autofuzz: HIT param={_bh.param!r} signal={_bh.signal} "
                         f"conf={_bh.confidence:.0%} (total {_fuzz_res.payloads_sent} reqs)")
                    # If high-confidence hit, mark as partially verified
                    if _bh.confidence >= 0.90:
                        result.verified = True
                        result.evidence["autofuzz"]["verified_by_fuzz"] = True
                        step("  autofuzz: conf ≥ 90% → marcado como verificado")
                else:
                    result.add_step("autofuzz", "fail",
                                    f"{_fuzz_res.payloads_sent} reqs, sin hits")
                    step(f"  autofuzz: sin hits en {_fuzz_res.payloads_sent} requests")
            else:
                step("  autofuzz: sin base_url disponible — omitido")
                result.add_step("autofuzz", "skip", "no base_url")
        except Exception as _fe:
            step(f"  autofuzz: error — {_fe}")
            result.add_step("autofuzz", "error", str(_fe)[:80])

    # ── Stage 5c: Post-verify impact escalation ──────────────────────────────
    # Fires when:
    # - result.verified = True
    # - vuln class is missing-auth / auth-bypass / broken-access-control / IDOR
    # - evidence already has an escalation source (impact_escalation) OR
    #   we can derive a base_url + verified endpoint from evidence
    # - Budget remaining >= 40s (escalation is relatively quick HTTP probes)
    # - NOT already escalated (evidence doesn't have impact_escalation)
    _ESCALATE_CLASSES = {
        "missing-authorization", "missing-auth", "broken-access-control",
        "auth-bypass", "authentication-bypass", "idor",
        "insecure-direct-object-reference",
    }
    _cve_class_esc = (result.cve_class or "").lower().replace(" ", "-")
    if (result.verified
            and _cve_class_esc in _ESCALATE_CLASSES
            and not result.evidence.get("impact_escalation")
            and _budget_ok(min_s=40.0)):
        _banner(step, "[5c/8] IMPACT ESCALATION — post-verify data extraction")
        # Find the base URL and bypass headers from evidence
        _esc_base_url = ""
        _esc_endpoint = ""
        _esc_bypass_headers: dict = {}
        # Try to get from verifier result
        if result.inv:
            _esc_vr = getattr(result.inv, "verify_result", None)
            if _esc_vr:
                _esc_ev = getattr(_esc_vr, "evidence", {}) or {}
                _esc_base_url = _esc_ev.get("base_url", "")
                _esc_endpoint = _esc_ev.get("endpoint", "") or llm_notes.get("endpoint", "")
                _bh = _esc_ev.get("bypass_header", "")
                _bv = _esc_ev.get("bypass_value", "")
                if _bh:
                    _esc_bypass_headers = {_bh: _bv}
        # Fallback to llm_notes
        if not _esc_base_url:
            _esc_base_url = llm_notes.get("base_url", "") or result.evidence.get("base_url", "")
        if not _esc_endpoint:
            _esc_endpoint = llm_notes.get("endpoint", "")
        if not _esc_bypass_headers and llm_notes.get("bypass_header"):
            _esc_bypass_headers = {
                llm_notes["bypass_header"]: llm_notes.get("bypass_value", "")
            }
        if _esc_base_url and _esc_endpoint:
            step(f"  escalada: base_url={_esc_base_url} endpoint={_esc_endpoint}")
            try:
                from .genericverify import _escalate_missing_auth_impact
                _remaining_esc = max(0.0, budget_s - (time.time() - t0))
                _esc_budget = min(_remaining_esc * 0.50, 90.0)
                _esc_result = _escalate_missing_auth_impact(
                    base_url=_esc_base_url,
                    verified_endpoint=_esc_endpoint,
                    bypass_headers=_esc_bypass_headers,
                    on_step=step,
                    budget_s=_esc_budget,
                )
                if _esc_result:
                    result.evidence["impact_escalation"] = _esc_result
                    _esc_cls = _esc_result.get("impact_class", "unknown")
                    _esc_max = _esc_result.get("max_impact_found", "unknown")
                    step(f"  escalada: clase={_esc_cls} max_impact={_esc_max}")
                    result.add_step("impact_escalation", "ok",
                                    f"class={_esc_cls} max={_esc_max}")
                    # Bump confidence if we got credential exposure or admin access
                    if _esc_cls in ("credential_exposure", "admin_access"):
                        result.engine_confidence = min(
                            1.0, result.engine_confidence + 0.05)
            except Exception as _esc_e:
                step(f"  escalada: error — {_esc_e}")
                result.add_step("impact_escalation", "error", str(_esc_e)[:80])
        else:
            step("  escalada: sin base_url/endpoint disponible — omitido")
            result.add_step("impact_escalation", "skip", "no base_url or endpoint")

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

    # Clear checkpoint now that the chain completed successfully
    _clear_checkpoint(cve_id)

    # Auto-learn from this run — record lessons for future chain runs of same stack
    try:
        from .cve_lessons import learn_from_chain_result
        learn_from_chain_result(result)
        step("  lecciones: resultado registrado en cve_lessons")
    except Exception:
        pass

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
    # Additional evidence bonuses
    if result.evidence.get("differential_test", {}).get("diff_reason"):
        _conf += 0.08   # differential confirms with irrefutable evidence
    if result.evidence.get("autofuzz", {}).get("verified_by_fuzz"):
        _conf += 0.05   # fuzzer found injection point with ≥90% confidence
    if result.evidence.get("impact_escalation", {}).get("impact_class") in (
            "credential_exposure", "admin_access"):
        _conf += 0.05   # actual credential/admin exposure proven
    if result.evidence.get("patch_analysis", {}).get("confidence", 0) >= 0.80:
        _conf += 0.03   # precise patch diff analysis available
    if result.evidence.get("correlation_hint", {}).get("relevance", 0) >= 0.70:
        _conf += 0.02   # similar CVE in same project confirmed the pattern
    # Semantic response analysis bonus: partial match without exact confirm_string
    _resp_analysis = result.evidence.get("response_analysis", {})
    if not result.verified and _resp_analysis.get("interesting"):
        _partial_conf = float(_resp_analysis.get("partial_confidence", 0.0))
        # Cap contribution at +0.15 so LLM-only cases don't exceed 0.55
        _conf += min(0.15, _partial_conf * 0.20)
    result.engine_confidence = round(max(0.0, min(1.0, _conf)), 2)

    # ── Lessons: record this CVE's outcome for future runs ────────────────────
    try:
        from .cve_lessons import detect_stack, record_cve_result, record_verified_lab
        inv = result.inv
        _les_desc = (cve_info.get("description") or "") if cve_info else ""
        _les_path = str(getattr(getattr(inv, "source", None), "local_path", "") or "")
        _les_stack = detect_stack(_les_desc + " " + _les_path)
        _les_notes = (getattr(inv, "llm_notes", {}) or {}) if inv else {}
        _les_ep = _les_notes.get("endpoint") or ""
        _les_bh = _les_notes.get("bypass_header") or ""
        _les_bv = _les_notes.get("bypass_value") or ""
        _les_vc = (getattr(inv, "vuln_class", "") or _les_notes.get("vuln_class", "")) if inv else ""
        _les_hm = _les_notes.get("http_method") or "GET"
        _les_cs = _les_notes.get("confirm_string") or ""
        _les_pv = _les_notes.get("vulnerable_version") or _les_notes.get("pkg_version") or ""
        # Detect auth method from evidence or llm_notes
        _les_am = ""
        _les_ev = result.evidence or {}
        if "ghost" in _les_stack or "ghost" in _les_path.lower():
            _les_am = "ghost-jwt"
        elif "strapi" in _les_stack or "strapi" in _les_path.lower():
            _les_am = "strapi-jwt"
        elif _les_ev.get("auth_header", "").startswith("Bearer "):
            _les_am = "bearer-jwt"
        elif _les_ev.get("auth_header", "").startswith("Token "):
            _les_am = "drf-token"
        elif _les_ev.get("cookie"):
            _les_am = "session-cookie"
        elif _les_notes.get("auth_required") in (False, "false", "no", "none", "0"):
            _les_am = "none"
        if result.verified:
            record_verified_lab(
                cve_id=cve_id, stack=_les_stack, endpoint=_les_ep,
                vuln_class=_les_vc, http_method=_les_hm,
                auth_method=_les_am, bypass_header=_les_bh,
                bypass_value=_les_bv, confirm_string=_les_cs,
                pkg_version=_les_pv,
            )
        else:
            record_cve_result(_les_stack, cve_id, _les_ep, False,
                              _les_bh, _les_bv, _les_vc,
                              auth_method=_les_am, http_method=_les_hm,
                              confirm_string=_les_cs, pkg_version=_les_pv)
    except Exception:
        pass

    # ── YWH writeup: auto-generate bug report skeleton on verified CVEs ─────
    if result.verified:
        try:
            from .ywh_writeup import build_writeup_from_chain
            _wu = build_writeup_from_chain(result)
            if _wu.title:
                _wu_path = None
                if result.report_path:
                    import pathlib as _pl
                    _wu_path = str(_pl.Path(result.report_path).with_suffix("")) + "_ywh.md"
                    _pl.Path(_wu_path).write_text(_wu.to_markdown(), encoding="utf-8")
                result.evidence["ywh_writeup"] = {
                    "title": _wu.title,
                    "severity": _wu.severity,
                    "vuln_class": _wu.vuln_class,
                    "platform_fields": _wu.platform_fields(),
                    "file": _wu_path or "",
                }
                step(f"  ywh: borrador de reporte generado → {_wu_path or 'evidence[ywh_writeup]'}")
        except Exception as _wu_e:
            step(f"  ywh: error generando writeup: {_wu_e}")

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
        "engine_confidence": result.engine_confidence,
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
            conf_pct = int(result.engine_confidence * 100)
            msg = (f"🔴 binoracle VERIFICADO\n"
                   f"CVE: {cve_id}\n"
                   f"Clase: {vc}\n"
                   f"Confianza: {conf_pct}%\n"
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

    # Smart CVE triage: filter out CVEs that binoracle cannot investigate
    # These are CVEs in firmware, kernel, C/C++ native code, or hardware —
    # outside the web app attack surface binoracle is designed for.
    _SKIP_PATTERNS = [
        # kernel / OS / firmware
        "linux kernel", "windows kernel", "bios", "uefi", "firmware", "bootloader",
        "embedded", "microcontroller", "hypervisor", "vmware esxi",
        # C/C++ native libs with no web surface
        "openssl", "libssl", "libc", "glibc", "libpng", "libxml", "libcurl",
        # Networking gear
        "cisco ios", "juniper junos", "palo alto", "checkpoint",
        # DB engines (not web apps using them)
        "mysql server", "mariadb server", "postgresql server",
        # Mobile
        "ios <", "ipados", "android kernel", "samsung kernel",
    ]
    _PREFER_PATTERNS = [
        # Explicit web stack keywords
        "cms", "wordpress", "drupal", "joomla", "ghost", "strapi", "directus",
        "wagtail", "craft cms", "payload cms", "django", "flask", "fastapi",
        "rails", "ruby on rails", "express", "nestjs", "graphql", "rest api",
        "web application", "web app", "authentication", "authorization",
        "api endpoint", "http request", "sql injection", "xss", "csrf",
    ]
    _before = len(entries)
    _filtered = []
    for _e in entries:
        _desc = _e.description.lower()
        # Skip if any skip pattern matches
        if any(_sk in _desc for _sk in _SKIP_PATTERNS):
            continue
        _filtered.append(_e)
    entries = _filtered
    _after = len(entries)
    if _after < _before:
        step(f"auto_queue_nvd: smart triage eliminó {_before - _after} CVEs fuera de scope "
             f"(firmware/kernel/native) — quedan {_after}")
    # Boost web-relevant CVEs within the filtered list
    def _triage_score(e) -> float:
        _d = e.description.lower()
        _web_score = sum(1 for _pw in _PREFER_PATTERNS if _pw in _d)
        return _web_score + e.cvss_score / 10.0  # web relevance + CVSS weight

    # Apply priority_mode sort
    _cms_kws = ("wordpress", "drupal", "joomla", "wp-")
    if priority_mode == "new":
        entries = sorted(entries, key=lambda e: e.published, reverse=True)
    elif priority_mode == "cms":
        entries = sorted(entries,
                         key=lambda e: (not any(k in e.description.lower() for k in _cms_kws),
                                        -e.cvss_score))
    else:
        # "cvss" or default: sort by combined triage score (web relevance + CVSS)
        entries = sorted(entries, key=_triage_score, reverse=True)
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
