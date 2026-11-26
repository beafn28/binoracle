"""Consulta de una CVE por identificador y deteccion de 'hueco' de exploit.

Dado un id CVE (p.ej. CVE-2021-3156), binoracle:
1. Descarga la descripcion y el CVSS de la NVD (API publica, solo stdlib urllib).
2. Detecta si ya EXISTE un exploit publico: la NVD etiqueta las referencias con `Exploit` cuando
   apuntan a un PoC/exploit (Exploit-DB, GitHub, PacketStorm...). Si ninguna referencia lleva esa
   etiqueta, se considera un 'hueco' (no consta exploit publico) y binoracle desarrolla uno.
3. Clasifica la vulnerabilidad desde el texto y llama al desarrollador de exploits.

Es best-effort y offline-graceful: sin internet, devuelve lo que se pueda y lo marca. Solo para
investigacion / objetivos autorizados.
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

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# Base curada de PoCs publicados en GitHub, por CVE (JSON por CVE). Fuente directa de "hay PoC".
GH_POC = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def is_cve_id(text: str) -> Optional[str]:
    """Devuelve el id CVE normalizado (mayusculas) si `text` contiene uno, o None."""
    if not text:
        return None
    m = _CVE_RE.search(text)
    return m.group(0).upper() if m else None


@dataclass
class ExploitRef:
    url: str
    source: str = ""          # exploit-db | github | packetstorm | otro
    edb_id: str = ""          # id de Exploit-DB si aplica


@dataclass
class CVEInfo:
    cve_id: str
    ok: bool = False
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    cvss_vector: str = ""
    published: str = ""
    references: List[dict] = field(default_factory=list)      # {url, tags}
    exploit_refs: List[ExploitRef] = field(default_factory=list)
    has_public_exploit: bool = False
    note: str = ""
    # EPSS — Exploit Prediction Scoring System (FIRST.org)
    epss_score: Optional[float] = None        # 0.0–1.0 probability of exploitation in 30 days
    epss_percentile: Optional[float] = None   # percentile vs all CVEs
    # CISA KEV — Known Exploited Vulnerabilities catalog
    in_cisa_kev: bool = False

    @property
    def is_gap(self) -> bool:
        """True si la consulta fue OK y NO consta exploit publico (hueco a cubrir)."""
        return self.ok and not self.has_public_exploit


def _classify_ref(url: str) -> ExploitRef:
    low = url.lower()
    if "exploit-db.com" in low:
        m = re.search(r"exploits?/(\d+)", low)
        return ExploitRef(url=url, source="exploit-db", edb_id=(m.group(1) if m else ""))
    if "github.com" in low:
        return ExploitRef(url=url, source="github")
    if "packetstorm" in low:
        return ExploitRef(url=url, source="packetstorm")
    return ExploitRef(url=url, source="otro")


_PROLIFIC_POC_OWNERS = [
    "RandomRobbieBF",   # prolific WP CVE PoC author — not always indexed by nomi-sec
    "d0rb",             # another frequent WP PoC contributor
]


def check_well_known_poc_repos(cve_id: str, timeout: float = 5.0) -> List[ExploitRef]:
    """Checks well-known CVE PoC contributor repos directly on GitHub.

    nomi-sec/PoC-in-GitHub only indexes community-submitted entries.
    Prolific PoC authors sometimes publish repos that nomi-sec hasn't
    indexed yet.  This function probes each known owner via a HEAD
    request (no auth needed for public repos).
    """
    cid = (cve_id or "").upper().strip()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
        return []
    refs = []
    for owner in _PROLIFIC_POC_OWNERS:
        url = f"https://github.com/{owner}/{cid}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "binoracle/1.0"},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 200:
                    refs.append(ExploitRef(url=url, source="github"))
        except Exception:
            pass
    return refs


def search_github_poc(cve_id: str, timeout: float = 6.0) -> List[ExploitRef]:
    """Consulta la base curada de PoCs en GitHub (nomi-sec/PoC-in-GitHub) para la CVE. Devuelve las
    referencias de repos con PoC (vacio si no hay o sin internet). Es una senal directa de exploit
    publico, complementaria a las referencias de la NVD."""
    cid = (cve_id or "").upper().strip()
    m = re.fullmatch(r"CVE-(\d{4})-\d{4,}", cid)
    if not m:
        return []
    url = GH_POC.format(year=m.group(1), cve=cid)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return []
    refs = []
    for item in (data or []):
        html = item.get("html_url") or ""
        if html:
            refs.append(ExploitRef(url=html, source="github"))
    return refs


def search_searchsploit(cve_id: str, timeout: float = 8.0) -> List[ExploitRef]:
    """Si `searchsploit` (Exploit-DB local) esta instalado, busca la CVE y devuelve las referencias
    EDB encontradas. Best-effort: si no esta, devuelve vacio (no es un error)."""
    import shutil
    import subprocess
    exe = shutil.which("searchsploit")
    if not exe:
        return []
    cid = (cve_id or "").upper().strip()
    try:
        out = subprocess.run([exe, "--cve", cid, "-j"], capture_output=True, text=True, timeout=timeout)
        data = json.loads(out.stdout or "{}")
    except Exception:
        return []
    refs = []
    for row in (data.get("RESULTS_EXPLOIT") or []):
        edb = str(row.get("EDB-ID") or row.get("Codes") or "")
        path = row.get("Path") or row.get("URL") or ""
        url = f"https://www.exploit-db.com/exploits/{edb}" if edb.isdigit() else path
        refs.append(ExploitRef(url=url, source="exploit-db", edb_id=edb if edb.isdigit() else ""))
    return refs


_NVD_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "binoracle", "nvd")
_NVD_CACHE_TTL = 86400 * 7   # 7 días — suficiente para runs repetidos, no tan largo que quede obsoleto


def _nvd_cache_path(cve_id: str) -> str:
    return os.path.join(_NVD_CACHE_DIR, f"{cve_id}.json")


def _nvd_cache_load(cve_id: str) -> Optional[dict]:
    """Devuelve la respuesta NVD cacheada si existe y no ha expirado, o None."""
    path = _nvd_cache_path(cve_id)
    try:
        stat = os.stat(path)
        if time.time() - stat.st_mtime > _NVD_CACHE_TTL:
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _nvd_cache_save(cve_id: str, data: dict) -> None:
    try:
        os.makedirs(_NVD_CACHE_DIR, exist_ok=True)
        with open(_nvd_cache_path(cve_id), "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass


_EPSS_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "binoracle", "epss")
_EPSS_CACHE_TTL = 86400          # 24 h
_CISA_KEV_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "binoracle", "cisa_kev.json")
_CISA_KEV_TTL  = 86400 * 0.25   # 6 h


def _fetch_epss(cve_id: str, timeout: float = 10.0) -> Optional[dict]:
    """Return EPSS data for `cve_id` from FIRST.org, with 24-h disk cache.

    Returns dict(epss, percentile, date) or None on any network/parse error.
    EPSS (Exploit Prediction Scoring System) gives the probability that the
    CVE will be exploited in the wild in the next 30 days (0.0–1.0).
    """
    cid = (cve_id or "").upper().strip()
    cache_path = os.path.join(_EPSS_CACHE_DIR, f"{cid}.json")
    # disk cache
    try:
        st = os.stat(cache_path)
        if time.time() - st.st_mtime < _EPSS_CACHE_TTL:
            with open(cache_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
    except (OSError, ValueError):
        pass
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cid}"
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = json.loads(r.read().decode("utf-8", "replace"))
        data_list = raw.get("data") or []
        if not data_list:
            return None
        item = data_list[0]
        result = {
            "epss":       float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0)),
            "date":       item.get("date", ""),
        }
        # save to cache
        try:
            os.makedirs(_EPSS_CACHE_DIR, exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh)
        except OSError:
            pass
        return result
    except Exception:
        return None


def _fetch_cisa_kev(timeout: float = 15.0) -> set:
    """Return the set of CVE IDs in the CISA Known Exploited Vulnerabilities catalog.

    Caches the full catalog locally for 6 hours. Returns empty set on any error.
    KEV inclusion means active, real-world exploitation has been confirmed by CISA.
    """
    try:
        st = os.stat(_CISA_KEV_CACHE)
        if time.time() - st.st_mtime < _CISA_KEV_TTL:
            with open(_CISA_KEV_CACHE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {v.get("cveID", "") for v in (data.get("vulnerabilities") or [])}
    except (OSError, ValueError):
        pass
    try:
        url = ("https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json")
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        try:
            os.makedirs(os.path.dirname(_CISA_KEV_CACHE), exist_ok=True)
            with open(_CISA_KEV_CACHE, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except OSError:
            pass
        return {v.get("cveID", "") for v in (data.get("vulnerabilities") or [])}
    except Exception:
        return set()


def risk_label(info: "CVEInfo") -> str:
    """Combine CVSS + EPSS + CISA KEV into a single triage risk label.

    Labels (most severe first):
      CRITICAL-WEAPONIZED — in CISA KEV (confirmed active exploitation)
      CRITICAL            — CVSS >= 9.0 or (CVSS >= 7 and EPSS >= 0.5)
      HIGH                — CVSS >= 7.0 or EPSS >= 0.2
      MEDIUM              — CVSS >= 4.0
      LOW                 — everything else
    """
    if info.in_cisa_kev:
        return "CRITICAL-WEAPONIZED"
    cvss = info.cvss_score or 0.0
    epss = info.epss_score or 0.0
    if cvss >= 9.0 or (cvss >= 7.0 and epss >= 0.5):
        return "CRITICAL"
    if cvss >= 7.0 or epss >= 0.2:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def fetch_cve(cve_id: str, timeout: float = 20.0, enrich: bool = True) -> CVEInfo:
    """Descarga la CVE de la NVD y, si `enrich`, cruza con PoCs de GitHub + Exploit-DB (searchsploit)
    para una deteccion de exploit publico mas completa. No lanza: ante error de red -> ok=False.

    Las respuestas NVD se cachean en ~/.cache/binoracle/nvd/ durante 7 dias para evitar el
    rate-limit publico (5 req/30s) en runs repetidos de la misma CVE -- confirmado en vivo con
    503 en la segunda ejecucion de CVE-2025-27610 inmediatamente despues de la primera."""
    cid = (cve_id or "").upper().strip()
    info = CVEInfo(cve_id=cid)
    if not _CVE_RE.fullmatch(cid):
        info.note = "identificador CVE no valido (formato CVE-AAAA-NNNN)"
        return info
    # Caché de disco: evita repetir la llamada NVD en runs de la misma sesion/dia
    _data = _nvd_cache_load(cid)
    # Reintentos con backoff para errores transitorios (503 rate-limit NVD, 429, 500).
    # Confirmado en vivo: NVD devuelve 503 en picos de carga y en CVEs muy recientes que aun
    # no estan indexados -- sin reintentos, un 503 puntual hace que el LLM trabaje sin datos
    # y el informe final queda casi vacio. Con 2 reintentos (1s + 2s) se recupera en la practica.
    _last_exc: Optional[Exception] = None
    if _data is None:
        for _attempt in range(3):
            try:
                req = urllib.request.Request(NVD_API + cid, headers={"User-Agent": "binoracle/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    _data = json.loads(r.read().decode("utf-8", "replace"))
                _nvd_cache_save(cid, _data)
                _last_exc = None
                break
            except urllib.error.HTTPError as e:
                _last_exc = e
                if e.code in (429, 500, 503) and _attempt < 2:
                    time.sleep(2 ** _attempt)
                    continue
                info.note = f"no se pudo consultar la NVD (sin internet o rate-limit): {e}"
                return info
            except Exception as e:
                info.note = f"no se pudo consultar la NVD (sin internet o rate-limit): {e}"
                return info
    if _last_exc is not None or _data is None:
        info.note = (f"no se pudo consultar la NVD (sin internet o rate-limit): {_last_exc}")
        return info
    data = _data
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        info.note = "la NVD no devolvio datos para esa CVE"
        # Intento fallback: buscar PoC en GitHub/nomi-sec aunque NVD no tenga la CVE aún.
        # Cubre CVEs recientes (< 7 días) que tienen PoC público pero NVD aún no los indexó.
        if enrich:
            seen_fb: set = set()
            for r in search_github_poc(cid) + check_well_known_poc_repos(cid) + search_searchsploit(cid):
                if r.url and r.url not in seen_fb:
                    seen_fb.add(r.url)
                    info.exploit_refs.append(r)
                    info.has_public_exploit = True
            if info.has_public_exploit:
                # Descripción mínima para que el LLM pueda trabajar
                info.description = f"{cid}: vulnerabilidad con exploit público (NVD pendiente de indexar)"
                info.ok = True
                info.note = ""
                return info
        return info
    cve = vulns[0].get("cve", {})
    # descripcion (ingles)
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            info.description = (d.get("value") or "").strip()
            break
    info.published = (cve.get("published") or "")[:10]
    # CVSS — usa el score más alto entre v3.1/v3.0/v2; v4.0 se guarda solo si no hay
    # ningún v3.x (CVSS 4.0 tiende a puntuar más bajo para la misma vuln que v3.1,
    # lo que causa que el filtro min_cvss descarte CVEs realmente críticos).
    metrics = cve.get("metrics", {})
    _best_score: float = 0.0
    _best_sev: str = ""
    _best_vec: str = ""
    # Recopilar todos los scores v3.x disponibles, quedarse con el más alto
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m0 = metrics[key][0].get("cvssData", {})
            sc = m0.get("baseScore") or 0.0
            if sc > _best_score:
                _best_score = sc
                _best_sev = m0.get("baseSeverity") or metrics[key][0].get("baseSeverity") or ""
                _best_vec = m0.get("vectorString", "")
    # Usar v4.0 solo cuando no hay score v3.x
    if _best_score == 0.0 and metrics.get("cvssMetricV40"):
        m0 = metrics["cvssMetricV40"][0].get("cvssData", {})
        _best_score = m0.get("baseScore") or 0.0
        _best_sev = (m0.get("baseSeverity") or
                     metrics["cvssMetricV40"][0].get("baseSeverity") or
                     metrics["cvssMetricV40"][0].get("cvssV4Severity", ""))
        _best_vec = m0.get("vectorString", "")
    if _best_score > 0.0:
        info.cvss_score = _best_score
        info.cvss_severity = _best_sev
        info.cvss_vector = _best_vec
    # referencias + deteccion de exploit publico (1) por las etiquetas de la NVD
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", []) or []
        info.references.append({"url": url, "tags": tags})
        if "Exploit" in tags:
            info.has_public_exploit = True
            info.exploit_refs.append(_classify_ref(url))
    # (2) crawling complementario: PoCs en GitHub (nomi-sec) + Exploit-DB (searchsploit si esta)
    if enrich:
        seen = {r.url for r in info.exploit_refs}
        for r in (search_github_poc(cid) + check_well_known_poc_repos(cid) + search_searchsploit(cid)):
            if r.url and r.url not in seen:
                seen.add(r.url)
                info.exploit_refs.append(r)
                info.has_public_exploit = True
        # Patch intelligence: fetch fix commits and affected ranges from NVD refs + OSV
        try:
            from .patch_intel import fetch_patch_intel
            _patch = fetch_patch_intel(
                cid,
                nvd_refs=[{"url": ref.get("url", "")} for ref in info.references],
                nvd_published=info.published,
            )
            if _patch.ok:
                info.references.append({"url": "patch_intel", "patch_intel": {
                    "fix_commits": [{"repo": fc.repo, "sha": fc.sha, "url": fc.url,
                                     "files": fc.files[:10], "message": fc.message[:200]}
                                    for fc in _patch.fix_commits],
                    "patched_versions": _patch.patched_versions[:10],
                    "affected_ranges": _patch.affected_ranges[:10],
                    "timeline": _patch.timeline[:10],
                    "sources": _patch.sources,
                }})
        except Exception:
            pass
        # EPSS — probability of exploitation in next 30 days
        epss_data = _fetch_epss(cid)
        if epss_data:
            info.epss_score = epss_data.get("epss")
            info.epss_percentile = epss_data.get("percentile")
        # CISA KEV — confirmed active exploitation in the wild
        kev_cves = _fetch_cisa_kev()
        if cid in kev_cves:
            info.in_cisa_kev = True
            info.has_public_exploit = True  # KEV = real-world exploitation confirmed
    info.ok = bool(info.description)
    if not info.ok and not info.note:
        info.note = "la NVD no incluyo descripcion para esa CVE"
    return info


def fetch_source_repo_from_advisory(cve_id: str, timeout: float = 12.0) -> Optional[str]:
    """Consulta OSV.dev y devuelve la URL del repositorio de código fuente del proyecto
    afectado, si el advisory la incluye en affected[].ranges[].repo.
    No usa ninguna tabla hardcodeada — saca el repo directamente del advisory.
    Devuelve None si no se encuentra o hay error de red."""
    cid = (cve_id or "").upper().strip()
    url = f"https://api.osv.dev/v1/vulns/{cid}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None
    # OSV: affected[].ranges[].repo → URL del repositorio (ej. https://github.com/strapi/strapi)
    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            repo = (rng.get("repo") or "").strip()
            if repo and repo.startswith("https://"):
                return repo
    # Fallback: buscar en referencias una URL de GitHub que sea un repo raiz (no issue/commit/PR)
    _GH_REPO_RE = re.compile(
        r'^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/(?:security/advisories|releases|tags|tree|blob).*)?$'
    )
    _ADVISORY_RE = re.compile(r'GHSA-', re.IGNORECASE)
    for ref in data.get("references", []):
        ref_url = (ref.get("url") or "").strip()
        if not ref_url or _ADVISORY_RE.search(ref_url):
            continue
        m = _GH_REPO_RE.match(ref_url)
        if m:
            return f"https://github.com/{m.group(1)}"
    return None


def render_cve_info(info: CVEInfo, lang: str = "es") -> str:
    """Resumen en markdown de la consulta CVE + estado de exploit publico (Exploit-DB)."""
    es = lang == "es"
    if not info.ok:
        return (f"### {info.cve_id}\n\n" +
                (info.note or ("No se pudo obtener informacion." if es else "Could not fetch info.")))
    out = [f"### {info.cve_id}" + (f"  (CVSS {info.cvss_score} {info.cvss_severity})"
                                   if info.cvss_score is not None else "")]
    if info.published:
        out.append(("Publicada: " if es else "Published: ") + info.published)
    out.append("\n" + info.description)
    if info.has_public_exploit:
        counts = {}
        for r in info.exploit_refs:
            counts[r.source] = counts.get(r.source, 0) + 1
        srcs = ", ".join(f"{k}: {v}" for k, v in counts.items()) or "referencias"
        out.append("\n**" + ("Exploit publico: SI consta" if es else "Public exploit: YES") +
                   f"** ({srcs}). " +
                   ("No es un hueco: revisa el PoC existente antes de desarrollar." if es else
                    "Not a gap: review the existing PoC before developing."))
        for r in info.exploit_refs[:8]:
            tag = f"EDB-{r.edb_id}" if r.edb_id else r.source
            out.append(f"- [{tag}] {r.url}")
        if len(info.exploit_refs) > 8:
            out.append(("...y %d mas" % (len(info.exploit_refs) - 8)) if es else
                       ("...and %d more" % (len(info.exploit_refs) - 8)))
    else:
        out.append("\n**" + ("Exploit publico: NO consta (NVD + GitHub + Exploit-DB) -> posible hueco"
                             if es else
                             "Public exploit: NONE (NVD + GitHub + Exploit-DB) -> possible gap") + "**. " +
                   ("binoracle desarrolla una aproximacion abajo." if es else
                    "binoracle develops an approximation below."))
    return "\n".join(out)


def lookup_and_develop(cve_id: str, config=None, lang: str = "es", verify: bool = False,
                       binary: str = ""):
    """Consulta la CVE, decide si es un hueco (sin exploit publico) y desarrolla el exploit para su
    clase. Devuelve (CVEInfo, ExploitPlan). Si hay binario, concreta+verifica; si no, plantilla."""
    from .cveplan import plan, plan_for_binary
    import os
    info = fetch_cve(cve_id)
    desc = info.description or cve_id
    if binary and os.path.exists(binary):
        pl = plan_for_binary(binary, text=desc, cve=info.cve_id, lang=lang, verify=verify)
    else:
        pl = plan(desc, {}, cve=info.cve_id, lang=lang)
    return info, pl


# ─── NVD scope search ─────────────────────────────────────────────────────────

NVD_SEARCH_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SCOPE_PRESETS: dict = {
    # Technology scopes → NVD keyword hints that reliably narrow results
    "wordpress-plugin":  ["wordpress plugin"],
    "wordpress":         ["wordpress"],
    "python-flask":      ["flask python", "flask"],
    "python-django":     ["django"],
    "python":            ["python"],
    "nodejs":            ["node.js", "nodejs", "npm"],
    "php":               ["php"],
    "java-spring":       ["spring boot", "spring framework"],
    "ruby-rails":        ["ruby on rails", "rails"],
    "apache":            ["apache httpd", "apache http server"],
    "nginx":             ["nginx"],
    "docker":            ["docker"],
    "kubernetes":        ["kubernetes"],
    "linux-kernel":      ["linux kernel"],
}


@dataclass
class NvdSearchResult:
    """One CVE entry returned by search_nvd_by_scope()."""
    cve_id:            str
    cvss_score:        Optional[float]
    cvss_severity:     str
    published:         str            # ISO date YYYY-MM-DD
    description:       str
    has_public_exploit: bool
    exploit_refs:      List[ExploitRef] = field(default_factory=list)
    keyword_matched:   str = ""


def search_nvd_by_scope(
    scope: str,
    min_cvss:          float    = 7.0,
    max_results:       int      = 50,
    days_back:         int      = 180,
    require_exploit:   bool     = False,
    severity_filter:   str      = "",   # "CRITICAL" | "HIGH" | "" (all)
    custom_keywords:   Optional[List[str]] = None,
    timeout:           float    = 20.0,
    enrich:            bool     = True,
) -> List[NvdSearchResult]:
    """Query NVD's keyword search API and return high-signal CVE candidates for autonomous
    exploit research. Rate-aware: sleeps between keyword pages, respects NVD's 5 req/30s limit.

    Args:
        scope:           Technology scope (key in _SCOPE_PRESETS) or a free-form keyword.
        min_cvss:        Minimum CVSS base score to include.
        max_results:     Hard cap on returned CVEs (NVD cap: 2000 per page).
        days_back:       Search window in days from today backward.
        require_exploit: If True, only return CVEs with a confirmed public PoC.
        severity_filter: NVD severity string to pass as cvssV3Severity filter ("CRITICAL", "HIGH").
        custom_keywords: Override the scope preset with these exact keywords (tried in order).
        timeout:         HTTP timeout per request.
        enrich:          Cross-check GitHub PoC database for each result.
    """
    from datetime import datetime, timedelta, timezone

    keywords  = custom_keywords or _SCOPE_PRESETS.get(scope, [scope])
    now       = datetime.now(timezone.utc)
    cutoff_dt = now - timedelta(days=days_back)
    cutoff_str = cutoff_dt.strftime("%Y-%m-%d")   # for client-side date filter

    seen_ids: set = set()
    results:  List[NvdSearchResult] = []

    for kw in keywords:
        if len(results) >= max_results:
            break
        # NVD 2.0 API does NOT support keywordSearch + pubDate range + severity
        # simultaneously — combining all three returns 404.  Fetch up to 2000
        # results per keyword (paginating in batches of 100) and apply date and
        # CVSS score filters client-side.  Results are sorted by CVE ID (oldest
        # first), so we reverse-paginate: fetch the LAST pages first.
        base_params = [f"keywordSearch={urllib.request.quote(kw)}"]
        if severity_filter:
            base_params.append(f"cvssV3Severity={severity_filter}")

        # Probe first page to get totalResults, then jump to the last pages.
        total_results = 0
        all_items: List[dict] = []
        try:
            probe_url = (NVD_SEARCH_API + "?" +
                         "&".join(base_params + ["resultsPerPage=1"]))
            req = urllib.request.Request(probe_url,
                                         headers={"User-Agent": "binoracle/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                probe_data = json.loads(r.read().decode("utf-8", "replace"))
            total_results = int(probe_data.get("totalResults") or 0)
        except Exception:
            continue

        # Reverse-paginate: last page first (most recently assigned CVE IDs).
        # Cap at 500 candidates to avoid overloading the API.
        _page_size = 100
        _max_items = min(total_results, 500)
        _start_indices = list(range(
            max(0, total_results - _page_size),  # start from last page
            max(0, total_results - _max_items) - 1,
            -_page_size,
        ))

        for start_idx in _start_indices:
            if len(all_items) >= _max_items:
                break
            page_params = base_params + [
                f"resultsPerPage={_page_size}",
                f"startIndex={start_idx}",
            ]
            try:
                page_url = NVD_SEARCH_API + "?" + "&".join(page_params)
                req = urllib.request.Request(page_url,
                                             headers={"User-Agent": "binoracle/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    page_data = json.loads(r.read().decode("utf-8", "replace"))
                # Reverse so newest CVE IDs come first
                page_items = list(reversed(page_data.get("vulnerabilities") or []))
                all_items.extend(page_items)
            except Exception:
                break
            time.sleep(0.4)   # NVD rate limit: 5 req/30s

        for item in all_items:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            if not cid or cid in seen_ids:
                continue
            seen_ids.add(cid)

            # Description
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = (d.get("value") or "").strip()
                    break

            # CVSS
            score: Optional[float] = None
            severity = ""
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m0 = metrics[key][0].get("cvssData", {})
                    score = m0.get("baseScore")
                    severity = (m0.get("baseSeverity") or
                                m0.get("cvssV4Severity") or "").upper()
                    break

            if score is not None and score < min_cvss:
                continue

            published = (cve.get("published") or "")[:10]
            # Client-side date filter (NVD can't combine it with keyword+severity)
            if published and published < cutoff_str:
                continue

            # Exploit references
            has_exploit = False
            exploit_refs: List[ExploitRef] = []
            for ref in cve.get("references", []):
                ref_url = ref.get("url", "")
                if "Exploit" in (ref.get("tags") or []):
                    has_exploit = True
                    exploit_refs.append(_classify_ref(ref_url))

            if enrich and not has_exploit:
                gh_refs = search_github_poc(cid)
                if gh_refs:
                    has_exploit = True
                    exploit_refs.extend(gh_refs)

            if require_exploit and not has_exploit:
                continue

            results.append(NvdSearchResult(
                cve_id=cid,
                cvss_score=score,
                cvss_severity=severity,
                published=published,
                description=desc,
                has_public_exploit=has_exploit,
                exploit_refs=exploit_refs,
                keyword_matched=kw,
            ))

            if len(results) >= max_results:
                break

        # NVD rate limit: 5 req/30s. Sleep briefly between keyword sweeps.
        time.sleep(0.7)

    # Sort by CVSS desc, then by date desc
    results.sort(key=lambda r: (r.cvss_score or 0, r.published), reverse=True)
    return results[:max_results]


# ─── Patchstack advisory feed ────────────────────────────────────────────────

_PATCHSTACK_RSS = "https://patchstack.com/database/wordpress/feed/"


@dataclass
class HuecoCandidateResult:
    """A HUECO CVE candidate — recent advisory with no confirmed public exploit."""
    cve_id:      str
    plugin_name: str
    description: str
    published:   str            # YYYY-MM-DD
    cvss_score:  Optional[float]
    cvss_severity: str
    source:      str            # "patchstack" | "nvd"
    advisory_url: str = ""


def _parse_patchstack_rss(xml_text: str, days_back: int = 30) -> List[HuecoCandidateResult]:
    """Extract CVE IDs and metadata from Patchstack RSS feed XML."""
    from datetime import datetime, timedelta, timezone
    import email.utils

    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    items: List[HuecoCandidateResult] = []

    # Simple regex XML parsing (no lxml dependency)
    for item_m in re.finditer(r"<item>(.*?)</item>", xml_text, re.S):
        block = item_m.group(1)

        title_m  = re.search(r"<title[^>]*><!\[CDATA\[(.*?)]]></title>|<title[^>]*>(.*?)</title>", block, re.S)
        link_m   = re.search(r"<link[^>]*>(.*?)</link>", block, re.S)
        desc_m   = re.search(r"<description[^>]*><!\[CDATA\[(.*?)]]>|<description[^>]*>(.*?)</description>", block, re.S)
        date_m   = re.search(r"<pubDate[^>]*>(.*?)</pubDate>", block, re.S)

        title    = (title_m.group(1) or title_m.group(2) or "").strip() if title_m else ""
        link     = (link_m.group(1) or "").strip() if link_m else ""
        raw_desc = (desc_m.group(1) or desc_m.group(2) or "").strip() if desc_m else ""
        raw_date = (date_m.group(1) or "").strip() if date_m else ""

        # Parse pubDate (RFC 2822) and filter by cutoff
        pub_iso = ""
        try:
            parsed_dt = email.utils.parsedate_to_datetime(raw_date)
            if parsed_dt < cutoff:
                continue
            pub_iso = parsed_dt.strftime("%Y-%m-%d")
        except Exception:
            pass

        # Extract CVE IDs from title or description
        cve_ids = list(dict.fromkeys(
            m.upper() for m in _CVE_RE.findall(title + " " + raw_desc[:800])
        ))
        if not cve_ids:
            continue

        # Extract plugin name from title: "PluginName <= X.Y.Z" pattern
        plugin_m = re.match(r"^(.+?)\s*(?:<=|<|–|-)\s*[\d.]+", title)
        plugin_name = plugin_m.group(1).strip() if plugin_m else title[:60]

        # Strip HTML tags from description
        clean_desc = re.sub(r"<[^>]+>", " ", raw_desc).strip()[:300]

        for cve_id in cve_ids:
            items.append(HuecoCandidateResult(
                cve_id=cve_id,
                plugin_name=plugin_name,
                description=clean_desc,
                published=pub_iso,
                cvss_score=None,
                cvss_severity="",
                source="patchstack",
                advisory_url=link,
            ))

    return items


def scout_hueco_cves(
    max_results: int = 25,
    days_back:   int = 45,
    min_cvss:    float = 5.0,
    timeout:     float = 15.0,
) -> List[HuecoCandidateResult]:
    """Find recent WordPress plugin CVEs with NO confirmed public exploit from two sources:
    1. Patchstack advisory RSS feed — earliest signal for new WP plugin vulns.
    2. NVD keyword search with `require_exploit=False` — cross-check.

    For each CVE found, cross-checks nomi-sec/PoC-in-GitHub to confirm it is
    truly a HUECO (no PoC repo indexed).  Returns only confirmed HUECOs.

    Rate-limited to stay within NVD's 5 req/30s. Best-effort: returns partial
    results on network errors rather than raising.
    """
    seen_ids: set = set()
    candidates: List[HuecoCandidateResult] = []

    # --- Source 1: Patchstack RSS ---
    try:
        req = urllib.request.Request(
            _PATCHSTACK_RSS,
            headers={"User-Agent": "binoracle/1.0 (security research)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            rss_xml = r.read().decode("utf-8", "replace")
        ps_items = _parse_patchstack_rss(rss_xml, days_back=days_back)
        for item in ps_items:
            if item.cve_id not in seen_ids:
                seen_ids.add(item.cve_id)
                candidates.append(item)
    except Exception:
        pass

    # --- Source 2: NVD search (wordpress-plugin scope, no exploit required) ---
    try:
        nvd_results = search_nvd_by_scope(
            scope="wordpress-plugin",
            min_cvss=min_cvss,
            days_back=days_back,
            max_results=max_results,
            require_exploit=False,
            enrich=False,          # skip per-CVE enrichment here, do it below
            timeout=timeout,
        )
        for r in nvd_results:
            if r.cve_id not in seen_ids:
                seen_ids.add(r.cve_id)
                candidates.append(HuecoCandidateResult(
                    cve_id=r.cve_id,
                    plugin_name=r.keyword_matched,
                    description=r.description[:300],
                    published=r.published,
                    cvss_score=r.cvss_score,
                    cvss_severity=r.cvss_severity,
                    source="nvd",
                ))
    except Exception:
        pass

    # --- Cross-check: keep only confirmed HUECOs (no GitHub PoC found) ---
    hueco: List[HuecoCandidateResult] = []
    for cand in candidates:
        # Also try to fill cvss_score from NVD if missing (Patchstack items)
        if cand.cvss_score is None:
            try:
                info = fetch_cve(cand.cve_id, timeout=timeout, enrich=True)
                if info.ok:
                    cand.cvss_score   = info.cvss_score
                    cand.cvss_severity = info.cvss_severity
                    if info.has_public_exploit:
                        continue   # has a public exploit — not a HUECO
                time.sleep(0.3)
            except Exception:
                pass
        else:
            # NVD result already enriched with has_public_exploit from search phase
            # Double-check with github PoC search
            poc_refs = search_github_poc(cand.cve_id, timeout=6.0)
            if poc_refs:
                continue  # GitHub PoC found — not a HUECO

        if cand.cvss_score is None or cand.cvss_score >= min_cvss:
            hueco.append(cand)
        if len(hueco) >= max_results:
            break

    # Sort by CVSS desc, recency as tiebreak
    hueco.sort(key=lambda c: (c.cvss_score or 0, c.published), reverse=True)
    return hueco[:max_results]


# ─── Multi-technology HUECO scout ────────────────────────────────────────────

OSV_API = "https://api.osv.dev/v1"

# Maps our tech names → (OSV ecosystem name, NVD scope keys, human label)
_TECH_PROFILE: dict = {
    "wordpress": {
        "nvd_scopes": ["wordpress-plugin"],
        "osv_ecosystem": None,          # Patchstack RSS covers this better
        "label": "WordPress Plugin",
    },
    "python": {
        "nvd_scopes": ["python-django", "python-flask", "python"],
        "osv_ecosystem": "PyPI",
        "label": "Python (PyPI)",
    },
    "nodejs": {
        "nvd_scopes": ["nodejs"],
        "osv_ecosystem": "npm",
        "label": "Node.js (npm)",
    },
    "ruby": {
        "nvd_scopes": ["ruby-rails"],
        "osv_ecosystem": "RubyGems",
        "label": "Ruby (RubyGems)",
    },
    "java": {
        "nvd_scopes": ["java-spring"],
        "osv_ecosystem": "Maven",
        "label": "Java (Maven)",
    },
    "go": {
        "nvd_scopes": ["go"],
        "osv_ecosystem": "Go",
        "label": "Go",
    },
    "php": {
        "nvd_scopes": ["php"],
        "osv_ecosystem": "Packagist",
        "label": "PHP (Packagist)",
    },
    "dotnet": {
        "nvd_scopes": ["dotnet"],
        "osv_ecosystem": "NuGet",
        "label": ".NET (NuGet)",
    },
}

# NVD scopes for techs not already in _SCOPE_PRESETS
_SCOPE_PRESETS.update({
    "go":     ["golang", "go programming language"],
    "dotnet": ["asp.net", "dotnet", ".net core"],
})


def _fetch_osv_recent(
    ecosystem: str,
    days_back: int = 30,
    max_results: int = 50,
    timeout: float = 15.0,
) -> List[HuecoCandidateResult]:
    """Fetch recent CVEs from OSV.dev for a given ecosystem.

    Uses the OSV.dev batch query endpoint, paginating over recently modified
    vulnerabilities. Returns HuecoCandidateResult list (cvss_score may be None).
    """
    from datetime import datetime, timedelta, timezone
    import json as _json

    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    results: List[HuecoCandidateResult] = []
    page_token: Optional[str] = None

    for _page in range(8):   # max 8 pages = 800 candidates
        if len(results) >= max_results:
            break
        payload: dict = {
            "package": {"ecosystem": ecosystem},
        }
        if page_token:
            payload["page_token"] = page_token

        try:
            body = _json.dumps(payload).encode()
            req = urllib.request.Request(
                f"{OSV_API}/query",
                data=body,
                headers={"Content-Type": "application/json",
                         "User-Agent": "binoracle/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = _json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            break

        vulns = data.get("vulns") or []
        page_token = data.get("next_page_token")

        for v in vulns:
            if len(results) >= max_results:
                break

            # Date filter
            modified = v.get("modified") or v.get("published") or ""
            if modified and modified < cutoff_str:
                continue

            # Extract CVE ID
            aliases = v.get("aliases") or []
            cve_id = next((a for a in aliases if a.upper().startswith("CVE-")),
                          v.get("id", ""))
            if not cve_id or not cve_id.upper().startswith("CVE-"):
                continue
            cve_id = cve_id.upper()

            # Package name
            affected = v.get("affected") or [{}]
            pkg_name = (affected[0].get("package") or {}).get("name", "")

            # Description
            details = (v.get("details") or v.get("summary") or "")[:300]

            # Published date
            pub_raw = v.get("published") or modified or ""
            pub_iso = pub_raw[:10] if pub_raw else ""

            results.append(HuecoCandidateResult(
                cve_id=cve_id,
                plugin_name=pkg_name,
                description=details,
                published=pub_iso,
                cvss_score=None,
                cvss_severity="",
                source=f"osv/{ecosystem.lower()}",
                advisory_url=f"https://osv.dev/vulnerability/{v.get('id', cve_id)}",
            ))

        if not page_token:
            break
        time.sleep(0.3)

    return results


def scout_hueco_cves_generic(
    techs:       Optional[List[str]] = None,
    min_cvss:    float = 6.0,
    days_back:   int   = 30,
    max_per_tech: int  = 15,
    timeout:     float = 15.0,
    skip_existing: Optional[set] = None,
) -> List[HuecoCandidateResult]:
    """Find recent HUECO CVEs across ALL supported technology stacks.

    techs: list of keys from _TECH_PROFILE, or None for all techs.
           e.g. ['nodejs', 'python', 'java', 'ruby', 'go', 'wordpress']

    For each tech:
      - WordPress: Patchstack RSS (best signal) + NVD
      - Others:    OSV.dev ecosystem query + NVD keyword search

    Cross-checks nomi-sec/PoC-in-GitHub to confirm HUECO status.
    Returns candidates sorted by CVSS desc across all techs.
    """
    if techs is None:
        techs = list(_TECH_PROFILE.keys())

    skip = skip_existing or set()
    seen_ids: set = set(skip)
    all_candidates: List[HuecoCandidateResult] = []

    for tech in techs:
        profile = _TECH_PROFILE.get(tech)
        if not profile:
            continue

        tech_candidates: List[HuecoCandidateResult] = []

        # --- WordPress: Patchstack RSS ---
        if tech == "wordpress":
            try:
                req = urllib.request.Request(
                    _PATCHSTACK_RSS,
                    headers={"User-Agent": "binoracle/1.0 (security research)"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    rss_xml = r.read().decode("utf-8", "replace")
                for item in _parse_patchstack_rss(rss_xml, days_back=days_back):
                    if item.cve_id not in seen_ids:
                        seen_ids.add(item.cve_id)
                        tech_candidates.append(item)
            except Exception:
                pass

        # --- OSV.dev: ecosystem CVEs (non-WordPress) ---
        osv_eco = profile.get("osv_ecosystem")
        if osv_eco:
            try:
                osv_items = _fetch_osv_recent(
                    osv_eco, days_back=days_back,
                    max_results=max_per_tech * 3, timeout=timeout)
                for item in osv_items:
                    if item.cve_id not in seen_ids:
                        seen_ids.add(item.cve_id)
                        tech_candidates.append(item)
            except Exception:
                pass

        # --- NVD keyword search for this tech ---
        for scope in profile.get("nvd_scopes", []):
            if len(tech_candidates) >= max_per_tech * 2:
                break
            try:
                nvd_results = search_nvd_by_scope(
                    scope=scope,
                    min_cvss=min_cvss,
                    days_back=days_back,
                    max_results=max_per_tech,
                    require_exploit=False,
                    enrich=False,
                    timeout=timeout,
                )
                for r in nvd_results:
                    if r.cve_id not in seen_ids:
                        # Skip immediately if NVD already flagged a public exploit
                        if r.has_public_exploit:
                            continue
                        seen_ids.add(r.cve_id)
                        tech_candidates.append(HuecoCandidateResult(
                            cve_id=r.cve_id,
                            plugin_name=r.keyword_matched or scope,
                            description=r.description[:300],
                            published=r.published,
                            cvss_score=r.cvss_score,
                            cvss_severity=r.cvss_severity,
                            source="nvd",
                        ))
            except Exception:
                pass
            time.sleep(1.0)   # conservative: NVD 5 req/30s across all techs

        # --- Cross-check: confirm HUECO status (no public PoC) ---
        confirmed: List[HuecoCandidateResult] = []
        for cand in tech_candidates:
            # OSV items have no CVSS yet — enrich from NVD
            if cand.cvss_score is None:
                try:
                    info = fetch_cve(cand.cve_id, timeout=timeout, enrich=True)
                    if info.ok:
                        cand.cvss_score    = info.cvss_score
                        cand.cvss_severity = info.cvss_severity
                        if info.has_public_exploit:
                            time.sleep(0.3)
                            continue
                    time.sleep(0.5)
                except Exception:
                    pass
            else:
                # NVD items: quick GitHub PoC double-check (lightweight)
                try:
                    poc_refs = search_github_poc(cand.cve_id, timeout=6.0)
                    if poc_refs:
                        continue
                except Exception:
                    pass   # network error → assume no PoC, keep candidate

            if cand.cvss_score is None or cand.cvss_score >= min_cvss:
                cand.plugin_name = f"[{tech}] {cand.plugin_name}"
                confirmed.append(cand)
            if len(confirmed) >= max_per_tech:
                break

        all_candidates.extend(confirmed)

    # Global sort: CVSS desc, then recency
    all_candidates.sort(key=lambda c: (c.cvss_score or 0, c.published), reverse=True)
    return all_candidates


def load_hueco_queue(queue_path: str) -> List[str]:
    """Load list of CVE IDs already in the queue file (one per line)."""
    if not os.path.exists(queue_path):
        return []
    with open(queue_path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip().startswith("CVE-")]


def append_hueco_queue(queue_path: str, candidates: List[HuecoCandidateResult]) -> int:
    """Append new HUECO candidates to the queue file. Returns count added."""
    existing = set(load_hueco_queue(queue_path))
    new_items = [c for c in candidates if c.cve_id not in existing]
    if not new_items:
        return 0
    os.makedirs(os.path.dirname(queue_path), exist_ok=True)
    with open(queue_path, "a", encoding="utf-8") as fh:
        for c in new_items:
            # Format: CVE-YYYY-NNNNN|tech-label|cvss|description_snippet
            desc_short = (c.description or "")[:80].replace("|", " ").replace("\n", " ")
            fh.write(f"{c.cve_id}|{c.plugin_name}|{c.cvss_score or '?'}|{desc_short}\n")
    return len(new_items)


def search_cves_by_product(product: str, keywords: Optional[List[str]] = None,
                           limit: int = 5, min_cvss: float = 7.0,
                           timeout: float = 10.0) -> List[CVEInfo]:
    """G31: Search NVD for CVEs affecting `product` matching optional keyword list.

    Returns up to `limit` CVEInfo objects with cvss_score >= min_cvss.
    Uses NVD /rest/json/cves/2.0 keyword search.  Non-fatal.
    """
    if not product:
        return []
    kws = keywords or []
    # Build search query: "product keyword1 OR keyword2"
    _q_parts = [product]
    if kws:
        _q_parts.append(" ".join(kws[:3]))  # limit query length
    keyword_q = " ".join(_q_parts)
    keyword_q = re.sub(r"[^a-zA-Z0-9 .-]", " ", keyword_q).strip()[:100]
    try:
        _base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        _url = f"{_base}?keywordSearch={urllib.request.quote(keyword_q)}&resultsPerPage={limit * 2}"
        req = urllib.request.Request(_url, headers={"User-Agent": "binoracle/cvesearch"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        results: List[CVEInfo] = []
        for vuln in (data.get("vulnerabilities") or []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue
            descs = cve_data.get("descriptions") or []
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            cvss_score = 0.0
            for metrics_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for m in (cve_data.get("metrics", {}).get(metrics_key) or []):
                    cvss_score = float(m.get("cvssData", {}).get("baseScore", 0))
                    break
                if cvss_score:
                    break
            if cvss_score < min_cvss:
                continue
            # Filter to ones matching any keyword
            if kws:
                desc_lower = desc.lower()
                if not any(kw.lower() in desc_lower for kw in kws):
                    continue
            info = CVEInfo(
                cve_id=cve_id,
                description=desc,
                cvss_score=cvss_score,
                cvss_severity="",
                ok=True,
            )
            results.append(info)
            if len(results) >= limit:
                break
        return results
    except Exception:
        return []
