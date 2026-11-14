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
        return info
    cve = vulns[0].get("cve", {})
    # descripcion (ingles)
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            info.description = (d.get("value") or "").strip()
            break
    info.published = (cve.get("published") or "")[:10]
    # CVSS (prioriza v3.1 > v3.0 > v2)
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m0 = metrics[key][0].get("cvssData", {})
            info.cvss_score = m0.get("baseScore")
            info.cvss_severity = (m0.get("baseSeverity") or
                                  metrics[key][0].get("baseSeverity") or "")
            info.cvss_vector = m0.get("vectorString", "")
            break
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
        for r in (search_github_poc(cid) + search_searchsploit(cid)):
            if r.url and r.url not in seen:
                seen.add(r.url)
                info.exploit_refs.append(r)
                info.has_public_exploit = True
    info.ok = bool(info.description)
    if not info.ok and not info.note:
        info.note = "la NVD no incluyo descripcion para esa CVE"
    return info


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
