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
import re
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
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


def fetch_cve(cve_id: str, timeout: float = 8.0) -> CVEInfo:
    """Descarga la CVE de la NVD. No lanza: ante error de red devuelve ok=False con nota."""
    cid = (cve_id or "").upper().strip()
    info = CVEInfo(cve_id=cid)
    if not _CVE_RE.fullmatch(cid):
        info.note = "identificador CVE no valido (formato CVE-AAAA-NNNN)"
        return info
    try:
        req = urllib.request.Request(NVD_API + cid, headers={"User-Agent": "binoracle/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        info.note = f"no se pudo consultar la NVD (sin internet o rate-limit): {e}"
        return info
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
    # referencias + deteccion de exploit publico
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", []) or []
        info.references.append({"url": url, "tags": tags})
        if "Exploit" in tags:
            info.has_public_exploit = True
            info.exploit_refs.append(_classify_ref(url))
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
        srcs = ", ".join(dict.fromkeys(r.source for r in info.exploit_refs)) or "referencias"
        out.append("\n**" + ("Exploit publico: SI consta" if es else "Public exploit: YES") +
                   f"** ({srcs}). " +
                   ("No es un hueco: revisa el PoC existente antes de desarrollar." if es else
                    "Not a gap: review the existing PoC before developing."))
        for r in info.exploit_refs[:8]:
            tag = f"EDB-{r.edb_id}" if r.edb_id else r.source
            out.append(f"- [{tag}] {r.url}")
    else:
        out.append("\n**" + ("Exploit publico: NO consta en las referencias de la NVD (posible hueco)"
                             if es else
                             "Public exploit: NONE in NVD references (possible gap)") + "**. " +
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
