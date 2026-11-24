"""AI enrichment layer: professional, complete analysis on top of grounded findings.

The LLM writes the human-facing analysis (description, impact, exploitation path,
remediation) and an executive summary, in the configured language. It is constrained: it
may NOT change the code-assigned verdict or severity, and it may NOT claim exploitability
beyond what the verdict allows. Evidence stays the raw tool output.

v2 adds:
  - `auto_cvss(finding) -> CvssEstimate` — derives a CVSS 3.1 BASE vector from finding
    facts (severity, verdict, location, evidence keywords) WITHOUT an LLM
  - `map_cwe(finding) -> List[str]` — keyword-based CWE mapping from evidence
  - `enrich_one(llm, finding, lang)` — enrich a single finding, returns enriched copy
  - structured JSON output: `enrich_to_json(findings)` for downstream consumers
  - batch rate-limited enrichment with on_step callback
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from ..llm.base import Message
from ..store.session import Finding

_VERDICT_RULE = {
    "es": {
        "verified": "La reachability/impacto ha sido PROBADA por un oracle (angr o debugger). Puedes afirmarlo.",
        "grounded": "Solo hay evidencia estatica. Es un candidato PENDIENTE de verificar; no afirmes que es explotable con certeza.",
        "unverified": "No hay evidencia suficiente. Trata esto como una hipotesis debil.",
    },
    "en": {
        "verified": "Reachability/impact has been PROVEN by an oracle (angr or debugger). You may assert it.",
        "grounded": "Only static evidence exists. It is a candidate PENDING verification; do not claim certain exploitability.",
        "unverified": "Not enough evidence. Treat this as a weak hypothesis.",
    },
}

# ── CVSS 3.1 auto-estimation ──────────────────────────────────────────────────

@dataclass
class CvssEstimate:
    vector:    str    # e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score:     float
    rationale: str


_SEVERITY_BASE = {
    "critical": 9.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.0,
}

# Keywords → impact components
_CONF_KEYWORDS = ["leak", "read", "/etc/passwd", "credential", "token", "secret", "infoleak",
                  "disclosure", "memory dump", "heap content", "stack content"]
_INTEG_KEYWORDS = ["write", "overwrite", "inject", "arbitrary code", "shell", "execve",
                   "got overwrite", "rop chain", "command injection", "sql", "rce"]
_AVAIL_KEYWORDS = ["crash", "dos", "null deref", "segfault", "sigsegv", "abort", "loop",
                   "infinite", "deadlock", "out of memory", "oom"]
_NETWORK_KEYWORDS = ["network", "tcp", "udp", "http", "recv", "socket", "remote", "web",
                     "api endpoint", "php", "django", "flask", "wordpress"]
_AUTH_KEYWORDS = ["authenticated", "auth required", "logged in", "admin only", "privilege"]


def auto_cvss(finding: Finding) -> CvssEstimate:
    """
    Derive a CVSS 3.1 BASE vector from finding facts.
    This is a heuristic estimate, NOT a certified CVSS score.
    Use as a starting point; always review against the actual target.
    """
    ev = ((finding.evidence or "") + " " + (finding.title or "") + " " +
          (finding.rationale or "")).lower()
    sev = (finding.severity or "medium").lower()

    # Attack Vector
    av = "N" if any(k in ev for k in _NETWORK_KEYWORDS) else "L"
    # Attack Complexity
    ac = "H" if any(k in ev for k in ["race condition", "heap spray", "bypass aslr", "precise timing"]) else "L"
    # Privileges Required
    pr = "H" if "admin" in ev else ("L" if any(k in ev for k in _AUTH_KEYWORDS) else "N")
    # User Interaction
    ui = "R" if any(k in ev for k in ["click", "open file", "visit", "user interaction", "phishing"]) else "N"
    # Scope
    sc = "C" if any(k in ev for k in ["container escape", "privilege escalation", "kernel", "hypervisor"]) else "U"
    # Confidentiality
    c_impact = "H" if any(k in ev for k in _CONF_KEYWORDS) else ("L" if sev in ("medium",) else "N")
    # Integrity
    i_impact = "H" if any(k in ev for k in _INTEG_KEYWORDS) else ("L" if sev in ("medium",) else "N")
    # Availability
    a_impact = "H" if any(k in ev for k in _AVAIL_KEYWORDS) else "N"

    # For verified RCE, force C/I/A all H
    if finding.verdict == "verified" and i_impact == "H":
        c_impact = i_impact = a_impact = "H"

    vector = f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{sc}/C:{c_impact}/I:{i_impact}/A:{a_impact}"

    # Approximate score from severity (heuristic)
    base = _SEVERITY_BASE.get(sev, 5.0)
    if finding.verdict == "verified":
        base = min(10.0, base + 0.5)
    if av == "N" and pr == "N":
        base = min(10.0, base + 0.3)
    base = round(base, 1)

    rationale = (
        f"AV:{av} ({'network' if av=='N' else 'local'}), "
        f"PR:{pr} ({'none' if pr=='N' else ('low' if pr=='L' else 'high')}), "
        f"C:{c_impact}/I:{i_impact}/A:{a_impact} from evidence keywords. "
        f"Score is a heuristic estimate — verify before submission."
    )
    return CvssEstimate(vector=vector, score=base, rationale=rationale)


# ── CWE mapping ───────────────────────────────────────────────────────────────

_CWE_PATTERNS: List[tuple] = [
    # (pattern_in_evidence, cwe_id, cwe_name)
    (r"buffer overflow|stack overflow|heap overflow|overread|overwrite.*buffer",
     "CWE-120", "Buffer Copy without Checking Size of Input"),
    (r"format string|%n|%s.*user|printf.*user",
     "CWE-134", "Use of Externally-Controlled Format String"),
    (r"use.after.free|uaf|dangling pointer|freed.*used",
     "CWE-416", "Use After Free"),
    (r"double.free|free.*twice",
     "CWE-415", "Double Free"),
    (r"integer overflow|integer underflow|wrap.around|arithmetic overflow",
     "CWE-190", "Integer Overflow or Wraparound"),
    (r"null.pointer|null.deref|dereference.*null",
     "CWE-476", "NULL Pointer Dereference"),
    (r"sql injection|sqli|'.*or.*'1'='1",
     "CWE-89", "Improper Neutralization of Special Elements in SQL Command"),
    (r"command injection|os.system|popen.*user|exec.*user",
     "CWE-78", "Improper Neutralization of Special Elements in OS Command"),
    (r"path traversal|\.\./|directory traversal",
     "CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"),
    (r"xss|cross.site.script|<script.*>|javascript.*inject",
     "CWE-79", "Improper Neutralization of Input During Web Page Generation"),
    (r"hardcoded.*password|hardcoded.*credential|password.*literal",
     "CWE-798", "Use of Hard-coded Credentials"),
    (r"race condition|toctou|time.of.check",
     "CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization"),
    (r"heap.*spray|heap.*feng.shui|tcache|fastbin",
     "CWE-787", "Out-of-bounds Write"),
    (r"rop chain|return.oriented|gadget chain",
     "CWE-693", "Protection Mechanism Failure"),
    (r"auth.bypass|authentication.*bypass|bypass.*auth",
     "CWE-287", "Improper Authentication"),
    (r"deserialization|pickle|yaml.load|unserialize",
     "CWE-502", "Deserialization of Untrusted Data"),
]


def map_cwe(finding: Finding) -> List[str]:
    """Return a list of likely CWE IDs based on finding evidence keywords."""
    text = ((finding.evidence or "") + " " + (finding.title or "") + " " +
            (finding.rationale or "")).lower()
    matched = []
    for pattern, cwe_id, cwe_name in _CWE_PATTERNS:
        if re.search(pattern, text):
            matched.append(f"{cwe_id}: {cwe_name}")
    return matched[:5]  # cap at 5 to avoid noise


# ── Single-finding enrichment ─────────────────────────────────────────────────

def enrich_one(llm, finding: Finding, lang: str = "es") -> Finding:
    """Enrich a single finding in-place: add LLM analysis, CVSS, CWE."""
    # Always run deterministic enrichment regardless of LLM
    finding.cvss = auto_cvss(finding)
    finding.cwes = map_cwe(finding)

    # LLM enrichment (optional)
    if llm is not None and llm.available():
        analysis = _analyze_one(llm, finding, lang)
        if analysis:
            finding.rationale = analysis
    return finding


# ── Original enrich_findings (preserved for backwards compatibility) ──────────

def enrich_findings(llm, findings: List[Finding], lang: str = "es",
                    store=None, on_step=None) -> List[Finding]:
    """Enrich all findings. Calls on_step(msg) between each if provided."""
    for i, f in enumerate(findings):
        if on_step:
            on_step(f"enrich {i+1}/{len(findings)}: {f.title}...")
        enrich_one(llm, f, lang)
        if store:
            store.add_finding(f)
    return findings


# ── JSON export ───────────────────────────────────────────────────────────────

def enrich_to_json(findings: List[Finding]) -> List[Dict]:
    """Export enriched findings as a list of dicts (JSON-serializable)."""
    out = []
    for f in findings:
        d: Dict = {
            "title":    f.title,
            "severity": f.severity,
            "verdict":  f.verdict,
            "location": f.location,
            "evidence": (f.evidence or "")[:2000],
            "rationale": f.rationale or "",
        }
        # CVSS
        if hasattr(f, "cvss") and f.cvss:
            d["cvss"] = {
                "vector": f.cvss.vector,
                "score":  f.cvss.score,
                "note":   f.cvss.rationale,
            }
        else:
            cvss = auto_cvss(f)
            d["cvss"] = {"vector": cvss.vector, "score": cvss.score, "note": cvss.rationale}
        # CWE
        if hasattr(f, "cwes") and f.cwes:
            d["cwes"] = f.cwes
        else:
            d["cwes"] = map_cwe(f)
        out.append(d)
    return out


# ── LLM analysis helpers (unchanged from v1) ─────────────────────────────────

def _analyze_one(llm, f: Finding, lang: str) -> str:
    rule = _VERDICT_RULE.get(lang, _VERDICT_RULE["es"]).get(f.verdict, "")
    cwe_hint = ""
    if hasattr(f, "cwes") and f.cwes:
        cwe_hint = f"\nCWEs detectados: {', '.join(f.cwes[:3])}"
    if lang == "es":
        sys = (
            "Eres un analista senior de reversing y explotacion. Escribe en espanol un analisis "
            "PROFESIONAL y conciso de este hallazgo, usando SOLO la evidencia dada. No inventes "
            "direcciones ni comportamiento no presente en la evidencia. No cambies la severidad "
            "ni el veredicto. Estructura la respuesta EXACTAMENTE con estos apartados en markdown:\n"
            "**Descripcion:** ...\n**Impacto:** ...\n**Ruta de explotacion:** ...\n"
            "**Remediacion:** ...\n"
            f"Regla de veredicto ({f.verdict}): {rule}"
        )
        user = (f"Titulo: {f.title}\nSeveridad: {f.severity}\nVeredicto: {f.verdict}\n"
                f"Ubicacion: {f.location}{cwe_hint}\n\nEvidencia (salida real de herramientas):\n{f.evidence}")
    else:
        sys = (
            "You are a senior RE/exploitation analyst. Write a professional, concise analysis of "
            "this finding using ONLY the given evidence. Do not invent anything. Do not change "
            "severity or verdict. Use exactly these markdown sections:\n"
            "**Description:** ...\n**Impact:** ...\n**Exploitation path:** ...\n**Remediation:** ...\n"
            f"Verdict rule ({f.verdict}): {rule}"
        )
        user = (f"Title: {f.title}\nSeverity: {f.severity}\nVerdict: {f.verdict}\n"
                f"Location: {f.location}{cwe_hint}\n\nEvidence (real tool output):\n{f.evidence}")
    try:
        return llm.chat([Message("system", sys), Message("user", user)]).strip()
    except Exception:
        return ""


def executive_summary(llm, binary: str, findings: List[Finding], mitigations: str = "",
                      lang: str = "es", prior: str = "") -> str:
    if llm is None or not llm.available():
        return ""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    verified = sum(1 for f in findings if f.verdict == "verified")
    inventory = "\n".join(f"- [{f.severity}/{f.verdict}] {f.title} ({f.location})" for f in findings)

    # Add CWE/CVSS context if available
    cvss_summary = ""
    if findings:
        scores = [auto_cvss(f).score for f in findings]
        max_score = max(scores) if scores else 0.0
        cvss_summary = f"\nMax CVSS estimate: {max_score}/10"

    if lang == "es":
        crit = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        med = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        risk = "critico" if crit else ("alto" if high else ("medio" if med else "bajo"))
        sys = (
            "Eres un analista de seguridad. Redacta en espanol un RESUMEN EJECUTIVO profesional "
            "(3-5 frases) para un CISO, basado SOLO en los hallazgos y mitigaciones dados. "
            f"El riesgo global es {risk} (severidades: {crit} criticas, {high} altas, {med} medias, "
            f"{low} bajas; {verified} verificadas de {len(findings)}). NO contradigas estos numeros: "
            "no llames criticos a hallazgos medios/bajos, no digas prioridad alta si el riesgo es "
            "medio/bajo. Distingue lo verificado de lo grounded (pendiente). No inventes ni exageres."
        )
        pr = (f"\n\nHechos verificados y conocimiento de targets similares (evidencia real por "
              f"angr/debugger; usalos como base, no los contradigas):\n{prior}") if prior else ""
        user = (f"Binario: {binary}\nMitigaciones:\n{mitigations or '(desconocidas)'}{cvss_summary}\n\n"
                f"Hallazgos ({len(findings)}, {verified} verificados):\n{inventory}{pr}")
    else:
        sys = ("You are a security analyst. Write a professional EXECUTIVE SUMMARY (3-5 sentences) "
               "for a CISO based ONLY on the given findings and mitigations. Distinguish verified "
               "from merely grounded. Do not invent findings.")
        pr = (f"\n\nVerified facts and knowledge from similar targets (real angr/debugger "
              f"evidence; build on them, do not contradict):\n{prior}") if prior else ""
        user = (f"Binary: {binary}\nMitigations:\n{mitigations or '(unknown)'}{cvss_summary}\n\n"
                f"Findings ({len(findings)}, {verified} verified):\n{inventory}{pr}")
    try:
        return llm.chat([Message("system", sys), Message("user", user)]).strip()
    except Exception:
        return ""
