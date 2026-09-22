"""AI enrichment layer: professional, complete analysis on top of grounded findings.

The LLM writes the human-facing analysis (description, impact, exploitation path,
remediation) and an executive summary, in the configured language. It is constrained: it
may NOT change the code-assigned verdict or severity, and it may NOT claim exploitability
beyond what the verdict allows. Evidence stays the raw tool output. This adds
professionalism and depth without introducing false positives."""
from __future__ import annotations

from typing import List, Optional

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


def enrich_findings(llm, findings: List[Finding], lang: str = "es", store=None) -> List[Finding]:
    if llm is None or not llm.available():
        return findings
    for f in findings:
        analysis = _analyze_one(llm, f, lang)
        if analysis:
            # replace the human-facing rationale with the professional version;
            # keep the raw evidence untouched.
            f.rationale = analysis
    return findings


def _analyze_one(llm, f: Finding, lang: str) -> str:
    rule = _VERDICT_RULE.get(lang, _VERDICT_RULE["es"]).get(f.verdict, "")
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
                f"Ubicacion: {f.location}\n\nEvidencia (salida real de herramientas):\n{f.evidence}")
    else:
        sys = (
            "You are a senior RE/exploitation analyst. Write a professional, concise analysis of "
            "this finding using ONLY the given evidence. Do not invent anything. Do not change "
            "severity or verdict. Use exactly these markdown sections:\n"
            "**Description:** ...\n**Impact:** ...\n**Exploitation path:** ...\n**Remediation:** ...\n"
            f"Verdict rule ({f.verdict}): {rule}"
        )
        user = (f"Title: {f.title}\nSeverity: {f.severity}\nVerdict: {f.verdict}\n"
                f"Location: {f.location}\n\nEvidence (real tool output):\n{f.evidence}")
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
        user = (f"Binario: {binary}\nMitigaciones:\n{mitigations or '(desconocidas)'}\n\n"
                f"Hallazgos ({len(findings)}, {verified} verificados):\n{inventory}{pr}")
    else:
        sys = ("You are a security analyst. Write a professional EXECUTIVE SUMMARY (3-5 sentences) "
               "for a CISO based ONLY on the given findings and mitigations. Distinguish verified "
               "from merely grounded. Do not invent findings.")
        pr = (f"\n\nVerified facts and knowledge from similar targets (real angr/debugger "
              f"evidence; build on them, do not contradict):\n{prior}") if prior else ""
        user = (f"Binary: {binary}\nMitigations:\n{mitigations or '(unknown)'}\n\n"
                f"Findings ({len(findings)}, {verified} verified):\n{inventory}{pr}")
    try:
        return llm.chat([Message("system", sys), Message("user", user)]).strip()
    except Exception:
        return ""
