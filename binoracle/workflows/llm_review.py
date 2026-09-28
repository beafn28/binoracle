"""Revision LLM completa del binario ("sin fronteras", pedido explicito del usuario): a diferencia
de enrich_findings() (redacta cada hallazgo YA encontrado) o executive_summary() (resume), este
paso le da al modelo local TODO el contexto grounded reunido hasta el momento -- mitigaciones,
mapa de capacidades, hallazgos ya encontrados por los scanners estaticos, y el codigo decompilado
-- y le pide que busque patrones que esos scanners (regex/xref, deterministas pero limitados a lo
que se les ocurrio buscar a mano) NO puedan detectar: logica de negocio sospechosa, combinaciones
de APIs peligrosas no evidentes por patron fijo, inconsistencias.

Honesto sobre su naturaleza: las sugerencias de este paso son HIPOTESIS del modelo, no hechos
probados por un oraculo determinista -- se marcan verdict="unverified" SIEMPRE (nunca "grounded"
ni "verified"), y el titulo deja explicito que vienen de una revision LLM. El prompt exige citar
solo lo que esta en el contexto dado (nunca inventar direcciones/funciones que no aparezcan ahi) y
responder "NADA"/"NOTHING" si no hay nada nuevo real que anadir -- evita rellenar el informe con
ruido solo por rellenar.
"""
from __future__ import annotations

import re
from typing import List

from ..llm.base import Message
from ..store.session import Finding

_SEV_WORDS = {"critical", "high", "medium", "low"}


def _build_context(mit: dict, capability_map: dict, findings: List[Finding], decompiled, lang: str) -> str:
    es = lang == "es"
    parts = []
    if mit:
        parts.append(("Mitigaciones:\n" if es else "Mitigations:\n")
                     + "\n".join(f"- {k}: {v}" for k, v in mit.items() if v is not None))
    if capability_map:
        parts.append(("Mapa de capacidades (imports):\n" if es else "Capability map (imports):\n")
                     + "\n".join(f"- {k}: {', '.join(v[:15])}" for k, v in capability_map.items()))
    if findings:
        parts.append((f"Hallazgos ya encontrados por scanners estaticos ({len(findings)}):\n" if es else
                      f"Findings already found by static scanners ({len(findings)}):\n")
                     + "\n".join(f"- [{f.severity}/{f.verdict}] {f.title} ({f.location})" for f in findings[:30]))
    if decompiled:
        for d in decompiled[:3]:
            code = (getattr(d, "annotated", "") or getattr(d, "raw", "") or "")[:4000]
            if code.strip():
                fn = getattr(d, "func", "?")
                parts.append((f"Codigo decompilado de {fn}:\n" if es else f"Decompiled code of {fn}:\n")
                             + f"```\n{code}\n```")
    return "\n\n".join(parts)


def llm_deep_review(llm, binary: str, mit: dict, capability_map: dict, findings: List[Finding],
                    decompiled, lang: str = "es") -> List[Finding]:
    """Hallazgos ADICIONALES sugeridos por el modelo sobre TODO el contexto grounded reunido
    (verdict='unverified' siempre -- hipotesis, no hecho probado). [] si no hay modelo disponible,
    no hay contexto suficiente, o el modelo no encuentra nada nuevo real (responde NADA/NOTHING)."""
    if llm is None or not getattr(llm, "available", lambda: False)():
        return []
    context = _build_context(mit, capability_map, findings, decompiled, lang)
    if not context.strip():
        return []
    es = lang == "es"
    if es:
        sys = (
            "Eres un auditor de seguridad senior revisando un binario. Se te da TODO el contexto "
            "grounded reunido hasta ahora (mitigaciones, capacidades, hallazgos ya encontrados por "
            "scanners automaticos, y codigo decompilado). Tu trabajo es buscar SOLO lo que esos "
            "scanners automaticos NO puedan detectar: logica de negocio sospechosa, combinaciones "
            "de APIs peligrosas no evidentes por regex, o inconsistencias entre lo que dice el "
            "codigo y las mitigaciones/capacidades. NO repitas hallazgos ya listados arriba. Si no "
            "encuentras nada nuevo y real, responde EXACTAMENTE la palabra NADA y nada mas. Si "
            "encuentras algo, para CADA hallazgo nuevo escribe un bloque asi (puede haber varios):\n"
            "### <titulo corto>\nSeveridad: <critical|high|medium|low>\n<explicacion de 2-4 frases, "
            "citando SOLO lo que esta en el contexto dado, sin inventar direcciones, funciones ni "
            "comportamiento que no aparezcan ahi>\n"
            "No inventes nada que no este en el contexto dado. Si tienes dudas, no lo reportes.")
        user = context[:12000]
    else:
        sys = (
            "You are a senior security auditor reviewing a binary. You are given ALL the grounded "
            "context gathered so far (mitigations, capabilities, findings already found by "
            "automated scanners, and decompiled code). Your job is to look ONLY for what those "
            "automated scanners CANNOT detect: suspicious business logic, dangerous API "
            "combinations not obvious via regex, or inconsistencies between what the code shows "
            "and the mitigations/capabilities. Do NOT repeat findings already listed above. If you "
            "find nothing new and real, answer EXACTLY the word NOTHING and nothing else. If you "
            "find something, for EACH new finding write a block like this (there may be several):\n"
            "### <short title>\nSeverity: <critical|high|medium|low>\n<2-4 sentence explanation, "
            "citing ONLY what is in the given context, without inventing addresses, functions or "
            "behavior not present there>\n"
            "Do not invent anything not in the given context. If unsure, do not report it.")
        user = context[:12000]
    try:
        resp = llm.chat([Message("system", sys), Message("user", user)])
    except Exception:
        return []
    return _parse_review(resp or "", lang)


def _parse_review(text: str, lang: str) -> List[Finding]:
    stripped = (text or "").strip()
    if not stripped or stripped.strip("*_. \n").upper() in ("NADA", "NOTHING", "NONE"):
        return []
    blocks = re.split(r"^###\s+", text, flags=re.M)[1:]
    es = lang == "es"
    out = []
    for b in blocks:
        lines = b.strip().splitlines()
        if not lines:
            continue
        title = lines[0].strip()
        rest = "\n".join(lines[1:]).strip()
        m = re.search(r"(?:Severidad|Severity)\s*:\s*(\w+)", rest, re.I)
        sev = (m.group(1).lower() if m else "low")
        if sev not in _SEV_WORDS:
            sev = "low"
        expl = re.sub(r"(?:Severidad|Severity)\s*:\s*\w+\s*", "", rest, flags=re.I).strip()
        if not title or not expl:
            continue
        out.append(Finding(
            title=(f"[Revision LLM] {title}" if es else f"[LLM review] {title}"),
            severity=sev, verdict="unverified",
            evidence=(("[revision LLM sobre contexto grounded, no verificado automaticamente]\n" if es
                      else "[LLM review over grounded context, not automatically verified]\n") + expl),
            location=("revision LLM" if es else "LLM review"),
            rationale=expl,
            recommendation=("Confirma manualmente antes de actuar: es una hipotesis del modelo, no "
                            "un hecho probado por un oraculo determinista." if es else
                            "Confirm manually before acting: this is a model hypothesis, not a fact "
                            "proven by a deterministic oracle."),
        ))
        if len(out) >= 8:
            break
    return out
