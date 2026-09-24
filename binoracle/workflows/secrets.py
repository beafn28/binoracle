"""Deteccion de credenciales y secretos hardcodeados en el binario.

Escanea las strings (r2 izz) buscando claves privadas, API keys, tokens, contrasenas y
connection strings con credenciales. Produce hallazgos grounded (la string exacta es la
evidencia). Patrones curados para minimizar falsos positivos; aun asi, se reporta como
'posible' y con la string a la vista para que el analista confirme.
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding

# (nombre, regex, severidad, descripcion ES, descripcion EN)
_PATTERNS = [
    ("Clave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "critical", "Clave privada embebida en el binario.", "Private key embedded in the binary."),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "high", "Clave de acceso AWS (AKIA...) hardcodeada.", "Hardcoded AWS access key (AKIA...)."),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "high", "Clave de API de Google (AIza...) hardcodeada.", "Hardcoded Google API key (AIza...)."),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
     "high", "Token de GitHub (ghp_/gho_...) hardcodeado.", "Hardcoded GitHub token (ghp_/gho_...)."),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     "high", "Token de Slack (xox...) hardcodeado.", "Hardcoded Slack token (xox...)."),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b"),
     "medium", "JSON Web Token (eyJ...) embebido: puede contener claims/sesion.",
     "Embedded JSON Web Token (eyJ...): may carry claims/session."),
    ("Connection string con credenciales",
     re.compile(r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ftp|https?)://[^\s:/@]+:[^\s:/@]+@", re.I),
     "high", "URL/connection string con usuario:password embebidos.",
     "URL/connection string with embedded user:password."),
    ("credencial en asignacion",
     re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\b"
                r"\s*[=:]\s*[\"']?([^\s\"';,]{6,})", re.I),
     "high", "Asignacion de contrasena/clave/token con un valor literal.",
     "Password/key/token assignment with a literal value."),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{16,}\b"),
     "medium", "Cabecera Authorization Bearer con token embebido.",
     "Authorization Bearer header with an embedded token."),
]

# Falsos positivos tipicos de asignaciones genericas (placeholders/nombres, no valores reales).
_FP = re.compile(r"^(?:none|null|nil|true|false|changeme|example|your[_-]?|<.*>|\$\{|%s|%d|xxx+|\.\.\.|test|dummy|placeholder)",
                 re.I)


def _mask(s: str, keep: int = 4) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return s[:keep] + "***"
    return s[:keep] + "***" + s[-keep:]


def scan_secrets(reg: ToolRegistry, binary: str = "", lang: str = "es") -> List[Finding]:
    """Devuelve hallazgos por credenciales/secretos hallados en las strings del binario."""
    st = reg.get("r2_strings")
    if not st:
        return []
    res = st.run()
    if not res.ok:
        return []
    text = res.data or ""
    findings: List[Finding] = []
    seen = set()
    for name, rx, sev, des_es, des_en in _PATTERNS:
        for m in rx.finditer(text):
            frag = m.group(0)
            # para asignaciones genericas, el valor esta en el grupo 1: filtra placeholders.
            val = m.group(1) if rx.groups and m.lastindex else frag
            if _FP.match((val or "").strip().strip("\"'")):
                continue
            key = (name, frag[:60])
            if key in seen:
                continue
            seen.add(key)
            snippet = frag if len(frag) < 120 else frag[:117] + "..."
            # enmascara el valor sensible en el titulo, pero deja la string cruda en la evidencia.
            findings.append(Finding(
                title=(f"Posible {name} hardcodeada" if lang == "es" else f"Possible hardcoded {name}"),
                severity=sev,
                verdict="grounded",     # string presente; que sea explotable lo confirma el analista
                evidence=f"[radare2: izz]\n{snippet}",
                location="seccion de datos (.rodata/.data)",
                rationale=(des_es + " Extraido de las strings del binario; confirma si es un valor "
                           "real y si esta en uso.") if lang == "es"
                          else (des_en + " Extracted from the binary strings; confirm it is a real "
                                "value and whether it is used."),
                recommendation=("No embebas secretos en el binario: usa variables de entorno, un "
                                "gestor de secretos o KMS, y rota el secreto expuesto.") if lang == "es"
                               else ("Do not embed secrets in the binary: use environment variables, "
                                     "a secrets manager or KMS, and rotate the exposed secret."),
                rationale_en=(des_en + " Extracted from the binary strings; confirm it is a real value "
                              "and whether it is used."),
                recommendation_en=("Do not embed secrets in the binary: use environment variables, a "
                                   "secrets manager or KMS, and rotate the exposed secret."),
            ))
            if len(findings) >= 40:
                return findings
    return findings
