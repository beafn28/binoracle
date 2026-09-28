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
     re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
                r"secret[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?key|db[_-]?pass|"
                r"encryption[_-]?key|auth[_-]?pass)\b"
                r"\s*[=:]\s*[\"']?([^\s\"';,]{6,})", re.I),
     "high", "Asignacion de contrasena/clave/token con un valor literal.",
     "Password/key/token assignment with a literal value."),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{16,}\b"),
     "medium", "Cabecera Authorization Bearer con token embebido.",
     "Authorization Bearer header with an embedded token."),
    # --- proveedores concretos (prefijos de bajo falso-positivo) ---
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}\b"),
     "critical", "Clave secreta LIVE de Stripe hardcodeada.", "Hardcoded Stripe LIVE secret key."),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
     "high", "Clave de API de OpenAI (sk-...) hardcodeada.", "Hardcoded OpenAI API key (sk-...)."),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-]{20,}\b"),
     "high", "Clave de API de Anthropic (sk-ant-...) hardcodeada.", "Hardcoded Anthropic API key (sk-ant-...)."),
    ("GitLab token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
     "high", "Token de GitLab (glpat-...) hardcodeado.", "Hardcoded GitLab token (glpat-...)."),
    ("npm token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"),
     "high", "Token de npm (npm_...) hardcodeado.", "Hardcoded npm token (npm_...)."),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
     "high", "Clave de API de SendGrid (SG....) hardcodeada.", "Hardcoded SendGrid API key (SG....)."),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     "high", "Clave de API de Twilio (SK...) hardcodeada.", "Hardcoded Twilio API key (SK...)."),
    ("Mailgun key", re.compile(r"\bkey-[0-9a-f]{32}\b"),
     "high", "Clave de Mailgun (key-...) hardcodeada.", "Hardcoded Mailgun key (key-...)."),
    ("Azure storage key",
     re.compile(r"DefaultEndpointsProtocol=[^\s;]+;AccountName=[^\s;]+;AccountKey=[A-Za-z0-9+/=]{40,}", re.I),
     "critical", "Connection string de Azure Storage con AccountKey.",
     "Azure Storage connection string with AccountKey."),
    ("GCP service account",
     re.compile(r'"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[0-9a-f]{20,}"'),
     "critical", "Credenciales de service account de Google Cloud (JSON) embebidas.",
     "Embedded Google Cloud service account credentials (JSON)."),
    ("Discord bot token",
     re.compile(r"\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b"),
     "high", "Token de bot de Discord hardcodeado.", "Hardcoded Discord bot token."),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
     "high", "Token de bot de Telegram hardcodeado.", "Hardcoded Telegram bot token."),
    ("clave criptografica",
     re.compile(r"\b(?:aes|des|iv|key|secret)[_-]?(?:key|iv)?\s*[=:]\s*[\"']?([0-9a-fA-F]{32,64})[\"']?", re.I),
     "high", "Material de clave/IV criptografico en hex embebido (clave simetrica fija).",
     "Embedded cryptographic key/IV hex material (fixed symmetric key)."),
]

# Falsos positivos tipicos de asignaciones genericas (placeholders/nombres, no valores reales).
_FP = re.compile(r"^(?:none|null|nil|true|false|changeme|example|your[_-]?|<.*>|\$\{|%s|%d|xxx+|\.\.\.|test|dummy|placeholder)",
                 re.I)


def _mask(s: str, keep: int = 4) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return s[:keep] + "***"
    return s[:keep] + "***" + s[-keep:]


# columna 3 (vaddr) de la tabla de r2 'izz': "nth paddr vaddr len size section type string"
_IZZ_LINE = re.compile(r"^\s*\d+\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)")


def _line_vaddr(text: str, pos: int):
    """Vaddr (columna 3 de la tabla `izz`) de la linea de `text` que contiene la posicion `pos`.
    None si la linea no tiene el formato de tabla esperado (p.ej. cabecera)."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    line = text[line_start:(line_end if line_end != -1 else len(text))]
    m = _IZZ_LINE.match(line)
    return m.group(1) if m else None


def _used_in(reg: ToolRegistry, vaddr) -> List[str]:
    """Funciones que referencian esta direccion (r2 axt: cross-references TO). Grounded: solo
    reporta lo que r2 realmente encuentra, nunca inventa un 'usado en' generico. Vacio si no hay
    vaddr, no hay xrefs (string sin referenciar directamente -- p.ej. tabla de reubicacion,
    simbolos stripped) o la herramienta no esta disponible."""
    if not vaddr:
        return []
    xt = reg.get("r2_xrefs")
    if not xt:
        return []
    try:
        res = xt.run(target=vaddr)
    except Exception:
        return []
    if not res.ok:
        return []
    fns = []
    for line in (res.data or "").splitlines():
        parts = line.split()
        if parts and parts[0] and parts[0] not in ("(no", "no"):
            fns.append(parts[0])
    return sorted(set(fns))[:5]


def scan_secrets(reg: ToolRegistry, binary: str = "", lang: str = "es") -> List[Finding]:
    """Devuelve hallazgos por credenciales/secretos hallados en las strings del binario. Para cada
    coincidencia, ademas de la string, se busca via r2 (axt sobre el vaddr de esa linea de la
    tabla `izz`) que FUNCION la referencia -- location deja de ser el generico fijo "seccion de
    datos" y pasa a decir donde se usa realmente, cuando r2 puede determinarlo."""
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
            vaddr = _line_vaddr(text, m.start())
            used_in = _used_in(reg, vaddr)
            if used_in:
                location = (f"usado en: {', '.join(used_in)}" if lang == "es"
                           else f"used in: {', '.join(used_in)}")
                usage_note = ((f" Referenciada desde {', '.join(used_in)} (r2 axt): esta es la "
                              f"funcion que lee/compara este valor, no una suposicion.") if lang == "es"
                              else (f" Referenced from {', '.join(used_in)} (r2 axt): this is the "
                                    f"function that reads/compares this value, not a guess."))
            else:
                location = ("seccion de datos (.rodata/.data), sin xref directo encontrado" if lang == "es"
                           else "data section (.rodata/.data), no direct xref found")
                usage_note = ((" No se encontro una funcion que referencie esta direccion "
                              "directamente (r2 axt): puede estar en una tabla, referenciada "
                              "indirectamente, o el binario tiene simbolos eliminados.") if lang == "es"
                              else (" No function directly referencing this address was found "
                                    "(r2 axt): it may be in a table, referenced indirectly, or the "
                                    "binary has stripped symbols."))
            # enmascara el valor sensible en el titulo, pero deja la string cruda en la evidencia.
            findings.append(Finding(
                title=(f"Posible {name} hardcodeada" if lang == "es" else f"Possible hardcoded {name}"),
                severity=sev,
                verdict="grounded",     # string presente; que sea explotable lo confirma el analista
                evidence=f"[radare2: izz + axt]\n{snippet}",
                location=location,
                rationale=(des_es + " Extraido de las strings del binario; confirma si es un valor "
                           "real y si esta en uso." + usage_note) if lang == "es"
                          else (des_en + " Extracted from the binary strings; confirm it is a real "
                                "value and whether it is used." + usage_note),
                recommendation=("No embebas secretos en el binario: usa variables de entorno, un "
                                "gestor de secretos o KMS, y rota el secreto expuesto.") if lang == "es"
                               else ("Do not embed secrets in the binary: use environment variables, "
                                     "a secrets manager or KMS, and rotate the exposed secret."),
                rationale_en=(des_en + " Extracted from the binary strings; confirm it is a real value "
                              "and whether it is used." + usage_note),
                recommendation_en=("Do not embed secrets in the binary: use environment variables, a "
                                   "secrets manager or KMS, and rotate the exposed secret."),
            ))
            if len(findings) >= 40:
                return findings
    return findings
