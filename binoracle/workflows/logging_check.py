"""OWASP DA10 - Registro y monitorizacion insuficientes.

Para un binario SENSIBLE (privilegiado: SUID/SGID, o de red: socket/bind/connect), comprueba si usa
alguna API de registro/auditoria (syslog/openlog, journald, o escribe a un log). Si NO hay ninguna,
lo senala como registro insuficiente: acciones privilegiadas o de red sin traza dificultan detectar
un abuso. Grounded en imports (r2 ii) + stat del binario. Conservador: NO se dispara en binarios no
sensibles (para no inflar el informe con ruido).
"""
from __future__ import annotations

import os
import stat as _stat
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding

_LOG_APIS = ("syslog", "openlog", "vsyslog", "__syslog", "sd_journal", "audit_log", "log_write")
_NET = ("socket", "bind", "listen", "accept", "connect", "recv", "send")


def _imports(reg: ToolRegistry) -> str:
    t = reg.get("r2_imports")
    if t:
        r = t.run()
        if r.ok:
            return (r.data or "").lower()
    return ""


def scan_logging(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    imports = _imports(reg)
    es = lang == "es"
    # sensibilidad del binario: privilegiado o de red
    suid = False
    try:
        mode = os.stat(binary).st_mode
        suid = bool(mode & _stat.S_ISUID or mode & _stat.S_ISGID)
    except OSError:
        pass
    from ._binfacts import has_network
    net = has_network(reg)          # imports de red REALES (no la columna 'bind' de la cabecera de ii)
    if not (suid or net):
        return []                      # no sensible: no se evalua logging (se marcaria como N/A)
    has_log = any(a in imports for a in _LOG_APIS)
    if has_log:
        return []                      # tiene logging: sin hallazgo (categoria revisada)
    razon = ("privilegiado (SUID/SGID)" if suid else "") + (" y de red" if suid and net else
             ("de red" if net else ""))
    razon_en = ("privileged (SUID/SGID)" if suid else "") + (" and network" if suid and net else
                ("network" if net else ""))
    return [Finding(
        title=("Registro/auditoria insuficiente en binario sensible"
               if es else "Insufficient logging/auditing in a sensitive binary"),
        severity="low", verdict="grounded", location="logging / auditoria",
        evidence="[radare2: ii + stat]\n" + ("SUID/SGID; " if suid else "")
                 + ("usa red; " if net else "") + "sin APIs de logging (syslog/openlog/journald)",
        rationale=(f"El binario es {razon} pero no usa ninguna API de registro/auditoria. Las acciones "
                   "privilegiadas o de red sin traza dificultan detectar y reconstruir un abuso "
                   "(accesos, fallos de auth, comandos)." if es else
                   f"The binary is {razon_en} but uses no logging/auditing API. Privileged or network "
                   "actions without a trail make it hard to detect and reconstruct abuse (accesses, "
                   "auth failures, commands)."),
        rationale_en=(f"The binary is {razon_en} but uses no logging/auditing API; privileged/network "
                      "actions leave no trail."),
        recommendation=("Registra los eventos de seguridad (autenticacion, acciones privilegiadas, "
                        "conexiones) via syslog/journald, con suficiente detalle y sin datos sensibles."
                        if es else
                        "Log security events (authentication, privileged actions, connections) via "
                        "syslog/journald, with enough detail and without sensitive data."),
        recommendation_en=("Log security events via syslog/journald with enough detail."))]
