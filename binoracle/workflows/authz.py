"""OWASP DA5 - Autorizacion incorrecta (escalada de privilegios en binarios privilegiados).

El caso fuerte y detectable estaticamente: un binario SUID/SGID que EJECUTA comandos o un shell
(system/exec/popen) pero NO suelta privilegios (no llama a setuid/setgid/setresuid antes). Cualquier
via de ejecucion en el corre entonces como el propietario (root) -> escalada. Tambien: SUID que abre
o escribe ficheros por ruta controlable sin bajar privilegios.

Grounded en stat del binario (bit SUID/SGID) + imports (exec vs drop de privilegios). Complementa
fileperms (que marca el bit SUID) centrandose en el USO privilegiado sin drop.
"""
from __future__ import annotations

import os
import stat as _stat
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding

_EXEC = ("system", "popen", "execl", "execlp", "execvp", "execv", "execve", "execle")
_DROP = ("setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid", "seteuid", "setegid")
_FILEW = ("fopen", "open", "open64", "openat", "creat", "chmod", "chown")


def _imp(reg):
    t = reg.get("r2_imports"); r = t.run() if t else None
    return (r.data or "").lower() if r and r.ok else ""


def _f(t_es, t_en, sev, ev, r_es, r_en, rec_es, rec_en, lang):
    return Finding(title=t_es if lang == "es" else t_en, severity=sev, verdict="grounded",
                   evidence=ev, location="autorizacion / privilegios",
                   rationale=r_es if lang == "es" else r_en,
                   recommendation=rec_es if lang == "es" else rec_en,
                   rationale_en=r_en, recommendation_en=rec_en)


def scan_authz(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    es = lang == "es"
    try:
        mode = os.stat(binary).st_mode
        suid = bool(mode & _stat.S_ISUID)
        sgid = bool(mode & _stat.S_ISGID)
    except OSError:
        return []
    if not (suid or sgid):
        return []                          # solo aplica a binarios privilegiados
    imports = _imp(reg)
    execs = [e for e in _EXEC if e in imports]
    drops = [d for d in _DROP if d in imports]
    findings: List[Finding] = []
    bit = "setuid" if suid else "setgid"

    if execs and not drops:
        findings.append(_f(
            f"Binario {bit} ejecuta comandos sin soltar privilegios",
            f"{bit} binary executes commands without dropping privileges", "high",
            f"[stat + ii]\nbit: {bit}\nejecucion: {', '.join(execs[:4])}\nsin drop de privilegios "
            "(setuid/setgid/setresuid)",
            f"El binario tiene el bit {bit} (corre como su propietario, tipicamente root) y ejecuta "
            "comandos/shell, pero no baja privilegios antes. Cualquier via de ejecucion (inyeccion, "
            "PATH, argumentos) corre como root: escalada de privilegios directa." if es else
            f"The binary has the {bit} bit (runs as its owner, typically root) and executes "
            "commands/shell but does not drop privileges first. Any execution path (injection, PATH, "
            "arguments) runs as root: direct privilege escalation.",
            f"A {bit} binary executes commands without dropping privileges: privilege escalation.",
            "Suelta privilegios lo antes posible (setresuid/setresgid al uid real) ANTES de ejecutar "
            "nada; mejor, no ejecutes comandos externos en un binario privilegiado." if es else
            "Drop privileges as early as possible (setresuid/setresgid to the real uid) BEFORE running "
            "anything; better, do not execute external commands in a privileged binary.",
            "Drop privileges (setresuid/setresgid) before executing anything; avoid external commands.",
            lang))

    if not execs and not drops and any(w in imports for w in _FILEW):
        findings.append(_f(
            f"Binario {bit} opera con ficheros sin soltar privilegios",
            f"{bit} binary handles files without dropping privileges", "medium",
            f"[stat + ii]\nbit: {bit}\nficheros: {', '.join(w for w in _FILEW if w in imports)[:60]}\n"
            "sin drop de privilegios",
            f"El binario {bit} abre/escribe/cambia permisos de ficheros con privilegios elevados y no "
            "los suelta. Si la ruta es controlable, permite leer/escribir ficheros como root (p.ej. "
            "sobrescribir /etc/passwd) -> escalada." if es else
            f"The {bit} binary opens/writes/chmods files with elevated privileges without dropping "
            "them. If the path is controllable, it can read/write files as root (e.g. overwrite "
            "/etc/passwd) -> escalation.",
            f"A {bit} binary handles files without dropping privileges; path-controlled read/write as root.",
            "Baja privilegios antes de tocar ficheros por ruta controlable; valida las rutas y usa "
            "O_NOFOLLOW; abre con el uid real." if es else
            "Drop privileges before touching path-controlled files; validate paths and use O_NOFOLLOW; "
            "open with the real uid.",
            "Drop privileges before file operations; validate paths and use O_NOFOLLOW.",
            lang))
    return findings
