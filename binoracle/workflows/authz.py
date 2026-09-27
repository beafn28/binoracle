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
from ._binfacts import imported_names, callers_of

_EXEC = ("system", "popen", "execl", "execlp", "execvp", "execv", "execve", "execle")
_DROP = ("setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid", "seteuid", "setegid")
_FILEW = ("fopen", "open", "open64", "openat", "creat", "chmod", "chown")


def _unsafe_callers(reg, risky: list, drop: list) -> set:
    """Funciones que llaman a algo de `risky` (exec/fichero) sin llamar TAMBIEN a un `drop`
    (setuid/setgid/...) -- exige que el drop este ausente en la MISMA funcion, no solo en el
    binario entero. Sin esto, un binario con setuid() en una funcion 'safe_path()' que nunca se
    invoca desde el camino que hace exec() en 'vuln_path()' se consideraba seguro (falso negativo
    real, confirmado con un binario sintetico: setuid+printf en una funcion, execl SIN drop en
    otra). Si no se resuelven llamadores para `risky` (estatico/stripped/analisis no disponible),
    cae al heuristico global anterior (drop ausente en TODO el binario) para no perder cobertura."""
    fns_risky = set()
    for r in risky:
        fns_risky |= callers_of(reg, r)
    if not fns_risky:
        return {"?"} if (risky and not drop) else set()   # sin resolver: heuristico global
    fns_drop = set()
    for d in drop:
        fns_drop |= callers_of(reg, d)
    return fns_risky - fns_drop


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
    names = imported_names(reg)
    execs = [e for e in _EXEC if e in names]
    drops = [d for d in _DROP if d in names]
    findings: List[Finding] = []
    bit = "setuid" if suid else "setgid"

    # exige que el drop este AUSENTE en la MISMA funcion que hace exec, no solo en todo el binario
    # (ver _unsafe_callers): un setuid() en una funcion 'safe_path()' no invocada desde el camino
    # real que hace exec() no protege ese camino.
    unsafe_exec_fns = _unsafe_callers(reg, execs, drops) if execs else set()
    if unsafe_exec_fns:
        fn_ev = (", ".join(sorted(unsafe_exec_fns))[:80] if unsafe_exec_fns != {"?"} else
                 "(no resuelto por xrefs; heuristico global: ningun drop en todo el binario)")
        findings.append(_f(
            f"Binario {bit} ejecuta comandos sin soltar privilegios",
            f"{bit} binary executes commands without dropping privileges", "high",
            f"[stat + ii + axt]\nbit: {bit}\nejecucion: {', '.join(execs[:4])}\nfuncion(es) sin drop "
            f"de privilegios antes del exec: {fn_ev}",
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

    filew = [w for w in _FILEW if w in names]
    unsafe_filew_fns = _unsafe_callers(reg, filew, drops) if (not unsafe_exec_fns and filew) else set()
    if unsafe_filew_fns:
        fn_ev = (", ".join(sorted(unsafe_filew_fns))[:80] if unsafe_filew_fns != {"?"} else
                 "(no resuelto por xrefs; heuristico global: ningun drop en todo el binario)")
        findings.append(_f(
            f"Binario {bit} opera con ficheros sin soltar privilegios",
            f"{bit} binary handles files without dropping privileges", "medium",
            f"[stat + ii + axt]\nbit: {bit}\nficheros: {', '.join(filew)[:60]}\n"
            f"funcion(es) sin drop de privilegios: {fn_ev}",
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
