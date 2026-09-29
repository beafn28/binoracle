"""Proteccion insuficiente de ficheros y permisos.

Cubre (a) los permisos del PROPIO binario (SUID/SGID/escribible por todos: superficie de
escalada), (b) funciones de manejo de ficheros inseguras que delatan como el binario CREA o
DESPLIEGA ficheros en runtime (temporales predecibles, escritura en /tmp, cambios de permisos
laxos, TOCTOU). Grounded: se apoya en stat del fichero, los imports (r2 ii) y las strings.
"""
from __future__ import annotations

import os
import stat as _stat
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding
from ._binfacts import shares_caller

# import peligroso -> (severidad, ES, EN)
_BAD_IMPORTS = {
    "tmpnam":  ("high", "Genera un nombre de temporal PREDECIBLE: race/symlink attack.",
                        "Generates a PREDICTABLE temp name: race/symlink attack."),
    "tempnam": ("high", "Nombre de temporal predecible (deprecado): race/symlink.",
                        "Predictable temp name (deprecated): race/symlink."),
    "mktemp":  ("high", "mktemp da un nombre predecible sin crear el fichero: race/symlink.",
                        "mktemp yields a predictable name without creating the file: race/symlink."),
    "chmod":   ("medium", "Cambia permisos de un fichero: si pone 0777/0666 lo deja escribible por todos.",
                          "Changes file permissions: 0777/0666 leaves it world-writable."),
    "fchmod":  ("medium", "Cambia permisos por descriptor: posible fichero escribible por todos.",
                          "Changes permissions by fd: possible world-writable file."),
    "chown":   ("low", "Cambia el propietario de un fichero: revisa si es explotable.",
                       "Changes file owner: check for abuse."),
    "access":  ("low", "access() antes de open() es un TOCTOU clasico (se cambia el fichero en medio).",
                       "access() before open() is a classic TOCTOU (file swapped in between)."),
    "system":  (None, "", ""),   # ya cubierto por vulnhunt; se ignora aqui
}
# funciones que CREAN/ESCRIBEN ficheros (la parte dinamica: el binario despliega un fichero)
_WRITE_FUNCS = ("creat", "fopen", "open64", "openat", "mkstemp", "tmpfile", "fwrite", "write")


def _imports_text(reg: ToolRegistry) -> str:
    t = reg.get("r2_imports")
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def _strings_text(reg: ToolRegistry) -> str:
    t = reg.get("r2_strings")
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def _f(title_es, title_en, sev, ev, rat_es, rat_en, rec_es, rec_en, lang):
    return Finding(
        title=title_es if lang == "es" else title_en,
        severity=sev, verdict="grounded", evidence=ev,
        location="binario / operaciones de fichero",
        rationale=rat_es if lang == "es" else rat_en,
        recommendation=rec_es if lang == "es" else rec_en,
        rationale_en=rat_en, recommendation_en=rec_en,
    )


def scan_file_perms(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []

    # (a) permisos del propio binario: SUID/SGID/escribible por todos
    try:
        mode = os.stat(binary).st_mode
        if mode & _stat.S_ISUID or mode & _stat.S_ISGID:
            bit = "setuid" if mode & _stat.S_ISUID else "setgid"
            findings.append(_f(
                f"Binario con bit {bit} (superficie de escalada)",
                f"Binary with {bit} bit (privilege escalation surface)", "high",
                f"[stat]\nmodo: {oct(mode & 0o7777)}  ({bit} activo)",
                f"El binario corre con privilegios elevados ({bit}). Cualquier vulnerabilidad de "
                "memoria o inyeccion aqui da escalada de privilegios (root).",
                f"The binary runs with elevated privileges ({bit}). Any memory or injection bug "
                "here yields privilege escalation (root).",
                "Elimina el bit setuid/setgid si no es imprescindible; si lo es, minimiza el "
                "codigo privilegiado (drop de privilegios cuanto antes).",
                "Remove the setuid/setgid bit unless strictly needed; if needed, minimize the "
                "privileged code (drop privileges as early as possible).", lang))
        if mode & _stat.S_IWOTH:
            findings.append(_f(
                "Binario escribible por todos", "World-writable binary", "high",
                f"[stat]\nmodo: {oct(mode & 0o7777)}  (escribible por 'otros')",
                "El binario es escribible por cualquier usuario: puede ser sustituido por uno "
                "malicioso (backdoor).",
                "The binary is writable by any user: it can be replaced by a malicious one.",
                "Corrige los permisos (p.ej. chmod 755) y revisa el propietario.",
                "Fix the permissions (e.g. chmod 755) and review ownership.", lang))
    except OSError:
        pass

    imports = _imports_text(reg)
    low_imp = imports.lower()
    for name, (sev, des_es, des_en) in _BAD_IMPORTS.items():
        if sev is None:
            continue
        if name in low_imp:
            findings.append(_f(
                f"Manejo inseguro de ficheros: '{name}'",
                f"Insecure file handling: '{name}'", sev,
                f"[radare2: ii]\nimport: {name}",
                des_es + " Detectado como import del binario.",
                des_en + " Detected as a binary import.",
                "Usa APIs seguras: mkstemp(3) con O_EXCL para temporales, permisos minimos "
                "(0600), y evita access()+open() (usa open() y comprueba el resultado).",
                "Use safe APIs: mkstemp(3) with O_EXCL for temp files, least-privilege modes "
                "(0600), and avoid access()+open() (open() and check the result).", lang))

    # (b) parte dinamica: el binario CREA/DESPLIEGA un fichero (write func) en una ruta insegura
    strings = _strings_text(reg)
    tmp_paths = sorted(set(_re_tmp(strings)))[:6]
    writes = any(w in low_imp for w in _WRITE_FUNCS)
    if tmp_paths and writes:
        findings.append(_f(
            "Despliegue de fichero en ruta temporal insegura",
            "File deployment to an insecure temp path", "medium",
            "[radare2: izz + ii]\nrutas: " + ", ".join(tmp_paths) +
            "\n(el binario importa funciones de escritura de ficheros)",
            "El binario escribe/despliega ficheros en rutas de /tmp hardcodeadas. En un directorio "
            "compartido y escribible es susceptible de race/symlink (un atacante prepara el fichero "
            "o un symlink antes).",
            "The binary writes/deploys files to hardcoded /tmp paths. In a shared world-writable "
            "directory this is prone to race/symlink attacks (an attacker pre-creates the file or "
            "a symlink).",
            "Crea los temporales con mkstemp(3) (nombre impredecible + O_EXCL) y permisos 0600; no "
            "uses rutas /tmp fijas ni sigas symlinks (O_NOFOLLOW).",
            "Create temp files with mkstemp(3) (unpredictable name + O_EXCL) and 0600 perms; do not "
            "use fixed /tmp paths and do not follow symlinks (O_NOFOLLOW).", lang))

    # (c) RPATH/RUNPATH inseguro -> secuestro de libreria (carga un .so desde ruta controlable)
    for tag, rp in _rpaths(binary):
        insecure = [p for p in rp.split(":") if p and (not p.startswith("/") or p.startswith("."))]
        if insecure:
            findings.append(_f(
                f"{tag} inseguro (secuestro de libreria)", f"Insecure {tag} (library hijacking)", "high",
                f"[dynamic]\n{tag}: {rp}",
                f"El {tag} incluye rutas relativas/no absolutas ({', '.join(insecure)}): el loader "
                "puede cargar una libreria maliciosa desde un directorio que controle el atacante.",
                f"The {tag} includes relative/non-absolute paths ({', '.join(insecure)}): the loader "
                "may load a malicious library from an attacker-controlled directory.",
                "Usa rutas absolutas y de confianza en RPATH/RUNPATH (o elimínalos); no uses rutas "
                "relativas ni directorios escribibles.",
                "Use absolute, trusted RPATH/RUNPATH paths (or drop them); no relative paths or "
                "writable directories.", lang))

    # (d) inyeccion por entorno: getenv cuyo valor llega a system/exec, EN LA MISMA FUNCION. Sin este
    # requisito, un getenv("LANG")/getenv("TERM") normal (elegir idioma, terminal...) en una funcion
    # y un system() de comando FIJO en otra, sin relacion, disparaba un falso positivo -- confirmado
    # con un binario sintetico (getenv para saludo, system("tar ...") en un helper de backup aparte).
    execs_d = [x for x in ("system", "popen", "execl", "execlp", "execvp") if x in low_imp]
    if "getenv" in low_imp and execs_d and shares_caller(reg, ["getenv"], execs_d, binary):
        findings.append(_f(
            "Posible inyeccion de comando via variable de entorno",
            "Possible command injection via environment variable", "medium",
            "[radare2: ii]\ngetenv + system/exec",
            "El binario lee variables de entorno (getenv) y ejecuta comandos (system/exec): si el "
            "valor del entorno llega al comando sin sanear, es inyeccion (especialmente peligroso "
            "si el binario es SUID).",
            "The binary reads environment variables (getenv) and executes commands (system/exec): "
            "if the env value reaches the command unsanitized, it is injection (especially "
            "dangerous if the binary is SUID).",
            "No pases entrada del entorno a system/exec; usa execve con argv fijo y una lista de "
            "argumentos, valida/escapa, y limpia el entorno en binarios privilegiados.",
            "Do not pass environment input to system/exec; use execve with a fixed argv list, "
            "validate/escape, and sanitize the environment in privileged binaries.", lang))
    return findings


def _rpaths(binary: str):
    """Devuelve [(RPATH|RUNPATH, valor)] leidos del .dynamic con pyelftools (best-effort)."""
    out = []
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        with open(binary, "rb") as fh:
            elf = ELFFile(fh)
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_RPATH":
                            out.append(("RPATH", tag.rpath))
                        elif tag.entry.d_tag == "DT_RUNPATH":
                            out.append(("RUNPATH", tag.runpath))
    except Exception:
        pass
    return out


def _re_tmp(text: str):
    import re
    return re.findall(r"(/(?:var/)?tmp/[\w.\-/]+)", text or "")
