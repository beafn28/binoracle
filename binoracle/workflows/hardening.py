"""OWASP DA6 - Configuracion de seguridad insuficiente (endurecimiento del binario y del runtime).

Cubre las casuisticas de misconfig detectables estaticamente que no ven otros scanners:
- ENDURECIMIENTO insuficiente del binario: protecciones de compilacion desactivadas (NX/stack no
  ejecutable, PIE/ASLR, RELRO, stack canary). Se consolida en UN hallazgo con lo que falta y su
  impacto. Grounded en checksec (r2).
- Manipulacion insegura del ENTORNO: setenv/putenv junto a LD_PRELOAD / LD_LIBRARY_PATH -> el
  binario altera la busqueda de librerias, riesgo de secuestro (sobre todo si es SUID).
- Ejecucion por PATH (relativa): system/popen con un comando SIN ruta absoluta -> PATH hijacking.

Complementa fileperms (SUID/RPATH), commsec (cripto/cert) y backdoors. No duplica: aqui va la
CONFIGURACION de build/runtime.
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding
from ._binfacts import string_values


def _checksec(reg: ToolRegistry) -> dict:
    t = reg.get("r2_checksec")
    if not t:
        return {}
    r = t.run()
    return r.meta if (r and r.ok) else {}


def _imports(reg: ToolRegistry) -> str:
    t = reg.get("r2_imports")
    if t:
        r = t.run()
        if r.ok:
            return (r.data or "").lower()
    return ""


def _strings(reg: ToolRegistry) -> str:
    t = reg.get("r2_strings")
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def _off(v) -> bool:
    return str(v).lower() in ("false", "no", "0", "off", "none", "nx_off")


def _f(title_es, title_en, sev, ev, rat_es, rat_en, rec_es, rec_en, lang, loc):
    return Finding(title=title_es if lang == "es" else title_en, severity=sev, verdict="grounded",
                   evidence=ev, location=loc, rationale=rat_es if lang == "es" else rat_en,
                   recommendation=rec_es if lang == "es" else rec_en,
                   rationale_en=rat_en, recommendation_en=rec_en)


def scan_hardening(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    es = lang == "es"
    m = _checksec(reg)
    # (a) endurecimiento insuficiente del binario
    weak = []
    impact = []
    if m:
        if _off(m.get("nx")):
            weak.append("NX (stack/heap ejecutable)")
            impact.append("stack/heap ejecutable: permite shellcode directo")
        if _off(m.get("pic")) and _off(m.get("pie", m.get("pic"))):
            weak.append("PIE/ASLR")
            impact.append("sin PIE: direcciones fijas, exploits sin fuga")
        if _off(m.get("canary")):
            weak.append("stack canary")
            impact.append("sin canary: un overflow pisa el retorno directamente")
        relro = str(m.get("relro", "")).lower()
        if relro and relro not in ("full",):
            weak.append(f"RELRO {relro or 'none'}")
            impact.append("GOT escribible: GOT overwrite / ret2dlresolve")
    if len(weak) >= 2:   # 2+ protecciones ausentes = configuracion de build debil
        sev = "high" if len(weak) >= 3 else "medium"
        findings.append(_f(
            "Endurecimiento de compilacion insuficiente", "Insufficient build hardening", sev,
            "[checksec]\nprotecciones ausentes: " + ", ".join(weak),
            "El binario se compilo/enlazo sin protecciones clave (" + ", ".join(weak) + "). "
            + "; ".join(impact) + ". Es una configuracion de build debil que amplia la superficie de "
            "explotacion." if es else
            "The binary was built/linked without key protections (" + ", ".join(weak) + "). "
            + "; ".join(impact) + ". Weak build configuration that widens the exploitation surface.",
            "The binary lacks key protections (" + ", ".join(weak) + "); weak build configuration.",
            "Recompila con NX (-z noexecstack), PIE (-pie -fPIE), stack canary "
            "(-fstack-protector-strong) y Full RELRO (-Wl,-z,relro,-z,now)." if es else
            "Rebuild with NX (-z noexecstack), PIE (-pie -fPIE), stack canary "
            "(-fstack-protector-strong) and Full RELRO (-Wl,-z,relro,-z,now).",
            "Rebuild with NX, PIE, stack canary and Full RELRO.", lang, "configuracion / build"))

    imports = _imports(reg)
    strings = _strings(reg)
    # (b) manipulacion insegura del entorno (LD_*): altera la busqueda de librerias
    if any(x in imports for x in ("setenv", "putenv")) and \
       re.search(r"LD_PRELOAD|LD_LIBRARY_PATH", strings):
        findings.append(_f(
            "Manipulacion insegura del entorno (LD_*)", "Insecure environment manipulation (LD_*)",
            "medium",
            "[radare2: ii + izz]\nsetenv/putenv + LD_PRELOAD/LD_LIBRARY_PATH",
            "El binario modifica variables del enlazador dinamico (LD_PRELOAD/LD_LIBRARY_PATH). Si un "
            "atacante controla el valor (o el binario es SUID), puede forzar la carga de una libreria "
            "maliciosa (library hijacking)." if es else
            "The binary modifies dynamic-linker variables (LD_PRELOAD/LD_LIBRARY_PATH). If an attacker "
            "controls the value (or the binary is SUID), it can force loading a malicious library.",
            "The binary sets LD_PRELOAD/LD_LIBRARY_PATH; risk of library hijacking (esp. if SUID).",
            "No manipules LD_* con datos no confiables; en binarios privilegiados limpia el entorno y "
            "usa rutas absolutas de confianza." if es else
            "Do not set LD_* from untrusted data; in privileged binaries sanitize the environment and "
            "use trusted absolute paths.",
            "Do not set LD_* from untrusted data; sanitize the environment in privileged binaries.",
            lang, "configuracion / entorno"))

    # (c) ejecucion por PATH relativa: system/popen + comando sin ruta absoluta. BUG previo: el
    # regex exigia comillas LITERALES ("cmd") en el texto, pero la tabla `izz` de r2 nunca envuelve
    # el VALOR del string entre comillas (son celdas de tabla) -- este check nunca pudo dispararse
    # en NINGUN binario real (falso negativo del 100%, no falso positivo). Se usa string_values()
    # (parseo real del valor) y se exige que la cadena COMPLETA sea el nombre de comando (no una
    # frase que solo lo mencione).
    if any(x in imports for x in ("system", "popen")):
        _cmd_names = {"sh", "bash", "ls", "cat", "cp", "mv", "rm", "id", "whoami", "ping", "curl",
                      "wget", "python", "perl", "env", "echo", "chmod", "chown", "kill", "ps"}
        cmds = []
        for v in string_values(reg):
            s = v.strip()
            parts = s.split()
            # primer token = nombre de comando conocido; resto = argumentos plausibles de linea de
            # comandos (sin espacios raros/control, cadena corta) -- no exige que sean flags '-x'
            # (comandos reales como 'ps aux' o 'curl example.com' no usan guion).
            if (parts and parts[0] in _cmd_names and len(s) <= 80
                    and re.fullmatch(r"[\x20-\x7e]+", s)):
                cmds.append(s)
        cmds = sorted(set(cmds))
        if cmds:
            findings.append(_f(
                "Ejecucion de comando por PATH (ruta relativa)", "Command execution via PATH (relative)",
                "medium",
                "[radare2: ii + izz]\nsystem/popen + comando(s) sin ruta absoluta: " + ", ".join(cmds[:4]),
                "El binario ejecuta comandos por nombre (sin ruta absoluta) con system/popen. Si el PATH "
                "o el directorio de trabajo son controlables, un atacante coloca un binario homonimo y "
                "logra ejecucion (PATH hijacking); critico si el binario es SUID." if es else
                "The binary runs commands by name (no absolute path) with system/popen. If PATH or the "
                "working directory are controllable, an attacker plants a same-named binary and gets "
                "execution (PATH hijacking); critical if SUID.",
                "The binary runs commands by name via system/popen; PATH hijacking risk.",
                "Usa rutas absolutas para los ejecutables y execve con argv fijo; fija un PATH seguro y "
                "no dependas del directorio de trabajo." if es else
                "Use absolute paths for executables and execve with a fixed argv; set a safe PATH and do "
                "not rely on the working directory.",
                "Use absolute paths and execve with a fixed argv; set a safe PATH.",
                lang, "configuracion / ejecucion"))
    return findings
