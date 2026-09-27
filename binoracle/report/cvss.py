"""CVSS 4.0 por hallazgo, sin inventar el numero.

Como funciona (transparente y auditable):
- A cada hallazgo se le asigna un VECTOR base CVSS 4.0 segun su CLASE de vulnerabilidad (tabla
  `_VECTORS`, conservadora y documentada). El vector es una valoracion por clase, no un invento
  por hallazgo: se muestra siempre para que sea verificable.
- El SCORE lo calcula el algoritmo OFICIAL CVSS 4.0 (libreria `cvss`, MacroVector de FIRST.org).
  Nunca se fabrica un numero: si la libreria no esta instalada, se muestra el vector y score=None.
- Madurez de explotacion (metrica Threat E), semantica oficial:
    * hallazgo VERIFICADO (exploit/alcanzabilidad probada en sandbox) -> E:A (Attacked)
    * hallazgo grounded (evidencia estatica, no probada)              -> E:P (Proof-of-Concept)
    * hallazgo sin verificar                                          -> E:U (Unreported/unproven)
  Asi un hallazgo verificado puntua por encima de uno solo grounded, reflejando la certeza real.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# clase de vulnerabilidad -> metricas base CVSS 4.0 (parte tras 'CVSS:4.0/').
# AV ataque, AC complejidad, AT requisitos, PR privilegios, UI interaccion,
# VC/VI/VA impacto en el sistema vulnerable, SC/SI/SA impacto en sistemas posteriores.
_VECTORS = {
    "mem_rce":     "AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # overflow/ret2win/ROP local -> exec
    "net_rce":     "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # bind/reverse shell, backdoor de red
    "exfil":       "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",  # callback saliente / C2 / exfiltracion
    "cmd_inj":     "AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # inyeccion de comando
    "secret":      "AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",  # credencial/secreto hardcodeado
    "cleartext":   "AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",  # transmision sin cifrar (MITM)
    "cert":        "AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",  # certificado no validado (MITM activo)
    "weak_crypto": "AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",  # cripto debil (MD5/DES/RC4/ECB)
    "weak_prng":   "AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",  # PRNG inseguro (rand/srand)
    "file_perms":  "AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # SUID/escribible -> escalada local
    "lib_hijack":  "AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # RPATH/RUNPATH -> secuestro de libreria
    "temp_file":   "AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N",  # temporal predecible / TOCTOU
    "fmt_string":  "AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # format string
    "dotnet_info": "AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",  # ensamblado .NET decompilable (info)
}

# clasificacion por palabras clave (ES + EN, minusculas) sobre titulo + location.
# ORDEN IMPORTANTE: lo mas especifico primero.
_RULES = [
    ("net_rce",     ("bind shell", "reverse shell", "backdoor", "puerta trasera", "bind/listen")),
    ("exfil",       ("conexion saliente", "outbound connection", "callback", "c2", "exfil", "escucha en puerto",
                     "listens on port")),
    ("cmd_inj",     ("inyeccion de comando", "command injection", "inyeccion por", "ejecucion de comando",
                     "command/shell execution", "ejecucion de shell", "shell execution")),
    ("fmt_string",  ("format string", "cadena de formato")),
    ("mem_rce",     ("ret2win", "desbordamiento", "overflow", "buffer", "rop", "ret2libc", "ret2syscall",
                     "exploit", "corrupcion de memoria", "memory corruption")),
    ("cert",        ("certificado", "certificate", "no validad", "not validated", "verifypeer", "insecureskip")),
    ("cleartext",   ("sin cifrar", "cleartext", "texto claro", "http://", "ftp://", "telnet")),
    ("weak_prng",   ("prng", "rand", "aleatori", "srand", "predecible", "predictable")),
    ("weak_crypto", ("criptografia", "crypto", "md5", "sha1", "des", "rc4", "ecb", "cifrado debil", "weak")),
    ("file_perms",  ("setuid", "setgid", "suid", "escribible por todos", "world-writable", "permisos",
                     "permission")),
    ("lib_hijack",  ("rpath", "runpath", "secuestro de libreria", "library hijack")),
    ("temp_file",   ("temporal", "temp path", "toctou", "despliegue de fichero", "file deployment", "tmp")),
    ("secret",      ("secreto", "secret", "credencial", "credential", "hardcod", "password", "api key",
                     "api_key", "apikey", "token", "clave privada", "private key", "aws")),
    ("dotnet_info", ("ensamblado .net", ".net assembly", "decompil")),
]


@dataclass
class CvssResult:
    cls: str = ""
    vector: str = ""            # vector completo CVSS:4.0/...(/E:x)
    base: Optional[float] = None
    severity: str = ""          # None/Low/Medium/High/Critical
    exploit_maturity: str = ""  # A|P|U
    note: str = ""              # nota sobre la madurez


def classify(finding) -> Optional[str]:
    """Devuelve la clase de vulnerabilidad de un hallazgo, o None si no encaja en ninguna
    (en ese caso NO se asigna CVSS: no se inventa)."""
    blob = ((getattr(finding, "title", "") or "") + " " + (getattr(finding, "location", "") or "")).lower()
    for cls, kws in _RULES:
        if any(k in blob for k in kws):
            return cls
    return None


def _maturity(verdict: str) -> str:
    return {"verified": "A", "grounded": "P"}.get(verdict, "U")


def cvss_for(finding) -> Optional[CvssResult]:
    """CVSS 4.0 de un hallazgo: vector por clase + score oficial + madurez segun el veredicto.
    None si el hallazgo no encaja en ninguna clase conocida (no se inventa un score)."""
    cls = classify(finding)
    if not cls:
        return None
    e = _maturity(getattr(finding, "verdict", ""))
    vector = "CVSS:4.0/" + _VECTORS[cls] + f"/E:{e}"
    r = CvssResult(cls=cls, vector=vector, exploit_maturity=e)
    r.note = {"A": "verificado: exploit/alcanzabilidad probada (E:A, Attacked)",
              "P": "grounded: evidencia estatica, no probada (E:P, Proof-of-Concept)",
              "U": "sin verificar (E:U, Unreported)"}[e]
    try:
        from cvss import CVSS4
        c = CVSS4(vector)
        r.base = c.base_score
        r.severity = c.severity
    except Exception:
        r.base = None
        r.severity = ""
    return r
