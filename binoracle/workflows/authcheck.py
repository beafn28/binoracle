"""OWASP DA2 - Autenticacion rota: patrones de autenticacion debil detectables estaticamente en el
binario.

Cubre:
- Autenticacion por COMPARACION con credencial hardcodeada: el binario usa strcmp/memcmp/strncmp y
  embebe un token/clave que parece una credencial -> comparar la entrada con una cadena fija es una
  puerta de auth debil (y ademas filtra por canal lateral de tiempo con strcmp).
- Ausencia de HASHING de contrasenas: hay comparacion de credenciales pero no se ve ninguna funcion
  de hash/derivacion (crypt/bcrypt/PBKDF2/SHA) -> contrasenas comparadas en claro.

Grounded en imports (r2 ii) + strings (r2 izz). No afirma que la auth sea explotable; senala el
patron para que se confirme. Complementa secrets (DA3) y backdoors (DA1).
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding

_CMP = ("strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp")
_HASH = ("crypt", "bcrypt", "pbkdf2", "scrypt", "argon2", "sha256", "sha512", "sha1_init",
         "md5_init", "evp_", "hmac")
# nombres de identificador/strings que sugieren una credencial usada en la comparacion
_CRED = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|licen[cs]e|serial|admin|auth|login|pin)",
                   re.I)


def _run(reg: ToolRegistry, name: str) -> str:
    t = reg.get(name)
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def scan_auth(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    findings: List[Finding] = []
    imports = _run(reg, "r2_imports").lower()
    strings = _run(reg, "r2_strings")
    es = lang == "es"

    cmp_used = [c for c in _CMP if c in imports]
    if not cmp_used:
        return findings
    has_hash = any(h in imports for h in _HASH)
    # strings que parecen credenciales embebidas (candidatas a la comparacion de auth)
    cred_lines = [ln.strip() for ln in strings.splitlines()
                  if _CRED.search(ln) and re.search(r'"[^"]{3,64}"|\b\w{4,64}\b', ln)][:6]

    if cred_lines:
        findings.append(Finding(
            title=("Autenticacion por comparacion con credencial hardcodeada"
                   if es else "Authentication by comparison against a hardcoded credential"),
            severity="high", verdict="grounded", location="auth / comparacion",
            evidence="[radare2: ii + izz]\ncomparacion: " + ", ".join(cmp_used)
                     + "\ncandidatas: " + " | ".join(cred_lines[:4]),
            rationale=("El binario compara entradas con " + ", ".join(cmp_used) + " y embebe cadenas que "
                       "parecen credenciales. Autenticar comparando contra una cadena fija es debil: la "
                       "credencial se extrae del binario (ver DA3) y strcmp filtra por canal lateral de "
                       "tiempo. Puede ser un backdoor o una clave maestra." if es else
                       "The binary compares inputs with " + ", ".join(cmp_used) + " and embeds strings that "
                       "look like credentials. Authenticating by comparing against a fixed string is weak: "
                       "the credential is extractable (see DA3) and strcmp leaks via a timing side channel. "
                       "It may be a backdoor or a master key."),
            rationale_en=("The binary compares inputs with " + ", ".join(cmp_used) + " and embeds "
                          "credential-like strings; comparing against a fixed string is weak auth."),
            recommendation=("No autentiques comparando contra credenciales hardcodeadas. Guarda solo un "
                            "hash con sal (bcrypt/Argon2/PBKDF2) y compara en tiempo constante." if es else
                            "Do not authenticate by comparing against hardcoded credentials. Store only a "
                            "salted hash (bcrypt/Argon2/PBKDF2) and compare in constant time."),
            recommendation_en="Store a salted password hash (bcrypt/Argon2/PBKDF2) and compare in constant time."))

    if cred_lines and not has_hash:
        findings.append(Finding(
            title=("Contrasenas comparadas sin hashing" if es else "Passwords compared without hashing"),
            severity="medium", verdict="grounded", location="auth / hashing",
            evidence="[radare2: ii]\ncomparacion: " + ", ".join(cmp_used)
                     + "\nsin funciones de hash/derivacion (crypt/bcrypt/PBKDF2/SHA/HMAC)",
            rationale=("Hay comparacion de credenciales pero no se ve ninguna funcion de hash o "
                       "derivacion de clave: las contrasenas se manejan/comparan en claro, sin sal ni "
                       "coste de calculo." if es else
                       "There is credential comparison but no hashing/KDF function is present: passwords "
                       "are handled/compared in cleartext, without salt or work factor."),
            rationale_en=("Credential comparison with no hashing/KDF present: passwords handled in cleartext."),
            recommendation=("Deriva la contrasena con bcrypt/Argon2/PBKDF2 (sal por usuario) y no compares "
                            "el texto en claro." if es else
                            "Hash passwords with bcrypt/Argon2/PBKDF2 (per-user salt); never compare cleartext."),
            recommendation_en="Hash passwords with bcrypt/Argon2/PBKDF2 (per-user salt)."))
    return findings
