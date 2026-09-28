"""OWASP DA2 - Autenticacion rota: patrones de autenticacion debil detectables estaticamente en el
binario.

Cubre:
- Autenticacion por COMPARACION con credencial hardcodeada: el binario usa strcmp/memcmp/strncmp y
  embebe un token/clave que parece una credencial -> comparar la entrada con una cadena fija es una
  puerta de auth debil (y ademas filtra por canal lateral de tiempo con strcmp).
- Ausencia de HASHING de contrasenas: hay comparacion de credenciales pero no se ve ninguna funcion
  de hash/derivacion (crypt/bcrypt/PBKDF2/SHA) -> contrasenas comparadas en claro.

Grounded en imports (r2 ii) + strings (r2 izz). Ademas de la correlacion (co-ocurrencia en el
binario), se intenta CONFIRMAR el enlace real: si una string candidata a credencial tiene un xref
directo (r2 axt) a una funcion, y esa MISMA funcion llama a una de las _CMP, es una conexion
verificada por cruce de referencias, no solo una coincidencia -- se distingue explicitamente del
caso puramente correlacional (cuando el xref no se puede establecer, p.ej. simbolos stripped).
Complementa secrets (DA3, que hace el mismo xref sobre CADA credencial encontrada) y backdoors (DA1).
"""
from __future__ import annotations

import re
from typing import List

from ..oracles.base import ToolRegistry
from ..store.session import Finding
from ._binfacts import string_values, _STR_ROW_RE
from .secrets import _line_vaddr, _used_in

# Bug real encontrado probando con un PE real (Ingrid.exe, que importa lstrcmpA): esta lista solo
# tenia nombres libc/POSIX -- ningun binario Windows (que compara con lstrcmp*/_stricmp/wcscmp, no
# strcmp) disparaba nunca este chequeo, aunque el mecanismo (imports+strings+xref) es igual de
# valido para PE. Se anaden los equivalentes Win32/MSVCRT reales.
_CMP = ("strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp",
        "lstrcmpa", "lstrcmpw", "lstrcmpia", "lstrcmpiw", "_stricmp", "_strnicmp", "_wcsicmp",
        "_wcsnicmp", "_memicmp", "wcscmp", "wcsncmp", "comparestringa", "comparestringw",
        "rtlequalstring", "rtlequalunicodestring", "rtlcomparememory")
# nombres cortos con prefijo "=": coincidencia EXACTA (mismo motivo que _PE_CAPABILITIES en
# report/html.py -- "sha256"/"hmac" sueltos son razonables como nombre exacto de import, pero un
# prefijo como "evp_" nunca coincide con un import real como "evp_encryptinit": bug preexistente,
# se corrige aqui a prefijo real).
_HASH = ("=crypt", "bcrypt", "pbkdf2", "scrypt", "argon2", "sha256", "sha512", "sha1_init",
         "md5_init", "evp_", "hmac", "cryptcreatehash", "cryptderivekey", "cryptacquirecontext",
         "bcrypthash", "bcryptopenalgorithmprovider", "ncryptopenstorageprovider")


def _has_hash_import(names) -> bool:
    """Bug preexistente corregido: `h in names` (membership EXACTA en el set de imports) nunca
    podia matchear entradas con prefijo como "evp_" contra un import real como "evp_encryptinit".
    "=" seguido de un nombre exige coincidencia EXACTA (evita que un nombre corto/generico como
    "crypt" haga match por prefijo con algo no relacionado); sin "=", es prefijo."""
    for h in _HASH:
        if h.startswith("="):
            if h[1:] in names:
                return True
        elif any(n.startswith(h) for n in names):
            return True
    return False


# nombres de identificador/strings que sugieren una credencial usada en la comparacion. Limite propio
# (no \b): \b trata '_' como caracter de palabra, asi que NO separaria "PASSWORD" dentro de
# "MASTER_PASSWORD_2024" (un identificador real, con guion bajo, que SI debe matchear). En cambio,
# sin ningun limite, "pin" hacia match dentro de "GetStartupInfoA" (falso positivo real confirmado en
# win_chall.exe: una API de Windows sin relacion, donde "pin" cae en medio de letras seguidas). El
# limite correcto es "no letra ADYACENTE": una palabra clave pegada a otras LETRAS es parte de un
# termino mas largo no relacionado; pegada a '_'/'-'/digitos/inicio/fin SI cuenta (identificador).
_CRED = re.compile(
    r"(?<![A-Za-z])(pass(word|wd)?|secret|token|api[_-]?key|licen[cs]e|serial|admin|auth|login|pin)"
    r"(?![A-Za-z])", re.I)
# un prompt de UI ("pass?", "login:", "enter password: ") no es una credencial EMBEBIDA: es la
# palabra clave seguida solo de puntuacion/espacios de prompt, sin ningun valor real adjunto.
_PROMPT_ONLY = re.compile(
    r"^\W*(enter\s+|please\s+enter\s+)?(pass(word|wd)?|secret|token|api[_-]?key|licen[cs]e|serial|"
    r"admin|auth|login|pin)\W*$", re.I)


def _run(reg: ToolRegistry, name: str) -> str:
    t = reg.get(name)
    if t:
        r = t.run()
        if r.ok:
            return r.data or ""
    return ""


def _cred_candidates_with_vaddr(reg):
    """(string, vaddr) de cada candidata a credencial, leyendo el texto crudo de `izz` (no la lista
    ya recortada de string_values) para poder localizar el vaddr de la MISMA linea via _line_vaddr.
    Mismo filtro que antes (_CRED, sin prompts de UI)."""
    st = reg.get("r2_strings")
    if not st:
        return []
    res = st.run()
    if not res.ok:
        return []
    text = res.data or ""
    out = []
    for m in _CRED.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.start())
        line = text[line_start:(line_end if line_end != -1 else len(text))]
        # el valor real de la string es lo que hay tras la columna 'type' (ascii/utf8/...), igual
        # que string_values() -- misma extraccion robusta, no un split() fragil por num de columnas.
        row = _STR_ROW_RE.search(line)
        val = row.group(2).strip() if row else line.strip()
        if _PROMPT_ONLY.match(val):
            continue
        if not re.search(r'"[^"]{3,64}"|\b\w{4,64}\b', val):
            continue
        vaddr = _line_vaddr(text, m.start())
        out.append((val, vaddr))
        if len(out) >= 12:
            break
    return out


def _confirm_via_xref(reg, candidates):
    """De las candidatas (string, vaddr), cuales tienen un xref directo (r2 axt) a una funcion que
    ADEMAS llama a una de las _CMP en su propio disassembly (r2 pdf) -- conexion REAL entre esa
    credencial concreta y la comparacion, no solo co-ocurrencia en el binario. Devuelve
    [(string, funcion, cmp_usada), ...], grounded: nunca inventa el enlace si r2 no lo confirma."""
    disasm = reg.get("r2_disasm")
    if not disasm:
        return []
    confirmed = []
    seen_fns = {}
    for val, vaddr in candidates:
        for fn in _used_in(reg, vaddr):
            if fn not in seen_fns:
                try:
                    r = disasm.run(target=fn)
                    seen_fns[fn] = (r.data or "") if r.ok else ""
                except Exception:
                    seen_fns[fn] = ""
            body = seen_fns[fn]
            hit = next((c for c in _CMP if re.search(rf"\bcall\b[^\n]*\b{re.escape(c)}\b", body)), None)
            if hit:
                confirmed.append((val, fn, hit))
    return confirmed[:6]


def get_confirmed_credentials(reg: ToolRegistry) -> List[tuple]:
    """Punto de entrada publico y reutilizable: [(credencial, funcion, cmp_usada), ...] confirmadas
    por xref (r2 axt + pdf). Usado por scan_auth() para el hallazgo estatico, y por el pipeline de
    informe (web.py) para decidir que credencial concreta intentar en el sandbox dinamico
    (authbypass.py) -- un unico calculo, sin duplicar la logica de xref en dos sitios."""
    return _confirm_via_xref(reg, _cred_candidates_with_vaddr(reg))


def scan_auth(reg: ToolRegistry, binary: str, lang: str = "es") -> List[Finding]:
    from ._binfacts import imported_names
    findings: List[Finding] = []
    names = imported_names(reg)          # nombres de import REALES (parseados), no texto crudo
    es = lang == "es"

    cmp_used = [c for c in _CMP if c in names]
    if not cmp_used:
        return findings
    has_hash = _has_hash_import(names)
    # strings que parecen credenciales EMBEBIDAS (no prompts de UI: "pass?"/"login:" no cuentan, son
    # la etiqueta sin ningun valor real adjunto -- ver _PROMPT_ONLY).
    cred_lines = [v.strip() for v in string_values(reg)
                  if _CRED.search(v) and not _PROMPT_ONLY.match(v.strip())
                  and re.search(r'"[^"]{3,64}"|\b\w{4,64}\b', v)][:6]

    if cred_lines:
        # intenta CONFIRMAR el enlace especifico credencial<->comparacion via xref (r2 axt + pdf),
        # no solo la correlacion "ambas cosas existen en el binario".
        confirmed = get_confirmed_credentials(reg)
        if confirmed:
            conf_txt = "; ".join(f"{fn} ({c})" for _v, fn, c in confirmed)
            title = ("Autenticacion por comparacion con credencial hardcodeada (confirmado por xref)"
                     if es else "Authentication by comparison against a hardcoded credential (xref-confirmed)")
            xref_note = ((f" CONFIRMADO por cruce de referencias (r2 axt + pdf): la(s) funcion(es) "
                         f"{conf_txt} referencian directamente una de las candidatas Y llaman a la "
                         f"comparacion en esa misma funcion -- no es solo co-ocurrencia en el binario, "
                         f"es el mismo camino de codigo.") if es else
                         (f" CONFIRMED by cross-reference (r2 axt + pdf): function(s) {conf_txt} "
                          f"directly reference one of the candidates AND call the comparison in that "
                          f"same function -- not just co-occurrence in the binary, the same code path."))
        else:
            title = ("Autenticacion por comparacion con credencial hardcodeada"
                     if es else "Authentication by comparison against a hardcoded credential")
            xref_note = ((" NO confirmado por xref: se ve la comparacion y strings candidatas en el "
                         "binario, pero r2 no pudo establecer que la MISMA funcion use la MISMA "
                         "credencial (simbolos stripped, referencia indirecta, o no relacionadas de "
                         "verdad) -- es una correlacion, confirmalo leyendo la funcion.") if es else
                         (" NOT xref-confirmed: the comparison and candidate strings are both present "
                          "in the binary, but r2 could not establish that the SAME function uses the "
                          "SAME credential (stripped symbols, indirect reference, or genuinely "
                          "unrelated) -- this is a correlation, confirm by reading the function."))
        findings.append(Finding(
            title=title,
            severity="high", verdict="grounded", location="auth / comparacion",
            evidence="[radare2: ii + izz]\ncomparacion: " + ", ".join(cmp_used)
                     + "\ncandidatas: " + " | ".join(cred_lines[:4])
                     + (("\nxref confirmado: " + conf_txt) if confirmed else ""),
            rationale=("El binario compara entradas con " + ", ".join(cmp_used) + " y embebe cadenas que "
                       "parecen credenciales. Autenticar comparando contra una cadena fija es debil: la "
                       "credencial se extrae del binario (ver DA3) y strcmp filtra por canal lateral de "
                       "tiempo. Puede ser un backdoor o una clave maestra." + xref_note if es else
                       "The binary compares inputs with " + ", ".join(cmp_used) + " and embeds strings that "
                       "look like credentials. Authenticating by comparing against a fixed string is weak: "
                       "the credential is extractable (see DA3) and strcmp leaks via a timing side channel. "
                       "It may be a backdoor or a master key." + xref_note),
            rationale_en=("The binary compares inputs with " + ", ".join(cmp_used) + " and embeds "
                          "credential-like strings; comparing against a fixed string is weak auth." + xref_note),
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
