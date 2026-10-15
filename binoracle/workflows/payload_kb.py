"""Carga en tiempo de ejecucion las wordlists REALES de PayloadsAllTheThings committeadas en
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
