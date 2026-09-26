"""Hechos del binario parseados de forma robusta (para que los escaneres no den falsos positivos).

El problema que resuelve: varios escaneres hacian matching de substring sobre la salida CRUDA de r2
(cabeceras de tabla incluidas) y sobre TODAS las strings, lo que en binarios estaticos (glibc entera
embebida) o con URLs de la toolchain producia falsos positivos (p.ej. la columna 'bind' de `ii` se
tomaba como uso de red; una URL http de gcc/debian como transmision en claro; strings SQL de glibc
como inyeccion SQL). Aqui se parsean los NOMBRES de import reales y se detecta el enlazado estatico,
para exigir evidencia de USO real, no presencia incidental.
"""
from __future__ import annotations

import re as _re
from typing import Dict, Set


def imported_names(reg) -> Set[str]:
    """Conjunto de NOMBRES de simbolos IMPORTADOS (dinamicos), en minusculas. Ignora la cabecera y la
    linea separadora de `ii`, y toma el nombre real (ultima columna). Vacio en binarios estaticos."""
    t = reg.get("r2_imports")
    r = t.run() if t else None
    names: Set[str] = set()
    if not (r and r.ok):
        return names
    for ln in (r.data or "").splitlines():
        s = ln.strip()
        if not s or s.lower().startswith("nth "):        # cabecera de la tabla
            continue
        if set(s) <= set("―—- \t"):            # linea separadora de guiones
            continue
        parts = s.split()
        if parts:
            nm = parts[-1].lower()
            names.add(nm)
            if "." in nm:                                # sym.imp.connect / imp.connect -> connect
                names.add(nm.rsplit(".", 1)[-1])
    return names


def is_static(reg) -> bool:
    """True si el binario esta enlazado ESTATICAMENTE (glibc embebida). En ese caso la presencia de un
    simbolo/string de libc NO implica que el programa lo use: los heuristicos por strings/simbolos no
    son fiables y deben exigir evidencia de xref/uso real."""
    t = reg.get("r2_info")
    r = t.run() if t else None
    if r and r.ok:
        for ln in (r.data or "").splitlines():
            low = ln.lower()
            if low.strip().startswith("static") and "true" in low:
                return True
            if low.strip().startswith("linktype") and "static" in low:
                return True
    # respaldo: sin imports dinamicos suele ser estatico (o muy minimo)
    return len(imported_names(reg)) == 0


_NET_APIS = {"socket", "connect", "bind", "listen", "accept", "accept4", "send", "sendto",
             "recv", "recvfrom", "sendmsg", "recvmsg", "getaddrinfo", "gethostbyname",
             "curl_easy_init", "curl_easy_perform", "ssl_connect", "ssl_new", "bio_new"}


# marcadores de string que denotan un CLIENTE de red/HTTP real (no una URL suelta de la toolchain):
# CURLOPT_/libcurl (uso de libcurl), cabeceras de peticion, agentes de usuario conocidos.
_NET_STR = ("curlopt_", "libcurl", "user-agent:", "wget/", "python-requests", "curl/")


def has_network(reg) -> bool:
    """True si el binario IMPORTA una API de red real (dinamica) O tiene marcadores claros de cliente
    HTTP/red en strings (CURLOPT_, libcurl, User-Agent...). En estatico sin esas evidencias devuelve
    False aunque glibc traiga los simbolos: no se afirma uso de red por presencia de simbolo."""
    if imported_names(reg) & _NET_APIS:
        return True
    t = reg.get("r2_strings")
    r = t.run() if t else None
    blob = (r.data or "").lower() if (r and r.ok) else ""
    return any(m in blob for m in _NET_STR)


_CALLER_RE = _re.compile(r"^([A-Za-z_][\w.]*)\s+0x[0-9a-f]+\s+\[[A-Za-z:\-]+\]\s+call\s+", _re.M)


def sink_callers(reg) -> Dict[str, Set[str]]:
    """Parsea `r2_sinks` a {nombre_del_sink: {funciones que lo llaman}}. Sirve para exigir que dos
    sinks (p.ej. un constructor de cadena y un exec) esten llamados desde la MISMA funcion antes de
    afirmar que uno alimenta al otro -- 'ambos importados en el binario' no prueba flujo de datos;
    'llamados desde la misma funcion' es una senal mucho mas fuerte (aunque no perfecta) de que sea
    la misma ruta de codigo. Vacio si r2_sinks no esta disponible."""
    t = reg.get("r2_sinks")
    r = t.run() if t else None
    out: Dict[str, Set[str]] = {}
    if not (r and r.ok):
        return out
    cur = None
    for ln in (r.data or "").splitlines():
        s = ln.strip()
        m = _re.match(r"###\s*sink:\s*(\w+)", s)
        if m:
            cur = m.group(1).lower()
            out.setdefault(cur, set())
            continue
        if cur is None or not s:
            continue
        cm = _CALLER_RE.match(ln)
        if cm:
            out[cur].add(cm.group(1).lower())
    return out


def callers_of(reg, symbol: str) -> Set[str]:
    """Funciones que llaman a `symbol`, via r2_xrefs (axt). Prueba `sym.imp.<nombre>` (dinamico) y
    `sym.<nombre>` (estatico) -- funciona para cualquier nombre, no solo los de DANGEROUS/r2_sinks."""
    t = reg.get("r2_xrefs")
    if not t:
        return set()
    out: Set[str] = set()
    for prefix in ("sym.imp.", "sym."):
        try:
            r = t.run(target=f"{prefix}{symbol}")
        except Exception:
            continue
        if not (r and r.ok):
            continue
        for m in _CALLER_RE.finditer((r.data or "") + "\n"):
            out.add(m.group(1).lower())
        if out:
            break
    return out


def shares_caller(reg, sinks_a, sinks_b) -> bool:
    """True si algun simbolo de `sinks_a` y algun simbolo de `sinks_b` estan llamados desde la MISMA
    funcion (via r2_xrefs, cualquier nombre de import). Uso: exigir que una fuente de entrada
    (fgets/read...) o un constructor (sprintf/strcpy...) y un sink peligroso (system/popen...)
    compartan funcion llamadora antes de afirmar que uno alimenta al otro -- 'ambos importados en el
    binario' no prueba flujo de datos; 'llamados desde la misma funcion' es una senal mucho mas
    fuerte (aunque no perfecta, sigue sin ser dataflow real) de que sea la misma ruta de codigo."""
    fns_a = set()
    for s in sinks_a:
        fns_a |= callers_of(reg, s)
    if not fns_a:
        return False
    fns_b = set()
    for s in sinks_b:
        fns_b |= callers_of(reg, s)
    return bool(fns_a & fns_b)
