"""Hechos del binario parseados de forma robusta (para que los escaneres no den falsos positivos).

El problema que resuelve: varios escaneres hacian matching de substring sobre la salida CRUDA de r2
(cabeceras de tabla incluidas) y sobre TODAS las strings, lo que en binarios estaticos (glibc entera
embebida) o con URLs de la toolchain producia falsos positivos (p.ej. la columna 'bind' de `ii` se
tomaba como uso de red; una URL http de gcc/debian como transmision en claro; strings SQL de glibc
como inyeccion SQL). Aqui se parsean los NOMBRES de import reales y se detecta el enlazado estatico,
para exigir evidencia de USO real, no presencia incidental.
"""
from __future__ import annotations

from typing import Set


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
