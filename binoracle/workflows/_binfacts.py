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
from typing import Dict, List, Optional, Set


_STR_ROW_RE = _re.compile(r"\b(ascii|utf8|utf16le|utf32le|wide|unicode|base64)\s+(.*)$")


def string_values(reg) -> List[str]:
    """Lista de VALORES de string reales de `r2_strings` (izz), sin la fila de tabla cruda (offset/
    seccion/tipo). Sin esto, un escaner que matchea sobre la linea entera podia citar como 'evidencia'
    el offset/tipo/columna en vez del contenido real, o hacer match sobre metadatos de la tabla."""
    t = reg.get("r2_strings")
    r = t.run() if t else None
    out: List[str] = []
    if not (r and r.ok):
        return out
    for ln in (r.data or "").splitlines():
        m = _STR_ROW_RE.search(ln)
        if m:
            out.append(m.group(2))
    return out


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


def callers_of(reg, symbol: str, binary: str = "") -> Set[str]:
    """Funciones que llaman a `symbol`, via r2_xrefs (axt). Prueba `sym.imp.<nombre>` (dinamico) y
    `sym.<nombre>` (estatico) -- funciona para cualquier nombre, no solo los de DANGEROUS/r2_sinks.

    Bug real encontrado en la logica de credenciales de authcheck.py (mismo patron, aqui aplicado
    de forma general): el ToolRegistry usa analisis LIGERO de r2 ('aa') por defecto, que puede no
    resolver algunos xrefs (p.ej. llamada indirecta via tabla de thunks/imports en binarios poco
    convencionales). Si `binary` esta disponible y el chequeo ligero no encuentra NADA para NINGUN
    prefijo, se reintenta UNA vez contra la sesion r2 compartida (r2session, analisis 'aaa'
    completo, cacheada y reutilizada por decompile.py en el mismo informe) antes de rendirse."""
    out: Set[str] = set()
    t = reg.get("r2_xrefs")
    if t is not None:
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
    if not out and binary:
        try:
            from ..oracles.r2session import cmd_timeout
            for prefix in ("sym.imp.", "sym."):
                txt = cmd_timeout(binary, f"axt @ {prefix}{symbol}", timeout=60) or ""
                for m in _CALLER_RE.finditer(txt + "\n"):
                    out.add(m.group(1).lower())
                if out:
                    break
        except Exception:
            pass
    return out


def shared_caller_fns(reg, sinks_a, sinks_b, binary: str = "") -> Set[str]:
    """Como shares_caller, pero devuelve las funciones REALES que comparten `sinks_a` y `sinks_b`
    (no solo si hay o no coincidencia) -- pedido explicito del usuario: no basta con "hay una
    coincidencia", hay que poder citar la funcion concreta en el hallazgo, igual que se hizo para
    las credenciales en authcheck.py. `binary` habilita el reintento con analisis profundo (ver
    callers_of) cuando el analisis ligero no encuentra nada."""
    fns_a = set()
    for s in sinks_a:
        fns_a |= callers_of(reg, s, binary)
    if not fns_a:
        return set()
    fns_b = set()
    for s in sinks_b:
        fns_b |= callers_of(reg, s, binary)
    return fns_a & fns_b


def shares_caller(reg, sinks_a, sinks_b, binary: str = "") -> bool:
    """True si algun simbolo de `sinks_a` y algun simbolo de `sinks_b` estan llamados desde la MISMA
    funcion (via r2_xrefs, cualquier nombre de import). Uso: exigir que una fuente de entrada
    (fgets/read...) o un constructor (sprintf/strcpy...) y un sink peligroso (system/popen...)
    compartan funcion llamadora antes de afirmar que uno alimenta al otro -- 'ambos importados en el
    binario' no prueba flujo de datos; 'llamados desde la misma funcion' es una senal mucho mas
    fuerte (aunque no perfecta, sigue sin ser dataflow real) de que sea la misma ruta de codigo.
    Wrapper booleano sobre shared_caller_fns(); usa esa funcion directamente si necesitas citar la
    funcion real en el hallazgo, no solo saber si existe coincidencia."""
    return bool(shared_caller_fns(reg, sinks_a, sinks_b, binary))


def disasm_of(reg, fn: str, binary: str = "") -> str:
    """Desensamblado de `fn` (r2 pdf). El ToolRegistry usa analisis ligero ('aa') por defecto, que
    puede no haber descubierto `fn` como funcion en absoluto (se encontro via 'aaa' en r2session,
    en una sesion r2 DISTINTA) -- 'pdf @ fn' sobre la sesion ligera saldria vacio aunque la funcion
    exista de verdad. Si el intento normal no da nada y hay `binary`, reintenta contra la sesion
    compartida (aaa, cacheada). Compartido por authcheck.py (credenciales) y aqui (dataflow)."""
    disasm = reg.get("r2_disasm")
    if disasm is not None:
        try:
            r = disasm.run(target=fn)
            if r.ok and (r.data or "").strip():
                return r.data
        except Exception:
            pass
    if binary:
        try:
            from ..oracles.r2session import cmd_timeout
            return cmd_timeout(binary, f"pdf @ {fn}", timeout=60) or ""
        except Exception:
            pass
    return ""


_CALL_RE = _re.compile(r"\bcall\b[^\n]*?\b([A-Za-z_][\w.]*)\s*$", _re.M)
# operandos "con nombre" que valen como senal de que dos llamadas comparten el MISMO dato: variable
# de pila con nombre r2 (var_18h) o registro de proposito general. eax/rax/esp/rsp/ebp/rbp se
# EXCLUYEN aposta: son de uso tan universal (valor de retorno, puntero de pila/marco) que compartirlos
# no significa nada -- serian ruido, no una senal real de dataflow.
_OPERAND_RE = _re.compile(r"\b(var_[0-9a-f]+h|e?[bcd]x|e?[sd]i|r1[0-5][dwb]?|r[bcd]x|r[sd]i)\b", _re.I)


def _operands_before(lines: List[str], idx: int, window: int = 4) -> Set[str]:
    ops: Set[str] = set()
    for ln in lines[max(0, idx - window):idx + 1]:
        for m in _OPERAND_RE.finditer(ln):
            ops.add(m.group(1).lower())
    return ops


def dataflow_hint(body: str, source_names, sink_names) -> Optional[dict]:
    """Heuristica de dataflow INTRAPROCEDURAL sobre el desensamblado de UNA funcion: busca una
    llamada a algo de `source_names` seguida (mas adelante, misma funcion) de una llamada a algo de
    `sink_names` que comparten un operando con nombre (variable de pila o registro no generico) en
    las instrucciones inmediatamente anteriores a cada llamada -- senal de que el MISMO buffer/valor
    pasado a la fuente se reutiliza como argumento del sink, no solo que ambas llamadas viven en la
    misma funcion. Sigue sin ser dataflow real (no hay symbolic execution ni resolucion de alias
    completa): es una heuristica sintactica, mejor que 'misma funcion' a secas pero no una prueba
    absoluta -- ver el nombre del retorno (dataflow_hint, no dataflow_proof) y como se cita en el
    hallazgo (siempre con el matiz de que es heuristico). None si no se encuentra nada asi."""
    lines = (body or "").splitlines()
    calls = []
    for i, ln in enumerate(lines):
        m = _CALL_RE.search(ln)
        if m:
            calls.append((i, m.group(1).rsplit(".", 1)[-1].lower()))
    src = {s.lower() for s in source_names}
    snk = {s.lower() for s in sink_names}
    for si, sname in calls:
        if sname not in src:
            continue
        src_ops = _operands_before(lines, si)
        if not src_ops:
            continue
        for ci, cname in calls:
            if ci <= si or cname not in snk:
                continue
            sink_ops = _operands_before(lines, ci)
            shared = sorted(src_ops & sink_ops)
            if shared:
                return {"source": sname, "sink": cname, "shared_operand": shared[0]}
    return None


def dataflow_confirmed(reg, source_names, sink_names, binary: str = "") -> Optional[dict]:
    """Punto de entrada: para cada funcion que comparte llamador entre `source_names` y
    `sink_names` (shared_caller_fns), intenta confirmar dataflow real via dataflow_hint sobre su
    desensamblado. Devuelve {"fn", "source", "sink", "shared_operand"} de la PRIMERA funcion donde
    se confirma, o None si ninguna lo confirma (aunque compartan llamador -- en ese caso sigue
    siendo solo la senal mas debil de shared_caller_fns, el llamador debe usarla como fallback)."""
    fns = shared_caller_fns(reg, source_names, sink_names, binary)
    for fn in sorted(fns):
        body = disasm_of(reg, fn, binary)
        if not body:
            continue
        hint = dataflow_hint(body, source_names, sink_names)
        if hint:
            hint["fn"] = fn
            return hint
    return None
