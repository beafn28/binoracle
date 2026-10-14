"""First-class native static queries: functions, call graph, xrefs, address naming, call paths.

These are the function-level static tools REA exposes on its own engine (`analyze_function`,
`get_call_graph`, `find_xrefs_to_name`, `address_name`, `build_call_path`/`trace_call_path`). In
binoracle they are grounded on the shared radare2 session oracle: radare2 DISASSEMBLES the binary,
it never executes it, and the session caches one `aaa` per file. Everything degrades honestly when
radare2 / r2pipe is not installed (caller-supplied, like the Ghidra connector). Bounded output;
the binary's own symbol/function names are data, not trusted input."""
from __future__ import annotations

import json

from ..oracles import r2session


def _j(binary: str, cmd: str, timeout: float = 90.0):
    """Run an r2 JSON command through the shared session and parse it. None if no r2 or parse fails."""
    out = r2session.cmd_timeout(binary, cmd, timeout=timeout)
    if out is None:
        return None
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def _no_r2() -> dict:
    return {"ok": False, "available": False, "tool": "native_query",
            "note": "radare2/r2pipe no disponible (instala radare2 y `pip install r2pipe`); "
                    "r2 desensambla, no ejecuta el binario"}


def _functions(binary: str):
    """All analyzed functions: list of {offset,name,size,nbbs,callrefs}. None if r2 absent."""
    fns = _j(binary, "aflj")
    return fns if isinstance(fns, list) else None


def _resolve(binary: str, name_or_addr: str):
    """Resolve a function name or address to its entry offset (int). None if unresolved."""
    s = str(name_or_addr).strip()
    if s.startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            pass
    elif s.isdigit():
        return int(s)
    info = _j(binary, f"afij @ {s}")
    if isinstance(info, list) and info and isinstance(info[0], dict) and "offset" in info[0]:
        return info[0]["offset"]
    for f in _functions(binary) or []:
        if f.get("name") == s or f.get("name", "").endswith("." + s):
            return f.get("offset")
    return None


def analyze_function(binary: str, func: str) -> dict:
    """analyze_function: info + disassembly of one function (r2 afij + pdfj). Static."""
    if r2session.get(binary) is None:
        return _no_r2()
    addr = _resolve(binary, func)
    if addr is None:
        return {"ok": False, "available": True, "tool": "native_query",
                "note": f"funcion no encontrada: {func}"}
    info = _j(binary, f"afij @ {addr}") or []
    meta = info[0] if isinstance(info, list) and info else {}
    dis = _j(binary, f"pdfj @ {addr}") or {}
    ops = []
    for op in (dis.get("ops") or [])[:400]:
        if op.get("disasm") is not None:
            ops.append({"addr": op.get("offset"), "disasm": op.get("disasm"),
                        "bytes": op.get("bytes"), "type": op.get("type")})
    callrefs = [c for c in (meta.get("callrefs") or []) if c.get("type") in ("call", "CALL")]
    return {"ok": True, "available": True, "tool": "native_query", "func": meta.get("name", func),
            "addr": meta.get("offset", addr), "size": meta.get("size"), "nbbs": meta.get("nbbs"),
            "calls": [c.get("addr") for c in callrefs][:60], "disasm": ops,
            "limitations": ["desensamblado estatico de radare2; no se ejecuta el binario"]}


def get_call_graph(binary: str, limit: int = 400) -> dict:
    """get_call_graph: nodes (functions) + edges (static call references) from r2's analysis."""
    if r2session.get(binary) is None:
        return _no_r2()
    fns = _functions(binary)
    if fns is None:
        return {"ok": False, "available": True, "tool": "native_query", "note": "sin funciones (¿aaa fallo?)"}
    byaddr = {f.get("offset"): f.get("name") for f in fns}
    nodes = [{"addr": f.get("offset"), "name": f.get("name"), "size": f.get("size")}
             for f in fns[:limit]]
    edges = []
    for f in fns[:limit]:
        src = f.get("offset")
        for c in (f.get("callrefs") or []):
            if c.get("type") in ("call", "CALL") and c.get("addr") in byaddr:
                edges.append({"from": src, "to": c.get("addr")})
            if len(edges) >= limit * 8:
                break
    return {"ok": True, "available": True, "tool": "native_query",
            "function_count": len(fns), "nodes": nodes, "edges": edges[:limit * 8],
            "limitations": ["grafo de llamadas estatico (radare2); llamadas indirectas pueden faltar"]}


def find_xrefs_to_name(binary: str, name: str) -> dict:
    """find_xrefs_to_name: all call/data xrefs that reach a symbol or function (r2 axtj)."""
    if r2session.get(binary) is None:
        return _no_r2()
    addr = _resolve(binary, name)
    target = addr if addr is not None else name
    refs = _j(binary, f"axtj @ {target}") or []
    out = []
    for r in refs if isinstance(refs, list) else []:
        out.append({"from": r.get("from"), "type": r.get("type"),
                    "fcn_name": r.get("fcn_name"), "opcode": r.get("opcode")})
    return {"ok": True, "available": True, "tool": "native_query", "name": name,
            "addr": addr, "xrefs": out[:200], "xref_count": len(out),
            "limitations": ["xrefs estaticas de radare2; referencias calculadas en runtime no se ven"]}


def address_name(binary: str, addr: str) -> dict:
    """address_name: resolve an address to its enclosing function + nearest flag/symbol (r2)."""
    if r2session.get(binary) is None:
        return _no_r2()
    a = _resolve(binary, addr if str(addr).startswith("0x") else str(addr))
    if a is None:
        try:
            a = int(str(addr), 0)
        except ValueError:
            return {"ok": False, "available": True, "tool": "native_query", "note": f"direccion invalida: {addr}"}
    info = _j(binary, f"afij @ {a}") or []
    meta = info[0] if isinstance(info, list) and info else {}
    flag = (r2session.cmd_timeout(binary, f"fd @ {a}") or "").strip()
    return {"ok": True, "available": True, "tool": "native_query", "addr": a,
            "function": meta.get("name"), "function_addr": meta.get("offset"),
            "offset_in_func": (a - meta["offset"]) if meta.get("offset") is not None else None,
            "nearest_flag": flag or None,
            "limitations": ["resolucion estatica de radare2"]}


def call_path(binary: str, src: str, dst: str, max_depth: int = 12) -> dict:
    """build_call_path / trace_call_path: a static call path from src to dst over the call graph (BFS)."""
    if r2session.get(binary) is None:
        return _no_r2()
    fns = _functions(binary)
    if fns is None:
        return {"ok": False, "available": True, "tool": "native_query", "note": "sin funciones"}
    name = {f.get("offset"): f.get("name") for f in fns}
    adj = {}
    for f in fns:
        adj[f.get("offset")] = [c.get("addr") for c in (f.get("callrefs") or [])
                                if c.get("type") in ("call", "CALL") and c.get("addr") in name]
    s = _resolve(binary, src)
    d = _resolve(binary, dst)
    if s is None or d is None:
        return {"ok": False, "available": True, "tool": "native_query",
                "note": f"no se resolvio {'src ' + src if s is None else ''} {'dst ' + dst if d is None else ''}".strip()}
    # BFS
    from collections import deque
    prev = {s: None}
    q = deque([(s, 0)])
    found = s == d
    while q and not found:
        cur, depth = q.popleft()
        if depth >= max_depth:
            continue
        for nxt in adj.get(cur, []):
            if nxt not in prev:
                prev[nxt] = cur
                if nxt == d:
                    found = True
                    break
                q.append((nxt, depth + 1))
    if d not in prev:
        return {"ok": True, "available": True, "tool": "native_query", "reachable": False,
                "note": f"sin ruta estatica de {src} a {dst} en profundidad {max_depth}",
                "limitations": ["solo llamadas directas; indirectas/virtuales no se siguen"]}
    path = []
    cur = d
    while cur is not None:
        path.append({"addr": cur, "name": name.get(cur)})
        cur = prev[cur]
    path.reverse()
    return {"ok": True, "available": True, "tool": "native_query", "reachable": True,
            "path": path, "length": len(path),
            "limitations": ["ruta por llamadas directas estaticas; indirectas/virtuales no se siguen"]}


def inspect_native_api(binary: str) -> dict:
    """inspect_native_api: the binary's API surface -- imported functions (+ their library), exported
    symbols, and linked libraries (DT_NEEDED) -- via radare2 (ii/iE/il). Static; degrades if no r2."""
    if r2session.get(binary) is None:
        return _no_r2()
    imps = _j(binary, "iij") or []
    exps = _j(binary, "iEj") or []
    libs = _j(binary, "ilj") or []
    imports = [{"name": i.get("name"), "library": i.get("libname"), "type": i.get("type"),
                "plt": i.get("plt")} for i in imps if isinstance(i, dict)]
    exports = [{"name": e.get("name"), "type": e.get("type"), "vaddr": e.get("vaddr")}
               for e in exps if isinstance(e, dict)]
    return {"ok": True, "available": True, "tool": "native_query",
            "libraries": [str(x) for x in libs][:60],
            "import_count": len(imports), "export_count": len(exports),
            "imports": imports[:300], "exports": exports[:300],
            "limitations": ["superficie de API estatica (radare2); importaciones resueltas en runtime "
                            "(dlopen/dlsym) no se ven"]}


def binary_overview(binary: str) -> dict:
    """binary_overview / inspect_analysis_view: a one-shot static analysis view -- arch/bits/type/OS,
    entrypoint, counts of functions/imports/exports/sections, and the top sections, via radare2."""
    if r2session.get(binary) is None:
        return _no_r2()
    info = _j(binary, "ij") or {}
    bcatch = info.get("bin", {}) if isinstance(info, dict) else {}
    fns = _functions(binary) or []
    imps = _j(binary, "iij") or []
    exps = _j(binary, "iEj") or []
    secs = _j(binary, "iSj") or []
    sections = [{"name": s.get("name"), "size": s.get("size"), "perm": s.get("perm")}
                for s in secs if isinstance(s, dict)][:40]
    return {"ok": True, "available": True, "tool": "native_query",
            "arch": bcatch.get("arch"), "bits": bcatch.get("bits"), "type": bcatch.get("bintype"),
            "os": bcatch.get("os"), "class": bcatch.get("class"), "endian": bcatch.get("endian"),
            "pic": bcatch.get("pic"), "canary": bcatch.get("canary"), "nx": bcatch.get("nx"),
            "entrypoint": (info.get("core", {}) or {}).get("baddr") if isinstance(info, dict) else None,
            "function_count": len(fns), "import_count": len(imps), "export_count": len(exps),
            "section_count": len(secs), "sections": sections,
            "limitations": ["vista de analisis estatica de radare2; no se ejecuta el binario"]}


def render_native_query(kind: str, r: dict) -> str:
    out = [f"## Consulta nativa estatica: {kind}\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "analyze_function":
        out.append(f"- `{r['func']}` @ {hex(r['addr']) if isinstance(r.get('addr'), int) else r.get('addr')} "
                   f"| size={r.get('size')} bbs={r.get('nbbs')} calls={len(r.get('calls') or [])}")
        for op in (r.get("disasm") or [])[:60]:
            a = op.get("addr")
            out.append(f"  {hex(a) if isinstance(a, int) else a}: {op.get('disasm')}")
    elif kind == "get_call_graph":
        out.append(f"- funciones: {r['function_count']} | nodos: {len(r['nodes'])} | aristas: {len(r['edges'])}")
        for e in r["edges"][:40]:
            out.append(f"  {hex(e['from'])} -> {hex(e['to'])}")
    elif kind == "find_xrefs_to_name":
        out.append(f"- `{r['name']}`"
                   + (f" @ {hex(r['addr'])}" if isinstance(r.get("addr"), int) else "")
                   + f": {r['xref_count']} xref(s)")
        for x in (r.get("xrefs") or [])[:40]:
            frm = x.get("from")
            out.append(f"  {hex(frm) if isinstance(frm, int) else frm} [{x.get('type')}] {x.get('fcn_name')}: {x.get('opcode')}")
    elif kind == "address_name":
        a = r.get("addr")
        out.append(f"- {hex(a) if isinstance(a, int) else a} -> funcion `{r.get('function')}`"
                   f" (+{r.get('offset_in_func')}) | flag: {r.get('nearest_flag')}")
    elif kind == "call_path":
        if not r.get("reachable"):
            out.append(f"- {r.get('note','sin ruta')}")
        else:
            out.append(f"- ruta ({r['length']}): "
                       + " -> ".join((p.get("name") or hex(p["addr"])) for p in r["path"]))
    elif kind == "native_api":
        out.append(f"- librerias: {', '.join(r.get('libraries') or []) or '-'}")
        out.append(f"- imports: {r.get('import_count')} | exports: {r.get('export_count')}")
        for i in (r.get("imports") or [])[:30]:
            out.append(f"  - import {i.get('name')} ({i.get('library') or '?'})")
        for e in (r.get("exports") or [])[:15]:
            out.append(f"  - export {e.get('name')}")
    elif kind == "overview":
        out.append(f"- {r.get('arch')}/{r.get('bits')}-bit {r.get('type')} ({r.get('os')}, "
                   f"{r.get('class')}, {r.get('endian')})")
        out.append(f"- PIC={r.get('pic')} NX={r.get('nx')} canary={r.get('canary')} | "
                   f"funciones={r.get('function_count')} imports={r.get('import_count')} "
                   f"exports={r.get('export_count')} secciones={r.get('section_count')}")
        for s in (r.get("sections") or [])[:14]:
            out.append(f"  - {s.get('name')} ({s.get('size')} B, {s.get('perm')})")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
