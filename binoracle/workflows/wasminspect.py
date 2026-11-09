"""Static WebAssembly module reader: magic/version, sections, imports and exports.

Parses a `.wasm` binary module straight from bytes -- no WABT, nothing executed -- giving the
structure a reverse engineer wants first: the section inventory, the type signatures, and every
import/export with its kind (func/table/memory/global). It does NOT decode instruction bodies to
WAT (that needs WABT); that limit is reported. The WebAssembly binary format is a fixed byte
layout: magic `\\0asm`, a u32 version, then LEB128-framed sections. Design adapted from REA's WASM
tooling (morluto/rea, MIT); re-implemented in Python (structural view only, no external tool)."""
from __future__ import annotations

_SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data",
    12: "data_count",
}
_EXTERN_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}
_VALTYPES = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
             0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}


def _uleb(buf: bytes, off: int):
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("LEB128 truncado")
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 63:
            raise ValueError("LEB128 desborda")


def _name(buf: bytes, off: int):
    n, p = _uleb(buf, off)
    if p + n > len(buf):
        raise ValueError("nombre truncado")
    return buf[p:p + n].decode("utf-8", "replace"), p + n


def _parse_types(payload: bytes):
    types = []
    try:
        count, off = _uleb(payload, 0)
        for _ in range(count):
            if payload[off] != 0x60:   # func type tag
                break
            off += 1
            npar, off = _uleb(payload, off)
            params = [_VALTYPES.get(payload[off + i], hex(payload[off + i])) for i in range(npar)]
            off += npar
            nres, off = _uleb(payload, off)
            results = [_VALTYPES.get(payload[off + i], hex(payload[off + i])) for i in range(nres)]
            off += nres
            types.append({"params": params, "results": results})
    except Exception:
        pass
    return types


def _parse_imports(payload: bytes):
    out = []
    try:
        count, off = _uleb(payload, 0)
        for _ in range(count):
            mod, off = _name(payload, off)
            field, off = _name(payload, off)
            kind = payload[off]
            off += 1
            entry = {"module": mod, "name": field, "kind": _EXTERN_KINDS.get(kind, str(kind))}
            # skip the descriptor to advance offset
            if kind == 0:
                _, off = _uleb(payload, off)
            elif kind == 1:
                off += 1
                off = _skip_limits(payload, off)
            elif kind == 2:
                off = _skip_limits(payload, off)
            elif kind == 3:
                off += 2
            out.append(entry)
    except Exception:
        pass
    return out


def _skip_limits(payload: bytes, off: int) -> int:
    flags = payload[off]
    off += 1
    _, off = _uleb(payload, off)            # min
    if flags & 0x1:
        _, off = _uleb(payload, off)        # max
    return off


def _parse_exports(payload: bytes):
    out = []
    try:
        count, off = _uleb(payload, 0)
        for _ in range(count):
            field, off = _name(payload, off)
            kind = payload[off]
            off += 1
            _, off = _uleb(payload, off)     # index
            out.append({"name": field, "kind": _EXTERN_KINDS.get(kind, str(kind))})
    except Exception:
        pass
    return out


def inspect_wasm(path: str) -> dict:
    """Parse a WASM module statically. Returns {ok, is_wasm, version, sections, types, imports,
    exports, ...} or {is_wasm: False}."""
    from ._artifact import read_bounded, ArtifactTooLarge
    try:
        data = read_bounded(path)
    except ArtifactTooLarge as e:
        return {"ok": False, "is_wasm": False, "note": str(e)}
    except Exception as e:
        return {"ok": False, "is_wasm": False, "note": f"no se pudo leer: {e}"}
    if len(data) < 8 or data[:4] != b"\x00asm":
        return {"ok": True, "is_wasm": False, "note": "sin magic '\\0asm' (no es un modulo WASM)"}
    version = int.from_bytes(data[4:8], "little")
    sections, types, imports, exports = [], [], [], []
    counts = {"function": 0, "memory": 0, "table": 0, "global": 0, "code": 0, "data": 0}
    off = 8
    try:
        while off < len(data):
            sid = data[off]
            off += 1
            size, off = _uleb(data, off)
            payload = data[off:off + size]
            off += size
            sname = _SECTION_NAMES.get(sid, f"id{sid}")
            sections.append({"id": sid, "name": sname, "size": size})
            if sid == 1:
                types = _parse_types(payload)
            elif sid == 2:
                imports = _parse_imports(payload)
            elif sid == 7:
                exports = _parse_exports(payload)
            elif sname in counts:
                try:
                    counts[sname], _ = _uleb(payload, 0)
                except Exception:
                    pass
    except Exception as e:
        return {"ok": True, "is_wasm": True, "version": version, "sections": sections,
                "note": f"modulo truncado/malformado tras {len(sections)} secciones: {e}"}
    return {"ok": True, "is_wasm": True, "version": version, "sections": sections,
            "types": types, "imports": imports, "exports": exports, "counts": counts,
            "limitations": ["no se decodifican los cuerpos de instrucciones a WAT (requiere WABT)"]}


def render_wasm(r: dict) -> str:
    out = ["## Inspeccion de modulo WASM (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_wasm"):
        return "\n".join(out + ["- No es un modulo WASM: " + r.get("note", "")])
    out.append(f"- version del formato: {r.get('version')}")
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    secs = r.get("sections") or []
    if secs:
        out.append(f"- secciones ({len(secs)}): " + ", ".join(f"{s['name']}({s['size']}B)" for s in secs))
    c = r.get("counts") or {}
    if c:
        out.append(f"- funciones: {c.get('function',0)}  memorias: {c.get('memory',0)}  "
                   f"tablas: {c.get('table',0)}  globals: {c.get('global',0)}")
    imps = r.get("imports") or []
    if imps:
        out.append(f"\n### Imports ({len(imps)})")
        for im in imps[:40]:
            out.append(f"- {im['kind']}  `{im['module']}.{im['name']}`")
    exps = r.get("exports") or []
    if exps:
        out.append(f"\n### Exports ({len(exps)})")
        for ex in exps[:40]:
            out.append(f"- {ex['kind']}  `{ex['name']}`")
    types = r.get("types") or []
    if types:
        out.append(f"\n### Tipos de funcion ({len(types)})")
        for i, t in enumerate(types[:20]):
            out.append(f"- t{i}: ({', '.join(t['params'])}) -> ({', '.join(t['results'])})")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
