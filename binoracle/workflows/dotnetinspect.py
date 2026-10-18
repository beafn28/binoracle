"""Static .NET / CLI metadata reader: runtime, streams, table row counts, name heap.

Reads a managed PE assembly without executing it: the CLI (COM descriptor) header, the metadata
root (BSJB), its streams (#~/#-, #Strings, #US, #GUID, #Blob), the metadata-table row counts
(Module/TypeDef/MethodDef/Assembly/AssemblyRef...), and a sample of the #Strings name heap
(module/type/method names). Uses pefile to locate the CLI header; the metadata parsing is a
self-contained re-implementation. Design adapted from REA's managed-code tooling (morluto/rea,
MIT). Nothing is executed."""
from __future__ import annotations

import struct

_BSJB = 0x424A5342  # 'BSJB' little-endian magic at the metadata root

# metadata table index -> name (common/high-value subset of ECMA-335 tables)
_TABLES = {
    0: "Module", 1: "TypeRef", 2: "TypeDef", 4: "Field", 6: "MethodDef", 8: "Param",
    9: "InterfaceImpl", 10: "MemberRef", 11: "Constant", 12: "CustomAttribute",
    14: "DeclSecurity", 17: "StandAloneSig", 20: "EventMap", 23: "PropertyMap",
    24: "MethodSemantics", 25: "MethodImpl", 26: "ModuleRef", 27: "TypeSpec",
    28: "ImplMap", 32: "Assembly", 35: "AssemblyRef", 38: "File", 39: "ExportedType",
    40: "ManifestResource", 41: "NestedClass", 42: "GenericParam",
}


def parse_metadata(md: bytes) -> dict:
    """Parse the metadata root (from the BSJB magic onward)."""
    if len(md) < 20 or struct.unpack_from("<I", md, 0)[0] != _BSJB:
        return {"error": "sin magic BSJB (no es metadata CLI)"}
    ver_len = struct.unpack_from("<I", md, 12)[0]
    version = md[16:16 + ver_len].split(b"\x00")[0].decode("utf-8", "replace")
    off = 16 + ((ver_len + 3) & ~3)
    off += 2                                   # Flags (u16)
    nstreams = struct.unpack_from("<H", md, off)[0]
    off += 2
    streams = []
    for _ in range(nstreams):
        soff, ssize = struct.unpack_from("<II", md, off)
        off += 8
        end = md.index(b"\x00", off)
        name = md[off:end].decode("ascii", "replace")
        off = end + 1
        off = (off + 3) & ~3                   # name padded to 4
        streams.append({"name": name, "offset": soff, "size": ssize})
    out = {"version": version, "streams": [s["name"] for s in streams], "tables": {}}
    by_name = {s["name"]: s for s in streams}
    # table stream: '#~' (optimized) or '#-' (unoptimized)
    ts = by_name.get("#~") or by_name.get("#-")
    if ts:
        t = md[ts["offset"]:ts["offset"] + ts["size"]]
        if len(t) >= 24:
            heap_sizes = t[6]
            valid = struct.unpack_from("<Q", t, 8)[0]
            p = 24
            counts = {}
            for i in range(64):
                if valid & (1 << i):
                    if p + 4 > len(t):
                        break
                    rows = struct.unpack_from("<I", t, p)[0]
                    p += 4
                    counts[_TABLES.get(i, f"table{i}")] = rows
            out["tables"] = counts
            out["heap_sizes"] = heap_sizes
    # #Strings heap sample (module/type/method names)
    ss = by_name.get("#Strings")
    if ss:
        heap = md[ss["offset"]:ss["offset"] + ss["size"]]
        names = [n.decode("utf-8", "replace") for n in heap.split(b"\x00") if n]
        out["string_names"] = names[:60]
    return out


def inspect_dotnet(path: str) -> dict:
    """Detect and read a managed PE assembly's CLI metadata. Returns {ok, is_dotnet, ...}."""
    try:
        import pefile
    except Exception as e:
        return {"ok": False, "is_dotnet": False, "note": f"falta pefile: {e}"}
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception as e:
        return {"ok": True, "is_pe": False, "is_dotnet": False, "note": f"no es PE: {e}"}
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
        com = getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None)
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if dd.VirtualAddress == 0 or dd.Size == 0:
            return {"ok": True, "is_pe": True, "is_dotnet": False,
                    "note": "PE nativo (sin COM descriptor / no es .NET)"}
        cli = pe.get_data(dd.VirtualAddress, min(dd.Size, 72))
        # IMAGE_COR20_HEADER
        (_cb, rt_major, rt_minor, md_rva, md_size, flags, entry_tok) = struct.unpack_from(
            "<IHHIIII", cli, 0)
        md = pe.get_data(md_rva, md_size)
        meta = parse_metadata(md)
        return {"ok": True, "is_pe": True, "is_dotnet": True,
                "runtime_version": f"{rt_major}.{rt_minor}", "flags": flags,
                "entrypoint_token": entry_tok, "metadata_version": meta.get("version"),
                "streams": meta.get("streams", []), "tables": meta.get("tables", {}),
                "string_names": meta.get("string_names", []),
                "limitations": ["no se desensamblan los cuerpos CIL de los metodos; nombres tomados "
                                "del heap #Strings (muestra)"]}
    except Exception as e:
        return {"ok": True, "is_pe": True, "is_dotnet": True, "note": f"metadata CLI malformada: {e}"}
    finally:
        try:
            pe.close()
        except Exception:
            pass


def render_dotnet(r: dict) -> str:
    out = ["## Inspeccion de ensamblado .NET / CLI (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_dotnet"):
        return "\n".join(out + ["- No es un ensamblado .NET: " + r.get("note", "")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    out.append(f"- version de runtime CLI: {r.get('runtime_version')}  |  metadata: {r.get('metadata_version')}")
    out.append(f"- flags: {hex(r.get('flags', 0))}  |  entrypoint token: {hex(r.get('entrypoint_token', 0))}")
    if r.get("streams"):
        out.append(f"- streams: {', '.join(r['streams'])}")
    tbl = r.get("tables") or {}
    if tbl:
        out.append("\n### Tablas de metadata (filas)")
        for k, v in tbl.items():
            out.append(f"- {k}: {v}")
    names = r.get("string_names") or []
    if names:
        out.append(f"\n### Nombres (#Strings, muestra de {len(names)})")
        out.append(", ".join(f"`{n}`" for n in names[:40]))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
