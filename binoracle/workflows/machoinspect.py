"""Static Mach-O (macOS) reader: arch, file type, load commands, linked dylibs, mitigations.

Parses a Mach-O image header and its load commands from bytes -- no execution. Reports the CPU
architecture, file type (executable/dylib/bundle), the segments with their protections (flagging
write+execute), the linked dynamic libraries (LC_LOAD_DYLIB), the entry point (LC_MAIN) and the
header mitigation flags (PIE, stack-exec via the allow-stack-exec/no-heap-exec bits). It also reads
the section table and surfaces Objective-C metadata (class and selector names from __objc_classname/
__objc_methname, class/protocol/category counts from the __objc_*list pointer sections) and Swift
metadata (presence and descriptor counts of the __swift5_* sections) -- grounded names and counts,
without walking the Obj-C class hierarchy (that needs VM->offset resolution). Fat (universal)
binaries are detected and their slices listed. Design adapted from REA's Mach-O tooling
(morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

import struct

_MAGICS = {
    0xFEEDFACE: ("32", "little"), 0xCEFAEDFE: ("32", "big"),
    0xFEEDFACF: ("64", "little"), 0xCFFAEDFE: ("64", "big"),
}
_FAT = {0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA}

_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32"}
_FILETYPES = {1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD",
              6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE", 9: "DYLIB_STUB", 10: "DSYM"}

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_ID_DYLIB = 0xD
LC_MAIN = 0x80000028
LC_UUID = 0x1B
LC_UNIXTHREAD = 0x5

MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_NO_HEAP_EXECUTION = 0x1000000


def _one_macho(data: bytes, base: int, magic: int) -> dict:
    bits, endian = _MAGICS[magic]
    e = "<" if endian == "little" else ">"
    o = base + 4
    cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(e + "iiIIII", data, o)
    o += 24
    if bits == "64":
        o += 4  # reserved
    segments, dylibs, entry, uuid, sections = [], [], None, None, []
    for _ in range(ncmds):
        if o + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(e + "II", data, o)
        if cmdsize < 8:
            break
        body = data[o:o + cmdsize]
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            is64 = cmd == LC_SEGMENT_64
            name = body[8:24].split(b"\x00")[0].decode("ascii", "replace")
            if is64:
                vmaddr, vmsize = struct.unpack_from(e + "QQ", body, 24)
                maxprot, initprot = struct.unpack_from(e + "ii", body, 24 + 32)
                nsects = struct.unpack_from(e + "I", body, 24 + 40)[0]
                shdr, ssz = 72, 80
            else:
                vmaddr, vmsize = struct.unpack_from(e + "II", body, 24)
                maxprot, initprot = struct.unpack_from(e + "ii", body, 24 + 16)
                nsects = struct.unpack_from(e + "I", body, 24 + 24)[0]
                shdr, ssz = 56, 68
            perms = ("r" if initprot & 1 else "-") + ("w" if initprot & 2 else "-") + ("x" if initprot & 4 else "-")
            segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize, "perms": perms})
            # secciones del segmento (para Obj-C/Swift metadata): sectname, addr, offset, size
            for si in range(min(nsects, 256)):
                so = shdr + si * ssz
                if so + ssz > len(body):
                    break
                sect = body[so:so + 16].split(b"\x00")[0].decode("ascii", "replace")
                if is64:
                    saddr, ssize = struct.unpack_from(e + "QQ", body, so + 32)
                    soff = struct.unpack_from(e + "I", body, so + 48)[0]
                else:
                    saddr, ssize = struct.unpack_from(e + "II", body, so + 32)
                    soff = struct.unpack_from(e + "I", body, so + 40)[0]
                sections.append({"sect": sect, "seg": name, "addr": saddr, "offset": soff, "size": ssize})
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB):
            noff = struct.unpack_from(e + "I", body, 8)[0]
            if 0 < noff < len(body):
                dylibs.append(body[noff:].split(b"\x00")[0].decode("utf-8", "replace"))
        elif cmd == LC_MAIN:
            entry = struct.unpack_from(e + "Q", body, 8)[0]
        elif cmd == LC_UUID:
            uuid = body[8:24].hex()
        o += cmdsize
    return {"bits": bits, "endian": endian, "arch": _CPU.get(cputype, hex(cputype)),
            "filetype": _FILETYPES.get(filetype, str(filetype)), "ncmds": ncmds,
            "flags": flags, "pie": bool(flags & MH_PIE),
            "allow_stack_exec": bool(flags & MH_ALLOW_STACK_EXECUTION),
            "segments": segments, "dylibs": dylibs, "entry": entry, "uuid": uuid,
            "rwx_segments": [s["name"] for s in segments if "w" in s["perms"] and "x" in s["perms"]],
            "objc": _objc_metadata(data, sections, bits),
            "swift": _swift_metadata(sections, bits)}


def _cstrings(data: bytes, off: int, size: int, cap: int = 4000):
    """Cadenas C (terminadas en NUL) de una seccion __cstring-like. Acotado."""
    out = []
    if off <= 0 or size <= 0 or off + size > len(data):
        return out
    for piece in data[off:off + size].split(b"\x00"):
        if piece:
            try:
                out.append(piece.decode("utf-8"))
            except UnicodeDecodeError:
                out.append(piece.decode("latin-1", "replace"))
        if len(out) >= cap:
            break
    return out


def _objc_metadata(data: bytes, sections: list, bits: str) -> dict:
    """Metadatos Obj-C derivados de las secciones __objc_* (estatico, sin runtime).
    - __objc_classname: nombres de clase (C-strings)
    - __objc_methname:  nombres de selector/metodo (C-strings)
    - __objc_classlist / __objc_protolist: conteo por numero de punteros
    Grounded: los nombres son exactamente las cadenas que el compilador emite; NO se camina la
    jerarquia de clases (eso requiere resolver class_ro_t via VM->offset)."""
    byname = {}
    for s in sections:
        byname.setdefault(s["sect"], s)
    if not any(k.startswith("__objc") for k in byname):
        return {"present": False}
    word = 8 if bits == "64" else 4
    classes = sorted(set(_cstrings(data, byname["__objc_classname"]["offset"],
                                   byname["__objc_classname"]["size"]))) if "__objc_classname" in byname else []
    methods = sorted(set(_cstrings(data, byname["__objc_methname"]["offset"],
                                   byname["__objc_methname"]["size"]))) if "__objc_methname" in byname else []
    def _ptrcount(name):
        s = byname.get(name)
        return (s["size"] // word) if s and s["size"] else 0
    return {"present": True,
            "class_count": _ptrcount("__objc_classlist") or len(classes),
            "classes": classes[:200],
            "protocol_count": _ptrcount("__objc_protolist"),
            "category_count": _ptrcount("__objc_catlist"),
            "selector_count": len(methods), "selectors": methods[:200]}


def _swift_metadata(sections: list, bits: str) -> dict:
    """Presencia y conteos de metadatos Swift5 (secciones __swift5_*). Cada descriptor es un offset
    relativo de 4 bytes, asi que size/4 aproxima el numero de entradas."""
    byname = {s["sect"]: s for s in sections}
    swift = {k: v for k, v in byname.items() if k.startswith("__swift5")}
    if not swift:
        return {"present": False}
    def _cnt(name):
        s = byname.get(name)
        return (s["size"] // 4) if s and s["size"] else 0
    return {"present": True, "sections": sorted(swift.keys()),
            "type_count": _cnt("__swift5_types"),
            "proto_count": _cnt("__swift5_proto"),
            "proto_conformance_count": _cnt("__swift5_protos"),
            "field_md": "__swift5_fieldmd" in byname}


def inspect_macho(path: str) -> dict:
    """Parse a Mach-O (thin or fat). Returns {ok, is_macho, images:[...]} or {is_macho: False}."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as ex:
        return {"ok": False, "is_macho": False, "note": f"no se pudo leer: {ex}"}
    if len(data) < 8:
        return {"ok": True, "is_macho": False, "note": "demasiado corto"}
    first = struct.unpack_from(">I", data, 0)[0]
    try:
        if first in _FAT:
            big = first in (0xCAFEBABE, 0xCAFEBABF)
            e = ">" if big else "<"
            nfat = struct.unpack_from(e + "I", data, 4)[0]
            images = []
            for i in range(min(nfat, 16)):
                off = 8 + i * 20
                offset = struct.unpack_from(e + "I", data, off + 8)[0]
                if offset + 4 <= len(data):
                    m = struct.unpack_from("<I", data, offset)[0]
                    if m not in _MAGICS:
                        m = struct.unpack_from(">I", data, offset)[0]
                    if m in _MAGICS:
                        images.append(_one_macho(data, offset, m))
            return {"ok": True, "is_macho": True, "fat": True, "images": images,
                    "limitations": ["binario universal (fat): se listan las slices"]}
        le = struct.unpack_from("<I", data, 0)[0]
        be = struct.unpack_from(">I", data, 0)[0]
        magic = le if le in _MAGICS else (be if be in _MAGICS else None)
        if magic is None:
            return {"ok": True, "is_macho": False, "note": "sin magic Mach-O"}
        return {"ok": True, "is_macho": True, "fat": False, "images": [_one_macho(data, 0, magic)],
                "limitations": ["no se desensambla codigo; protecciones por flags/initprot"]}
    except Exception as ex:
        return {"ok": True, "is_macho": True, "note": f"Mach-O malformado: {ex}"}


def render_macho(r: dict) -> str:
    out = ["## Inspeccion de Mach-O (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_macho"):
        return "\n".join(out + ["- No es un Mach-O: " + r.get("note", "")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    if r.get("fat"):
        out.append(f"- binario universal (fat) con {len(r.get('images') or [])} slices")
    for idx, im in enumerate(r.get("images") or []):
        out.append(f"\n### imagen {idx}: {im['arch']} {im['bits']}-bit {im['endian']}  ({im['filetype']})")
        out.append(f"- PIE: **{'si' if im['pie'] else 'no'}**  |  pila ejecutable permitida: "
                   f"**{'SI (peligro)' if im['allow_stack_exec'] else 'no'}**  |  flags: {hex(im['flags'])}")
        if im.get("entry") is not None:
            out.append(f"- entrypoint (LC_MAIN offset): {hex(im['entry'])}")
        if im.get("uuid"):
            out.append(f"- uuid: {im['uuid']}")
        if im.get("dylibs"):
            out.append(f"- dylibs ({len(im['dylibs'])}): " + ", ".join(im["dylibs"][:20]))
        if im.get("segments"):
            out.append("- segmentos: " + ", ".join(f"{s['name']}({s['perms']})" for s in im["segments"][:20]))
        if im.get("rwx_segments"):
            out.append(f"- **segmentos W+X: {', '.join(im['rwx_segments'])}**")
        objc = im.get("objc") or {}
        if objc.get("present"):
            out.append(f"- **Obj-C**: {objc.get('class_count')} clases, {objc.get('protocol_count')} "
                       f"protocolos, {objc.get('category_count')} categorias, "
                       f"{objc.get('selector_count')} selectores")
            if objc.get("classes"):
                out.append("  - clases: " + ", ".join(objc["classes"][:20]))
            if objc.get("selectors"):
                out.append("  - selectores: " + ", ".join(objc["selectors"][:20]))
        swift = im.get("swift") or {}
        if swift.get("present"):
            out.append(f"- **Swift**: {swift.get('type_count')} tipos, "
                       f"{swift.get('proto_count')} protocolos; secciones: {', '.join(swift['sections'])}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
