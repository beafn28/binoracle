"""Static Go build-information reader: compiler version, modules, replacements and build settings.

Go embeds a build-info blob in every binary (what `go version -m` prints). This reads it WITHOUT a
Go toolchain and without running the target, purely by parsing bytes -- a grounded reversing fact
for Go malware/CTF targets. The format: a magic header `\xff Go buildinf:`, then ptrSize/flags;
in the modern inline encoding (Go 1.18+) the compiler version and module text follow as
uvarint-length-prefixed strings; the module text is framed by two 16-byte sentinels and carries
`path`/`mod`/`dep`/`=>`/`build` lines. Absence of the blob is NOT a verdict that the binary is not
Go (it can be stripped) -- we report what we observe and its limits. Design adapted from REA
(morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

MAGIC = bytes.fromhex("ff20476f206275696c64696e663a")        # "\xff Go buildinf:"
MODULE_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
MODULE_END = bytes.fromhex("f932433186182072008242104116d8f2")
_MAX = 1024 * 1024


def _uvarint(buf: bytes, off: int):
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("uvarint truncado")
        b = buf[off]
        off += 1
        if shift >= 63 and b > 1:
            raise ValueError("uvarint desborda 64 bits")
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def _read_inline(buf: bytes, off: int):
    n, p = _uvarint(buf, off)
    if n > _MAX or p + n > len(buf):
        raise ValueError("string inline fuera de rango")
    return buf[p:p + n], p + n


def _vaddr_to_off(path: str, vaddr: int, size: int):
    """Map a virtual address to a file offset via ELF PT_LOAD segments (pyelftools)."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                va, fsz, foff = seg["p_vaddr"], seg["p_filesz"], seg["p_offset"]
                if va <= vaddr and vaddr + size <= va + fsz:
                    return foff + (vaddr - va)
    except Exception:
        return None
    return None


def _word(buf: bytes, off: int, ptr_size: int, little: bool) -> int:
    chunk = buf[off:off + ptr_size]
    if len(chunk) != ptr_size:
        raise ValueError("puntero truncado")
    return int.from_bytes(chunk, "little" if little else "big")


def _read_pointer_string(path: str, buf: bytes, hdr_vaddr_base, header: int,
                         field_off: int, ptr_size: int, little: bool) -> bytes:
    """Pointer encoding (older Go): the field holds a vaddr of a Go string header {dataPtr, len}."""
    str_hdr_va = _word(buf, field_off, ptr_size, little)
    if str_hdr_va == 0:
        return b""
    hdr_off = _vaddr_to_off(path, str_hdr_va, 2 * ptr_size)
    if hdr_off is None:
        raise ValueError("no se pudo mapear la cabecera de string (modo puntero)")
    data_va = _word(buf, hdr_off, ptr_size, little)
    length = _word(buf, hdr_off + ptr_size, ptr_size, little)
    if length <= 0 or length > _MAX:
        return b""
    data_off = _vaddr_to_off(path, data_va, length)
    if data_off is None:
        raise ValueError("no se pudo mapear los bytes del string (modo puntero)")
    return buf[data_off:data_off + length]


def _parse_module_text(text: str) -> dict:
    """Parse the `go version -m` module text into main module, deps, replacements, build settings."""
    main_path = None
    main = None
    deps = []
    build = {}
    last = None
    for line in text.split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag == "path" and len(parts) >= 2:
            main_path = parts[1]
        elif tag == "mod" and len(parts) >= 3:
            main = {"path": parts[1], "version": parts[2], "sum": parts[3] if len(parts) > 3 else None}
            last = main
        elif tag == "dep" and len(parts) >= 3:
            d = {"path": parts[1], "version": parts[2], "sum": parts[3] if len(parts) > 3 else None,
                 "replacement": None}
            deps.append(d)
            last = d
        elif tag == "=>" and len(parts) >= 3 and last is not None:
            last["replacement"] = {"path": parts[1], "version": parts[2],
                                   "sum": parts[3] if len(parts) > 3 else None}
        elif tag == "build" and len(parts) >= 2:
            rest = "\t".join(parts[1:])
            if "=" in rest:
                k, v = rest.split("=", 1)
                build[k.strip()] = v
            elif len(parts) >= 3:
                build[parts[1]] = parts[2]
    return {"main_path": main_path, "main_module": main, "dependencies": deps, "build_settings": build}


def inspect_go(path: str) -> dict:
    """Read a binary's Go build info. Returns {is_go, go_version, module..., encoding, ...} or
    {is_go: False} when no build-info blob is present. Never raises on a normal missing blob."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        return {"ok": False, "is_go": False, "note": f"no se pudo leer: {e}"}
    i = data.find(MAGIC)
    if i < 0 or i + 16 > len(data):
        return {"ok": True, "is_go": False,
                "note": "sin blob 'Go buildinf:' (no es Go, o esta stripeado/empaquetado)"}
    try:
        ptr_size = data[i + 14]
        flags = data[i + 15]
        if flags & ~3:
            return {"ok": True, "is_go": True, "note": f"flags de buildinfo no soportados: {flags:#x}"}
        little = (flags & 1) == 0
        encoding = "inline" if (flags & 2) else "pointer"
        if encoding == "inline":
            ver_bytes, nxt = _read_inline(data, i + 32)
            mod_bytes, _ = _read_inline(data, nxt)
        else:
            if ptr_size not in (4, 8):
                return {"ok": True, "is_go": True, "note": f"ptrSize invalido: {ptr_size}"}
            ver_bytes = _read_pointer_string(path, data, None, i, i + 16, ptr_size, little)
            mod_bytes = _read_pointer_string(path, data, None, i, i + 16 + ptr_size, ptr_size, little)
        go_version = ver_bytes.decode("utf-8", "replace").strip()
        module_text = ""
        if len(mod_bytes) >= 33 and mod_bytes[:16] == MODULE_START and mod_bytes[-16:] == MODULE_END:
            module_text = mod_bytes[16:-16].decode("utf-8", "replace")
        parsed = _parse_module_text(module_text) if module_text else {
            "main_path": None, "main_module": None, "dependencies": [], "build_settings": {}}
        return {"ok": True, "is_go": True, "header_offset": i, "ptr_size": ptr_size,
                "byte_order": "little" if little else "big", "encoding": encoding,
                "go_version": go_version or None, "module_text": module_text, **parsed}
    except Exception as e:
        return {"ok": True, "is_go": True, "note": f"buildinfo malformado: {e}", "header_offset": i}


def render_go(r: dict) -> str:
    out = ["## Inspeccion de binario Go (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_go"):
        return "\n".join(out + ["- **No es un binario Go** (o esta stripeado): " + r.get("note", "")])
    out.append(f"- version del compilador: **{r.get('go_version') or '?'}**")
    out.append(f"- codificacion buildinfo: {r.get('encoding')}  |  ptr={r.get('ptr_size')}B  "
               f"|  orden: {r.get('byte_order')}  |  offset: {hex(r.get('header_offset', 0))}")
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    if r.get("main_path"):
        out.append(f"- modulo principal (path): `{r['main_path']}`")
    mm = r.get("main_module")
    if mm:
        out.append(f"- modulo: `{mm['path']}` {mm.get('version') or ''}")
    deps = r.get("dependencies") or []
    if deps:
        out.append(f"\n### Dependencias ({len(deps)})")
        for d in deps[:60]:
            line = f"- `{d['path']}` {d.get('version') or ''}"
            if d.get("replacement"):
                rep = d["replacement"]
                line += f"  => `{rep['path']}` {rep.get('version') or ''}"
            out.append(line)
        if len(deps) > 60:
            out.append(f"- ... (+{len(deps) - 60} mas)")
    bs = r.get("build_settings") or {}
    if bs:
        out.append("\n### Build settings")
        for k, v in list(bs.items())[:40]:
            out.append(f"- {k} = {v}")
    out.append("\n_Hecho observado por lectura estatica; la ausencia de buildinfo no prueba que no sea Go._")
    return "\n".join(out)
