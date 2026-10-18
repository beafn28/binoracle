"""Static ASAR (Electron app archive) reader: file tree, entry point, package.json, integrity.

Electron desktop apps ship their JavaScript inside an `app.asar` archive. ASAR is a simple
concatenation format with a JSON header (a Chromium Pickle) describing a file tree, followed by
the raw file bytes. This reads it straight from bytes -- no Node, nothing executed: the file/
directory inventory, the embedded `package.json` (name, version, `main` entry point, declared
dependencies), the JavaScript modules present, and the per-file `integrity` block (SHA-256 of the
header / blocks) that newer Electron embeds. Because the header carries each file's offset+size, we
can slice the (small) `package.json` out of the archive without executing anything. Design adapted
from REA's JS/Electron tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

import json


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


def _parse_header(raw: bytes):
    """Return (header_dict, data_base_offset) or raise. ASAR layout: pickle1 (bytes[0:8]) holds the
    size of pickle2; pickle2 (at offset 8) holds the JSON header string; file data starts right
    after pickle2."""
    if len(raw) < 16:
        raise ValueError("demasiado corto para una cabecera ASAR")
    if _u32(raw, 0) != 4:
        raise ValueError("primer campo pickle != 4 (no es ASAR)")
    header_size = _u32(raw, 4)                 # size of pickle2 buffer (starts at offset 8)
    if header_size < 8 or 8 + header_size > len(raw):
        raise ValueError("header_size fuera de rango")
    str_len = _u32(raw, 12)                     # length of the JSON string
    start = 16
    if start + str_len > len(raw):
        raise ValueError("string de cabecera truncado")
    text = raw[start:start + str_len].decode("utf-8", "replace")
    header = json.loads(text)
    if not isinstance(header, dict) or "files" not in header:
        raise ValueError("cabecera sin 'files'")
    return header, 8 + header_size


def _walk(node: dict, prefix: str, files: list, dirs: list, depth: int = 0):
    if depth > 64:
        return
    for name, meta in (node.get("files") or {}).items():
        path = f"{prefix}/{name}" if prefix else name
        if isinstance(meta, dict) and "files" in meta:
            dirs.append(path)
            _walk(meta, path, files, dirs, depth + 1)
        elif isinstance(meta, dict):
            entry = {"path": path, "size": meta.get("size")}
            if "offset" in meta:
                entry["offset"] = meta["offset"]
            if meta.get("unpacked"):
                entry["unpacked"] = True
            if meta.get("executable"):
                entry["executable"] = True
            if "integrity" in meta and isinstance(meta["integrity"], dict):
                integ = meta["integrity"]
                entry["integrity"] = {"algorithm": integ.get("algorithm"),
                                      "hash": (integ.get("hash") or "")[:32]}
            files.append(entry)


def _find(files: list, target: str):
    for f in files:
        if f["path"] == target or f["path"].endswith("/" + target):
            return f
    return None


def _slice_file(raw: bytes, data_base: int, entry: dict):
    """Return the raw bytes of a file entry, or None (unpacked files live outside the archive)."""
    if entry.get("unpacked") or "offset" not in entry:
        return None
    try:
        off = int(entry["offset"])
        size = int(entry["size"])
    except (TypeError, ValueError):
        return None
    start = data_base + off
    if start < 0 or start + size > len(raw) or size < 0 or size > 4_000_000:
        return None
    return raw[start:start + size]


def inspect_asar(path: str) -> dict:
    """Parse an Electron ASAR archive statically. Returns {ok, is_asar, file_count, dir_count,
    entry_point, package, js_files, integrity, ...}."""
    from ._artifact import read_bounded, ArtifactTooLarge
    try:
        raw = read_bounded(path)
    except ArtifactTooLarge as e:
        return {"ok": False, "is_asar": False, "note": str(e)}
    except Exception as e:
        return {"ok": False, "is_asar": False, "note": f"no se pudo leer: {e}"}
    try:
        header, data_base = _parse_header(raw)
    except Exception as e:
        return {"ok": True, "is_asar": False, "note": f"no es un ASAR valido: {e}"}
    files, dirs = [], []
    _walk(header, "", files, dirs)
    out = {"ok": True, "is_asar": True, "file_count": len(files), "dir_count": len(dirs),
           "header_integrity": None}
    if isinstance(header.get("files"), dict):
        # archive-level integrity sometimes lives on the root node in newer Electron
        root_integ = header.get("integrity")
        if isinstance(root_integ, dict):
            out["header_integrity"] = {"algorithm": root_integ.get("algorithm"),
                                       "hash": (root_integ.get("hash") or "")[:32]}
    # package.json: slice and parse (name/version/main/deps) without executing anything
    pkg_entry = _find(files, "package.json")
    if pkg_entry is not None:
        blob = _slice_file(raw, data_base, pkg_entry)
        if blob is not None:
            try:
                pkg = json.loads(blob.decode("utf-8", "replace"))
                out["package"] = {
                    "name": pkg.get("name"), "version": pkg.get("version"),
                    "main": pkg.get("main"), "productName": pkg.get("productName"),
                    "dependencies": sorted((pkg.get("dependencies") or {}).keys())[:60],
                    "electron_version": (pkg.get("devDependencies") or {}).get("electron"),
                }
                out["entry_point"] = pkg.get("main")
            except Exception as e:
                out["package_error"] = f"package.json ilegible: {e}"
    js_files = [f["path"] for f in files if f["path"].endswith((".js", ".mjs", ".cjs"))]
    out["js_files"] = js_files[:200]
    out["js_count"] = len(js_files)
    out["node_modules"] = sorted({f["path"].split("/")[1] for f in files
                                  if f["path"].startswith("node_modules/")
                                  and len(f["path"].split("/")) > 1})[:80]
    integ_count = sum(1 for f in files if "integrity" in f)
    out["integrity_files"] = integ_count
    out["sample"] = [f["path"] for f in files[:40]]
    out["limitations"] = ["se lista el arbol y se extrae package.json; NO se ejecuta ni se "
                          "desminifica JS; los ficheros 'unpacked' viven fuera del .asar (en "
                          "app.asar.unpacked) y no se incluyen"]
    return out


def render_asar(r: dict) -> str:
    out = ["## Inspeccion de archivo ASAR (Electron, estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_asar"):
        return "\n".join(out + ["- No es un ASAR: " + r.get("note", "")])
    out.append(f"- ficheros: {r.get('file_count')}  |  directorios: {r.get('dir_count')}  |  "
               f"JS: {r.get('js_count')}")
    pkg = r.get("package") or {}
    if pkg:
        out.append("\n### package.json")
        out.append(f"- nombre: {pkg.get('name')}  |  version: {pkg.get('version')}")
        if pkg.get("productName"):
            out.append(f"- productName: {pkg.get('productName')}")
        out.append(f"- punto de entrada (main): **{pkg.get('main')}**")
        if pkg.get("electron_version"):
            out.append(f"- electron (devDependency): {pkg.get('electron_version')}")
        deps = pkg.get("dependencies") or []
        if deps:
            out.append(f"- dependencias ({len(deps)}): " + ", ".join(deps[:40]))
    elif r.get("package_error"):
        out.append(f"- {r['package_error']}")
    nm = r.get("node_modules") or []
    if nm:
        out.append(f"\n- node_modules empaquetados ({len(nm)}): " + ", ".join(nm[:40]))
    if r.get("header_integrity"):
        hi = r["header_integrity"]
        out.append(f"- integridad de cabecera: {hi.get('algorithm')} {hi.get('hash')}…")
    if r.get("integrity_files"):
        out.append(f"- ficheros con bloque de integridad: {r['integrity_files']}")
    sample = r.get("sample") or []
    if sample:
        out.append(f"\n### Muestra del arbol ({len(sample)})")
        for p in sample:
            out.append(f"- {p}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
