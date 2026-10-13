"""Unified artifact identifier + router: detect the format and dispatch to the right reader.

One entry point that sniffs an artifact's magic/structure and routes to the matching grounded
reader -- ELF (layout, or core dump, or Go build-info), Mach-O, PE/.NET, WebAssembly, SQLite,
Android APK (ZIP), or a HAR capture. Returns the detected format and that reader's result. This is
the "reverse engineer anything" front door: give it any file and it figures out what it is and what
binoracle can say about it, with nothing executed."""
from __future__ import annotations


def _read_head(path: str, n: int = 64) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def detect_format(path: str) -> str:
    """Return a short format tag by sniffing magic/structure. 'unknown' if nothing matches."""
    try:
        head = _read_head(path, 64)
    except Exception:
        return "unknown"
    if len(head) < 4:
        return "unknown"
    if head[:4] == b"\x7fELF":
        # ET_CORE is e_type==4 at offset 16 (little) / 17 (big)
        et = head[16] if head[5] == 1 else head[17]
        return "elf-core" if et == 4 else "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") \
            or head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return "macho"
    if head[:4] == b"\x00asm":
        return "wasm"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if head[:2] == b"MZ":
        return "pe"
    if head[:2] == b"PK" and head[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08"):
        return "zip"
    # text-ish: HAR (JSON with log.entries)
    stripped = head.lstrip()
    if stripped[:1] == b"{":
        try:
            import json
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
            if isinstance(doc, dict) and isinstance(doc.get("log"), dict) and "entries" in doc["log"]:
                return "har"
        except Exception:
            pass
        return "json"
    return "unknown"


def identify(path: str) -> dict:
    """Detect the format and run the matching reader. Returns {ok, format, detail:{...reader...}}."""
    import os
    if not os.path.exists(path):
        return {"ok": False, "format": "unknown", "note": f"no existe: {path}"}
    fmt = detect_format(path)
    detail = None
    routed = fmt
    try:
        if fmt == "elf-core":
            from .coredump import inspect_core
            detail = inspect_core(path)
        elif fmt == "elf":
            # prefer Go build-info if present, else the ELF layout
            from .goinspect import inspect_go
            go = inspect_go(path)
            if go.get("is_go"):
                routed = "elf-go"
                detail = go
            else:
                from .elflayout import inspect_elf
                detail = inspect_elf(path)
        elif fmt == "macho":
            from .machoinspect import inspect_macho
            detail = inspect_macho(path)
        elif fmt == "wasm":
            from .wasminspect import inspect_wasm
            detail = inspect_wasm(path)
        elif fmt == "sqlite":
            from .sqliteinspect import inspect_sqlite
            detail = inspect_sqlite(path)
        elif fmt == "pe":
            from .dotnetinspect import inspect_dotnet
            dn = inspect_dotnet(path)
            routed = "pe-dotnet" if dn.get("is_dotnet") else "pe"
            detail = dn
        elif fmt == "zip":
            from .apkinspect import inspect_apk
            apk = inspect_apk(path)
            routed = "apk" if apk.get("is_apk") else "zip"
            detail = apk
        elif fmt in ("har", "json"):
            from .harinspect import inspect_har
            har = inspect_har(path)
            routed = "har" if har.get("is_har") else "json"
            detail = har
    except Exception as e:
        return {"ok": True, "format": fmt, "routed": routed, "note": f"error al enrutar: {e}"}
    return {"ok": True, "format": fmt, "routed": routed, "detail": detail}


def render_identify(r: dict) -> str:
    out = ["## Identificacion de artefacto\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- formato detectado: **{r.get('routed') or r.get('format')}**")
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    routed = r.get("routed")
    detail = r.get("detail")
    if detail is None:
        out.append("- (sin lector especifico para este formato en binoracle; "
                    "prueba `triage`/`analyze_chains` para ELF/PE)")
        return "\n".join(out)
    renderers = {
        "elf-core": ("coredump", "render_core"), "elf": ("elflayout", "render_elf"),
        "elf-go": ("goinspect", "render_go"), "macho": ("machoinspect", "render_macho"),
        "wasm": ("wasminspect", "render_wasm"), "sqlite": ("sqliteinspect", "render_sqlite"),
        "pe-dotnet": ("dotnetinspect", "render_dotnet"), "pe": ("dotnetinspect", "render_dotnet"),
        "apk": ("apkinspect", "render_apk"), "zip": ("apkinspect", "render_apk"),
        "har": ("harinspect", "render_har"), "json": ("harinspect", "render_har"),
    }
    mod_fn = renderers.get(routed)
    if mod_fn:
        import importlib
        mod = importlib.import_module("binoracle.workflows." + mod_fn[0])
        out.append("\n" + getattr(mod, mod_fn[1])(detail))
    return "\n".join(out)
