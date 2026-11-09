"""Static property-list reader (Apple Info.plist etc.): bundle id, executable, versions, usage keys.

Reads a binary or XML plist with the built-in plistlib (no execution) and surfaces the
reverse-engineering-relevant keys of an Apple bundle's Info.plist: bundle identifier, executable
name, display name, versions, minimum OS, URL schemes, and the privacy usage-description keys
(camera/location/microphone...) that reveal what the app touches. Design adapted from REA's Apple
bundle tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

_NOTABLE = [
    ("CFBundleIdentifier", "bundle_id"), ("CFBundleName", "name"),
    ("CFBundleDisplayName", "display_name"), ("CFBundleExecutable", "executable"),
    ("CFBundleShortVersionString", "version"), ("CFBundleVersion", "build"),
    ("MinimumOSVersion", "min_os"), ("LSMinimumSystemVersion", "min_macos"),
    ("DTPlatformName", "platform"),
]


def inspect_plist(path: str) -> dict:
    """Parse a plist. Returns {ok, is_plist, bundle_id, ..., usage_descriptions, url_schemes}."""
    import plistlib
    from ._artifact import read_bounded, ArtifactTooLarge
    try:
        raw = read_bounded(path)
    except ArtifactTooLarge as e:
        return {"ok": False, "is_plist": False, "note": str(e)}
    except Exception as e:
        return {"ok": False, "is_plist": False, "note": f"no se pudo leer: {e}"}
    head = raw[:8]
    if not (head[:8] == b"bplist00" or raw.lstrip()[:5] == b"<?xml" or raw.lstrip()[:6] == b"<plist"):
        return {"ok": True, "is_plist": False, "note": "sin cabecera plist (bplist00 o XML)"}
    try:
        doc = plistlib.loads(raw)
    except Exception as e:
        return {"ok": True, "is_plist": True, "note": f"plist malformado: {e}"}
    if not isinstance(doc, dict):
        return {"ok": True, "is_plist": True, "note": "plist raiz no es un diccionario",
                "root_type": type(doc).__name__}
    out = {"ok": True, "is_plist": True, "format": "binary" if head[:8] == b"bplist00" else "xml"}
    for key, alias in _NOTABLE:
        if key in doc:
            out[alias] = doc[key]
    # privacy usage descriptions (NS...UsageDescription) -> what the app accesses
    usage = {k: v for k, v in doc.items() if k.endswith("UsageDescription")}
    if usage:
        out["usage_descriptions"] = usage
    # URL schemes it registers
    schemes = []
    for entry in (doc.get("CFBundleURLTypes") or []):
        for s in (entry.get("CFBundleURLSchemes") or []):
            schemes.append(s)
    if schemes:
        out["url_schemes"] = schemes
    out["key_count"] = len(doc)
    out["limitations"] = ["solo claves de alto nivel; no se resuelven referencias ni binarios enlazados"]
    return out


def render_plist(r: dict) -> str:
    out = ["## Inspeccion de plist (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_plist"):
        return "\n".join(out + ["- No es un plist: " + r.get("note", "")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    out.append(f"- formato: {r.get('format')}  |  claves: {r.get('key_count')}")
    for alias, label in (("bundle_id", "bundle id"), ("name", "nombre"), ("display_name", "display"),
                         ("executable", "ejecutable"), ("version", "version"), ("build", "build"),
                         ("min_os", "min iOS"), ("min_macos", "min macOS"), ("platform", "plataforma")):
        if r.get(alias) is not None:
            out.append(f"- {label}: {r[alias]}")
    if r.get("url_schemes"):
        out.append(f"- esquemas URL: {', '.join(map(str, r['url_schemes']))}")
    usage = r.get("usage_descriptions") or {}
    if usage:
        out.append(f"\n### Permisos de privacidad declarados ({len(usage)})")
        for k, v in usage.items():
            out.append(f"- {k}: {str(v)[:80]}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
