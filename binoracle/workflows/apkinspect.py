"""Static Android APK reader: DEX, native libraries, framework, signature, Flutter snapshot.

An APK is a ZIP; this reads it with the built-in zipfile (no Apktool, nothing executed): the DEX
files, the native libraries grouped by ABI, the app framework it detects (Flutter via libapp.so /
libflutter.so, React Native, Unity, Xamarin), the signing files (v1 JAR signature, and v2/v3 via
the APK Signing Block), and SHA-256 digests of the key native libs (e.g. the Flutter Dart snapshot
in libapp.so per ABI). The binary AndroidManifest.xml is detected but not decoded to text (that
needs an AXML decoder / Apktool); that limit is reported. Design adapted from REA's Android/Flutter
tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

import hashlib

_FRAMEWORK_MARKERS = {
    "libflutter.so": "Flutter", "libapp.so": "Flutter",
    "libreactnativejni.so": "React Native", "libjsc.so": "React Native",
    "libhermes.so": "React Native (Hermes)", "libunity.so": "Unity",
    "libil2cpp.so": "Unity (IL2CPP)", "libmonodroid.so": "Xamarin/.NET",
    "libmono-native.so": "Xamarin/.NET",
}


def inspect_apk(path: str) -> dict:
    """Read an APK (zip). Returns {ok, is_apk, dex, native_libs, frameworks, signing, ...}."""
    import zipfile
    try:
        if not zipfile.is_zipfile(path):
            return {"ok": True, "is_apk": False, "note": "no es un ZIP (los APK son ZIP)"}
        zf = zipfile.ZipFile(path)
    except Exception as e:
        return {"ok": False, "is_apk": False, "note": f"no se pudo abrir: {e}"}
    try:
        names = zf.namelist()
        has_manifest = "AndroidManifest.xml" in names
        if not has_manifest and not any(n.endswith(".dex") for n in names):
            return {"ok": True, "is_apk": False, "note": "sin AndroidManifest.xml ni .dex (no parece APK)"}
        dex = sorted(n for n in names if n.endswith(".dex"))
        libs_by_abi = {}
        frameworks = set()
        lib_digests = {}
        for n in names:
            if n.startswith("lib/") and n.endswith(".so"):
                parts = n.split("/")
                if len(parts) >= 3:
                    abi, soname = parts[1], parts[-1]
                    libs_by_abi.setdefault(abi, []).append(soname)
                    if soname in _FRAMEWORK_MARKERS:
                        frameworks.add(_FRAMEWORK_MARKERS[soname])
                    if soname in ("libapp.so", "libflutter.so"):
                        try:
                            data = zf.read(n)
                            lib_digests[f"{abi}/{soname}"] = {
                                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                        except Exception:
                            pass
        # signing: v1 (META-INF/*.RSA|DSA|EC) + v2/v3 (APK Signing Block before the central dir)
        v1 = sorted(n for n in names if n.startswith("META-INF/")
                    and n.upper().endswith((".RSA", ".DSA", ".EC", ".SF")))
        v2v3 = _has_apk_sig_block(path)
        return {"ok": True, "is_apk": True, "entry_count": len(names),
                "has_manifest": has_manifest, "dex": dex,
                "native_abis": sorted(libs_by_abi.keys()),
                "native_libs": {k: sorted(set(v)) for k, v in libs_by_abi.items()},
                "frameworks": sorted(frameworks), "flutter_snapshots": lib_digests,
                "signing": {"v1_jar": v1, "v2_v3_block": v2v3},
                "limitations": ["AndroidManifest.xml es binario (AXML): se detecta pero no se decodifica "
                                "a texto (requiere un decodificador AXML/Apktool); no se desensambla DEX"]}
    except Exception as e:
        return {"ok": True, "is_apk": True, "note": f"APK malformado: {e}"}
    finally:
        try:
            zf.close()
        except Exception:
            pass


def _has_apk_sig_block(path: str) -> bool:
    """Detect the APK Signing Block v2/v3 by its magic 'APK Sig Block 42' before the ZIP central dir."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        return b"APK Sig Block 42" in data
    except Exception:
        return False


def render_apk(r: dict) -> str:
    out = ["## Inspeccion de APK Android (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_apk"):
        return "\n".join(out + ["- No es un APK: " + r.get("note", "")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    out.append(f"- entradas: {r.get('entry_count')}  |  AndroidManifest.xml: "
               f"{'si' if r.get('has_manifest') else 'no'}  |  DEX: {len(r.get('dex') or [])}")
    if r.get("frameworks"):
        out.append(f"- framework detectado: **{', '.join(r['frameworks'])}**")
    if r.get("native_abis"):
        out.append(f"- ABIs nativas: {', '.join(r['native_abis'])}")
    for abi, libs in (r.get("native_libs") or {}).items():
        out.append(f"  - {abi}: {', '.join(libs[:20])}")
    fs = r.get("flutter_snapshots") or {}
    if fs:
        out.append("\n### Snapshots Flutter (libapp/libflutter)")
        for k, v in fs.items():
            out.append(f"- {k}: sha256={v['sha256'][:16]}… ({v['size']} B)")
    sign = r.get("signing") or {}
    out.append(f"\n- firma v1 (JAR): {', '.join(sign.get('v1_jar') or []) or 'no'}")
    out.append(f"- bloque de firma v2/v3: {'si' if sign.get('v2_v3_block') else 'no'}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
