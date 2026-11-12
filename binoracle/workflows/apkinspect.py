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


def extract_native_libs(path: str, out_dir: str, abi: str = "") -> list:
    """Extrae a disco las librerias nativas (.so) de una APK -- son ELF normales (ARM/x86/x86_64),
    con la MISMA superficie de corrupcion de memoria que cualquier otro binario. Bug/gap real:
    este modulo (y el resto del analisis de APK) solo LISTA los .so por ABI (via inspect_apk),
    pero nunca los saca a disco -- sin eso, no hay forma de apuntar el pipeline de exploiting que
    binoracle ya tiene (`hunt`/`cveplan`/`autopwn`/`chainanalyzer`) contra una libreria nativa real
    empaquetada en una app (juegos, codecs multimedia, JNI a medida son el caso tipico de un .so
    vulnerable dentro de una APK). Con `abi` vacio extrae TODAS las ABIs; si se da, solo esa.
    Devuelve la lista de rutas extraidas (vacia si la APK no tiene .so o el ABI pedido no existe)."""
    import os
    import zipfile
    out = []
    try:
        zf = zipfile.ZipFile(path)
    except Exception:
        return out
    try:
        os.makedirs(out_dir, exist_ok=True)
        for n in zf.namelist():
            if not (n.startswith("lib/") and n.endswith(".so")):
                continue
            parts = n.split("/")
            if len(parts) < 3:
                continue
            lib_abi, soname = parts[1], parts[-1]
            if abi and lib_abi != abi:
                continue
            dest_dir = os.path.join(out_dir, lib_abi)
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, soname)
            with open(dest, "wb") as f:
                f.write(zf.read(n))
            out.append(dest)
    except Exception:
        pass
    return out


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
        result = {"ok": True, "is_apk": True, "entry_count": len(names),
                "has_manifest": has_manifest, "dex": dex,
                "native_abis": sorted(libs_by_abi.keys()),
                "native_libs": {k: sorted(set(v)) for k, v in libs_by_abi.items()},
                "frameworks": sorted(frameworks), "flutter_snapshots": lib_digests,
                "signing": {"v1_jar": v1, "v2_v3_block": v2v3},
                "limitations": ["AndroidManifest.xml es binario (AXML): se detecta pero no se decodifica "
                                "a texto (requiere un decodificador AXML/Apktool); no se desensambla DEX"]}
        # Opcional, sin romper el diseno "puro" (zipfile, nada ejecutado) de este modulo: si
        # apktool SI esta instalado, apunta a `binoracle audit`/`androidmanifest` para el
        # desglose completo del manifest, en vez de dejar la nota de arriba sonando a limite
        # permanente cuando en realidad es solo "esta funcion en concreto no lo hace".
        # Gap visto probando esto en vivo contra InsecureBankv2.apk: `binoracle apk` (el
        # comando "rapido") sigue diciendo "no decodifica AXML" incluso con apktool presente
        # y `binoracle audit` ya decodificandolo perfectamente -- confuso para quien solo
        # prueba `apk` primero.
        if has_manifest:
            try:
                from .androidmanifest import project_mobile_application_graph
                g = project_mobile_application_graph(path)
            except Exception:
                g = {"ok": False}
            if g.get("ok"):
                result["manifest_package"] = g.get("package")
                result["manifest_permissions"] = g.get("permissions")
                result["manifest_component_count"] = g.get("component_count")
                result["manifest_exported_count"] = g.get("exported_count")
                result["limitations"][0] = ("AndroidManifest.xml decodificado (apktool): paquete/"
                                            "permisos/componentes abajo; para el desglose completo "
                                            "(flags debuggable/allowBackup, componentes exportados "
                                            "con sus intent-filters) usa `binoracle audit`.")
        return result
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
    if r.get("manifest_package") is not None:
        out.append(f"- paquete: **{r.get('manifest_package')}**  |  componentes: "
                   f"{r.get('manifest_component_count')} (exportados: "
                   f"{r.get('manifest_exported_count')})  |  permisos: "
                   f"{len(r.get('manifest_permissions') or [])}")
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
