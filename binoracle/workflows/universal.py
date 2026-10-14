"""Universal analyzer: one entry point for anything — a single artifact, a ZIP, or a folder.

Give it a file and it identifies the format and runs the right grounded analysis. Give it a ZIP or a
directory and it walks the tree, picks every artifact it recognizes (APK/DEX, ELF/Mach-O/PE/.NET,
wasm, jar/class, sqlite, plist, asar, HAR...) and analyzes ALL of them, then aggregates one report.

Routing:
  - an APK (even when the upload is a .zip that is really an APK) -> Android audit
    (manifest + decompiled Java + insecure-pattern scan),
  - a native ELF/Mach-O/PE -> the grounded reader (layout + mitigations),
  - any other recognized format -> its reader,
  - a ZIP/folder of several -> each of the above, aggregated.

Static and grounded: it never executes the target. Uploaded archives are untrusted, so extraction is
bounded (no path traversal, capped file count and total size) into a throwaway temp dir.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import zipfile

_MAX_FILES = 400              # artefactos a analizar como mucho
_MAX_TOTAL = 600 * 1024 * 1024  # 600 MB descomprimidos (anti zip-bomb)
# formatos que merecen analisis propio dentro de un bundle
_INTERESTING = {"elf", "elf-core", "macho", "pe", "wasm", "sqlite", "plist", "asar", "apk", "class"}


def _is_apk(path: str) -> bool:
    try:
        if path.lower().endswith(".apk"):
            return True
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        return any(n == "AndroidManifest.xml" or n.endswith(".dex") for n in names)
    except Exception:
        return False


def _safe_extract(zip_path: str) -> str:
    """Extrae un ZIP a un directorio temporal con cotas y sin path-traversal. Devuelve la ruta."""
    dest = tempfile.mkdtemp(prefix="binoracle_bundle_")
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename
            # rechaza rutas absolutas o con ".." (zip-slip)
            if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                continue
            total += info.file_size
            if total > _MAX_TOTAL:
                break
            try:
                z.extract(info, dest)
            except Exception:
                continue
    return dest


def _detect(path: str) -> str:
    from .identify import detect_format
    try:
        return detect_format(path)
    except Exception:
        return "unknown"


def _reader_md(path: str) -> str:
    """Resumen fundamentado de un artefacto via el identificador unificado."""
    from .identify import identify, render_identify
    try:
        return render_identify(identify(path))
    except Exception as e:
        return f"- error leyendo {os.path.basename(path)}: {e}"


def analyze_one(path: str, config=None, store=None, on_step=None, ai: bool = False) -> dict:
    """Analiza UN artefacto y devuelve {kind, title, md, findings}. Un APK va a la auditoria
    Android; el resto, a su lector fundamentado."""
    base = os.path.basename(path)
    if _is_apk(path):
        try:
            from .androidaudit import run_android_audit
            res = run_android_audit(path, llm=None, config=config, store=store, on_step=on_step)
            return {"kind": "apk", "title": base, "md": res.answer, "findings": res.findings}
        except Exception as e:
            return {"kind": "apk", "title": base, "md": f"error en auditoria Android: {e}", "findings": []}
    return {"kind": _detect(path), "title": base, "md": _reader_md(path), "findings": []}


def analyze_bundle(path: str, config=None, store=None, on_step=None, ai: bool = False) -> dict:
    """Analiza un ZIP/carpeta: identifica y analiza TODOS los artefactos de dentro y agrega un
    informe. Si `path` es un fichero suelto (o un APK), delega en analyze_one."""
    def emit(msg):
        if on_step:
            try:
                on_step(msg)
            except Exception:
                pass

    # APK (aunque venga como .zip) -> auditoria Android directa, no bundle-walk.
    if _is_apk(path):
        emit("APK detectado: auditoria Android")
        one = analyze_one(path, config=config, store=store, on_step=None, ai=ai)
        return {"ok": True, "kind": "apk", "items": [one], "report_md": one["md"],
                "findings": one.get("findings", [])}

    # determinar raiz a recorrer
    tmp = None
    if os.path.isdir(path):
        root = path
    elif zipfile.is_zipfile(path):
        emit("extrayendo ZIP (en sandbox temporal, con cotas)")
        root = tmp = _safe_extract(path)
    else:
        # fichero suelto no-zip
        one = analyze_one(path, config=config, store=store, on_step=on_step, ai=ai)
        return {"ok": True, "kind": "single", "items": [one], "report_md":
                f"# Analisis — {one['title']}\n\n{one['md']}", "findings": one.get("findings", [])}

    try:
        # recolectar candidatos
        candidates = []
        skipped = 0
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                fp = os.path.join(dirpath, fn)
                fmt = _detect(fp)
                if fmt in _INTERESTING or fn.lower().endswith((".apk", ".dex", ".dll", ".so", ".exe")):
                    candidates.append((fp, fmt))
                else:
                    skipped += 1
                if len(candidates) >= _MAX_FILES:
                    break
            if len(candidates) >= _MAX_FILES:
                break

        emit(f"{len(candidates)} artefacto(s) para analizar ({skipped} ficheros no-binarios omitidos)")
        items = []
        all_findings = []
        for i, (fp, _fmt) in enumerate(candidates, 1):
            rel = os.path.relpath(fp, root)
            emit(f"[{i}/{len(candidates)}] {rel}")
            one = analyze_one(fp, config=config, store=store, on_step=None, ai=ai)
            one["title"] = rel
            items.append(one)
            all_findings += one.get("findings", [])

        # informe agregado
        head = [f"# Analisis de bundle — {os.path.basename(path)}",
                f"- artefactos analizados: **{len(items)}**  ·  hallazgos: **{len(all_findings)}**  "
                f"·  ficheros no-binarios omitidos: {skipped}\n"]
        if not items:
            head.append("_No se encontraron binarios/apps reconocibles dentro. "
                        "(Para codigo fuente web/PHP/JS usa el analisis de fuentes correspondiente.)_")
        for one in items:
            head.append(f"\n## {one['title']}  ·  _{one['kind']}_\n")
            head.append(one["md"])
        return {"ok": True, "kind": "bundle", "items": items,
                "report_md": "\n".join(head), "findings": all_findings}
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
