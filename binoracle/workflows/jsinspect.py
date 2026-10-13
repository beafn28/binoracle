"""Static JavaScript / Electron reader: source maps, module imports, Electron/IPC boundaries.

Reads a JavaScript artifact with nothing executed -- a single `.js` file, a `.js.map` source map, or
an extracted app directory (Electron/Node). It recovers:
- source maps: the original source paths (and whether their contents are embedded), the generator
  (webpack/rollup/esbuild/terser) and version -- so minified bundles map back to real files;
- module imports: bare `require(...)` / `import ... from '...'` specifiers (external packages) vs
  relative imports, as a per-file summary and a package set;
- Electron / IPC boundaries: ipcMain/ipcRenderer channels, contextBridge exposures, preload scripts,
  BrowserWindow/webContents use and Node capabilities reached from renderer code (child_process, fs,
  net) -- the trust boundaries a reviewer looks at first;
- native add-ons: references to `.node` binaries.
All of it is heuristic (regex over source, not a full JS parse) and reported as such. Design parity
with REA's JavaScript/Electron surface (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

import os
import re

_REQUIRE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT = re.compile(r"""import\s+(?:[^'"]+?\s+from\s+)?['"]([^'"]+)['"]""")
_DYN_IMPORT = re.compile(r"""import\(\s*['"]([^'"]+)['"]\s*\)""")
_IPC_CHANNEL = re.compile(r"""ipc(?:Main|Renderer)\s*\.\s*(?:on|handle|once|send|invoke|handleOnce)\s*\(\s*['"]([^'"]+)['"]""")
_CONTEXT_BRIDGE = re.compile(r"""contextBridge\s*\.\s*exposeInMainWorld\s*\(\s*['"]([^'"]+)['"]""")
_ROUTE = re.compile(r"""\b(?:app|router)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*['"]([^'"]+)['"]""")

_ELECTRON_MARKERS = {
    "electron": "import de electron", "ipcMain": "IPC (main)", "ipcRenderer": "IPC (renderer)",
    "contextBridge": "contextBridge (puente aislado)", "BrowserWindow": "BrowserWindow",
    "webContents": "webContents", "nodeIntegration": "nodeIntegration (flag de seguridad)",
    "webSecurity": "webSecurity (flag de seguridad)", "preload": "preload script",
    "child_process": "child_process (ejecucion de comandos)", "shell.openExternal": "shell.openExternal",
}

_MAX_FILES = 4000
_MAX_BYTES_PER_FILE = 4 * 1024 * 1024


def _scan_source(text: str, rel: str, acc: dict):
    ext_mods, rel_mods = set(), set()
    for rx in (_REQUIRE, _IMPORT, _DYN_IMPORT):
        for m in rx.finditer(text):
            spec = m.group(1)
            if spec.startswith("."):
                rel_mods.add(spec)
            else:
                ext_mods.add(spec.split("/")[0] if not spec.startswith("@")
                             else "/".join(spec.split("/")[:2]))
    for pkg in ext_mods:
        acc["packages"][pkg] = acc["packages"].get(pkg, 0) + 1
    for ch in _IPC_CHANNEL.findall(text):
        acc["ipc_channels"].add(ch)
    for name in _CONTEXT_BRIDGE.findall(text):
        acc["context_bridge"].add(name)
    for verb, path in _ROUTE.findall(text):
        acc["routes"].add(f"{verb.upper()} {path}")
    for marker, label in _ELECTRON_MARKERS.items():
        if marker in text:
            acc["electron"].setdefault(label, 0)
            acc["electron"][label] += 1
    if ".node" in text:
        acc["native_addon_refs"] += 1
    if ext_mods or rel_mods:
        acc["imports_by_file"].append({"file": rel, "external": sorted(ext_mods)[:20],
                                       "relative": len(rel_mods)})


def _inspect_sourcemap(path: str) -> dict:
    import json
    from ._artifact import read_bounded, ArtifactTooLarge
    try:
        doc = json.loads(read_bounded(path).decode("utf-8", "replace"))
    except ArtifactTooLarge as e:
        return {"ok": False, "note": str(e)}
    except Exception as e:
        return {"ok": True, "is_js": False, "note": f"no es un source map JSON: {e}"}
    if not isinstance(doc, dict) or "version" not in doc or "sources" not in doc:
        return {"ok": True, "is_js": False, "note": "JSON sin forma de source map (version/sources)"}
    sources = doc.get("sources") or []
    gen = ""
    x = doc.get("x_google_ignoreList")
    for key in ("webpack", "rollup", "esbuild", "terser"):
        if any(key in str(s).lower() for s in sources[:50]):
            gen = key
            break
    return {"ok": True, "is_js": True, "kind": "sourcemap", "map_version": doc.get("version"),
            "source_count": len(sources), "sources": [str(s) for s in sources[:200]],
            "has_sources_content": bool(doc.get("sourcesContent")),
            "generator": gen or (doc.get("file") or ""),
            "limitations": ["source map: rutas de fuentes originales; no reconstruye el arbol completo"]}


def inspect_js(path: str) -> dict:
    """Inspect a .js file, a .js.map, or an app directory. Returns a static summary."""
    if os.path.isfile(path) and (path.endswith(".map") or path.endswith(".js.map")):
        return _inspect_sourcemap(path)
    acc = {"packages": {}, "ipc_channels": set(), "context_bridge": set(), "routes": set(),
           "electron": {}, "native_addon_refs": 0, "imports_by_file": [], "file_count": 0,
           "sourcemaps": []}
    files = []
    if os.path.isdir(path):
        for root, _d, fns in os.walk(path):
            if "node_modules" in root.split(os.sep):   # skip deps; focus on app code
                continue
            for fn in fns:
                if fn.endswith((".js", ".mjs", ".cjs")):
                    files.append(os.path.join(root, fn))
                elif fn.endswith(".map"):
                    acc["sourcemaps"].append(os.path.relpath(os.path.join(root, fn), path))
                if len(files) >= _MAX_FILES:
                    break
            if len(files) >= _MAX_FILES:
                break
    elif os.path.isfile(path):
        files = [path]
    else:
        return {"ok": False, "is_js": False, "note": f"no existe: {path}"}
    base = path if os.path.isdir(path) else os.path.dirname(path)
    for fp in files:
        try:
            with open(fp, "rb") as fh:
                raw = fh.read(_MAX_BYTES_PER_FILE)
            text = raw.decode("utf-8", "replace")
        except Exception:
            continue
        rel = os.path.relpath(fp, base) if os.path.isdir(path) else os.path.basename(fp)
        _scan_source(text, rel, acc)
        acc["file_count"] += 1
    top_pkgs = sorted(acc["packages"].items(), key=lambda kv: -kv[1])[:60]
    return {"ok": True, "is_js": True, "kind": "bundle" if os.path.isdir(path) else "file",
            "file_count": acc["file_count"],
            "packages": dict(top_pkgs), "package_count": len(acc["packages"]),
            "ipc_channels": sorted(acc["ipc_channels"])[:80],
            "context_bridge": sorted(acc["context_bridge"])[:40],
            "routes": sorted(acc["routes"])[:80],
            "electron": acc["electron"], "is_electron": bool(acc["electron"]),
            "native_addon_refs": acc["native_addon_refs"],
            "sourcemaps": acc["sourcemaps"][:60],
            "imports_sample": acc["imports_by_file"][:40],
            "limitations": ["heuristico por regex (no es un parser JS completo); se omite node_modules; "
                            "rutas/IPC detectadas por patron, no por analisis de flujo"]}


def render_js(r: dict) -> str:
    out = ["## Inspeccion de JavaScript / Electron (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + (r.get("note") or "")])
    if not r.get("is_js"):
        return "\n".join(out + ["- No es JS/source map: " + (r.get("note") or "")])
    if r.get("kind") == "sourcemap":
        out.append(f"- source map v{r.get('map_version')}  |  fuentes: {r.get('source_count')}  |  "
                   f"contenido embebido: {'si' if r.get('has_sources_content') else 'no'}")
        if r.get("generator"):
            out.append(f"- generador: {r['generator']}")
        for s in (r.get("sources") or [])[:40]:
            out.append(f"  - {s}")
        for lim in r.get("limitations", []):
            out.append(f"\n_limite: {lim}_")
        return "\n".join(out)
    out.append(f"- ficheros JS: {r.get('file_count')}  |  paquetes externos: {r.get('package_count')}  |  "
               f"Electron: {'SI' if r.get('is_electron') else 'no'}")
    pk = r.get("packages") or {}
    if pk:
        out.append("- paquetes: " + ", ".join(f"{k}({v})" for k, v in list(pk.items())[:30]))
    el = r.get("electron") or {}
    if el:
        out.append("\n### Fronteras Electron / capacidades")
        for label, n in el.items():
            out.append(f"- {label}: {n}")
    if r.get("context_bridge"):
        out.append("- contextBridge expone: " + ", ".join(r["context_bridge"]))
    ipc = r.get("ipc_channels") or []
    if ipc:
        out.append(f"\n### Canales IPC ({len(ipc)})")
        out.append(", ".join(ipc[:50]))
    routes = r.get("routes") or []
    if routes:
        out.append(f"\n### Rutas detectadas ({len(routes)})")
        for rt in routes[:40]:
            out.append(f"- {rt}")
    if r.get("native_addon_refs"):
        out.append(f"\n- referencias a add-ons nativos (.node): {r['native_addon_refs']}")
    if r.get("sourcemaps"):
        out.append(f"- source maps presentes: {len(r['sourcemaps'])} (usa `binoracle js <mapa>.map`)")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
