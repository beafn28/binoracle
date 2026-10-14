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


def _safe_rel(source: str) -> str | None:
    """Map a source-map `sources` entry to a safe relative output path (no traversal, no absolute,
    strip the webpack:// etc. scheme and leading ../). None if nothing usable remains."""
    import posixpath
    s = str(source)
    for scheme in ("webpack://", "rollup://", "esbuild://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
    s = s.split("://", 1)[-1]                 # drop any remaining scheme
    s = s.lstrip("/")
    parts = []
    for part in s.replace("\\", "/").split("/"):
        if part in ("", ".", ".."):
            continue
        parts.append(part)
    rel = posixpath.join(*parts) if parts else None
    return rel


def recover_js_sources(path: str, out_dir: str = None, max_files: int = 5000) -> dict:
    """recover_javascript_sources: reconstruct the ORIGINAL source tree a bundle shipped in its
    `.js.map` via sourcesContent. Reads a `.js.map` (or a `.js` whose trailing sourceMappingURL
    points at a sibling `.map`). Writes nothing unless `out_dir` is given. Nothing executed."""
    import json
    import os
    from ._artifact import read_bounded, ArtifactTooLarge

    mappath = path
    if os.path.isfile(path) and not path.endswith(".map"):
        # follow a trailing //# sourceMappingURL=... to a sibling .map (no remote fetch)
        try:
            tail = read_bounded(path)[-4096:].decode("utf-8", "replace")
        except Exception:
            tail = ""
        hint = None
        for line in tail.splitlines():
            if "sourceMappingURL=" in line:
                hint = line.split("sourceMappingURL=", 1)[1].strip()
        cand = os.path.join(os.path.dirname(path), hint) if hint and "://" not in hint else path + ".map"
        if os.path.isfile(cand):
            mappath = cand
        elif os.path.isfile(path + ".map"):
            mappath = path + ".map"
        else:
            return {"ok": True, "tool": "js_recover", "recovered": 0,
                    "note": "no se encontro un .js.map adyacente con sourcesContent",
                    "limitations": ["solo lectura local; no se descargan source maps remotos"]}
    try:
        doc = json.loads(read_bounded(mappath).decode("utf-8", "replace"))
    except ArtifactTooLarge as e:
        return {"ok": False, "tool": "js_recover", "note": str(e)}
    except Exception as e:
        return {"ok": False, "tool": "js_recover", "note": f"no es un source map JSON: {e}"}

    sources = doc.get("sources") or []
    contents = doc.get("sourcesContent") or []
    if not contents:
        return {"ok": True, "tool": "js_recover", "recovered": 0, "source_count": len(sources),
                "note": "el source map no incluye sourcesContent (solo rutas); nada que reconstruir",
                "limitations": ["sin sourcesContent no hay codigo original embebido"]}

    files = []
    written = 0
    base = os.path.abspath(out_dir) if out_dir else None
    if base:
        os.makedirs(base, exist_ok=True)
    for i, src in enumerate(sources[:max_files]):
        if i >= len(contents) or contents[i] is None:
            continue
        rel = _safe_rel(src)
        if not rel:
            continue
        code = contents[i]
        files.append({"path": rel, "bytes": len(code.encode("utf-8", "replace"))})
        if base:
            dest = os.path.join(base, rel)
            # containment check: never write outside out_dir
            if not os.path.abspath(dest).startswith(base + os.sep):
                continue
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(code)
                written += 1
            except Exception:
                pass
    return {"ok": True, "tool": "js_recover", "map": mappath, "source_count": len(sources),
            "with_content": len(files), "recovered": written,
            "files": [f["path"] for f in files[:200]], "out_dir": base,
            "note": (f"reconstruidos {written} fichero(s) en {base}" if base
                     else f"{len(files)} fuente(s) con codigo embebido (pasa out_dir para escribir)"),
            "limitations": ["reconstruye desde sourcesContent del .js.map; no deofusca ni re-bundlea",
                            "rutas saneadas (sin traversal); objetivo autorizado"]}


def render_js_recover(r: dict) -> str:
    out = ["## Recuperacion de fuentes JS (desde source map)\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    out.append(f"- fuentes en el mapa: {r.get('source_count', 0)} | con codigo embebido: "
               f"{r.get('with_content', 0)} | escritas: {r.get('recovered', 0)}")
    if r.get("out_dir"):
        out.append(f"- directorio: `{r['out_dir']}`")
    for f in (r.get("files") or [])[:40]:
        out.append(f"  - {f}")
    out.append("- " + r.get("note", ""))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)


# bundler fingerprints + module-count heuristics
_BUNDLER_SIGS = (
    ("__webpack_require__", "webpack"), ("webpackJsonp", "webpack"), ("webpackChunk", "webpack"),
    ("System.register", "SystemJS"), ("__esm(", "esbuild"), ("__commonJS(", "esbuild"),
    ("define.amd", "AMD/RequireJS"), ("parcelRequire", "Parcel"), ("__vite__", "Vite"),
    ("/* @vite", "Vite"), ("rollup", "rollup"),
)
_WEBMCP_SIGS = (
    "navigator.modelContext", "window.mcp", "window.__MCP", "registerTool(", "provideContext(",
    "modelcontextprotocol", "@modelcontextprotocol", "McpServer(", "listTools(", "callTool(",
    "window.agent", "navigator.ai",
)
_TOOL_NAME_RE = re.compile(r"""(?:registerTool|tool|name)\s*[:(]\s*['"]([a-zA-Z0-9_.\-]{2,64})['"]""")


def analyze_web_bundle(path: str, max_bytes: int = 32 * 1024 * 1024) -> dict:
    """analyze_web_bundle: fingerprint a bundled .js (webpack/rollup/esbuild/Vite/Parcel/SystemJS),
    estimate the module count, and sample module/chunk ids. Static read; nothing executed."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read(max_bytes)
    except Exception as e:
        return {"ok": False, "tool": "web_bundle", "note": f"no se pudo leer: {e}"}
    bundlers = sorted({label for sig, label in _BUNDLER_SIGS if sig in text})
    # webpack module map: numeric or string module keys in a big object/array; esbuild: __commonJS({...})
    modules = len(re.findall(r"""\b\d{1,6}\s*:\s*(?:function|\(function|\(\s*\w*\s*=>|\[function)""", text))
    modules += len(re.findall(r"""['"][^'"]+['"]\s*:\s*(?:function|\(function)\s*\(""", text))
    chunks = re.findall(r"""webpackChunk\w*|chunk-[0-9a-f]{6,}|\b(\d{1,5})\.[0-9a-f]{8,}\.js""", text)
    return {"ok": True, "tool": "web_bundle", "bundlers": bundlers,
            "is_bundle": bool(bundlers) or modules > 5,
            "estimated_modules": modules, "size": len(text),
            "minified": (text.count("\n") < len(text) / 200) if text else False,
            "chunk_hints": sorted({c for c in chunks if c})[:40],
            "limitations": ["fingerprint estatico por patrones; conteo de modulos aproximado"]}


def _collect_imports(text: str):
    ext, rel, dyn = set(), set(), set()
    for m in _REQUIRE.findall(text) + _IMPORT.findall(text):
        (rel if m.startswith(".") or m.startswith("/") else ext).add(m)
    for m in _DYN_IMPORT.findall(text):
        dyn.add(m)
    return ext, rel, dyn


def trace_web_module_imports(path: str, max_files: int = 4000) -> dict:
    """trace_web_module_imports: the module import graph of a file or app directory -- each file's
    static imports (require / import / dynamic import), split into external packages and relative
    modules. Static; nothing executed."""
    files = []
    if os.path.isdir(path):
        for base, _dirs, names in os.walk(path):
            if "node_modules" in base.split(os.sep):
                continue
            for n in names:
                if n.endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")):
                    files.append(os.path.join(base, n))
                    if len(files) >= max_files:
                        break
    elif os.path.isfile(path):
        files = [path]
    else:
        return {"ok": False, "tool": "web_imports", "note": "ruta no encontrada"}
    edges = []
    packages = set()
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(8 * 1024 * 1024)
        except Exception:
            continue
        rel_name = os.path.relpath(fp, path) if os.path.isdir(path) else os.path.basename(fp)
        ext, rel, dyn = _collect_imports(text)
        packages |= ext
        for spec in sorted(ext):
            edges.append({"from": rel_name, "to": spec, "kind": "external"})
        for spec in sorted(rel):
            edges.append({"from": rel_name, "to": spec, "kind": "relative"})
        for spec in sorted(dyn):
            edges.append({"from": rel_name, "to": spec, "kind": "dynamic"})
    return {"ok": True, "tool": "web_imports", "file_count": len(files),
            "package_count": len(packages), "packages": sorted(packages)[:200],
            "edge_count": len(edges), "edges": edges[:3000],
            "limitations": ["grafo estatico de imports (require/import/import()); "
                            "node_modules se omite; imports calculados en runtime no se ven"]}


def discover_webmcp_tools(path: str, max_bytes: int = 32 * 1024 * 1024) -> dict:
    """discover_webmcp_tools: find WebMCP / in-page agent tool declarations in JS (navigator.
    modelContext, window.mcp, registerTool(...), MCP server/tool APIs) and extract candidate tool
    names. Static pattern scan; nothing executed."""
    paths = []
    if os.path.isdir(path):
        for base, _dirs, names in os.walk(path):
            if "node_modules" in base.split(os.sep):
                continue
            for n in names:
                if n.endswith((".js", ".mjs", ".cjs", ".ts")):
                    paths.append(os.path.join(base, n))
    elif os.path.isfile(path):
        paths = [path]
    else:
        return {"ok": False, "tool": "webmcp", "note": "ruta no encontrada"}
    signals = {}
    tool_names = set()
    for fp in paths[:4000]:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(max_bytes)
        except Exception:
            continue
        for sig in _WEBMCP_SIGS:
            if sig in text:
                signals[sig] = signals.get(sig, 0) + text.count(sig)
        if "registerTool(" in text or "modelContext" in text or "McpServer(" in text:
            for nm in _TOOL_NAME_RE.findall(text):
                tool_names.add(nm)
    return {"ok": True, "tool": "webmcp", "is_webmcp": bool(signals),
            "signals": signals, "tool_names": sorted(tool_names)[:100],
            "limitations": ["deteccion estatica por patrones de WebMCP/agente; los nombres de tool "
                            "son candidatos (de literales cercanos), no una enumeracion ejecutada"]}


def render_web(kind: str, r: dict) -> str:
    out = [f"## Web ({kind})\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "bundle":
        out.append(f"- bundlers: {', '.join(r['bundlers']) or '-'} | bundle: {r['is_bundle']} | "
                   f"modulos~{r['estimated_modules']} | minificado: {r['minified']}")
        if r.get("chunk_hints"):
            out.append(f"- chunks: {', '.join(r['chunk_hints'][:12])}")
    elif kind == "imports":
        out.append(f"- ficheros: {r['file_count']} | paquetes externos: {r['package_count']} | "
                   f"aristas: {r['edge_count']}")
        if r.get("packages"):
            out.append(f"- paquetes: {', '.join(r['packages'][:30])}")
    elif kind == "webmcp":
        out.append(f"- WebMCP detectado: **{'SI' if r['is_webmcp'] else 'no'}**")
        if r.get("signals"):
            out.append("- señales: " + ", ".join(f"{k}×{v}" for k, v in list(r["signals"].items())[:12]))
        if r.get("tool_names"):
            out.append(f"- tools candidatas: {', '.join(r['tool_names'][:20])}")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)


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
