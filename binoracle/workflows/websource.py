"""Fetch the real source of a web/app vulnerability (plugin/repo) and ground the hypothesis in it.

This closes the same blocker dockerfetch.py closes for native binaries ("hace falta el binario
concreto") but for web CVEs ("hace falta el plugin/repo concreto"): download the actual vulnerable
source so the LLM's hypothesis (vulnerable_functions, trigger, endpoint) can be checked against real
code instead of staying a guess. Two sources, both WITHOUT executing anything:

  - a WordPress.org plugin slug (+ optional version)  -> downloads the official release zip
    (downloads.wordpress.org), the same artifact `wp plugin install` would fetch.
  - a git repository URL                               -> `git clone --depth 1` (optionally a ref).

Then `grep_vulnerable_functions` searches the fetched tree for the function/method names the LLM
cited, with file:line evidence. A match is GROUNDED evidence ("this function exists in the real
source, here it is"); it is not proof the bug is exploitable, and is never promoted to 'verified'
here — only a real run against an authorized live target can do that.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional

_WP_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
_WP_DOWNLOAD = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
_WP_DOWNLOAD_LATEST = "https://downloads.wordpress.org/plugin/{slug}.zip"

_MAX_DOWNLOAD = 80 * 1024 * 1024     # 80 MB: un plugin/tema no deberia pasar de esto
_MAX_SCAN_FILES = 4000
_MAX_SCAN_BYTES = 1_500_000           # por fichero


@dataclass
class SourceFetchResult:
    ok: bool = False
    kind: str = ""              # "wordpress-plugin" | "git" | ""
    source: str = ""            # slug o URL pedido
    resolved_version: str = ""
    local_path: str = ""        # directorio con el codigo ya extraido/clonado
    note: str = ""


def _urlopen(url: str, timeout: float = 30.0):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "binoracle (authorized research)"})
    return urllib.request.urlopen(req, timeout=timeout)


def looks_like_git_url(text: str) -> bool:
    t = (text or "").strip()
    return bool(re.match(r"^(https?://(github|gitlab|bitbucket)\.[^/]+/|git@)", t)) or t.endswith(".git")


def looks_like_wp_slug(text: str) -> bool:
    """Un 'source_url' que en realidad es un slug de WordPress.org: sin espacios/esquema, solo
    minusculas/digitos/guion (p.ej. 'divi-form-builder')."""
    t = (text or "").strip()
    return bool(t) and bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,80}", t)) and "/" not in t


def fetch_wordpress_plugin(slug: str, version: str = "", dest_dir: str = "",
                           on_step: Optional[Callable[[str], None]] = None,
                           timeout: float = 60.0) -> SourceFetchResult:
    """Descarga el .zip OFICIAL de un plugin de WordPress.org (el mismo artefacto que `wp plugin
    install` traeria), a una version concreta si se da, o a la ultima estable si no. No lo ejecuta."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="wordpress-plugin", source=slug)
    slug = (slug or "").strip().lower()
    if not slug:
        res.note = "slug de plugin vacio"
        return res
    step(f"resolviendo plugin '{slug}' en WordPress.org...")
    try:
        with _urlopen(_WP_API.format(slug=slug), timeout=timeout) as r:
            import json
            info = json.loads(r.read(2 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception as e:
        res.note = f"plugin '{slug}' no resuelto en WordPress.org: {e}"
        return res
    if not isinstance(info, dict) or info.get("error"):
        res.note = f"plugin '{slug}' no encontrado en WordPress.org"
        return res
    versions = info.get("versions") or {}
    if version and version in versions:
        url = versions[version]
        res.resolved_version = version
    elif version:
        # version pedida no listada (las antiguas a veces no aparecen en 'versions'); intenta la
        # URL de descarga versionada directamente, WordPress.org la sirve igual si existe.
        url = _WP_DOWNLOAD.format(slug=slug, version=version)
        res.resolved_version = version
    else:
        url = info.get("download_link") or _WP_DOWNLOAD_LATEST.format(slug=slug)
        res.resolved_version = info.get("version", "")
    step(f"descargando {slug} {res.resolved_version or '(ultima)'} ({url})...")
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_wp_")
    zfd, zpath = tempfile.mkstemp(prefix="binoracle_wp_", suffix=".zip")
    os.close(zfd)
    try:
        with _urlopen(url, timeout=timeout) as r:
            total = 0
            with open(zpath, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD:
                        raise ValueError(f"descarga excede {_MAX_DOWNLOAD} bytes (abortada)")
                    f.write(chunk)
    except Exception as e:
        res.note = f"fallo descargando {url}: {e}"
        return res
    try:
        with zipfile.ZipFile(zpath) as z:
            for info_z in z.infolist():
                name = info_z.filename
                if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                    continue
                z.extract(info_z, dest_dir)
    except Exception as e:
        res.note = f"fallo extrayendo {zpath}: {e}"
        return res
    finally:
        try:
            os.remove(zpath)
        except Exception:
            pass
    res.ok = True
    res.local_path = dest_dir
    step(f"codigo del plugin obtenido en {dest_dir}")
    return res


def fetch_git_source(url: str, ref: str = "", dest_dir: str = "",
                     on_step: Optional[Callable[[str], None]] = None,
                     timeout: float = 90.0) -> SourceFetchResult:
    """`git clone --depth 1 [--branch ref]`. No ejecuta nada del repo, solo lo trae."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="git", source=url)
    git = shutil.which("git")
    if not git:
        res.note = "git no disponible"
        return res
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_git_")
    cmd = [git, "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, dest_dir]
    step(f"git clone --depth 1 {url} ...")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        res.note = f"fallo git clone: {e}"
        return res
    if out.returncode != 0:
        res.note = f"git clone fallo: {(out.stderr or '').strip()[:300]}"
        return res
    res.ok = True
    res.local_path = dest_dir
    res.resolved_version = ref or "HEAD"
    step(f"repositorio clonado en {dest_dir}")
    return res


def fetch_source(target: str, version: str = "", on_step: Optional[Callable[[str], None]] = None,
                 timeout: float = 90.0) -> SourceFetchResult:
    """Despacha por la forma de `target`: URL de git -> clone; si no, se trata como slug de
    WordPress.org. Punto de entrada unico para cve_agent."""
    target = (target or "").strip()
    if not target:
        return SourceFetchResult(note="sin source_url/slug para resolver")
    if looks_like_git_url(target):
        return fetch_git_source(target, ref=version, on_step=on_step, timeout=timeout)
    if looks_like_wp_slug(target):
        return fetch_wordpress_plugin(target, version=version, on_step=on_step, timeout=timeout)
    return SourceFetchResult(source=target,
                             note=f"'{target}' no parece una URL de git ni un slug de WordPress.org")


# --- confirmacion fundamentada: ¿existen de verdad las funciones citadas por el LLM? ---
# Heuristica deliberadamente simple (ver grep_vulnerable_functions): busca "nombre(" como palabra
# completa. Es laxo a proposito (cubre `function foo(`, `def foo(`, `foo(args) {`, una llamada...)
# porque el objetivo es fundamentar "este nombre existe en el codigo real", no parsear el lenguaje.

_SCAN_EXT = (".php", ".py", ".js", ".ts", ".java", ".cs", ".go", ".rb", ".c", ".cpp", ".h")


@dataclass
class FuncMatch:
    name: str
    file: str
    line: int
    snippet: str


def grep_vulnerable_functions(root: str, names: List[str]) -> dict:
    """Busca definiciones de cada nombre en `names` dentro de `root` (cota de ficheros/tamano).
    Devuelve {"found": {name: [FuncMatch,...]}, "not_found": [name,...]}. Heuristico (regex, no AST):
    confirma que el NOMBRE existe como posible definicion en el codigo real, no que sea explotable."""
    names = [n for n in (names or []) if isinstance(n, str) and n.strip()]
    found: dict = {n: [] for n in names}
    if not names or not root or not os.path.isdir(root):
        return {"found": {}, "not_found": names}
    compiled = {n: re.compile(r"\b" + re.escape(n) + r"\s*\(") for n in names}
    scanned = 0
    for dirpath, _dirs, files in os.walk(root):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in files:
            if not fn.lower().endswith(_SCAN_EXT):
                continue
            if scanned >= _MAX_SCAN_FILES:
                break
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except Exception:
                continue
            for n, rx in compiled.items():
                for m in rx.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    try:
                        snippet = text.splitlines()[line_no - 1].strip()[:200]
                    except Exception:
                        snippet = ""
                    found[n].append(FuncMatch(n, os.path.relpath(fp, root), line_no, snippet))
        if scanned >= _MAX_SCAN_FILES:
            break
    not_found = [n for n in names if not found.get(n)]
    return {"found": {n: v for n, v in found.items() if v}, "not_found": not_found}
