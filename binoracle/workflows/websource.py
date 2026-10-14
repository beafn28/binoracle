"""Fetch the real source of a web/app vulnerability (plugin/repo) and ground the hypothesis in it.

This closes the same blocker dockerfetch.py closes for native binaries ("hace falta el binario
concreto") but for web CVEs ("hace falta el plugin/repo concreto"): download the actual vulnerable
source so the LLM's hypothesis (vulnerable_functions, trigger, endpoint) can be checked against real
code instead of staying a guess. Four sources, all WITHOUT executing anything:

  - a WordPress.org plugin slug (+ optional version)  -> downloads the official release zip
    (downloads.wordpress.org), the same artifact `wp plugin install` would fetch. Only covers
    plugins in the FREE directory; a commercial/premium plugin (sold directly by its vendor, e.g.
    Divi Engine's own "Divi Form Builder" vs. the unrelated free "forms-for-divi" on WordPress.org)
    is NOT there and this 404s honestly — see the other three sources for that case.
  - a git repository URL                               -> `git clone --depth 1` (optionally a ref).
  - a direct HTTPS URL to a .zip                       -> downloads it (e.g. a vendor's own direct
    download link, or one from an account/marketplace you have access to).
  - a LOCAL .zip path already on disk                  -> extracts it directly. The realistic path
    for a commercial plugin: you buy/download it yourself from the vendor (Divi Engine, Elegant
    Themes Marketplace, CodeCanyon...) and point --source at that file.

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
    kind: str = ""              # "wordpress-plugin" | "git" | "local-zip" | "zip-url" | ""
    source: str = ""            # slug/URL/ruta pedido (tal cual, para mostrar)
    resolved_version: str = ""
    local_path: str = ""        # directorio con el codigo ya extraido/clonado
    plugin_dir: str = ""        # carpeta DENTRO de local_path que contiene el plugin (ver
                                 # detect_plugin_folder: para wordpress-plugin coincide con el
                                 # slug; para local-zip/zip-url/git NO tiene por que, se detecta)
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
        # 404 en esta API tiene VARIAS causas reales, no solo "slug mal escrito":
        # 1) plugin COMERCIAL/premium (confirmado en vivo con CVE-2026-5523, Divi Form Builder):
        #    nunca estuvo en el directorio gratuito, se vende directo por el fabricante.
        # 2) plugin CERRADO/retirado del directorio (confirmado en vivo con CVE-2024-43982, Login
        #    As Users: cerrado el 5-nov-2024 tras el aviso de seguridad) -- SI fue gratuito, pero
        #    la API de info ya no lo lista. En este caso el zip de una VERSION CONCRETA a veces
        #    sigue descargable directamente aunque la API de info ya no exista: si se pidio
        #    --version, se intenta igualmente antes de rendirse.
        if version:
            step(f"la API de info fallo ({e}), pero se pidio la version {version}: probando la "
                 f"descarga directa igualmente (algunos plugins cerrados siguen sirviendo zips "
                 f"de versiones concretas aunque ya no esten listados)...")
            return _download_wp_zip(slug, _WP_DOWNLOAD.format(slug=slug, version=version),
                                    version, dest_dir, step, timeout, res)
        res.note = (f"plugin '{slug}' no resuelto en WordPress.org: {e}. Posibles causas: (a) es "
                    f"COMERCIAL/premium (vendido directo por el fabricante, nunca estuvo en el "
                    f"directorio gratuito), o (b) fue CERRADO/retirado del directorio (frecuente "
                    f"tras un aviso de seguridad) -- en este ultimo caso, prueba pasando --version "
                    f"con la version vulnerable exacta: a veces el zip de esa version concreta "
                    f"sigue descargable aunque el plugin ya no aparezca listado. Si nada de esto "
                    f"funciona, pasa --source con la ruta a tu .zip ya descargado, o una URL de "
                    f"descarga directa (https://.../plugin.zip)")
        return res
    if not isinstance(info, dict) or info.get("error"):
        res.note = f"plugin '{slug}' no encontrado en WordPress.org (sin detalle adicional)"
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
    return _download_wp_zip(slug, url, res.resolved_version, dest_dir, step, timeout, res)


def _download_wp_zip(slug: str, url: str, resolved_version: str, dest_dir: str, step,
                     timeout: float, res: "SourceFetchResult") -> "SourceFetchResult":
    """Descarga+extrae un zip de plugin de WordPress.org ya resuelto a una URL concreta. Compartido
    por el camino normal (API de info resuelta) y el de respaldo (API caida pero se pidio una
    version concreta, ver fetch_wordpress_plugin)."""
    res.resolved_version = resolved_version
    step(f"descargando {slug} {resolved_version or '(ultima)'} ({url})...")
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
        _safe_extract_zip(zpath, dest_dir)
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
    res.plugin_dir = slug          # convencion de WordPress.org: la carpeta del zip es el slug
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
    # plugin_dir se deja vacio a proposito: un repo git normalmente tiene el plugin EN LA RAIZ
    # del clon (no en una subcarpeta como los zips), asi que "" significa aqui "esta en local_path
    # mismo". Si el repo SI anida el plugin en una subcarpeta, pasa --functions/--source ajustados
    # o usa el .zip/carpeta real en vez del repo completo.
    step(f"repositorio clonado en {dest_dir}")
    return res


def detect_plugin_folder(local_path: str, hint: str = "") -> str:
    """Nombre de la carpeta, DENTRO de `local_path`, que contiene el plugin de verdad. Para un zip
    de WordPress.org coincide siempre con el slug; para un .zip comercial (local o por URL) o un
    repo git NO hay garantia de que el nombre del fichero/URL coincida con la carpeta real (p.ej.
    'divi-form-builder.zip' puede extraer a 'DiviFormBuilder/' o similar) -- necesario para que
    wpverify.py sepa que copiar dentro del laboratorio Docker. Estrategia: 1) si `hint` ya es una
    carpeta real ahi, usala tal cual; 2) si solo hay UNA carpeta de primer nivel, es esa; 3) si hay
    varias, busca la que tenga un .php con una cabecera 'Plugin Name:' (la convencion de WordPress).
    Cadena vacia si no se puede determinar con confianza (ambiguo)."""
    try:
        if hint and os.path.isdir(os.path.join(local_path, hint)):
            return hint
        entries = [e for e in os.listdir(local_path)
                  if os.path.isdir(os.path.join(local_path, e)) and not e.startswith((".", "__MACOSX"))]
        if len(entries) == 1:
            return entries[0]
        for e in entries:
            sub = os.path.join(local_path, e)
            for fn in os.listdir(sub):
                if not fn.lower().endswith(".php"):
                    continue
                try:
                    with open(os.path.join(sub, fn), "r", encoding="utf-8", errors="replace") as f:
                        head = f.read(4000)
                except Exception:
                    continue
                if re.search(r"Plugin\s*Name\s*:", head, re.I):
                    return e
    except Exception:
        pass
    return ""


def _safe_extract_zip(zpath: str, dest_dir: str) -> None:
    """Extraccion de ZIP sin path-traversal (zip-slip): comun a las cuatro vias de fetch."""
    with zipfile.ZipFile(zpath) as z:
        for info_z in z.infolist():
            name = info_z.filename
            if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                continue
            z.extract(info_z, dest_dir)


def looks_like_zip_url(text: str) -> bool:
    t = (text or "").strip()
    return bool(re.match(r"^https?://", t)) and (t.split("?", 1)[0].lower().endswith(".zip"))


def looks_like_local_zip(text: str) -> bool:
    t = (text or "").strip()
    return bool(t) and t.lower().endswith(".zip") and os.path.isfile(t)


def fetch_local_zip(path: str, dest_dir: str = "",
                    on_step: Optional[Callable[[str], None]] = None) -> SourceFetchResult:
    """Extrae un .zip YA EN DISCO (el caso real de un plugin comercial: lo compraste/descargaste tu
    mismo del vendedor y le pasas la ruta). No descarga nada, no ejecuta nada del contenido."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="local-zip", source=path)
    if not os.path.isfile(path):
        res.note = f"no existe el fichero: {path}"
        return res
    step(f"extrayendo {path} (ya en disco)...")
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_localzip_")
    try:
        _safe_extract_zip(path, dest_dir)
    except Exception as e:
        res.note = f"fallo extrayendo {path}: {e}"
        return res
    res.ok = True
    res.local_path = dest_dir
    res.plugin_dir = detect_plugin_folder(dest_dir)
    step(f"codigo extraido en {dest_dir}" +
        (f" (carpeta del plugin: {res.plugin_dir})" if res.plugin_dir else ""))
    return res


def fetch_zip_url(url: str, dest_dir: str = "", on_step: Optional[Callable[[str], None]] = None,
                  timeout: float = 60.0) -> SourceFetchResult:
    """Descarga un .zip de una URL DIRECTA (no WordPress.org): un enlace de descarga del propio
    vendedor, de una cuenta/Marketplace al que tengas acceso, etc."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="zip-url", source=url)
    step(f"descargando {url}...")
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_zipurl_")
    zfd, zpath = tempfile.mkstemp(prefix="binoracle_zipurl_", suffix=".zip")
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
        _safe_extract_zip(zpath, dest_dir)
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
    res.plugin_dir = detect_plugin_folder(dest_dir)
    step(f"codigo obtenido en {dest_dir}" +
        (f" (carpeta del plugin: {res.plugin_dir})" if res.plugin_dir else ""))
    return res


def fetch_source(target: str, version: str = "", on_step: Optional[Callable[[str], None]] = None,
                 timeout: float = 90.0) -> SourceFetchResult:
    """Despacha por la forma de `target`: .zip ya en disco -> extrae; URL http(s) directa a un .zip
    -> descarga (ANTES que la comprobacion de git: una URL de github.com/.../archive/x.zip es un
    .zip, no un repo a clonar, aunque el host coincida); URL de git -> clone; si no, se trata como
    slug de WordPress.org (el directorio GRATUITO; un plugin comercial nunca estara ahi, usa las
    otras tres vias). Punto de entrada unico para cve_agent."""
    target = (target or "").strip()
    if not target:
        return SourceFetchResult(note="sin source_url/slug para resolver")
    if looks_like_local_zip(target):
        return fetch_local_zip(target, on_step=on_step)
    if looks_like_zip_url(target):
        return fetch_zip_url(target, on_step=on_step, timeout=timeout)
    if looks_like_git_url(target):
        return fetch_git_source(target, ref=version, on_step=on_step, timeout=timeout)
    if looks_like_wp_slug(target):
        return fetch_wordpress_plugin(target, version=version, on_step=on_step, timeout=timeout)
    return SourceFetchResult(source=target,
                             note=f"'{target}' no parece una URL de git, un .zip (local o URL) ni "
                                 f"un slug de WordPress.org")


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
