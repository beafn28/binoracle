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

# API de actualizaciones de Drupal.org -- la MISMA que el propio modulo "Update Manager" de
# Drupal usa para comprobar nuevas versiones; devuelve XML con cada release y su download_link.
# No hay un equivalente a la API JSON simple de WordPress.org: hay que parsear XML.
_DRUPAL_UPDATE_XML = "https://updates.drupal.org/release-history/{project}/current"

_MAX_DOWNLOAD = 80 * 1024 * 1024     # 80 MB: un plugin/tema no deberia pasar de esto
_MAX_SCAN_FILES = 4000
_MAX_SCAN_BYTES = 1_500_000           # por fichero

# Cache local de plugins/modulos YA descargados, por (kind, slug, version) -- confirmado en vivo:
# un investigate-batch relanzando varias CVEs (o reintentando la misma CVE tras arreglar un bug)
# volvia a bajar EL MISMO .zip de WordPress.org/Drupal.org cada vez, aunque no hubiera cambiado
# nada -- tiempo y ancho de banda tirados sin necesidad. BINORACLE_CACHE_DIR la reubica;
# BINORACLE_NO_CACHE=1 la desactiva (p.ej. para forzar una descarga fresca).
_CACHE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle", "sources")
_CACHE_DISABLED = os.environ.get("BINORACLE_NO_CACHE", "") not in ("", "0")


def _cache_path_for(kind: str, slug: str, version: str) -> Optional[str]:
    """Directorio de cache para (kind, slug, version), o None si no se puede/debe cachear (sin
    version concreta resuelta -- 'latest' envejece, cachearla serviria pan viejo en la siguiente
    ejecucion -- o la cache esta desactivada)."""
    if _CACHE_DISABLED or not version:
        return None
    safe_slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", slug)[:100] or "_"
    safe_version = re.sub(r"[^a-zA-Z0-9_.-]", "_", version)[:50] or "_"
    return os.path.join(_CACHE_DIR, kind, safe_slug, safe_version)


def _copy_from_cache(cache_path: str, dest_dir: str, plugin_dir_name: str) -> bool:
    """Copia el contenido cacheado a dest_dir/plugin_dir_name -- cada llamada necesita su PROPIA
    copia independiente (nunca compartir el directorio de cache directamente): el laboratorio
    Docker monta esta carpeta como volumen y puede escribir en ella, y dos investigaciones del
    mismo lote en paralelo podrian pedir el mismo plugin a la vez."""
    try:
        target = os.path.join(dest_dir, plugin_dir_name)
        shutil.copytree(cache_path, target, dirs_exist_ok=True)
        return True
    except Exception:
        return False


def _save_to_cache(source_dir: str, cache_path: str) -> None:
    """Guarda una copia de `source_dir` (el contenido YA extraido del plugin/modulo) en la cache,
    de forma atomica (copia a un temporal + rename) para que dos investigaciones guardando el
    MISMO plugin a la vez (un lote en paralelo) nunca dejen la cache a medio escribir -- si pierde
    la carrera, simplemente descarta su copia: la que gano ya sirve igual de bien. Cachear es un
    plus best-effort: un fallo aqui nunca debe tirar abajo la descarga real, que ya tuvo exito."""
    try:
        tmp = tempfile.mkdtemp(prefix="binoracle_cache_tmp_")
        shutil.rmtree(tmp)   # copytree exige que el destino NO exista
        shutil.copytree(source_dir, tmp)
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        try:
            os.replace(tmp, cache_path)
        except OSError:
            shutil.rmtree(tmp, ignore_errors=True)
    except Exception:
        pass

_VERSION_RE = re.compile(r"^[0-9]+(?:[.\-][0-9A-Za-z]+)*$")


def _looks_like_version(v: str) -> bool:
    """True solo si `v` tiene pinta de numero de version real (empieza por digito, solo
    digitos/letras/puntos/guiones) -- rechaza frases libres como 'from n/a through 3.92.0' que
    a veces llegan como affected_version desde la hipotesis del LLM (texto de la descripcion del
    CVE, no un campo estructurado), y que romperian la URL de descarga si se usaran tal cual
    (espacios -> 'URL can't contain control characters', confirmado en vivo)."""
    return bool(v) and bool(_VERSION_RE.match(v.strip()))


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


def looks_like_drupal_slug(text: str) -> bool:
    """Un 'source_url' que en realidad es el machine name de un modulo de Drupal.org (p.ej.
    'webform', 'views_bulk_operations') -- a diferencia de WordPress, Drupal usa GUION BAJO, no
    guion, como separador de palabras en el machine name. Esto es solo una pista de ORDEN (ver
    fetch_source: con guion bajo se prueba Drupal.org primero), no una certeza -- el `cms_hint`
    explicito manda si se da."""
    t = (text or "").strip()
    return bool(t) and bool(re.fullmatch(r"[a-z][a-z0-9_]{1,80}", t)) and "/" not in t and "_" in t


def _extract_wp_org_plugin_slug(text: str) -> Optional[str]:
    """Si `text` es la URL de la PAGINA del directorio (https://wordpress.org/plugins/<slug>/...,
    con o sin 'www.', con o sin ruta/query/fragmento detras) -- no el slug desnudo -- devuelve el
    slug; None si no tiene esa forma. Confirmado en vivo: la hipotesis del LLM a veces trae esto
    en vez del slug que el resto del despacho espera. Casuistica cubierta (revisado a fondo, no
    solo el caso que fallo): esquema opcional (el LLM a veces omite 'https://'), subdominios de
    idioma (es./de./fr./pt-br.wordpress.org -- WordPress.org los tiene para CADA idioma, no solo
    'www'), y cualquier terminador real de URL detras del slug (/, ?, #, o fin de cadena -- no
    solo los tres que el primer intento cubria)."""
    m = re.match(
        r"^(?:https?://)?(?:(?:www|[a-z]{2}(?:-[a-z]{2})?)\.)?wordpress\.org/plugins/"
        r"([a-z0-9][a-z0-9-]{1,80})(?:[/?#]|$)",
        (text or "").strip(), re.IGNORECASE)
    return m.group(1).lower() if m else None


def _extract_wp_trac_plugin_slug(text: str) -> Optional[str]:
    """Si `text` es una URL del repositorio Trac de plugins de WordPress.org
    (https://plugins.trac.wordpress.org/changeset/<rev>/<slug>/..., .../browser/<slug>/...,
    .../log/<slug>/...) devuelve el slug; None si no tiene esa forma. Confirmado en vivo: NVD
    referencia muy a menudo el changeset Trac que arreglo una CVE (es literalmente el parche),
    asi que el LLM a veces trae esa URL como source_url en vez de la pagina del directorio o el
    slug desnudo que el resto del despacho espera -- igual de inservible para fetch_source() sin
    este extractor."""
    m = re.match(
        r"^(?:https?://)?plugins\.trac\.wordpress\.org/"
        r"(?:changeset/\d+|browser|log)/([a-z0-9][a-z0-9_-]{1,80})(?:[/?#]|$)",
        (text or "").strip(), re.IGNORECASE)
    return m.group(1).lower() if m else None


def _extract_drupal_org_module_slug(text: str) -> Optional[str]:
    """Analogo de _extract_wp_org_plugin_slug para la pagina de un proyecto de Drupal.org
    (https://www.drupal.org/project/<machine_name>...) -- misma casuistica (esquema opcional,
    cualquier terminador real de URL)."""
    m = re.match(r"^(?:https?://)?(?:www\.)?drupal\.org/project/([a-z][a-z0-9_]{1,80})(?:[/?#]|$)",
                (text or "").strip(), re.IGNORECASE)
    return m.group(1).lower() if m else None


def detect_module_folder(local_path: str, hint: str = "") -> str:
    """Analogo a detect_plugin_folder() pero nombrado para la convencion de Drupal (un modulo se
    declara con un .info.yml con 'type: module|theme') -- detect_plugin_folder ya reconoce AMBAS
    convenciones (WordPress y Drupal) en la misma pasada, asi que esto es solo un alias con el
    nombre que tiene sentido llamar desde el lado de Drupal."""
    return detect_plugin_folder(local_path, hint=hint)


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
    # confirmado en vivo: 'affected_version' puede venir de la hipotesis del LLM como una FRASE
    # libre de la descripcion del CVE ("from n/a through 3.92.0"), no una version limpia -- si se
    # concatena tal cual en la URL de descarga rompe con un error de bajo nivel confuso ("URL
    # can't contain control characters", por el espacio). En vez de propagar eso, se valida aqui:
    # si no tiene pinta de version real, se ignora (se descarga la ultima estable) en vez de
    # construir una URL rota.
    if version and not _looks_like_version(version):
        step(f"'{version}' no tiene pinta de numero de version real (vino como texto libre de "
             f"la hipotesis) -- se ignora y se prueba con la ultima version estable en su lugar")
        version = ""
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
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_wp_")
    cache_path = _cache_path_for("wordpress-plugin", slug, resolved_version)
    if cache_path and os.path.isdir(cache_path) and os.listdir(cache_path):
        step(f"'{slug}' {resolved_version} ya estaba en cache local ({cache_path}) -- copiando "
             f"en vez de volver a descargar...")
        if _copy_from_cache(cache_path, dest_dir, slug):
            res.ok = True
            res.local_path = dest_dir
            res.plugin_dir = slug
            return res
        step("la copia desde cache fallo -- descargando de nuevo igualmente...")
    step(f"descargando {slug} {resolved_version or '(ultima)'} ({url})...")
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
    if cache_path:
        _save_to_cache(os.path.join(dest_dir, slug), cache_path)
    return res


def fetch_drupal_module(slug: str, version: str = "", dest_dir: str = "",
                        on_step: Optional[Callable[[str], None]] = None,
                        timeout: float = 60.0) -> SourceFetchResult:
    """Descarga el .tar.gz OFICIAL de un modulo de Drupal.org, usando la misma API de
    actualizaciones que el propio 'Update Manager' de Drupal consulta (XML, no JSON como
    WordPress.org). Sin libreria de terceros: XML con xml.etree.ElementTree, que ya viene con
    Python. No ejecuta nada del modulo."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="drupal-module", source=slug)
    slug = (slug or "").strip().lower()
    if not slug:
        res.note = "machine name de modulo vacio"
        return res
    if version and not _looks_like_version(version):
        step(f"'{version}' no tiene pinta de numero de version real -- se ignora y se prueba "
             f"con la ultima release estable en su lugar")
        version = ""
    step(f"resolviendo modulo '{slug}' en Drupal.org...")
    import xml.etree.ElementTree as ET
    try:
        with _urlopen(_DRUPAL_UPDATE_XML.format(project=slug), timeout=timeout) as r:
            xml_bytes = r.read(2 * 1024 * 1024)
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        res.note = (f"modulo '{slug}' no resuelto en Drupal.org: {e}. Puede ser que (a) el "
                    f"machine name este mal escrito (revisa la URL del proyecto, "
                    f"drupal.org/project/<machine_name>), (b) sea un modulo que ya no se "
                    f"mantiene/fue retirado, o (c) sea una distribucion/modulo privado que no "
                    f"esta en Drupal.org -- en ese caso pasa --source con la ruta a tu .tar.gz/"
                    f".zip ya descargado, o una URL de descarga directa")
        return res
    releases = root.findall("./releases/release")
    if not releases:
        res.note = f"Drupal.org no listo ninguna release para '{slug}'"
        return res
    chosen = None
    if version:
        for rel in releases:
            v = (rel.findtext("version") or "").strip()
            if v == version or v.endswith(version):
                chosen = rel
                break
        if chosen is None:
            res.note = (f"version '{version}' no encontrada entre las releases de '{slug}' en "
                        f"Drupal.org; prueba sin --version (toma la ultima estable) o revisa el "
                        f"numero exacto en https://www.drupal.org/project/{slug}/releases")
            return res
    else:
        for rel in releases:
            status = (rel.findtext("status") or "").strip().lower()
            if status in ("published", "") and not rel.findtext("version_extra"):
                chosen = rel
                break
        chosen = chosen or releases[0]
    download_url = (chosen.findtext("download_link") or "").strip()
    resolved_version = (chosen.findtext("version") or "").strip()
    if not download_url:
        res.note = f"la release elegida de '{slug}' no trae download_link"
        return res
    res.resolved_version = resolved_version
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_drupal_")
    cache_path = _cache_path_for("drupal-module", slug, resolved_version)
    if cache_path and os.path.isdir(cache_path) and os.listdir(cache_path):
        step(f"'{slug}' {resolved_version} ya estaba en cache local ({cache_path}) -- copiando "
             f"en vez de volver a descargar...")
        if _copy_from_cache(cache_path, dest_dir, slug):
            res.ok = True
            res.local_path = dest_dir
            res.plugin_dir = slug
            return res
        step("la copia desde cache fallo -- descargando de nuevo igualmente...")
    step(f"descargando {slug} {resolved_version} ({download_url})...")
    import tarfile
    tfd, tpath = tempfile.mkstemp(prefix="binoracle_drupal_", suffix=".tar.gz")
    os.close(tfd)
    try:
        with _urlopen(download_url, timeout=timeout) as r:
            total = 0
            with open(tpath, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD:
                        raise ValueError(f"descarga excede {_MAX_DOWNLOAD} bytes (abortada)")
                    f.write(chunk)
    except Exception as e:
        res.note = f"fallo descargando {download_url}: {e}"
        return res
    try:
        if download_url.endswith(".tar.gz") or download_url.endswith(".tgz"):
            with tarfile.open(tpath, "r:gz") as tf:
                safe_members = [m for m in tf.getmembers()
                               if not m.name.startswith("/") and ".." not in m.name.split("/")]
                tf.extractall(dest_dir, members=safe_members)
        else:
            _safe_extract_zip(tpath, dest_dir)
    except Exception as e:
        res.note = f"fallo extrayendo {tpath}: {e}"
        return res
    finally:
        try:
            os.remove(tpath)
        except Exception:
            pass
    res.ok = True
    res.local_path = dest_dir
    # convencion de Drupal.org: el tar.gz extrae a una carpeta == machine name; si por lo que sea
    # no fuera asi (empaquetado distinto), se detecta por el .info.yml real en vez de asumirlo.
    res.plugin_dir = (slug if os.path.isdir(os.path.join(dest_dir, slug))
                      else detect_module_folder(dest_dir))
    step(f"codigo del modulo obtenido en {dest_dir}" +
        (f" (carpeta del modulo: {res.plugin_dir})" if res.plugin_dir else ""))
    if cache_path and res.plugin_dir == slug:
        _save_to_cache(os.path.join(dest_dir, slug), cache_path)
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
    # confirmado en vivo: una URL que no existe/requiere credenciales (un repo privado, una org
    # mal escrita, source_url una hipotesis del LLM que no es un repo real) hace que git, SIN
    # esto, se quede colgado pidiendo usuario/contrasena por el terminal en vez de fallar al
    # momento -- aqui no hay terminal interactivo esperando esa respuesta, asi que el proceso
    # colgaba hasta agotar el `timeout` entero (90s) sin hacer nada util. GIT_TERMINAL_PROMPT=0
    # hace que git falle YA (exit code distinto de 0, mensaje de error normal) en vez de esperar.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
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
    varias, busca la que tenga un .php con una cabecera 'Plugin Name:' (la convencion de
    WordPress), un .info.yml con 'type: module|theme' (la convencion de Drupal -- ver
    detect_module_folder, mismo chequeo), o un .xml de manifiesto con `<extension type="...">`
    (la convencion de Joomla -- component/module/plugin/template/library/package), para que un
    .zip/URL comercial de CUALQUIER CMS se detecte sin que el analista tenga que decir cual es.
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
                low = fn.lower()
                if low.endswith(".php"):
                    try:
                        with open(os.path.join(sub, fn), "r", encoding="utf-8", errors="replace") as f:
                            head = f.read(4000)
                    except Exception:
                        continue
                    if re.search(r"Plugin\s*Name\s*:", head, re.I):
                        return e
                elif low.endswith(".info.yml"):
                    try:
                        with open(os.path.join(sub, fn), "r", encoding="utf-8", errors="replace") as f:
                            head = f.read(2000)
                    except Exception:
                        continue
                    if re.search(r"^\s*type\s*:\s*['\"]?(module|theme)['\"]?\s*$", head, re.M | re.I):
                        return e
                elif low.endswith(".xml"):
                    try:
                        with open(os.path.join(sub, fn), "r", encoding="utf-8", errors="replace") as f:
                            head = f.read(2000)
                    except Exception:
                        continue
                    if re.search(r"<extension\b[^>]*\btype\s*=\s*['\"]"
                                r"(component|module|plugin|template|library|package)['\"]",
                                head, re.I):
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
                 timeout: float = 90.0, cms_hint: str = "") -> SourceFetchResult:
    """Despacha por la forma de `target`: .zip ya en disco -> extrae; URL http(s) directa a un .zip
    -> descarga (ANTES que la comprobacion de git: una URL de github.com/.../archive/x.zip es un
    .zip, no un repo a clonar, aunque el host coincida); URL de git -> clone; si no, se trata como
    slug/machine-name de un directorio de plugins/modulos (WordPress.org o Drupal.org -- ambos son
    directorios GRATUITOS; un plugin/modulo comercial nunca estara ahi, usa las otras tres vias).

    `cms_hint` ("wordpress"/"drupal"/"") desambigua cuando el analista YA SABE de que CMS es (el
    machine name de Drupal y el slug de WordPress pueden coincidir en forma, p.ej. 'webform'
    podria en teoria ser cualquiera de los dos): si se da, se intenta SOLO ese directorio. Sin
    hint, se usa una pista de forma (guion bajo -> probablemente Drupal, ver
    looks_like_drupal_slug) para decidir cual probar PRIMERO, pero si falla se intenta el otro
    directorio tambien antes de rendirse -- mas lento en el caso ambiguo, pero nunca falla por
    haber adivinado el CMS equivocado cuando el nombre si existe en el otro."""
    target = (target or "").strip()
    cms_hint = (cms_hint or "").strip().lower()
    if not target:
        return SourceFetchResult(note="sin source_url/slug para resolver")
    if looks_like_local_zip(target):
        return fetch_local_zip(target, on_step=on_step)
    if looks_like_zip_url(target):
        return fetch_zip_url(target, on_step=on_step, timeout=timeout)
    if looks_like_git_url(target):
        return fetch_git_source(target, ref=version, on_step=on_step, timeout=timeout)
    # confirmado en vivo: la hipotesis del LLM a veces trae la URL de la PAGINA del directorio
    # (https://wordpress.org/plugins/ultimate-member/), no el slug desnudo que el resto de este
    # despacho espera -- se reconoce aparte y se extrae el slug, en vez de rechazarla entera.
    wp_page_slug = _extract_wp_org_plugin_slug(target)
    if wp_page_slug:
        target, cms_hint = wp_page_slug, "wordpress"
    else:
        # confirmado en vivo: NVD referencia a menudo el changeset Trac del parche en vez de la
        # pagina del directorio -- el LLM a veces trae esa URL de source_url tal cual.
        wp_trac_slug = _extract_wp_trac_plugin_slug(target)
        if wp_trac_slug:
            target, cms_hint = wp_trac_slug, "wordpress"
        else:
            drupal_page_slug = _extract_drupal_org_module_slug(target)
            if drupal_page_slug:
                target, cms_hint = drupal_page_slug, "drupal"

    if cms_hint == "drupal":
        return fetch_drupal_module(target, version=version, on_step=on_step, timeout=timeout)
    if cms_hint == "wordpress":
        return fetch_wordpress_plugin(target, version=version, on_step=on_step, timeout=timeout)

    is_wp_shaped = looks_like_wp_slug(target)
    is_drupal_shaped = looks_like_drupal_slug(target)
    if not (is_wp_shaped or is_drupal_shaped):
        return SourceFetchResult(source=target,
                                 note=f"'{target}' no parece una URL de git, un .zip (local o "
                                     f"URL), ni un slug/machine-name de WordPress.org o "
                                     f"Drupal.org")
    # orden de intento por forma: guion bajo -> Drupal primero; si no, WordPress primero (es el
    # caso mas comun en el uso real de binoracle hasta ahora). El perdedor se intenta igual como
    # segunda pasada si el primero no resuelve -- un nombre de una sola palabra sin separadores
    # (p.ej. 'webform') tiene forma valida en ambos y no hay como saberlo sin probar.
    first, second = ((fetch_drupal_module, fetch_wordpress_plugin) if is_drupal_shaped
                    else (fetch_wordpress_plugin, fetch_drupal_module))
    r1 = first(target, version=version, on_step=on_step, timeout=timeout)
    if r1.ok:
        return r1
    r2 = second(target, version=version, on_step=on_step, timeout=timeout)
    if r2.ok:
        return r2
    # ninguno resolvio: se devuelve el primer intento (mismo 'note' que antes de este cambio para
    # el caso WordPress-only), pero con ambos fallos anotados para no esconder el segundo intento.
    r1.note = (r1.note or "") + f" | tambien se probo como modulo/plugin del otro CMS: {r2.note}"
    return r1


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
