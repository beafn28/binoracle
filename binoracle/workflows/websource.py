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

import json as _json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional

_WP_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
_WP_DOWNLOAD = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
_WP_DOWNLOAD_LATEST = "https://downloads.wordpress.org/plugin/{slug}.zip"
_WP_SEARCH = "https://api.wordpress.org/plugins/info/1.2/"

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
    (espacios -> 'URL can't contain control characters', confirmado en vivo).
    Tambien rechaza enteros sueltos sin punto ('1', '2') que el LLM a veces alucina copiando
    el numero de version principal del titulo del CVE -- ningun plugin real de WordPress.org
    tiene un numero de version sin al menos un punto."""
    if not v:
        return False
    s = v.strip()
    return bool(_VERSION_RE.match(s)) and "." in s


def _version_sort_key(v: str):
    """Clave de orden para comparar versiones '1.6.9' < '1.7.0' numericamente (no lexicografico:
    '1.10.0' lexicografico queda ANTES de '1.9.0', que es al reves de lo real) -- usada para
    encontrar la ultima version publicada ANTES de un limite exclusivo (ver
    fetch_wordpress_plugin). Deliberadamente simple: cada segmento numerico se compara como int,
    cualquier sufijo no numerico ('beta1') se compara como texto detras de todos los numeros."""
    key = []
    for part in re.split(r"[.\-]", v or ""):
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


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


def _search_wp_plugin_slug(wrong_slug: str, timeout: float = 30.0,
                            display_name: str = "") -> Optional[str]:
    """Gap real encontrado en vivo (CVE-2026-2991, KiviCare): la hipotesis del LLM a veces trae
    un slug CASI correcto (una palabra de mas o de menos, p.ej. 'kivicare-clinic-PATIENT-
    management-system' en vez del real 'kivicare-clinic-management-system') -- la API de info
    exacta (_WP_API) no tiene tolerancia a eso y da 404 directo, bloqueando TODA la verificacion
    dinamica en el primer paso aunque el plugin real exista y el analista/LLM tuviera el nombre
    casi bien. Busca el slug con la API de BUSQUEDA de WordPress.org (la misma que el buscador
    del directorio usa), usando el propio slug con guiones->espacios como consulta, y solo acepta
    el primer resultado si comparte al menos la mitad de sus palabras con el slug original
    (Jaccard sobre el split por '-') -- para no sustituir silenciosamente un plugin NO relacionado
    que simplemente aparezca primero en una busqueda demasiado generica.

    `display_name`: nombre de producto original (antes de transformarlo a slug), p.ej. "GiveWP"
    para CVE-2024-5932. Cuando se da se usa como texto de busqueda y se acepta el primer
    resultado si el nombre/slug del plugin encontrado contiene cualquiera de las palabras de
    display_name (> 3 letras) -- cubre el caso "GiveWP" -> slug "give" donde el Jaccard sobre el
    slug es 0 pero la palabra "give" aparece en el nombre del resultado "GiveWP – Donation Plugin".

    None si no hay API disponible, no hay resultados, o el mejor resultado no se parece bastante."""
    try:
        import json
        from urllib.parse import urlencode
        # Cuando tenemos el nombre de producto original, usarlo para buscar (da mejores resultados
        # que el slug slugificado).
        q = (display_name or wrong_slug).replace("-", " ").replace("_", " ")
        url = f"{_WP_SEARCH}?{urlencode({'action': 'query_plugins', 'request[search]': q, 'request[per_page]': 3})}"
        with _urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read(2 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception:
        return None
    plugins = (data or {}).get("plugins") or []
    if not plugins:
        return None
    candidate = (plugins[0].get("slug") or "").strip().lower()
    if not candidate or candidate == wrong_slug:
        return None
    # Metodo 1: Jaccard sobre el split por '-' (funciona para slugs casi-correctos)
    orig_words = set(wrong_slug.split("-"))
    cand_words = set(candidate.split("-"))
    if orig_words and cand_words:
        overlap = len(orig_words & cand_words) / len(orig_words | cand_words)
        if overlap >= 0.5:
            return candidate
    # Metodo 2: si hay display_name, aceptar si alguna palabra significativa del display_name
    # (>3 letras) aparece en el slug o en el nombre del resultado. Cubre el caso "GiveWP" -> "give"
    # donde el Jaccard es 0 pero "give" esta en "GiveWP" y en el nombre "GiveWP - Donation Plugin".
    if display_name:
        dn_lower = display_name.lower()
        plugin_name = (plugins[0].get("name") or "").lower()
        dn_words = [w for w in re.split(r'[^a-z0-9]+', dn_lower) if len(w) > 3]
        if dn_words:
            # acepta si el candidato es un prefijo/sufijo significativo del display_name o viceversa
            if (candidate in dn_lower or dn_lower.startswith(candidate)
                    or any(w in candidate or w in plugin_name for w in dn_words)):
                return candidate
    # Metodo 3: subset check -- el slug del LLM es el nombre completo del plugin (p.ej.
    # "hash-form-drag-drop-form-builder") mientras el slug real es una version abreviada
    # ("hash-form"). Acepta si TODAS las palabras del candidato aparecen en el slug original.
    # Esto cubre slugs abreviados sin sustituir plugins no relacionados (un slug ajeno no
    # tendria todas sus palabras en el slug largo del LLM).
    if cand_words and cand_words <= orig_words:
        return candidate
    return None


def fetch_wordpress_plugin(slug: str, version: str = "", dest_dir: str = "",
                           on_step: Optional[Callable[[str], None]] = None,
                           timeout: float = 60.0,
                           exclusive_upper_bound: bool = False,
                           _allow_slug_correction: bool = True) -> SourceFetchResult:
    """Descarga el .zip OFICIAL de un plugin de WordPress.org (el mismo artefacto que `wp plugin
    install` traeria), a una version concreta si se da, o a la ultima estable si no. No lo ejecuta.

    `exclusive_upper_bound`: True si `version` es un limite EXCLUSIVO ('antes de X', X ya
    parcheada -- ver _affected_version_is_exclusive en cve_agent.py). En ese caso, en vez de
    descargar `version` tal cual (que seria la version YA ARREGLADA, inservible para verificar
    nada), se busca -- en la lista REAL de versiones publicadas que ya devuelve la API de
    WordPress.org -- la mas reciente publicada ANTES de ese limite, y se descarga esa. Confirmado
    en vivo, CVE-2024-3552: 'before 1.7.0' descargaba 1.7.0 (el fix) hasta este cambio."""
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
    # Algunos plugins/LLMs dan versiones con prefijo 'v' (ej. 'v2.28.1'): quitarlo antes de
    # construir la URL de descarga (WordPress.org sirve '2.28.1', no 'v2.28.1').
    if version and version.startswith(("v", "V")) and _looks_like_version(version[1:]):
        version = version[1:]
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
        # 404 en esta API tiene VARIAS causas reales, no solo "slug mal escrito": intenta
        # primero corregir un slug CASI correcto via la API de busqueda (ver
        # _search_wp_plugin_slug -- caso real confirmado hoy con CVE-2026-2991/KiviCare, un slug
        # con una palabra de mas bloqueaba TODA la verificacion en este primer paso) antes de
        # asumir que es alguna de las otras dos causas reales de 404 de abajo.
        if _allow_slug_correction:
            corrected = _search_wp_plugin_slug(slug, timeout=timeout)
            if corrected:
                step(f"'{slug}' no resolvio en WordPress.org -- la busqueda del directorio "
                     f"sugiere que el slug real es '{corrected}' (suficiente solape de "
                     f"palabras); reintentando con ese...")
                return fetch_wordpress_plugin(corrected, version=version, dest_dir=dest_dir,
                                              on_step=on_step, timeout=timeout,
                                              exclusive_upper_bound=exclusive_upper_bound,
                                              _allow_slug_correction=False)
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
            _r_direct = _download_wp_zip(slug, _WP_DOWNLOAD.format(slug=slug, version=version),
                                         version, dest_dir, step, timeout, res)
            if _r_direct.ok:
                return _r_direct
            # Plugin cerrado + zip no disponible → intentar SVN histórico
            # WordPress mantiene SVN de todos los plugins aunque estén cerrados/retirados
            _r_svn = _svn_fetch_wp_plugin_version(slug, version, dest_dir, step, timeout)
            if _r_svn.ok:
                return _r_svn
            return _r_direct  # devuelve el resultado del intento directo con su error
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
    if version and exclusive_upper_bound and version in versions:
        older = [v for v in versions if v.lower() != "trunk" and _looks_like_version(v)
                and _version_sort_key(v) < _version_sort_key(version)]
        if older:
            older.sort(key=_version_sort_key)
            picked = older[-1]
            step(f"'{version}' es un limite EXCLUSIVO ('antes de', no la incluye) -- esa version "
                 f"ya esta parcheada; descargando la ultima version REALMENTE publicada antes de "
                 f"esa, '{picked}', en vez de la version del fix...")
            version = picked
        else:
            step(f"'{version}' es un limite exclusivo pero no se encontro ninguna version "
                 f"publicada anterior en WordPress.org -- se prueba con esa igualmente (puede "
                 f"estar ya parcheada)")
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
    r = _download_wp_zip(slug, url, res.resolved_version, dest_dir, step, timeout, res)
    # Fallback 1: SVN tag directory — antiguas versiones que ya no están en downloads.wordpress.org
    # pero sí en el SVN histórico (plugins.svn.wordpress.org/{slug}/tags/{version}/).
    # Crítico para CVEs que afectan a versiones antiguas (ej. unlimited-elements 1.5.126).
    if not r.ok and version and version == res.resolved_version:
        svn_res = _svn_fetch_wp_plugin_version(slug, version, dest_dir, step, timeout)
        if svn_res.ok:
            return svn_res
    # Fallback 2: si se pidio una version concreta (que el LLM puede haber alucinado) y la URL
    # versionada 404 y el SVN tampoco lo tiene, intenta con la ultima estable de la API -- al
    # menos el motor tendra codigo real para analizar aunque no sea exactamente la version
    # vulnerable. Confirmado en vivo con varios CVEs donde el LLM da un numero de version que
    # nunca existio en wordpress.org.
    if not r.ok and version and res.resolved_version:
        latest_url = info.get("download_link") or _WP_DOWNLOAD_LATEST.format(slug=slug)
        latest_ver = info.get("version", "")
        if latest_url != url:
            step(f"version '{version}' no descargable -- probando la ultima estable ({latest_ver}) "
                 f"como alternativa para analizar el codigo real...")
            r2 = _download_wp_zip(slug, latest_url, latest_ver, dest_dir, step, timeout,
                                   SourceFetchResult(kind="wordpress-plugin", source=slug))
            if r2.ok:
                return r2
    return r


def _svn_fetch_wp_plugin_version(slug: str, version: str, dest_dir: str, step,
                                  timeout: float) -> "SourceFetchResult":
    """Descarga una version especifica de un plugin desde el SVN de WordPress.org.
    Util cuando la version ya no esta en downloads.wordpress.org (antiguas releases).
    URL: https://plugins.svn.wordpress.org/{slug}/tags/{version}/
    Descarga recursivamente todos los ficheros .php/.js/.css del tag."""
    import urllib.request as _ur
    import re as _re
    import os as _os

    res = SourceFetchResult(kind="wordpress-plugin", source=slug)
    base_svn = f"https://plugins.svn.wordpress.org/{slug}/tags/{version}/"

    # Cache check primero
    cache_path = _cache_path_for("wordpress-plugin", slug, version)
    if cache_path and _os.path.isdir(cache_path) and _os.listdir(cache_path):
        step(f"'{slug}' {version} ya en cache SVN ({cache_path}) -- reutilizando...")
        if _copy_from_cache(cache_path, dest_dir, slug):
            res.ok = True
            res.local_path = dest_dir
            res.resolved_version = version
            return res

    step(f"version '{version}' no en downloads.wordpress.org -- intentando SVN tag ({base_svn})...")

    def _svn_list_dir(url: str) -> list:
        """GET al directorio SVN y extrae enlaces de ficheros y subdirectorios."""
        try:
            req = _ur.Request(url, headers={"User-Agent": "binoracle/1.0"})
            with _ur.urlopen(req, timeout=min(timeout, 20)) as r:
                if r.status != 200:
                    return []
                html = r.read().decode("utf-8", errors="replace")
            # SVN directory listing: <li><a href="filename">filename</a></li>
            return _re.findall(r'href="([^"?#]+)"', html)
        except Exception:
            return []

    _DOWNLOAD_EXTS = {".php", ".js", ".css", ".txt", ".json", ".html", ".htm",
                      ".svg", ".pot", ".po", ".mo"}
    _SKIP_NAMES = {"../", "..", ".", ""}

    def _svn_fetch_recursive(base_url: str, local_base: str, depth: int = 0) -> int:
        """BFS concurrente: explora directorios Y descarga ficheros en paralelo.

        Fase 1 — BFS de directorios con 20 threads: cada nivel del árbol se
        procesa en una sola ronda de peticiones paralelas (en vez de secuencial).
        Convierte 100+ requests secuenciales (~1300s) en ~4 rondas paralelas (~20s).

        Fase 2 — descarga de ficheros con 20 threads (igual que antes).
        """
        import concurrent.futures as _cf

        step("SVN: explorando directorios en paralelo (BFS concurrente)...")

        # Cada elemento de la cola es (dir_url, local_dir_path, depth)
        pending_dirs = [(base_url, local_base, depth)]
        file_tasks = []  # (file_url, local_path)

        def _list_one_dir(args):
            """Devuelve (dir_url, local_dir, depth, subdirs, files)."""
            dir_url, local_dir, d = args
            if d > 8:
                return dir_url, local_dir, d, [], []
            entries = _svn_list_dir(dir_url)
            subdirs, files = [], []
            for entry in entries:
                if entry in _SKIP_NAMES or entry.startswith("?") or entry.startswith("//"):
                    continue
                if entry.endswith("/"):
                    sub_local = _os.path.join(local_dir, entry.rstrip("/"))
                    _os.makedirs(sub_local, exist_ok=True)
                    subdirs.append((dir_url + entry, sub_local, d + 1))
                else:
                    _, ext = _os.path.splitext(entry.lower())
                    if ext in _DOWNLOAD_EXTS:
                        files.append((dir_url + entry, _os.path.join(local_dir, entry)))
            return dir_url, local_dir, d, subdirs, files

        # BFS: cada ronda procesa todos los directorios pendientes en paralelo
        with _cf.ThreadPoolExecutor(max_workers=20) as pool:
            while pending_dirs:
                results = list(pool.map(_list_one_dir, pending_dirs))
                pending_dirs = []
                for _, _, _, subdirs, files in results:
                    pending_dirs.extend(subdirs)
                    file_tasks.extend(files)

        if not file_tasks:
            return 0
        step(f"SVN: {len(file_tasks)} ficheros encontrados — descargando en paralelo (20 threads)...")

        def _download_one(args) -> bool:
            file_url, local_file = args
            try:
                req = _ur.Request(file_url, headers={"User-Agent": "binoracle/1.0"})
                with _ur.urlopen(req, timeout=min(timeout, 15)) as r:
                    if r.status == 200:
                        content = r.read()
                        with open(local_file, "wb") as fh:
                            fh.write(content)
                        return True
            except Exception:
                pass
            return False

        downloaded = 0
        with _cf.ThreadPoolExecutor(max_workers=20) as pool:
            for ok in pool.map(_download_one, file_tasks):
                if ok:
                    downloaded += 1
        return downloaded

    try:
        # Verificar que el tag existe
        entries = _svn_list_dir(base_svn)
        if not entries or all(e in _SKIP_NAMES for e in entries):
            # Tag exacto no existe — listar todos los tags disponibles y buscar el
            # más cercano al solicitado (versión más alta ≤ version_pedida).
            # Esto cubre el caso común donde el publisher no etiquetó CADA release
            # pero sí las principales: unlimited-elements tiene 1.5.102 pero no 1.5.126.
            svn_tags_base = f"https://plugins.svn.wordpress.org/{slug}/tags/"
            tag_entries = _svn_list_dir(svn_tags_base)
            available = sorted(
                [t.rstrip("/") for t in tag_entries
                 if t not in _SKIP_NAMES and not t.startswith("?") and t.endswith("/")
                 and _re.match(r"^\d", t)],
                key=lambda v: [int(x) if x.isdigit() else x
                               for x in _re.split(r"[.\-]", v)])
            # Versiones ≤ solicitada (candidatas vulnerables)
            _vkey = [int(x) if x.isdigit() else x
                     for x in _re.split(r"[.\-]", version)]
            older = [v for v in available
                     if [int(x) if x.isdigit() else x
                         for x in _re.split(r"[.\-]", v)] <= _vkey]
            if older:
                best = older[-1]  # mayor versión ≤ solicitada
                step(f"SVN: tag '{version}' no existe — usando la más cercana disponible "
                     f"'{best}' (de {len(available)} tags en SVN)")
                version = best
                base_svn = f"{svn_tags_base}{best}/"
                res.resolved_version = best
                # actualizar cache_path para la versión resuelta
                cache_path = _cache_path_for("wordpress-plugin", slug, best)
                if cache_path and _os.path.isdir(cache_path) and _os.listdir(cache_path):
                    step(f"'{slug}' {best} ya en cache SVN ({cache_path}) -- reutilizando...")
                    if _copy_from_cache(cache_path, dest_dir, slug):
                        res.ok = True
                        res.local_path = dest_dir
                        return res
                entries = _svn_list_dir(base_svn)
            if not entries or all(e in _SKIP_NAMES for e in entries):
                step(f"SVN: no se encontraron tags disponibles para '{slug}' ≤ {version}")
                return res

        plugin_local_dir = _os.path.join(dest_dir, slug)
        _os.makedirs(plugin_local_dir, exist_ok=True)
        n_files = _svn_fetch_recursive(base_svn, plugin_local_dir)
        if n_files == 0:
            step(f"SVN tag '{version}' encontrado pero no se descargo ningun fichero")
            return res

        step(f"SVN: descargados {n_files} ficheros de '{slug}' v{version} desde SVN")
        res.ok = True
        res.local_path = dest_dir
        res.resolved_version = version

        # Guardar en cache para proximas ejecuciones
        if cache_path:
            try:
                import shutil as _shutil
                _shutil.copytree(dest_dir, cache_path, dirs_exist_ok=True)
            except Exception:
                pass
    except Exception as exc:
        step(f"SVN fetch error para '{slug}' {version}: {exc}")
    return res


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
                        timeout: float = 60.0, exclusive_upper_bound: bool = False
                        ) -> SourceFetchResult:
    """Descarga el .tar.gz OFICIAL de un modulo de Drupal.org, usando la misma API de
    actualizaciones que el propio 'Update Manager' de Drupal consulta (XML, no JSON como
    WordPress.org). Sin libreria de terceros: XML con xml.etree.ElementTree, que ya viene con
    Python. No ejecuta nada del modulo.

    `exclusive_upper_bound`: True si `version` es un limite EXCLUSIVO ('antes de X', X ya
    parcheada -- ver _affected_version_is_exclusive en cve_agent.py), igual que en
    fetch_wordpress_plugin(). Mismo mecanismo: entre las releases REALES que Drupal.org lista
    para el proyecto, se busca la mas reciente publicada ANTES de ese limite (por
    _version_sort_key, que ya entiende el formato 'NUCLEO.x-MAYOR.MENOR' de Drupal: el prefijo
    de compatibilidad de core se compara como segmento de texto, los numeros de version real
    numericamente) y se descarga esa en vez de la version X tal cual -- misma logica, no
    adivinada: el problema (un rango de version EXCLUSIVO del CVE apuntando a la version YA
    ARREGLADA si se toma literal) es una propiedad de como se describen los CVEs, no del
    mecanismo de descarga de WordPress.org en concreto."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="drupal-module", source=slug)
    slug = (slug or "").strip().lower()
    if not slug:
        res.note = "machine name de modulo vacio"
        return res
    if version and version.startswith(("v", "V")) and _looks_like_version(version[1:]):
        version = version[1:]
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
    if version and exclusive_upper_bound:
        real_versions = [(rel.findtext("version") or "").strip() for rel in releases]
        if any(v == version or v.endswith(version) for v in real_versions):
            older = [v for v in real_versions if _looks_like_version(v)
                    and _version_sort_key(v) < _version_sort_key(version)]
            if older:
                older.sort(key=_version_sort_key)
                picked = older[-1]
                step(f"'{version}' es un limite EXCLUSIVO ('antes de', no la incluye) -- esa "
                     f"version ya esta parcheada; descargando la ultima release REALMENTE "
                     f"publicada antes de esa, '{picked}', en vez de la version del fix...")
                version = picked
            else:
                step(f"'{version}' es un limite exclusivo pero no se encontro ninguna release "
                     f"publicada anterior en Drupal.org -- se prueba con esa igualmente (puede "
                     f"estar ya parcheada)")
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
    # Quick existence check for GitHub repos to avoid a 90s git-clone timeout
    # on repos that don't exist (hallucinated URLs from LLM).
    _gh_match = re.match(r'https?://github\.com/([^/]+/[^/]+?)(?:\.git|/)?$', url)
    if _gh_match:
        import urllib.request as _ureq
        import urllib.error as _uerr
        _api_url = f"https://api.github.com/repos/{_gh_match.group(1)}"
        try:
            _req = _ureq.Request(_api_url,
                                  headers={"Accept": "application/vnd.github+json",
                                           "User-Agent": "binoracle/1.0"})
            _ureq.urlopen(_req, timeout=6)
        except _uerr.HTTPError as _he:
            if _he.code == 404:
                res.note = f"repo GitHub no existe (404): {url}"
                return res
        except Exception:
            pass  # network issue — let git clone try anyway
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
        err_text = (out.stderr or "").strip()
        # Branch/tag not found: retry with v-prefix (npm convention) then without --branch
        if ref and ("remote branch" in err_text.lower() or
                    "not found in upstream" in err_text.lower() or
                    "no encontrada" in err_text.lower()):
            import shutil as _sh
            # 1) try v{version} tag (npm/node packages tag as v1.2.3 not 1.2.3)
            if ref and not ref.startswith("v"):
                v_ref = f"v{ref}"
                dest_dir_v = tempfile.mkdtemp(prefix="binoracle_git_")
                cmd_v = [git, "clone", "--depth", "1", "--branch", v_ref, url, dest_dir_v]
                try:
                    out_v = subprocess.run(cmd_v, capture_output=True,
                                           text=True, timeout=timeout, env=env)
                    if out_v.returncode == 0:
                        res.ok = True
                        res.local_path = dest_dir_v
                        res.resolved_version = v_ref
                        step(f"clonado con tag '{v_ref}' en {dest_dir_v}")
                        return res
                    else:
                        _sh.rmtree(dest_dir_v, ignore_errors=True)
                except Exception:
                    _sh.rmtree(dest_dir_v, ignore_errors=True)
            # 2) fallback: clone default branch (HEAD)
            step(f"rama '{ref}' no existe, reintentando sin --branch ...")
            try:
                _sh.rmtree(dest_dir, ignore_errors=True)
                dest_dir2 = tempfile.mkdtemp(prefix="binoracle_git_")
                cmd2 = [git, "clone", "--depth", "1", url, dest_dir2]
                out = subprocess.run(cmd2, capture_output=True,
                                     text=True, timeout=timeout, env=env)
                if out.returncode == 0:
                    res.ok = True
                    res.local_path = dest_dir2
                    return res
            except Exception:
                pass
        res.note = f"git clone fallo: {err_text[:300]}"
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
    """Descarga un .zip o .tar.gz de una URL DIRECTA (no WordPress.org).
    Detecta automáticamente el formato por extensión de la URL o por los primeros bytes."""
    step = on_step or (lambda _m: None)
    res = SourceFetchResult(kind="zip-url", source=url)
    step(f"descargando {url}...")
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="binoracle_zipurl_")
    # Determinar extensión por la URL para elegir el nombre del fichero temporal
    _url_path = url.split("?", 1)[0].lower()
    _is_tgz = _url_path.endswith(".tar.gz") or _url_path.endswith(".tgz")
    _suffix = ".tar.gz" if _is_tgz else ".zip"
    zfd, zpath = tempfile.mkstemp(prefix="binoracle_zipurl_", suffix=_suffix)
    os.close(zfd)
    try:
        with _urlopen(url, timeout=timeout) as r:
            total = 0
            # Re-check Content-Type header for format detection
            _ct = ""
            try:
                _ct = (r.headers.get("Content-Type") or "").lower()
            except Exception:
                pass
            if "gzip" in _ct or "tar" in _ct:
                _is_tgz = True
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
    # Detectar por magic bytes si la URL no daba pista suficiente
    try:
        with open(zpath, "rb") as _mf:
            _magic = _mf.read(3)
        if _magic[:2] == b"\x1f\x8b":  # gzip magic
            _is_tgz = True
    except Exception:
        pass
    try:
        if _is_tgz:
            _extract_tarball(zpath, dest_dir)
        else:
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


_PYPI_API        = "https://pypi.org/pypi/{name}/{version}/json"
_PYPI_API_LATEST = "https://pypi.org/pypi/{name}/json"
_NPM_REGISTRY    = "https://registry.npmjs.org/{name}/{version}"
_NPM_LATEST      = "https://registry.npmjs.org/{name}/latest"
_RUBYGEMS_API    = "https://rubygems.org/api/v1/gems/{name}.json"
_RUBYGEMS_DL     = "https://rubygems.org/gems/{name}-{version}.gem"
_MAVEN_CENTRAL   = ("https://search.maven.org/remotecontent?filepath="
                    "{gpath}/{a}/{v}/{a}-{v}-sources.jar")


def _http_get_json(url: str, timeout: float = 20.0) -> dict:
    """Fetch JSON from URL; raises urllib.error.URLError / ValueError on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0 CVE-research"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return _json.loads(resp.read().decode("utf-8", errors="replace"))


def _http_download(url: str, dest_path: str, timeout: float = 90.0,
                   max_bytes: int = 80 * 1024 * 1024) -> None:
    """Download URL to dest_path (streaming, capped at max_bytes)."""
    req = urllib.request.Request(url, headers={"User-Agent": "binoracle/1.0 CVE-research"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, \
         open(dest_path, "wb") as fh:
        read = 0
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            read += len(chunk)
            if read > max_bytes:
                raise ValueError(f"download exceeded {max_bytes} bytes: {url}")
            fh.write(chunk)


def _extract_tarball(tarball_path: str, dest_dir: str) -> None:
    """Extract .tar.gz or .tgz to dest_dir, stripping the leading component."""
    with tarfile.open(tarball_path, "r:gz") as tf:
        members = tf.getmembers()
        # strip leading directory (e.g. 'package/' from npm, 'django-tenants-3.4/' from PyPI)
        if members:
            prefix = members[0].name.split("/")[0] + "/"
            for m in members:
                if m.name.startswith(prefix):
                    m.name = m.name[len(prefix):]
            tf.extractall(dest_dir, members=[m for m in members if m.name])


def fetch_pypi_package(name: str, version: str = "",
                       on_step: Optional[Callable[[str], None]] = None,
                       timeout: float = 90.0) -> "SourceFetchResult":
    """Download a PyPI package sdist (.tar.gz) for a given name + version."""
    step = on_step or (lambda _m: None)
    name = name.strip()
    ver  = version.strip()
    # Normalise: PyPI uses '-' or '_' interchangeably
    name_norm = name.replace("-", "-").lower()
    try:
        url = (_PYPI_API.format(name=name_norm, version=ver) if ver
               else _PYPI_API_LATEST.format(name=name_norm))
        meta = _http_get_json(url, timeout=min(timeout, 20))
    except Exception as e:
        # Try with underscore variant if hyphen variant fails
        alt = name_norm.replace("-", "_")
        if alt != name_norm:
            try:
                url = (_PYPI_API.format(name=alt, version=ver) if ver
                       else _PYPI_API_LATEST.format(name=alt))
                meta = _http_get_json(url, timeout=min(timeout, 20))
                name_norm = alt
            except Exception:
                return SourceFetchResult(source=name,
                                         note=f"PyPI API failed for '{name}': {e}")
        else:
            return SourceFetchResult(source=name, note=f"PyPI API failed for '{name}': {e}")

    if not ver:
        ver = meta.get("info", {}).get("version", "")
    # Prefer sdist (.tar.gz), fall back to wheel
    urls = meta.get("urls") or []
    if not urls and ver:
        urls = meta.get("releases", {}).get(ver, [])
    sdist_url = next((u["url"] for u in urls if u.get("packagetype") == "sdist"), None)
    if not sdist_url:
        sdist_url = next((u["url"] for u in urls if u.get("url", "").endswith(".tar.gz")), None)
    if not sdist_url:
        # Last resort: any wheel
        sdist_url = next((u["url"] for u in urls), None)
    if not sdist_url:
        return SourceFetchResult(source=name, note=f"PyPI: no downloadable release for '{name}' {ver}")

    dest_dir = tempfile.mkdtemp(prefix=f"bino_pypi_{name_norm}_")
    tarball  = os.path.join(dest_dir, "sdist.tar.gz")
    step(f"descargando PyPI {name_norm}=={ver} ({sdist_url})...")
    try:
        _http_download(sdist_url, tarball, timeout=timeout)
        extract_dir = os.path.join(dest_dir, "src")
        os.makedirs(extract_dir, exist_ok=True)
        if tarball.endswith(".tar.gz") or tarball.endswith(".tgz"):
            _extract_tarball(tarball, extract_dir)
        else:
            with zipfile.ZipFile(tarball) as zf:
                zf.extractall(extract_dir)
        os.remove(tarball)
    except Exception as e:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return SourceFetchResult(source=name, note=f"PyPI download/extract failed: {e}")

    res = SourceFetchResult(kind="local-dir", source=sdist_url)
    res.ok         = True
    res.local_path = extract_dir
    res.version    = ver
    return res


def fetch_npm_package(name: str, version: str = "",
                      on_step: Optional[Callable[[str], None]] = None,
                      timeout: float = 90.0) -> "SourceFetchResult":
    """Download an npm package tarball for a given name + version."""
    step = on_step or (lambda _m: None)
    name = name.strip()
    ver  = version.strip()
    # URL-encode scoped packages: @scope/pkg → %40scope%2Fpkg
    encoded = name.replace("@", "%40").replace("/", "%2F")
    try:
        url = (_NPM_REGISTRY.format(name=encoded, version=ver) if ver
               else _NPM_LATEST.format(name=encoded))
        meta = _http_get_json(url, timeout=min(timeout, 20))
    except Exception as e:
        return SourceFetchResult(source=name, note=f"npm registry failed for '{name}': {e}")

    tarball_url = (meta.get("dist", {}).get("tarball") or
                   meta.get("dist", {}).get("url") or "")
    if not ver:
        ver = meta.get("version", "")
    if not tarball_url:
        return SourceFetchResult(source=name, note=f"npm: no tarball URL for '{name}' {ver}")

    dest_dir = tempfile.mkdtemp(prefix=f"bino_npm_{name.replace('/', '_').replace('@', '')}_")
    tarball  = os.path.join(dest_dir, "pkg.tgz")
    step(f"descargando npm {name}@{ver} ({tarball_url})...")
    try:
        _http_download(tarball_url, tarball, timeout=timeout)
        extract_dir = os.path.join(dest_dir, "src")
        os.makedirs(extract_dir, exist_ok=True)
        _extract_tarball(tarball, extract_dir)
        os.remove(tarball)
    except Exception as e:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return SourceFetchResult(source=name, note=f"npm download/extract failed: {e}")

    res = SourceFetchResult(kind="local-dir", source=tarball_url)
    res.ok         = True
    res.local_path = extract_dir
    res.version    = ver
    return res


def fetch_gem_package(name: str, version: str = "",
                      on_step: Optional[Callable[[str], None]] = None,
                      timeout: float = 90.0) -> "SourceFetchResult":
    """Download a RubyGem and extract its contents."""
    step = on_step or (lambda _m: None)
    name = name.strip()
    ver  = version.strip()
    if not ver:
        try:
            meta = _http_get_json(_RUBYGEMS_API.format(name=name), timeout=min(timeout, 20))
            ver  = meta.get("version", "")
        except Exception as e:
            return SourceFetchResult(source=name, note=f"RubyGems API failed for '{name}': {e}")
    if not ver:
        return SourceFetchResult(source=name, note=f"RubyGems: could not determine version for '{name}'")
    dl_url   = _RUBYGEMS_DL.format(name=name, version=ver)
    dest_dir = tempfile.mkdtemp(prefix=f"bino_gem_{name}_")
    gem_path = os.path.join(dest_dir, f"{name}-{ver}.gem")
    step(f"descargando gem {name}-{ver}...")
    try:
        _http_download(dl_url, gem_path, timeout=timeout)
        # A .gem is a tar archive containing data.tar.gz (the library source)
        extract_dir = os.path.join(dest_dir, "src")
        os.makedirs(extract_dir, exist_ok=True)
        with tarfile.open(gem_path, "r") as outer:
            outer.extract("data.tar.gz", path=dest_dir)
        data_tgz = os.path.join(dest_dir, "data.tar.gz")
        _extract_tarball(data_tgz, extract_dir)
        os.remove(gem_path)
        os.remove(data_tgz)
    except Exception as e:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return SourceFetchResult(source=name, note=f"gem download/extract failed: {e}")
    res = SourceFetchResult(kind="local-dir", source=dl_url)
    res.ok         = True
    res.local_path = extract_dir
    res.version    = ver
    return res


def _github_repo_fallback(name: str, version: str = "",
                          on_step: Optional[Callable[[str], None]] = None,
                          timeout: float = 90.0) -> Optional["SourceFetchResult"]:
    """Search GitHub API for a repo matching `name` and clone it.

    Returns a SourceFetchResult on success, None if not found or on error.
    Only called when WP/Drupal/PyPI/npm paths all failed.
    """
    step = on_step or (lambda _m: None)
    # Normalize: strip version-range qualifiers ("through-v0-12-34", "before-1-2-3", etc.)
    # and standalone version numbers so GitHub gets just the product name.
    import re as _re
    clean = name
    # 1. Strip whole range suffix: "-through-v0-12-34", "-before-3-0", "-prior-to-1-2"
    clean = _re.sub(r"[-_]+(through|before|prior[-_]?to?|up[-_]?to|since|from)[-_].*$",
                    "", clean, flags=_re.I)
    # 2. Strip trailing version number: "-v0-12-34", "-1-2-3", "-0.12.34"
    clean = _re.sub(r"[-_]+v?\d[\d.\-]*$", "", clean, flags=_re.I)
    clean = clean.strip("-_ ").lower()
    if not clean or len(clean) < 3:
        return None
    try:
        import urllib.request as _ur
        import json as _json
        api_url = f"https://api.github.com/search/repositories?q={clean}+in:name&sort=stars&per_page=5"
        req = _ur.Request(api_url, headers={"Accept": "application/vnd.github+json",
                                             "User-Agent": "binoracle-source-fetcher/1.0"})
        with _ur.urlopen(req, timeout=15) as resp:
            data = _json.loads(resp.read())
        items = data.get("items") or []
        if not items:
            step(f"GitHub search '{clean}': sin resultados")
            return None
        # Pick best match: exact name match first, else highest stars
        exact = [r for r in items if r.get("name", "").lower() == clean]
        repo = exact[0] if exact else items[0]
        clone_url = repo.get("clone_url") or repo.get("html_url")
        stars = repo.get("stargazers_count", 0)
        step(f"GitHub fallback: '{clean}' → {repo['full_name']} ({stars}★) — clonando...")
        return fetch_git_source(clone_url, ref=version, on_step=on_step, timeout=timeout)
    except Exception as exc:
        step(f"GitHub fallback error para '{clean}': {exc}")
        return None


def fetch_source(target: str, version: str = "", on_step: Optional[Callable[[str], None]] = None,
                 timeout: float = 90.0, cms_hint: str = "",
                 exclusive_upper_bound: bool = False) -> SourceFetchResult:
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
    haber adivinado el CMS equivocado cuando el nombre si existe en el otro.

    `exclusive_upper_bound`: True cuando `version` viene de una frase de rango EXCLUSIVA ('before
    X'/'prior to X'/'<X', ver _affected_version_is_exclusive en cve_agent.py) -- esa version YA
    esta parcheada, asi que fetch_wordpress_plugin() busca la ultima version PUBLICADA antes de
    esa en vez de descargar la propia version (que no es la vulnerable). Confirmado en vivo,
    CVE-2024-3552: '<1.7.0' descargaba 1.7.0 tal cual -- la version del FIX, no la vulnerable --
    y por eso la inyeccion SQL nunca se podia confirmar contra ese codigo."""
    target = (target or "").strip()
    cms_hint = (cms_hint or "").strip().lower()
    if not target:
        return SourceFetchResult(note="sin source_url/slug para resolver")

    # Optimización: para cualquier repo GitHub con versión conocida, intentar el tarball
    # del tag exacto (/archive/refs/tags/v<ver>.tar.gz) antes de git clone — mucho más
    # rápido (sólo el snapshot, sin historial git). No requiere tabla hardcodeada: funciona
    # para cualquier proyecto en GitHub que siga el convención de tags vX.Y.Z.
    # fetch_zip_url acepta .tar.gz aunque looks_like_zip_url solo vea .zip.
    if looks_like_git_url(target) and version and "github.com" in target.lower():
        _step = on_step or (lambda _m: None)
        _base = target.rstrip("/")
        for _vfmt in (f"v{version}", version):
            _tgz_url = f"{_base}/archive/refs/tags/{_vfmt}.tar.gz"
            _step(f"descargando snapshot {cms_hint} tag={_vfmt} (tarball, sin historial git)...")
            try:
                _r = fetch_zip_url(_tgz_url, on_step=on_step, timeout=timeout)
                if _r.ok:
                    _r.kind = "git"
                    return _r
            except Exception:
                pass
        _step(f"tarball de tag no disponible — git clone --depth 1 --branch {version}...")

    if looks_like_local_zip(target):
        return fetch_local_zip(target, on_step=on_step)
    if looks_like_zip_url(target):
        return fetch_zip_url(target, on_step=on_step, timeout=timeout)
    if looks_like_git_url(target):
        return fetch_git_source(target, ref=version, on_step=on_step, timeout=timeout)
    # ---- Package registries (PyPI / npm / RubyGems) --------------------------
    # cms_hint="pypi" or "python" → fetch from PyPI directly
    if cms_hint in ("pypi", "python"):
        step = on_step or (lambda _m: None)
        step(f"resolviendo '{target}' como paquete PyPI (hint='{cms_hint}')...")
        r = fetch_pypi_package(target, version=version, on_step=on_step, timeout=timeout)
        if r.ok:
            return r
        step(f"PyPI fallo ({r.note}) -- intentando git clone como fallback...")
        # Don't fall through to WP — return the PyPI failure after git attempt
    # cms_hint="npm" or "nodejs" or "node" → fetch from npm registry
    if cms_hint in ("npm", "nodejs", "node"):
        step = on_step or (lambda _m: None)
        step(f"resolviendo '{target}' como paquete npm (hint='{cms_hint}')...")
        r = fetch_npm_package(target, version=version, on_step=on_step, timeout=timeout)
        if r.ok:
            return r
        step(f"npm fallo ({r.note}) -- intentando git clone como fallback...")
    # cms_hint="gem" or "ruby" → fetch from RubyGems
    if cms_hint in ("gem", "ruby"):
        step = on_step or (lambda _m: None)
        step(f"resolviendo '{target}' como RubyGem (hint='{cms_hint}')...")
        r = fetch_gem_package(target, version=version, on_step=on_step, timeout=timeout)
        if r.ok:
            return r
        step(f"RubyGems fallo ({r.note}) -- continuando...")
    # cms_hint="ghost"/"strapi"/"craft"/"directus"/"wagtail" → versioned GitHub release tarball
    # When the LLM gives only the app name (not a full URL) and we know the CMS, try to pull
    # the exact vulnerable version from the official GitHub releases before falling back to
    # a generic git clone (which would pull latest/patched code).
    _GITHUB_CMS_REPOS: dict = {
        "ghost":       "TryGhost/Ghost",
        "strapi":      "strapi/strapi",
        "craft":       "craftcms/cms",
        "directus":    "directus/directus",
        "wagtail":     "wagtail/wagtail",
        "keystone":    "keystonejs/keystone",
        "payload":     "payloadcms/payload",
        "drupal":        "drupal/drupal",
        "joomla":        "joomla/joomla-cms",
        "typo3":         "TYPO3/typo3",
        "contao":        "contao/contao",
        "mattermost":    "mattermost/mattermost",
        "gitea":         "go-gitea/gitea",
        "nextcloud":     "nextcloud/server",
        # Java/server-level projects
        "tomcat":        "apache/tomcat",
        "jenkins":       "jenkinsci/jenkins",
        "spring":        "spring-projects/spring-framework",
        "struts":        "apache/struts",
        "log4j":         "apache/logging-log4j2",
        "shiro":         "apache/shiro",
        "activemq":      "apache/activemq",
        "springboot":    "spring-projects/spring-boot",
        "springsecurity":"spring-projects/spring-security",
        # Ruby/Python
        "rails":         "rails/rails",
        "flask":         "pallets/flask",
        "django":        "django/django",
        "fastapi":       "fastapi/fastapi",
        # PHP
        "symfony":       "symfony/symfony",
        "laravel":       "laravel/framework",
        "pimcore":       "pimcore/pimcore",
        "magento":       "magento/magento2",
        "mediawiki":     "wikimedia/mediawiki",
        # Go / Node
        "traefik":       "traefik/traefik",
        "harbor":        "goharbor/harbor",
        "grafana":       "grafana/grafana",
        "gitlab":        "gitlab-org/gitlab",
        "discourse":     "discourse/discourse",
    }
    if cms_hint in _GITHUB_CMS_REPOS and not target.startswith(("http://", "https://", "git://")):
        step = on_step or (lambda _m: None)
        _gh_repo = _GITHUB_CMS_REPOS[cms_hint]
        _gh_ver  = version.lstrip("v") if version else ""
        if _gh_ver:
            _tarball = f"https://github.com/{_gh_repo}/archive/refs/tags/v{_gh_ver}.tar.gz"
            step(f"[cms:{cms_hint}] descargando release v{_gh_ver} desde GitHub ({_gh_repo})...")
            r = fetch_zip_url(_tarball, on_step=on_step, timeout=timeout)
            if r.ok:
                return r
            # Try without 'v' prefix (some repos tag as X.Y.Z not vX.Y.Z)
            _tarball2 = f"https://github.com/{_gh_repo}/archive/refs/tags/{_gh_ver}.tar.gz"
            r2 = fetch_zip_url(_tarball2, on_step=on_step, timeout=timeout)
            if r2.ok:
                return r2
            step(f"[cms:{cms_hint}] tarball v{_gh_ver} no disponible — clonando latest como fallback")
        # Fall through: clone full repo (latest) if no version or tarball failed
        target = f"https://github.com/{_gh_repo}"
    # Gap confirmado con CVE-2024-23334: un directorio LOCAL (ya clonado/preparado por el analista)
    # caia en el camino de "ni URL git ni zip" y se rechazaba como "slug no reconocido". Se trata
    # directamente como fuente lista para usar: local_path apunta al directorio tal cual.
    # plugin_dir se deja vacio a proposito: un directorio local generico NO es un plugin de CMS;
    # detect_plugin_folder devolveria la unica subcarpeta (p.ej. "static/" en un servidor aiohttp)
    # por la heuristica de "1 entrada = es esa", lo que haria que not plugin_dir == False en
    # cve_agent.py y bloquearia la rama de verificacion generica de path-traversal (linea 2139).
    if os.path.isdir(target):
        step = on_step or (lambda _m: None)
        step(f"fuente local (directorio): {target}")
        res = SourceFetchResult(kind="local-dir", source=target)
        res.ok = True
        res.local_path = target
        return res
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
        return fetch_drupal_module(target, version=version, on_step=on_step, timeout=timeout,
                                   exclusive_upper_bound=exclusive_upper_bound)
    if cms_hint == "wordpress":
        return fetch_wordpress_plugin(target, version=version, on_step=on_step, timeout=timeout,
                                      exclusive_upper_bound=exclusive_upper_bound)

    is_wp_shaped = looks_like_wp_slug(target)
    is_drupal_shaped = looks_like_drupal_slug(target)
    if not (is_wp_shaped or is_drupal_shaped):
        # Ultimo intento: target puede ser un nombre de producto en CamelCase o con mayusculas
        # (p.ej. "GiveWP" para CVE-2024-5932, donde el slug real es "give") -- el LLM a veces
        # pone el nombre del producto en vez del slug de WP.org. Se slugifica (lowercase +
        # sustituir no-alphanumerico por guion) y se busca en WP.org con el nombre original.
        if "/" not in target and "." not in target:
            display_name = target
            slugified = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")
            if looks_like_wp_slug(slugified):
                step = on_step or (lambda _m: None)
                # Intentar primero el slug slugificado directamente
                r_direct = fetch_wordpress_plugin(slugified, version=version, on_step=on_step,
                                                  timeout=timeout,
                                                  exclusive_upper_bound=exclusive_upper_bound)
                if r_direct.ok:
                    step(f"'{display_name}' resolvio como slug '{slugified}' en WordPress.org")
                    return r_direct
                # Si falla, buscar en WP.org con el nombre original para encontrar el slug real
                corrected = _search_wp_plugin_slug(slugified, timeout=timeout,
                                                   display_name=display_name)
                if corrected:
                    step(f"'{display_name}' resolvio como slug '{corrected}' via busqueda WP.org")
                    return fetch_wordpress_plugin(corrected, version=version, on_step=on_step,
                                                  timeout=timeout,
                                                  exclusive_upper_bound=exclusive_upper_bound)
        # GitHub fallback: si el target parece el nombre de un proyecto (no un slug CMS),
        # buscar el repo en GitHub API y clonar si se encuentra.
        _gh = _github_repo_fallback(target, version=version, on_step=on_step, timeout=timeout)
        if _gh is not None:
            return _gh
        return SourceFetchResult(source=target,
                                 note=f"'{target}' no parece una URL de git, un .zip (local o "
                                     f"URL), ni un slug/machine-name de WordPress.org o "
                                     f"Drupal.org; GitHub search también falló")
    # orden de intento por forma: guion bajo -> Drupal primero; si no, WordPress primero (es el
    # caso mas comun en el uso real de binoracle hasta ahora). El perdedor se intenta igual como
    # segunda pasada si el primero no resuelve -- un nombre de una sola palabra sin separadores
    # (p.ej. 'webform') tiene forma valida en ambos y no hay como saberlo sin probar.
    first, second = ((fetch_drupal_module, fetch_wordpress_plugin) if is_drupal_shaped
                    else (fetch_wordpress_plugin, fetch_drupal_module))
    r1 = first(target, version=version, on_step=on_step, timeout=timeout,
              exclusive_upper_bound=exclusive_upper_bound)
    if r1.ok:
        return r1
    r2 = second(target, version=version, on_step=on_step, timeout=timeout,
               exclusive_upper_bound=exclusive_upper_bound)
    if r2.ok:
        return r2
    # ninguno resolvio: último intento via GitHub antes de rendirse.
    r1.note = (r1.note or "") + f" | tambien se probo como modulo/plugin del otro CMS: {r2.note}"
    _gh2 = _github_repo_fallback(target, version=version, on_step=on_step, timeout=timeout)
    if _gh2 is not None:
        return _gh2
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


@dataclass
class SqlSink:
    param: str          # nombre del superglobal leido ($_GET['x'] -> 'x')
    function: str       # funcion que contiene la linea, si se reconoce ('' si no)
    file: str
    line: int
    snippet: str


_SUPERGLOBAL_READ_RE = re.compile(r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([A-Za-z0-9_\[\]]+)['\"]\s*\]")
# confirmado en vivo, CVE-2024-3552: la hipotesis del LLM citaba 'w2dc_get_map_marker_info' (una
# consulta YA parametrizada con %d, segura de verdad) como la funcion vulnerable, pero el
# verdadero sumidero sin saneo ('$where .= "...". $_GET['w2dc_level_filter'] . "..."') estaba en
# OTRA funcion por completo (level_filter_where), nunca citada por el LLM ni por el PoC publico
# -- grep_vulnerable_functions() solo confirma nombres YA CITADOS, nunca iba a encontrar esto.
# Heuristica: una linea que lee un superglobal ($_GET/$_POST/$_REQUEST) y, en esa MISMA linea,
# tambien usa el operador de concatenacion '.' junto a una variable con pinta de SQL ($where/
# $query/$sql/$join/$order/$having) o una llamada directa a $wpdb->query/get_results/get_var/
# get_row con una cadena construida con '.' -- la MISMA forma que el bug real, no una suposicion
# generica. Deliberadamente simple (regex, no parser real de PHP): cubre el patron universal de
# WordPress ("querystring => WHERE/JOIN de un WP_Query sin wpdb->prepare()"), no garantiza que
# CADA resultado sea explotable (un falso positivo posible es %d/intval() en la MISMA linea, que
# si saneara) -- pensado para ENSENAR al analista/LLM donde mirar, no para marcar verificado.
_SQL_VAR_HINT_RE = re.compile(
    r"\$(?:where|query|sql|join|order|having|order_by)\b.*\.(?!\s*=\s*['\"])|"
    r"\$wpdb\s*->\s*(?:query|get_results|get_var|get_row)\s*\(", re.IGNORECASE)
_SANITIZER_NEARBY_RE = re.compile(
    r"\bintval\s*\(|\babsint\s*\(|%d\b|%s\b|->\s*prepare\s*\(|\(int\)|\besc_sql\s*\(",
    re.IGNORECASE)


def find_unsafe_sql_concat_sinks(local_path: str, plugin_dir: str) -> List[SqlSink]:
    """Busca, en TODO el codigo del plugin (no solo la funcion que cito el LLM), lineas que leen
    un parametro de la peticion ($_GET/$_POST/$_REQUEST) y lo concatenan directo en una variable/
    llamada con pinta de SQL, SIN ningun saneo visible en la misma linea (intval()/%d/%s/
    prepare()/esc_sql()) -- el patron real de SQL injection por concatenacion, al contrario que
    grep_vulnerable_functions() (que solo confirma si un nombre YA CITADO existe). Pensado para
    cuando la hipotesis del LLM/el PoC publico cita una funcion que resulta estar bien
    parametrizada: en vez de rendirse, esto busca en el resto del plugin un sumidero real que la
    hipotesis nunca menciono. Heuristico (regex, no AST): puede dar falsos positivos (saneo en
    otra linea, no en la misma) y falsos negativos (concatenacion repartida en varias lineas) --
    pensado para ENSENAR donde mirar, nunca para marcar nada como verificado por si solo."""
    base = os.path.join(local_path, plugin_dir) if plugin_dir else local_path
    sinks: List[SqlSink] = []
    scanned = 0
    for dirpath, _dirs, files in os.walk(base):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in files:
            if not fn.lower().endswith(".php") or scanned >= _MAX_SCAN_FILES:
                continue
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue
            current_function = ""
            for i, line in enumerate(lines):
                fn_m = re.search(r"\bfunction\s+([A-Za-z0-9_]+)\s*\(", line)
                if fn_m:
                    current_function = fn_m.group(1)
                sg_m = _SUPERGLOBAL_READ_RE.search(line)
                if not sg_m:
                    continue
                if not _SQL_VAR_HINT_RE.search(line):
                    continue
                if _SANITIZER_NEARBY_RE.search(line):
                    continue
                sinks.append(SqlSink(param=sg_m.group(1), function=current_function,
                                     file=os.path.relpath(fp, base), line=i + 1,
                                     snippet=line.strip()[:300]))
        if scanned >= _MAX_SCAN_FILES:
            break
    return sinks


_JOIN_RELATIONSHIP_RE = re.compile(
    r"LEFT JOIN\s+\{?\$wpdb->(\w+)\}?\s+AS\s+(\w+)\s+ON\s+\2\.(\w+)\s*=\s*\{?\$wpdb->posts\}?\.ID",
    re.IGNORECASE)


def find_join_relationship_table(local_path: str, plugin_dir: str) -> Optional[dict]:
    """Busca un LEFT JOIN de WordPress contra una tabla de relacion PROPIA del plugin, enlazada
    por post ID (`LEFT JOIN {$wpdb->tabla} AS alias ON alias.columna = {$wpdb->posts}.ID`) --
    confirmado en vivo, CVE-2024-3552: el sumidero SQLi real (level_filter_where) solo devuelve
    algo si el post atacado tiene una fila en ESTA tabla (si no, la columna del JOIN sale NULL y
    el WHERE nunca es verdadero, con o sin inyeccion) -- asi que atacar una pagina generica
    (ver find_shortcode_name) no basta para ESTA clase de sumidero: hace falta una fila de
    verdad en la tabla de relacion para el post atacado, insertada por _bootstrap_lab via
    wp-cli ANTES del ataque (ver `relationship_table` en verify_wordpress_sqli).
    Patron (LEFT JOIN propio + relacion por post ID) comun en plugins de listados/directorios de
    WordPress -- no especifico de este plugin en concreto. Deliberadamente simple (regex, no
    parser real de PHP): si el plugin tiene varios JOIN de este tipo, se devuelve el primero."""
    base = os.path.join(local_path, plugin_dir) if plugin_dir else local_path
    scanned = 0
    for dirpath, _dirs, files in os.walk(base):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in sorted(files):
            if not fn.lower().endswith(".php") or scanned >= _MAX_SCAN_FILES:
                continue
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            m = _JOIN_RELATIONSHIP_RE.search(text)
            if m:
                return {"wpdb_property": m.group(1), "alias": m.group(2),
                       "join_column": m.group(3)}
        if scanned >= _MAX_SCAN_FILES:
            break
    return None


_ADD_SHORTCODE_RE = re.compile(r"add_shortcode\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]")


def find_shortcode_name(local_path: str, plugin_dir: str,
                        vulnerable_file: str = "") -> Optional[str]:
    """Busca el shortcode que el propio plugin registra (add_shortcode('nombre', ...)) mas
    probable de servir para disparar el sumidero vulnerable -- confirmado en vivo, CVE-2024-3552:
    atacar '/' (la portada por defecto de WordPress, sin posts ni contenido) nunca puede mostrar
    una diferencia booleana ni una fila UNION reflejada, aunque la inyeccion sea real, porque esa
    pagina no renderiza NADA del plugin -- hace falta una pagina de verdad que invoque su
    funcionalidad (su shortcode) para que el resultado del query inyectado tenga alguna
    superficie visible donde reflejarse. Con el nombre real del shortcode, _bootstrap_lab puede
    crear una pagina de verdad con el (via wp-cli) ANTES de atacar, en vez de adivinar una URL o
    depender de que el analista la conozca de antemano.

    Deliberadamente simple (regex, no parser real de PHP). Si el plugin registra VARIOS
    shortcodes, no hay forma generica de saber cual es 'el principal' sin leer la documentacion
    del plugin -- pero SI hay dos senales reales que no requieren adivinar nada especifico del
    plugin, en orden de prioridad:
      1. `vulnerable_file` (si se pasa, p.ej. desde la hipotesis del LLM/grep_vulnerable_functions):
         el shortcode registrado en ESE fichero exacto es casi siempre el que lleva al sumidero
         vulnerable -- es informacion real sobre ESTE CVE en concreto, no una suposicion generica.
      2. Un shortcode registrado en un fichero que tambien usa `$wpdb` (acceso a la base de
         datos) es mas probable que sirva para disparar una SQLi que uno en un fichero puramente
         de presentacion (CSS/JS/formularios estaticos) -- senal generica, no especifica del
         plugin.
    Si ninguna senal aplica (o varios candidatos empatan en la misma senal), se devuelve el
    primero en orden de recorrido de ficheros, igual que antes."""
    base = os.path.join(local_path, plugin_dir) if plugin_dir else local_path
    # `vulnerable_file` llega ya como la misma ruta que grep_vulnerable_functions() devuelve
    # (FuncMatch.file, formada con os.walk desde el mismo `local_path`) -- NO se reune con
    # `local_path` otra vez (eso duplicaria el prefijo); solo se normaliza para comparar.
    vuln_abs = os.path.abspath(vulnerable_file) if vulnerable_file else ""
    candidates = []   # [(nombre, fichero_abs, usa_wpdb)]
    scanned = 0
    for dirpath, _dirs, files in os.walk(base):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in sorted(files):
            if not fn.lower().endswith(".php") or scanned >= _MAX_SCAN_FILES:
                continue
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            m = _ADD_SHORTCODE_RE.search(text)
            if m:
                candidates.append((m.group(1), os.path.abspath(fp), "$wpdb" in text))
        if scanned >= _MAX_SCAN_FILES:
            break
    if not candidates:
        return None
    if vuln_abs:
        for name, fp, _wpdb in candidates:
            if fp == vuln_abs:
                return name
    for name, _fp, uses_wpdb in candidates:
        if uses_wpdb:
            return name
    return candidates[0][0]


def extract_function_body(local_path: str, relative_file: str, start_line: int,
                          max_lines: int = 40) -> Optional[str]:
    """Extrae el cuerpo real de una funcion ya localizada (fichero/linea exactos, p.ej. de
    grep_vulnerable_functions o inv.source_grounding) -- cuenta llaves '{'/'}' desde la primera
    que aparece en start_line hasta que todas cierran, con un tope de max_lines por si el conteo
    se descuadra (una llave dentro de un string o comentario, un fichero enorme) para nunca
    devolver medio fichero. Heuristico y deliberadamente simple (igual que grep_vulnerable_functions:
    no es un parser real de PHP/JS, es 'esto es lo que hay ahi, con bastante fiabilidad' -- pensado
    para que el pipeline pueda ensenar el codigo real de un handler sin depender de que el analista
    lo baje y lo grep-ee a mano cada vez que una verificacion dinamica no se confirma)."""
    fp = os.path.join(local_path, relative_file)
    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None
    if start_line < 1 or start_line > len(lines):
        return None
    out = []
    depth = 0
    started = False
    end = min(len(lines), start_line - 1 + max_lines)
    for i in range(start_line - 1, end):
        line = lines[i]
        out.append(line.rstrip("\n"))
        depth += line.count("{") - line.count("}")
        if line.count("{"):
            started = True
        if started and depth <= 0:
            break
    return "\n".join(out) if out else None


_PLUGIN_HEADER_RE = re.compile(r"^\s*(?:\*|//)?\s*Plugin Name\s*:", re.IGNORECASE | re.MULTILINE)


def find_plugin_main_file(local_path: str, plugin_dir: str, max_head_bytes: int = 4000,
                          content_lines: int = 200) -> Optional[dict]:
    """Localiza el fichero BOOTSTRAP del plugin (el que lleva la cabecera WordPress estandar
    'Plugin Name: ...') dentro de `plugin_dir` -- NO siempre coincide con el slug/nombre de la
    carpeta (confirmado en vivo, CVE-2024-50508: carpeta 'woo-product-design', fichero real
    'woocommerce-product-design.php'), asi que hay que buscarlo por contenido, no adivinar el
    nombre. Solo mira los .php de primer nivel (la cabecera siempre va ahi por convencion de
    WordPress.org, nunca en un subdirectorio) -- deliberadamente simple, igual que el resto de
    heuristicas de este modulo. Devuelve {"relative_path": ..., "content": (primeras
    content_lines lineas)} o None si no se encuentra ninguno."""
    base = os.path.join(local_path, plugin_dir) if plugin_dir else local_path
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return None
    for fn in entries:
        if not fn.lower().endswith(".php"):
            continue
        fp = os.path.join(base, fn)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(max_head_bytes)
        except OSError:
            continue
        if _PLUGIN_HEADER_RE.search(head):
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()[:content_lines]
            except OSError:
                continue
            rel = os.path.join(plugin_dir, fn) if plugin_dir else fn
            return {"relative_path": rel, "content": "".join(lines)}
    return None


# WordPress.org exige que una dependencia de OTRO plugin se comprueba via 'active_plugins'
# (la opcion que wp-cli tambien usa) contra la ruta '<slug>/<slug-principal>.php' -- asi la
# comprueban in_array()/array_key_exists() (patron clasico, 'active_plugins') y la funcion de
# core is_plugin_active() (que hace exactamente por dentro). Confirmado en vivo,
# CVE-2024-50508: el constructor del plugin corta en seco ANTES de registrar ningun hook AJAX
# si WooCommerce no esta activo -- sin esto, cualquier verificacion dinamica contra un plugin
# asi falla siempre, sea cual sea el payload, porque el codigo vulnerable nunca llega a cargarse.
_COMPANION_PLUGIN_RE = re.compile(
    r"(?:is_plugin_active|in_array|array_key_exists)\s*\(\s*(?:[^,]+,\s*)?"
    r"['\"]([a-z0-9][a-z0-9_-]*)/[a-z0-9][a-z0-9_.-]*\.php['\"]", re.IGNORECASE)
# confirma que la comprobacion de verdad CORTA la ejecucion (return false/exit/die cerca), no es
# una integracion OPCIONAL -- confirmado en vivo, falso positivo real: CVE-2024-3552 (Web
# Directory Free) tiene comprobaciones de is_plugin_active()/in_array() para Yoast SEO/
# WooCommerce Search que solo anaden campos EXTRA si estan activos, nunca bloquean nada si no lo
# estan. Un 'return;'/'return $x;' simple NO cuenta (es el final normal de cualquier funcion
# void, no una senal de bloqueo) -- se exige especificamente 'return false' (el patron real que
# usan los constructores de WordPress para decir 'no sigas inicializando') o exit()/die()/
# wp_die(), que SI paran la ejecucion de verdad.
_BLOCKING_NEARBY_RE = re.compile(r"\breturn\s+false\b|\bexit\s*\(|\bdie\s*\(|\bwp_die\s*\(")

# Algunos plugins detectan WooCommerce via function_exists('WC') en lugar de is_plugin_active().
# El patron clasico de WooCommerce extensions: `if ( ! function_exists( 'WC' ) ) { return; }`.
# El 'return;' simple no cumple _BLOCKING_NEARBY_RE (excluido para evitar falsos positivos), pero
# en este contexto -- un condicional que solo comprueba function_exists sin hacer nada mas -- SI
# es una comprobacion bloqueante. Mapeamos las funciones globales conocidas a su slug.
_KNOWN_GLOBAL_FN_TO_SLUG: dict = {
    "WC": "woocommerce",
    "WooCommerce": "woocommerce",
    "EDD": "easy-digital-downloads",
    "GFFormsModel": "gravityforms",
    "bbp_get_version": "bbpress",
    "bp_core_install": "buddypress",
}
_COMPANION_FUNCTION_RE = re.compile(
    r"function_exists\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")


def detect_required_companion_plugins(local_path: str, plugin_dir: str) -> List[str]:
    """Busca companions requeridos en el bootstrap del plugin.

    Dos vías:
    1. Análisis del bootstrap (is_plugin_active bloqueante, function_exists WC/EDD) — necesita
       el fichero principal encontrado por find_plugin_main_file.
    2. Heurística de slug/nombre — funciona SIN fichero principal, cubre addons de Elementor
       que no tienen is_plugin_active() bloqueante (unlimited-elements, essential-addons…).
    """
    slugs: List[str] = []
    seen: set = set()

    # Vía 2 primero: heurística por slug — no requiere el fichero principal.
    # Los addons de Elementor raramente tienen is_plugin_active('elementor') bloqueante;
    # se detectan porque su nombre/slug incluye "for Elementor" o "-for-elementor".
    if "elementor" not in seen:
        slug_lower = (plugin_dir or "").lower()
        if (slug_lower.endswith("-for-elementor")
                or slug_lower.endswith("-elementor-addon")
                or slug_lower.endswith("-elementor-addons")):
            seen.add("elementor")
            slugs.append("elementor")

    main = find_plugin_main_file(local_path, plugin_dir, max_head_bytes=20_000,
                                  content_lines=400)
    if not main:
        # Si hay double-nesting (tmpdir/slug/slug/), intentar un nivel más abajo
        import os as _os
        nested = _os.path.join(local_path, plugin_dir, plugin_dir) if plugin_dir else ""
        if nested and _os.path.isdir(nested):
            main = find_plugin_main_file(_os.path.join(local_path, plugin_dir),
                                          plugin_dir, max_head_bytes=20_000, content_lines=400)
        if not main:
            # Intentar leer el nombre del plugin de cualquier .php en el primer nivel del subdir
            if "elementor" not in seen:
                try:
                    import os as _os2
                    base = _os2.path.join(local_path, plugin_dir) if plugin_dir else local_path
                    for _fn in sorted(_os2.listdir(base)):
                        if not _fn.lower().endswith(".php"):
                            continue
                        _fp = _os2.path.join(base, _fn)
                        if not _os2.path.isfile(_fp):
                            continue
                        with open(_fp, "r", encoding="utf-8", errors="replace") as _f:
                            _head = _f.read(4000)
                        _m = re.search(r"Plugin Name\s*:\s*(.+)", _head, re.IGNORECASE)
                        if _m:
                            _pname = _m.group(1).strip().lower()
                            if ("for elementor" in _pname or "elementor addon" in _pname
                                    or "elementor widget" in _pname):
                                seen.add("elementor")
                                slugs.append("elementor")
                            break
                except OSError:
                    pass
            return slugs
    text = main["content"]
    lines = text.splitlines()
    slugs: List[str] = []
    seen = set()
    for m in _COMPANION_PLUGIN_RE.finditer(text):
        slug = m.group(1).lower()
        if slug in seen or slug == (plugin_dir or "").lower():
            continue
        line_no = text.count("\n", 0, m.start())
        nearby = "\n".join(lines[line_no:line_no + 8])
        if _BLOCKING_NEARBY_RE.search(nearby):
            seen.add(slug)
            slugs.append(slug)
    # Detecta tambien el patron function_exists('WC') / function_exists('EDD') etc.
    # que usan extensiones de WooCommerce/EDD en lugar de is_plugin_active().
    # Solo se cuenta cuando el condicional usa negacion (!function_exists) y va seguido
    # de return/exit dentro de las primeras lineas -- comprobacion bloqueante real.
    _fn_block_re = re.compile(
        r"!\s*function_exists\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
        r"[^)]*\).*?\{[^}]*?\breturn\b", re.DOTALL)
    for m in _fn_block_re.finditer(text):
        fn_name = m.group(1)
        mapped = _KNOWN_GLOBAL_FN_TO_SLUG.get(fn_name)
        if mapped and mapped not in seen and mapped != (plugin_dir or "").lower():
            seen.add(mapped)
            slugs.append(mapped)
    # Detecta plugins que son addons/widgets de Elementor sin un is_plugin_active() bloqueante
    # (patrón típico: nombre del plugin incluye "for Elementor" en la cabecera, o el slug
    # termina en "-for-elementor" / "-elementor-addon").  Muchos addons de Elementor
    # (unlimited-elements, essential-addons, jet-elements…) no comprueban is_plugin_active('elementor')
    # de forma bloqueante -- simplemente no registran sus widgets si el SDK de Elementor no está
    # cargado.  El nombre de la cabecera es el indicador más fiable del patrón.
    if "elementor" not in seen:
        plugin_name_m = re.search(r"Plugin Name\s*:\s*(.+)", text, re.IGNORECASE)
        plugin_name = plugin_name_m.group(1).strip().lower() if plugin_name_m else ""
        slug_lower = (plugin_dir or "").lower()
        is_elementor_addon = (
            "for elementor" in plugin_name
            or "elementor addon" in plugin_name
            or "elementor widget" in plugin_name
            or slug_lower.endswith("-for-elementor")
            or slug_lower.endswith("-elementor-addon")
            or slug_lower.endswith("-elementor-addons")
        )
        if is_elementor_addon:
            seen.add("elementor")
            slugs.append("elementor")
    return slugs


_AJAX_ACTION_HANDLER_RE_TMPL = (
    r"add_action\s*\(\s*['\"]wp_ajax(?:_nopriv)?_{action}['\"]\s*,\s*"
    r"(?:['\"]([A-Za-z0-9_]+)['\"]"
    # callback como array($this, 'metodo') -- con o sin coma final (formato multilinea):
    r"|array\s*\(\s*\$this\s*,\s*['\"]([A-Za-z0-9_]+)['\"]\s*,?\s*\)"
    r"|array\s*\(\s*self::class\s*,\s*['\"]([A-Za-z0-9_]+)['\"]\s*,?\s*\)"
    # callback como array( SomeClass::method(), 'method' ) o array( UM()->foo(), 'method' )
    # -- el primer elemento puede ser cualquier expresion PHP sin comas ni comillas literales,
    # cubriendo patrones como array( UM()->member_directory(), 'ajax_get_members' ) (UM 2.8.x):
    r"|array\s*\(\s*[^,'\"]+,\s*['\"]([A-Za-z0-9_]+)['\"]\s*,?\s*\))"
)


def find_all_ajax_actions(local_path: str) -> List[str]:
    """Escanea los ficheros PHP del plugin y devuelve todos los nombres de accion AJAX registrados
    (el fragmento <action> de add_action('wp_ajax[_nopriv]_<action>', ...)).
    Usado como fallback cuando el LLM propone un nombre de accion que no existe en el codigo real
    -- en ese caso se devuelve la lista completa y el caller elige la mas relevante."""
    _ALL_AJAX_RE = re.compile(
        r"add_action\s*\(\s*['\"]wp_ajax(?:_nopriv)?_([A-Za-z0-9_]+)['\"]"
    )
    actions: List[str] = []
    seen: set = set()
    if not local_path or not os.path.isdir(local_path):
        return actions
    scanned = 0
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in files:
            if not fn.lower().endswith(".php") or scanned >= _MAX_SCAN_FILES:
                continue
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            for m in _ALL_AJAX_RE.finditer(text):
                act = m.group(1)
                if act not in seen:
                    seen.add(act)
                    actions.append(act)
        if scanned >= _MAX_SCAN_FILES:
            break
    return actions


def find_ajax_action_for_param(local_path: str, param_name: str) -> Optional[str]:
    """Busca la accion AJAX cuyo handler accede directamente al parametro POST indicado.

    Util cuando la similitud de nombres no basta (el LLM adivina 'elv_get_logs' pero el
    parametro vulnerable 'order[0][dir]' solo aparece dentro del handler de
    'elvwp_datatable_loglist'). Tres pasos:
      1. Leer todos los PHP del plugin y construir mapa accion->funcion_handler.
      2. Para cada fichero, encontrar las funciones que usan $_POST['<clave>'].
      3. Cruzar: la primera accion cuya funcion_handler usa el parametro gana.
    """
    if not param_name or not local_path or not os.path.isdir(local_path):
        return None
    # clave de primer nivel: "order[0][dir]" -> "order", "dir" -> "dir"
    top_key = re.split(r"[\[\(]", param_name.strip())[0].strip("'\" ")
    if not top_key or len(top_key) < 2:
        return None

    param_pats = [
        re.compile(rf"\$_POST\s*\[\s*['\"]?{re.escape(top_key)}['\"]?\s*\]"),
        re.compile(rf"\$_REQUEST\s*\[\s*['\"]?{re.escape(top_key)}['\"]?\s*\]"),
    ]
    # registro de acciones AJAX: captura la accion y luego extrae el nombre del metodo/funcion
    # del segundo argumento, que puede ser:
    #   - string simple: add_action('wp_ajax_foo', 'function_name')
    #   - array($this, 'method') o array(Class::class, 'method') -- posiblemente multilínea
    _AJAX_ACTION_RE = re.compile(
        r"add_action\s*\(\s*['\"]wp_ajax(?:_nopriv)?_([A-Za-z0-9_]+)['\"]",
        re.DOTALL
    )
    # extrae el nombre de metodo/funcion del segundo arg, buscando a partir del segundo ','
    # tras la accion: 'method_name' o array(...,'method_name',...)
    _METHOD_FROM_ARRAY_RE = re.compile(r"['\"]([A-Za-z0-9_]+)['\"]\s*,?\s*\)")
    _METHOD_SIMPLE_RE = re.compile(r"['\"]([A-Za-z0-9_]+)['\"]")
    _FUNC_NAME_RE = re.compile(r"function\s+(\w+)\s*\(")

    # Paso 1: leer todos los PHP y registrar handlers
    all_texts: dict = {}
    action_to_handler: dict = {}
    scanned = 0
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in files:
            if not fn.lower().endswith(".php") or scanned >= _MAX_SCAN_FILES:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            scanned += 1
            all_texts[fp] = text
            for m in _AJAX_ACTION_RE.finditer(text):
                action = m.group(1)
                if action in action_to_handler:
                    continue
                # buscar el handler en el resto de la llamada add_action (hasta el ')' de cierre)
                after = text[m.end():]
                close = after.find(");")
                chunk = after[:close + 2] if close != -1 else after[:300]
                # forma array($this, 'method') -- la ultima cadena antes del ')' de cierre del array
                am = _METHOD_FROM_ARRAY_RE.search(chunk)
                if am:
                    action_to_handler[action] = am.group(1)
                else:
                    # forma simple 'function_name'
                    sm = _METHOD_SIMPLE_RE.search(chunk)
                    if sm:
                        action_to_handler[action] = sm.group(1)
        if scanned >= _MAX_SCAN_FILES:
            break

    if not action_to_handler:
        return None

    # Paso 2: encontrar funciones que usan el parametro
    funcs_with_param: set = set()
    for _fp, text in all_texts.items():
        for pat in param_pats:
            for m in pat.finditer(text):
                pre = text[:m.start()]
                fn_matches = list(_FUNC_NAME_RE.finditer(pre))
                if fn_matches:
                    funcs_with_param.add(fn_matches[-1].group(1))

    if not funcs_with_param:
        return None

    # Paso 3: cruzar
    for action, handler in action_to_handler.items():
        if handler in funcs_with_param:
            return action
    return None


def find_ajax_handler_function(local_path: str, action: str) -> Optional[dict]:
    """Busca el handler REAL registrado para una accion AJAX ya conocida
    (add_action('wp_ajax[_nopriv]_<action>', <callback>)) -- al reves que grep_vulnerable_functions
    (que confirma si un nombre de funcion YA CITADO existe en el codigo), esta funcion encuentra el
    nombre REAL de la funcion a partir de la accion, para cuando la hipotesis del LLM sobre
    'vulnerable_functions' no acerto (confirmado en vivo en CVE-2024-50508: el LLM dijo
    'handle_file_upload', esa funcion no existe en el codigo real -- pero la accion real
    ('pc_added_uploaded_image') SI se conocia, extraida del PoC real, y buscar POR ELLA en vez de
    por el nombre adivinado encuentra el callback de verdad).
    Reconoce el callback como string ('func') y como metodo de objeto/clase
    (array($this, 'metodo'), array(self::class, 'metodo')).
    Devuelve {"function": nombre, "location": "fichero:linea"} o None si no se encuentra."""
    if not action or not local_path or not os.path.isdir(local_path):
        return None
    if not re.match(r"^[A-Za-z0-9_]+$", action):
        return None
    pattern = re.compile(_AJAX_ACTION_HANDLER_RE_TMPL.format(action=re.escape(action)))
    scanned = 0
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in files:
            if not fn.lower().endswith(".php"):
                continue
            if scanned >= _MAX_SCAN_FILES:
                break
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            m = pattern.search(text)
            if m:
                func_name = m.group(1) or m.group(2) or m.group(3) or m.group(4)
                line_no = text.count("\n", 0, m.start()) + 1
                return {"function": func_name, "location": f"{os.path.relpath(fp, local_path)}:{line_no}"}
        if scanned >= _MAX_SCAN_FILES:
            break
    return None


def find_ajax_action_for_ssrf(local_path: str) -> Optional[dict]:
    """Busca la accion AJAX mas probable de producir SSRF: un handler que
    (a) lee una URL de $_GET/$_POST/$_REQUEST y
    (b) la pasa a wp_remote_get / wp_remote_post / wp_safe_remote_get /
        wp_safe_remote_post / curl_exec / file_get_contents.

    Devuelve {"action": nombre, "url_param": nombre_del_param, "location": "file:line"}
    o None si no encuentra nada.  Usado como fallback deterministico para CVEs de clase
    ssrf cuando el LLM no identifica el endpoint correcto.
    """
    if not local_path or not os.path.isdir(local_path):
        return None

    # patrones de fetch de URL en PHP
    _FETCH_RE = re.compile(
        r"\b(?:wp_remote_get|wp_remote_post|wp_safe_remote_get|wp_safe_remote_post"
        r"|wp_remote_request|curl_exec|file_get_contents)\s*\("
    )
    # patron de lectura de parametro desde superglobal: captura el nombre de la clave
    _PARAM_RE = re.compile(
        r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\]"
    )
    _URL_KEYS = {"url", "uri", "src", "source", "link", "feed", "webhook",
                 "callback", "image", "avatar", "file_url", "endpoint",
                 "redirect", "remote", "import", "fetch", "proxy", "target",
                 "request_url", "external_url", "api_url", "notify_url",
                 "download_url", "remote_url", "import_url", "webhook_url",
                 "site_url", "ping_url", "iframe_url", "embed_url", "hook_url"}

    _AJAX_REG_RE = re.compile(
        r"add_action\s*\(\s*['\"]wp_ajax(?:_nopriv)?_([A-Za-z0-9_]+)['\"]",
        re.DOTALL
    )
    # file -> text map + action -> file positions
    action_positions: list = []  # list of (action, fp, start_in_file)
    all_texts: dict = {}

    scanned = 0
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in sorted(files):
            if not fn.lower().endswith(".php"):
                continue
            if scanned >= _MAX_SCAN_FILES:
                break
            scanned += 1
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            all_texts[fp] = text
            for m in _AJAX_REG_RE.finditer(text):
                action_positions.append((m.group(1), fp, m.start()))
        if scanned >= _MAX_SCAN_FILES:
            break

    if not action_positions:
        return None

    # patron de asignacion: $varname = ... $_POST/GET[key] ...
    # captura tanto la clave del superglobal como el nombre de la variable que lo recibe
    _VAR_ASSIGN_RE = re.compile(
        r'\$(\w+)\s*=\s*[^\n;]{0,120}\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([A-Za-z0-9_\-]+)[\'"]\s*\]'
    )
    # patron del argumento pasado a la funcion de fetch: captura el primer argumento
    _FETCH_ARG_RE = re.compile(
        r"\b(?:wp_remote_get|wp_remote_post|wp_safe_remote_get|wp_safe_remote_post"
        r"|wp_remote_request|curl_exec|file_get_contents)\s*\(\s*\$(\w+)"
    )

    best: Optional[tuple] = None  # (action, url_param, fp, line_no, url_score, fetch_char_pos)
    for fp, text in all_texts.items():
        fetch_matches = list(_FETCH_RE.finditer(text))
        if not fetch_matches:
            continue

        # --- paso 1: ventana amplia (3000 chars) alrededor de cada fetch ---
        # SOLO cuenta si la clave del superglobal es un hint de URL (reduce falsos positivos
        # de variables como 'action', 'post_ID', 'nonce' que aparecen cerca de cualquier fetch)
        for fm in fetch_matches:
            fetch_pos = fm.start()
            window_start = max(0, fetch_pos - 3000)
            window = text[window_start: fetch_pos + 200]
            for pm in _PARAM_RE.finditer(window):
                pname = pm.group(1)
                if pname.lower() not in _URL_KEYS:
                    continue  # ignorar claves no-URL
                url_score = 2
                containing_action = None
                best_dist: Optional[int] = None
                for act, act_fp, act_start in action_positions:
                    if act_fp != fp or act_start > fetch_pos:
                        continue
                    dist = fetch_pos - act_start
                    if best_dist is None or dist < best_dist:
                        best_dist = dist
                        containing_action = act
                if containing_action is None and action_positions:
                    containing_action = action_positions[0][0]
                if best is None or url_score > best[4]:
                    line_no = text.count("\n", 0, fm.start()) + 1
                    best = (containing_action, pname, fp, line_no, url_score, fm.start())

        # --- paso 2: taint a nivel de fichero: $var = $_POST[key] ... fetch($var) ---
        # une el nombre de variable para encontrar chains mas largas no captadas por la ventana
        file_assigns: dict = {}  # varname -> (key, pos)
        for am in _VAR_ASSIGN_RE.finditer(text):
            vname, key = am.group(1), am.group(2)
            file_assigns[vname] = (key, am.start())
        if file_assigns:
            for fm in _FETCH_ARG_RE.finditer(text):
                fetch_var = fm.group(1)
                if fetch_var not in file_assigns:
                    continue
                key, assign_pos = file_assigns[fetch_var]
                # solo promover si la clave parece una URL (evita falsos positivos como
                # post_ID, action, nonce que tambien se pasan a funciones de fetch)
                if key.lower() not in _URL_KEYS:
                    continue
                if True:
                    url_score = 3  # bonus: coincidencia de variable + clave URL
                    if best is not None and url_score <= best[4]:
                        continue
                    fetch_pos = fm.start()
                    containing_action = None
                    best_dist = None
                    for act, act_fp, act_start in action_positions:
                        if act_fp != fp or act_start > fetch_pos:
                            continue
                        dist = fetch_pos - act_start
                        if best_dist is None or dist < best_dist:
                            best_dist = dist
                            containing_action = act
                    if containing_action is None and action_positions:
                        containing_action = action_positions[0][0]
                    line_no = text.count("\n", 0, fetch_pos) + 1
                    best = (containing_action, key, fp, line_no, url_score, fetch_pos)

    if best is None:
        return None
    action, url_param, fp, line_no, _score, _fetch_char_pos = best

    # Detectar bypass de fragmento URL: si hay un preg_match cercano al fetch que filtra
    # la URL a un patron especifico, se puede hacer bypass con un fragmento URL
    # (#fragment es ignorado por wp_remote_get pero si aparece en la cadena evaluada por
    # el regex -- util cuando el regex no tiene ancla inicial y acepta el patron en cualquier
    # posicion de la cadena).
    bypass_fragment: str = ""
    _PREG_RE = re.compile(r"preg_match\s*\(\s*['\"]([^'\"]{10,300})['\"]", re.DOTALL)
    best_text = all_texts.get(fp, "")
    # buscar preg_match en las 1500 chars alrededor del fetch donde se encontro el mejor hit
    _search_start = max(0, _fetch_char_pos - 1500)
    _search_end = min(len(best_text), _fetch_char_pos + 1500)
    for preg_m in _PREG_RE.finditer(best_text[_search_start:_search_end]):
        pat = preg_m.group(1).lstrip("^").rstrip("$^").strip()
        # extraer prefijo URL (hasta el primer wildcard) y sufijo literal (despues del ultimo)
        parts = re.split(r"\(\.\*\??\)", pat)
        if len(parts) >= 2:
            prefix = parts[0].lstrip("^")          # e.g. "https://givewp.com/downloads/plugins/"
            suffix = parts[-1].rstrip("$^").strip() # e.g. "/readme.txt"
            if prefix.startswith("http") and suffix:
                bypass_fragment = f"#{prefix}evil{suffix}"
                break

    result: dict = {
        "action": action,
        "url_param": url_param,
        "location": f"{os.path.relpath(fp, local_path)}:{line_no}",
    }
    if bypass_fragment:
        result["bypass_fragment"] = bypass_fragment
    return result


def find_stored_xss_endpoint(local_path: str) -> Optional[dict]:
    """Busca un par injection-point/view-path de XSS almacenado de forma deterministica:

    Paso 1 — Injection point: accion AJAX sin restriccion de privilegio (wp_ajax_nopriv_X
    o wp_ajax_ registrada y abierta a suscriptores) que pasa $_POST['param'] a
    $wpdb->insert() o $wpdb->update() sin sanitize_text_field / esc_sql / intval.

    Paso 2 — View path: pagina de admin PHP en el mismo plugin (add_menu_page /
    add_submenu_page o fichero en admin/) que hace SELECT sobre la misma tabla y
    hace echo/print del resultado sin esc_html / esc_attr.

    Devuelve {"inject_action", "inject_param", "view_path", "table_hint"} o None.
    """
    if not local_path or not os.path.isdir(local_path):
        return None

    _MAX_FILES = 6000
    _MAX_BYTES = 500_000

    # -- Patrones injection side --
    # registro de accion AJAX
    _AJAX_REG_RE = re.compile(
        r"add_action\s*\(\s*['\"]wp_ajax_(?:nopriv_)?(\w+)['\"]"
    )
    # lectura POST sin sanitizar
    _POST_READ_RE = re.compile(
        r"\$_(?:POST|REQUEST)\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\]"
    )
    # insercion en BD
    _WPDB_WRITE_RE = re.compile(
        r"\$wpdb\s*->\s*(?:insert|update|query)\s*\("
    )
    # sanitizacion
    _SANITIZE_RE = re.compile(
        r"\b(?:sanitize_text_field|sanitize_textarea_field|esc_sql|intval|absint"
        r"|wp_kses|wp_kses_post|strip_tags|htmlspecialchars)\s*\("
    )
    # nombre de tabla heuristica ($wpdb->prefix.'tabla' o tabla directa)
    _TABLE_NAME_RE = re.compile(
        r"""\$wpdb\s*->\s*(?:prefix\s*\.\s*)?['"]([\w]{3,40})['"]"""
        r"""|""" r"""\$wpdb\s*->\s*(?:insert|update)\s*\(\s*\$(?:wpdb\s*->\s*prefix\s*\.\s*)?['\"]?([\w_]{3,40})['\"]?"""
        r"""|(?:[\w\\]*::)?table\s*\(\s*['"]([\w_]{2,40})['"]\s*\)"""
    )

    # -- Patrones view side --
    # registro de pagina de admin
    _MENU_PAGE_RE = re.compile(
        r"add_(?:menu|submenu)_page\s*\([^;]{0,400}['\"]([A-Za-z0-9_\-]+/[^'\"]{1,100}\.(php))['\"]"
        r"|['\"]page=([A-Za-z0-9_\-]+)['\"]"
    )
    # echo/print sin escapar (heuristica: echo $row o echo $result sin esc_)
    _UNSAFE_ECHO_RE = re.compile(
        r"\becho\b[^;]{0,80}\$(?:row|result|data|entry|item|record)\b"
        r"|\bprint\b[^;]{0,80}\$(?:row|result|data|entry|item|record)\b"
    )
    # get_results / query de lectura
    _SELECT_RE = re.compile(r"\$wpdb\s*->\s*(?:get_results|get_row|query)\s*\(")

    all_texts: dict = {}
    action_positions: list = []  # (action, fp)
    best_inject: Optional[dict] = None
    scanned = 0
    for dirpath, _dirs, files in os.walk(local_path):
        for fn in sorted(files):
            if not fn.lower().endswith(".php"):
                continue
            scanned += 1
            if scanned > _MAX_FILES:
                break
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_BYTES)
            except OSError:
                continue
            all_texts[fp] = text
            for m in _AJAX_REG_RE.finditer(text):
                action_positions.append((m.group(1), fp))

    # -- Segunda pasada: REST API routes (register_rest_route) sin autenticacion --
    # Detecta rutas REST abiertas (permission_callback = __return_true / return true)
    # que almacenan params de la request sin sanitizar.
    # Detecta rutas REST abiertas (permission_callback = __return_true / lambda return true)
    # Soporta tanto namespaces literales como referencias a self::$namespace (busca la
    # propiedad en el mismo fichero o en ficheros del mismo directorio api/).
    _REST_ROUTE_RE = re.compile(
        r"register_rest_route\s*\("
        r"([^,]+),\s*"           # 1er arg: namespace (literal o self::$prop)
        r"'/?([^']+)'|"          # 2do arg: route literal
        r"register_rest_route\s*\("
        r"([^,]+),\s*"
        r'"/?([^"]+)"'           # 2do arg: route literal doble comilla
    )
    # Patron alternativo para rutas con endpoint en variable: busca solo la perm callback
    _REST_ROUTE_ANY_RE = re.compile(r"register_rest_route\s*\(")
    _REST_PARAM_RE = re.compile(
        r"\$request\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\]"
        r"|\$request\s*->\s*get_param\s*\(\s*['\"]([A-Za-z0-9_\-]+)['\"]\s*\)"
    )
    # args array en la definicion del route: 'param_name' => array('required' => true ...)
    _ROUTE_ARG_RE = re.compile(
        r"['\"]([A-Za-z0-9_\-]{2,40})['\"]\s*=>\s*array\s*\(\s*['\"](?:required|type)['\"]"
    )
    _OPEN_PERM_RE = re.compile(
        r"['\"]permission_callback['\"]\s*=>\s*['\"]__return_true['\"]"
        r"|['\"]permission_callback['\"]\s*=>\s*function[^{]{0,80}\{\s*return\s+true"
    )
    # Namespace estatico: public static $namespace = 'wp-statistics/v2'
    _NS_STATIC_RE = re.compile(
        r"(?:public\s+)?static\s+\$namespace\s*=\s*['\"]([^'\"]+)['\"]"
    )
    # Endpoint estatico: public static $endpoint = 'hit'
    _EP_STATIC_RE = re.compile(
        r"(?:public\s+)?static\s+\$endpoint\s*=\s*['\"]([^'\"]+)['\"]"
    )

    _SKIP = {"nonce", "id", "action", "_wpnonce", "type", "security", "verify"}

    for fp, text in all_texts.items():
        for rm in _REST_ROUTE_ANY_RE.finditer(text):
            window_start = rm.start()
            window = text[window_start: window_start + 3000]
            if not _OPEN_PERM_RE.search(window):
                continue
            # Extraer namespace: literal en el texto o buscar la propiedad estatica
            ns_literal_m = re.search(r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]", text[window_start:window_start+200])
            if ns_literal_m:
                ns = ns_literal_m.group(1).strip("/")
            else:
                ns_prop_m = _NS_STATIC_RE.search(text)
                if not ns_prop_m:
                    # Buscar en cualquier fichero del plugin (el namespace suele estar en la clase base)
                    ns = ""
                    for _ofp2, otext2 in all_texts.items():
                        nm2 = _NS_STATIC_RE.search(otext2)
                        if nm2 and "/" in nm2.group(1):
                            ns = nm2.group(1).strip("/")
                            break
                else:
                    ns = ns_prop_m.group(1).strip("/")
            if not ns:
                continue
            # Extraer route: literal de >= 2 chars O endpoint estatico
            route_literal_m = re.search(
                r"register_rest_route\s*\([^,]+,\s*['\"][/]?([^'\"]{2,80})['\"]",
                text[window_start:window_start+300]
            )
            if route_literal_m:
                route = route_literal_m.group(1).strip("/")
            else:
                ep_m = _EP_STATIC_RE.search(text)
                route = ep_m.group(1).strip("/") if ep_m else ""
            if not route:
                continue
            # Params: desde args del route O desde $request[] en todo el fichero
            rest_params = [m.group(1) or m.group(2)
                           for m in _REST_PARAM_RE.finditer(window)
                           if m.group(1) or m.group(2)]
            if not rest_params:
                # Buscar en el arg definition de todo el fichero
                rest_params = [m.group(1) for m in _ROUTE_ARG_RE.finditer(text)
                               if m.group(1).lower() not in _SKIP]
            if not rest_params:
                continue
            text_params = [p for p in rest_params if p.lower() not in _SKIP]
            _URI_HINTS = ("uri", "url", "path", "page", "query", "search",
                          "message", "content", "text", "title", "name")
            uri_params = [p for p in text_params
                          if any(h in p.lower() for h in _URI_HINTS)]
            inject_param = uri_params[0] if uri_params else (text_params[0] if text_params else rest_params[0])
            table_m = _TABLE_NAME_RE.search(window)
            table_hint = (table_m.group(1) or table_m.group(2) or table_m.group(3)) if table_m else ""
            rest_endpoint = f"/wp-json/{ns}/{route}"
            # Detectar si el param se pasa por base64_decode (bypass de sanitize_url)
            # Busca en TODOS los ficheros del plugin, no solo el que registra la ruta
            _B64_PAT = re.compile(
                rf"base64_decode\s*\([^){{}}]*{re.escape(inject_param)}[^){{}}]*\)"
                rf"|base64_decode\s*\(\s*\$(?:request|this->[a-zA-Z_]+)->{re.escape(inject_param)}"
                rf"|base64_decode\s*\(\s*\$_(?:GET|REQUEST|POST)\s*\[\s*['\"]?{re.escape(inject_param)}['\"]?\s*\]"
            )
            payload_transform = ""
            if _B64_PAT.search(text):
                payload_transform = "base64"
            else:
                for _ofp2, _otext2 in all_texts.items():
                    if _B64_PAT.search(_otext2):
                        payload_transform = "base64"
                        break
            # Detectar params de activacion: algunos plugins comprueban un key adicional
            # (p.ej. 'wp_statistics_hit_rest') en $_REQUEST para activar el filtro que
            # decodifica page_uri; sin ese key el payload nunca se almacena.
            # Patron: static $<var> = '<key>' + isset($_REQUEST[self::$<var>]) gateando
            # add_filter() en el constructor (no en logica de exclusion).
            _ACT_STATIC_RE = re.compile(
                r"static\s+\$(\w+)\s*=\s*['\"]([A-Za-z0-9_]{3,60})['\"]"
            )
            # Solo activar cuando el isset esta directamente junto a add_filter/add_action
            # o dentro de la definicion de is_rest_hit() — no en logica de exclusion
            _REST_HIT_GATE_RE = re.compile(
                r"isset\s*\(\s*\$_REQUEST\s*\[\s*self::\$[A-Za-z_]+\s*\]"
            )
            activation_params: dict = {}
            for _afp, _atext in all_texts.items():
                # Buscar gating key: static $key_var = 'key_name' + isset($_REQUEST[self::$key_var])
                if _REST_HIT_GATE_RE.search(_atext):
                    for vm in _ACT_STATIC_RE.finditer(_atext):
                        var_name, key_val = vm.group(1), vm.group(2)
                        # Confirmar que self::$var_name aparece en el isset
                        if re.search(rf"self::\${re.escape(var_name)}", _atext):
                            activation_params[key_val] = "1"
                # Buscar current_page_type / current_page_id si se pasan como params del filtro
                if (re.search(r"current_page_type", _atext) and
                        re.search(r"add_filter\s*\(", _atext)):
                    activation_params.setdefault("current_page_type", "home")
                    activation_params.setdefault("current_page_id", "0")
                # Patron: isset($this->rest_hits->X) and $this->rest_hits->X == 1
                # -> necesita X=1 para activar el filtro correspondiente
                for _m in re.finditer(
                    r"isset\s*\(\s*\$this->rest_hits->(\w+)\s*\)\s*and\s*\$this->rest_hits->\1\s*==\s*1",
                    _atext
                ):
                    activation_params.setdefault(_m.group(1), "1")
            # Merge rest_params: activation_params primero (base), luego rest_params (incluye inject_param)
            merged_params = list(activation_params.keys()) + [
                p for p in rest_params if p not in activation_params
            ]
            best_inject = {
                "action": None,
                "inject_param": inject_param,
                "table_hint": table_hint,
                "fp": fp,
                "rest_endpoint": rest_endpoint,
                "rest_params": merged_params,
                "activation_params": activation_params,
                "payload_transform": payload_transform,
            }
            break
        if best_inject is not None:
            break

    if not action_positions and best_inject is None:
        return None

    if action_positions and best_inject is None:
        pass  # sigue con la logica AJAX abajo

    if best_inject is not None and best_inject.get("rest_endpoint"):
        # Buscar view_path para el REST result.
        # Estrategia 0 (tabla): trazado de datos — qué archivos hacen SELECT de la misma
        #   tabla donde se inyecta y qué slug de admin page registran/usan esos archivos.
        # Estrategia 1: slug template dinamico 'prefix_[slug]_suffix' + primera clave de
        #   los archivos que leen de esa tabla (o de todos si la tabla no matchea nada).
        # Estrategia 2 (fallback): add_menu_page con slug literal en archivo con SELECT.
        view_path = ""
        slug_template = ""
        table_hint = best_inject.get("table_hint", "")

        _PAGE_KEY_RE = re.compile(
            r"['\"](?:overview|main|stats|dashboard|report|home|"
            r"pages|page|search|referrers|referrer|visits|visit|hit|hits|url|urls)['\"]"
        )
        # Recoger slug_template de cualquier archivo
        for _vfp, vtext in all_texts.items():
            tpl_m = re.search(
                r"static\s+\$\w+\s*=\s*['\"]([A-Za-z0-9_]*\[slug\][A-Za-z0-9_]*)['\"]",
                vtext
            )
            if tpl_m and not slug_template:
                slug_template = tpl_m.group(1)
                break

        # Estrategia 0: trazado de tabla — buscar en qué archivos se hace SELECT de la
        # tabla donde se inyecta y recoger page-keys SOLO de esos archivos.
        # Si table_hint viene vacío del window local del endpoint (ocurre cuando el plugin
        # usa un helper abstracto como DB::table('x') en un método distinto), hacer un
        # scan global de todos los archivos del plugin para extraerlo.
        _view_candidate_keys: list = []
        # Si table_hint sigue vacío, buscar la tabla en los archivos que contienen el
        # inject_param (nombre de columna) cerca de una escritura en DB — esos son los
        # que realmente almacenan el valor inyectado, no cualquier archivo del plugin.
        if not table_hint:
            _ip_name = best_inject.get("inject_param", "")
            _ip_re = re.compile(re.escape(_ip_name), re.IGNORECASE) if _ip_name else None
            _WRITE_RE = re.compile(r"\$wpdb\s*->\s*(?:insert|update|replace)\b", re.IGNORECASE)
            for _gfp, _gtext in all_texts.items():
                if _ip_re and not _ip_re.search(_gtext):
                    continue
                if not _WRITE_RE.search(_gtext):
                    continue
                _gm = _TABLE_NAME_RE.search(_gtext)
                if _gm:
                    table_hint = (_gm.group(1) or _gm.group(2) or _gm.group(3)) or ""
                    if table_hint:
                        break

        if table_hint and slug_template:
            _sel_tbl_re = re.compile(
                rf"SELECT\b.{{0,500}}{re.escape(table_hint)}\b",
                re.IGNORECASE | re.DOTALL,
            )
            for _vfp, vtext in all_texts.items():
                if _sel_tbl_re.search(vtext):
                    for km in _PAGE_KEY_RE.finditer(vtext):
                        key = km.group(0).strip("'\"")
                        if key not in _view_candidate_keys:
                            _view_candidate_keys.append(key)

        # Estrategia 0.5: si la tabla no estrechó la lista, trazar el nombre del inject_param
        # como nombre de columna en los SELECT de archivos admin — esos son los que muestran
        # exactamente el campo que se inyecta.
        # Requiere que el SELECT contenga TODOS los parts del inject_param (AND lógico)
        # para evitar matches demasiado amplios (ej. "uri" solo matchea demasiados archivos).
        if not _view_candidate_keys and slug_template:
            _ip_parts = [p for p in re.split(r"[_\s]+", best_inject.get("inject_param", ""))
                         if len(p) >= 3 and p.lower() not in ("get", "set", "has", "the", "new")]
            if _ip_parts:
                for _vfp, vtext in all_texts.items():
                    # El archivo debe tener un SELECT que contenga TODOS los parts
                    _select_blocks = re.findall(r"SELECT\b.{0,800}", vtext, re.IGNORECASE | re.DOTALL)
                    for _blk in _select_blocks:
                        if all(re.search(r"\b" + re.escape(p) + r"\b", _blk, re.IGNORECASE)
                               for p in _ip_parts):
                            for km in _PAGE_KEY_RE.finditer(vtext):
                                key = km.group(0).strip("'\"")
                                if key not in _view_candidate_keys:
                                    _view_candidate_keys.append(key)
                            break

        if slug_template and _view_candidate_keys:
            # Priorizar la clave que más se parece al nombre de la tabla inyectada:
            # coincidencia exacta > prefijo/sufijo > primera encontrada.
            _best_key = _view_candidate_keys[0]
            if table_hint:
                for _ck in _view_candidate_keys:
                    if _ck == table_hint or table_hint.startswith(_ck) or _ck.startswith(table_hint):
                        _best_key = _ck
                        break
            view_path = f"/wp-admin/admin.php?page={slug_template.replace('[slug]', _best_key)}"

        # Estrategia 1 (fallback): recoger todas las page-keys de todos los archivos
        if not view_path and slug_template:
            _all_page_keys: list = []
            for _vfp, vtext in all_texts.items():
                for km in _PAGE_KEY_RE.finditer(vtext):
                    key = km.group(0).strip("'\"")
                    if key not in _all_page_keys:
                        _all_page_keys.append(key)
            if _all_page_keys:
                view_path = f"/wp-admin/admin.php?page={slug_template.replace('[slug]', _all_page_keys[0])}"

        # Estrategia 2 (fallback): add_menu_page con slug literal en archivo que hace SELECT
        if not view_path:
            for vfp, vtext in all_texts.items():
                is_admin = ("admin" in vfp.lower() or "dashboard" in vfp.lower()
                            or "page" in vfp.lower() or "entries" in vfp.lower()
                            or bool(re.search(r"add_(?:menu|submenu)_page\s*\(", vtext)))
                if not is_admin:
                    continue
                if not _SELECT_RE.search(vtext):
                    continue
                slug_m = re.search(
                    r"add_(?:menu|submenu)_page\s*\([^;]{5,400}?['\"]([A-Za-z0-9_\-]{3,60})['\"]",
                    vtext
                )
                if slug_m:
                    view_path = f"/wp-admin/admin.php?page={slug_m.group(1)}"
                    break
        if not view_path:
            view_path = "/wp-admin/admin.php"

        # Detectar contexto de renderizado del valor inyectado en los archivos de vista.
        # Traza: archivos que SELECT de table_hint → buscar echo/print del inject_param
        # o de columnas con nombre similar → ver qué HTML rodea ese echo.
        # Resultado: "href" | "html" | "js_string" | "url" | "unknown"
        render_context = "unknown"
        _inject_col = best_inject.get("inject_param", "").replace("_", "").lower()
        if table_hint:
            _sel_tbl_re2 = re.compile(
                rf"SELECT\b.{{0,300}}{re.escape(table_hint)}\b",
                re.IGNORECASE | re.DOTALL,
            )
            for _vfp, vtext in all_texts.items():
                if not _sel_tbl_re2.search(vtext):
                    continue
                # Buscar fragmentos de ~200 chars alrededor de cada echo del valor
                _echo_re = re.compile(
                    rf"(?:echo|print)\s+.*?(?:{re.escape(best_inject['inject_param'])}|"
                    rf"{re.escape(_inject_col)})[^;]{{0,120}};",
                    re.IGNORECASE | re.DOTALL,
                )
                for em in _echo_re.finditer(vtext):
                    start = max(0, em.start() - 200)
                    snippet = vtext[start: em.end() + 100]
                    if re.search(r"""href\s*=\s*['"]""", snippet, re.IGNORECASE):
                        render_context = "href"
                    elif re.search(r"<script\b", snippet, re.IGNORECASE):
                        render_context = "js_string"
                    elif re.search(r"""(?:src|action|data)\s*=\s*['"]""", snippet, re.IGNORECASE):
                        render_context = "url"
                    else:
                        render_context = "html"
                    break
                if render_context != "unknown":
                    break

        # Always scan JS files for template literals fed into .html()/innerHTML, even if the
        # PHP scan already found a render_context. The PHP context ("url", "href") is for
        # server-side echoes; the actual XSS sink may be in JS that reads from the DB and
        # renders unescaped via jQuery.html() — a different render context that takes
        # priority (js_innerHTML → 5 specific payloads instead of 532).
        # Patron: `<a href="${siteUrl}${value['str_url']}"...` → jQuery.html() → XSS.
        if True:
            _col_name = best_inject.get("inject_param", "")
            _col_variants = {_col_name.lower(), _col_name.replace("_", "").lower()}
            _col_variants.update({"str_url", "uri", "url", "link", "href", "page_uri"})
            _col_variants.discard("")
            # Template literal que empieza con un tag HTML y contiene la columna
            # de inject_param sin escapar — sin exigir cierre del template (puede ser largo)
            _TMPL_VAR_RE = re.compile(
                r"""[`]\s*<[a-z][^`]{0,3000}\$\{[^}]{0,100}(?:"""
                + "|".join(re.escape(c) for c in sorted(_col_variants, key=len, reverse=True))
                + r""")[^}]{0,50}\}""",
                re.IGNORECASE | re.DOTALL,
            )
            _js_scanned = 0
            for _jsdp, _jsdirs, _jsfiles in os.walk(local_path):
                _jsdirs[:] = [d for d in _jsdirs
                              if d not in ("vendor", "node_modules", "bower_components")]
                for _jsfn in sorted(_jsfiles):
                    if not _jsfn.lower().endswith(".js"):
                        continue
                    if _jsfn.lower().endswith(".min.js"):
                        continue
                    _js_scanned += 1
                    if _js_scanned > 60:
                        break
                    _jsfp2 = os.path.join(_jsdp, _jsfn)
                    try:
                        with open(_jsfp2, "r", encoding="utf-8", errors="replace") as _jsh:
                            _jstext = _jsh.read(200_000)
                    except OSError:
                        continue
                    if _TMPL_VAR_RE.search(_jstext):
                        render_context = "js_innerHTML"
                    if render_context == "js_innerHTML":
                        break
                if _js_scanned >= 60 or render_context == "js_innerHTML":
                    break

        # When render_context is js_innerHTML (the XSS fires via a JS meta-box loaded by
        # AJAX), the meta-box renders on the plugin's OVERVIEW/main page, not on the
        # table-specific sub-page (which may have the run_meta_box call commented out).
        # Scan ALL plugin PHP files for a slug_template match whose key is overview/main
        # so the engine loads the page where do_meta_boxes() renders the meta-box visibly.
        if render_context == "js_innerHTML" and slug_template:
            _OVERVIEW_PRIORITY = ('overview', 'main', 'stats', 'summary')
            # Build a regex that matches slug_template with any _OVERVIEW_PRIORITY key
            _overview_slug_re = re.compile(
                r"\b(" + "|".join(
                    re.escape(slug_template.replace("[slug]", k)) for k in _OVERVIEW_PRIORITY
                ) + r")\b",
                re.IGNORECASE,
            )
            for _avfp, _avtext in all_texts.items():
                _om = _overview_slug_re.search(_avtext)
                if _om:
                    view_path = f"/wp-admin/admin.php?page={_om.group(1)}"
                    break

        _act_p = best_inject.get("activation_params", {})
        return {
            "inject_action": None,
            "inject_endpoint": best_inject["rest_endpoint"],
            "inject_params_all": best_inject.get("rest_params", []),
            "inject_param": best_inject["inject_param"],
            "inject_base_params": _act_p,  # params fijos que activan el hook
            "table_hint": best_inject["table_hint"],
            "view_path": view_path,
            "http_method": "GET",
            "payload_transform": best_inject.get("payload_transform", ""),
            "render_context": render_context,
        }

    # Paso 1: buscar action AJAX que hace db-write con POST sin sanitizar
    for action, fp in action_positions:
        text = all_texts[fp]
        # Encontrar inicio del handler para esta accion (dentro de ~5000 chars)
        for arm in re.finditer(re.escape(action), text):
            pos = arm.start()
            # Buscar la funcion handler cerca (600 chars despues)
            handler_window = text[pos: pos + 600]
            func_m = re.search(r"['\"]([A-Za-z0-9_]+)['\"\s]*\)", handler_window)
            if not func_m:
                continue
            func_name = func_m.group(1)
            # Buscar el body de la funcion
            func_re = re.compile(
                rf"function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{", re.DOTALL
            )
            func_def = func_re.search(text)
            if func_def is None:
                # buscar en otros ficheros del plugin
                for _ofp, otext in all_texts.items():
                    func_def2 = func_re.search(otext)
                    if func_def2:
                        func_body_text = otext
                        func_body_start = func_def2.end()
                        break
                else:
                    continue
                func_body_end = func_body_start + 3000
                func_body = func_body_text[func_body_start:func_body_end]
            else:
                func_body_start = func_def.end()
                func_body = text[func_body_start: func_body_start + 3000]

            # ¿hace db-write?
            if not _WPDB_WRITE_RE.search(func_body):
                continue
            # ¿sin sanitizacion inmediata?
            if _SANITIZE_RE.search(func_body):
                continue
            # ¿lee POST?
            post_params = _POST_READ_RE.findall(func_body)
            if not post_params:
                continue
            # coger la primera tabla mencionada
            table_m = _TABLE_NAME_RE.search(func_body)
            table_hint = (table_m.group(1) or table_m.group(2) or table_m.group(3)) if table_m else ""
            best_inject = {
                "action": action,
                "inject_param": post_params[0],
                "table_hint": table_hint,
                "fp": fp,
            }
            break
        if best_inject:
            break

    if best_inject is None:
        return None

    # Paso 2: buscar pagina admin que muestra esa tabla sin escapar
    table_hint = best_inject["table_hint"]
    view_path: str = ""
    for fp, text in all_texts.items():
        # paginas admin: ficheros en admin/ o que tengan add_menu_page
        is_admin = ("admin" in fp.lower() or "dashboard" in fp.lower()
                    or "page" in fp.lower() or "entries" in fp.lower()
                    or bool(re.search(r"add_(?:menu|submenu)_page\s*\(", text)))
        if not is_admin:
            continue
        # tiene SELECT
        if not _SELECT_RE.search(text):
            continue
        # tiene echo sin esc_ (heuristica)
        if not _UNSAFE_ECHO_RE.search(text):
            if not re.search(r"\becho\b[^;]{0,60}\$row\b|\becho\b[^;]{0,60}\$item\b", text):
                continue
        # intenta extraer page slug del menu registration
        slug_m = re.search(
            r"add_(?:menu|submenu)_page\s*\([^;]{5,400}?['\"]([A-Za-z0-9_\-]{3,60})['\"]",
            text
        )
        if slug_m:
            page_slug = slug_m.group(1)
            view_path = f"/wp-admin/admin.php?page={page_slug}"
        else:
            # fallback: nombre del fichero como view_path
            rel = os.path.relpath(fp, local_path)
            if "admin" in rel.lower():
                # e.g. give/includes/admin/entries.php -> /wp-admin/admin.php?page=give-entries
                view_path = "/wp-admin/admin.php?page=plugin-entries"
        if view_path:
            break

    if not view_path:
        # fallback generico: edit-comments o dashboard
        view_path = "/wp-admin/edit.php"

    return {
        "inject_action": best_inject["action"],
        "inject_param": best_inject["inject_param"],
        "table_hint": best_inject["table_hint"],
        "view_path": view_path,
    }


def find_unsanitized_sqli_params(local_path: str) -> List[dict]:
    """Analisis taint simplificado: rastrea parametros que fluyen desde $_GET/$_POST/$_REQUEST
    hasta $wpdb->query/get_results/get_row/get_col/prepare sin pasar por $wpdb->prepare().
    Devuelve lista de {param, hook, file, line} para cada sumidero inyectable encontrado.

    Este scanner no depende del LLM ni de un PoC publico -- lee el codigo fuente y aplica
    logica estructural para identificar el patron exacto de la vulnerabilidad. Util cuando
    is_gap=True (sin exploit publico) y el LLM no puede adivinar el endpoint correcto."""
    if not local_path or not os.path.isdir(local_path):
        return []

    # Patron 1a: asignacion directa $var = $_GET/POST/REQUEST['param']
    _TAINT_ASSIGN = re.compile(
        r"""\$([A-Za-z_]\w*)\s*=\s*(?:sanitize_text_field\s*\(\s*wp_unslash\s*\(\s*)?"""
        r"""\$_(GET|POST|REQUEST)\s*\[\s*['"]([\w\-]+)['"]\s*\]""",
        re.I,
    )
    # Patron 1b: REST API — $var = $request['param'] or $request->get_param('param')
    # sanitize_params_submitted/sanitize_text_field wrapping still tainted (doesn't strip SQL chars)
    _REST_PARAM_ASSIGN = re.compile(
        r"""\$([A-Za-z_]\w*)\s*=\s*"""
        r"""(?:[A-Za-z_][\w\\]*(?:::[A-Za-z_]\w*)?\s*\([^)]{0,80})?\s*"""
        r"""(?:\$request\s*\[\s*['"]([\w\-]+)['"]\s*\]"""
        r"""|\$request\s*->\s*get_param\s*\(\s*['"]([\w\-]+)['"]\s*\))""",
        re.S | re.I,
    )
    # Patron 1c: $filter->prop = fn($request['param']) — taint through filter object
    # ORDER BY p.{$filter->order_by} in execute() is the classic sink (CVE-2022-45808)
    _FILTER_PROP_ASSIGN = re.compile(
        r"""\$(?:filter|this)\s*->\s*([A-Za-z_]\w*)\s*=\s*"""
        r"""(?:[A-Za-z_][\w\\]*(?:::[A-Za-z_]\w*)?\s*\([^)]{0,120})?\s*"""
        r"""(?:\$request\s*\[\s*['"]([\w\-]+)['"]\s*\]"""
        r"""|\$request\s*->\s*get_param\s*\(\s*['"]([\w\-]+)['"]\s*\))""",
        re.S | re.I,
    )
    # Patron 2a: uso directo en query raw (sin prepare)
    _WPDB_QUERY = re.compile(
        r"""\$wpdb\s*->\s*(?:query|get_results|get_row|get_col|get_var)\s*\("""
        r"""\s*["\'][^"\']{0,600}""",
        re.S,
    )
    # Patron 2b: prepare() con interpolacion directa {$var} — prepare NO protege vars interpoladas
    _WPDB_PREPARE_INTERP = re.compile(
        r"""\$wpdb\s*->\s*prepare\s*\(\s*["\']"""
        r"""[^"\']{0,800}\{\s*\$([A-Za-z_]\w*)\s*\}""",
        re.S,
    )
    # Patron 2c: ORDER BY .{$var} en cualquier string (dentro o fuera de prepare)
    _ORDERBY_INTERP = re.compile(
        r"""ORDER\s+BY\s+[^"\';\n]{0,40}\{\s*\$([A-Za-z_]\w*)\s*\}""",
        re.S | re.I,
    )
    # Patron 3: hook AJAX o REST en el mismo archivo (para saber el endpoint)
    _AJAX_HOOK = re.compile(
        r"""add_action\s*\(\s*['"]wp_ajax(?:_nopriv)?_([A-Za-z0-9_]+)['"]""",
    )
    _REST_HOOK = re.compile(
        r"""register_rest_route\s*\([^)]{0,200}['"]([A-Za-z0-9/_\-{}]+)['"]""",
        re.S,
    )
    # Patron 4: template_redirect con $wpdb (como appsplate)
    _TEMPLATE_REDIRECT = re.compile(
        r"""add_action\s*\(\s*['"]template_redirect['"]""",
    )

    results: list = []
    seen_pairs: set = set()

    if not os.path.isdir(local_path):
        return results

    # Primera pasada: leer todos los archivos PHP del plugin
    all_texts: dict = {}
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in files:
            if not fn.lower().endswith(".php"):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    all_texts[fp] = fh.read(_MAX_SCAN_BYTES)
            except OSError:
                continue
            if len(all_texts) >= _MAX_SCAN_FILES:
                break
        if len(all_texts) >= _MAX_SCAN_FILES:
            break

    # Segunda pasada: detectar asignaciones tainted y queries vulnerables
    for fp, text in all_texts.items():
            # Paso 1a: $_GET/$_POST/$_REQUEST taint
            tainted: dict = {}  # var_name -> param_name
            for m in _TAINT_ASSIGN.finditer(text):
                var, _src, param = m.group(1), m.group(2), m.group(3)
                tainted[var] = param

            # Paso 1b: REST $request['param'] taint
            for m in _REST_PARAM_ASSIGN.finditer(text):
                var = m.group(1)
                param = m.group(2) or m.group(3) or ""
                if var and param:
                    tainted[var] = param

            # Paso 1c: $filter->prop = fn($request['param']) — registrar (prop_name, param_name)
            filter_props: dict = {}  # filter_prop -> http_param_name
            for m in _FILTER_PROP_ASSIGN.finditer(text):
                prop = m.group(1)
                param = m.group(2) or m.group(3) or ""
                if prop and param:
                    filter_props[prop] = param

            if not tainted and not filter_props:
                continue

            # Paso 1d: buscar ORDER BY {$prop} donde prop está en filter_props
            # Esto detecta sinks cross-file: file A establece $filter->order_by desde request,
            # file B tiene ORDER BY p.{$order_by}. Escaneamos TODOS los archivos para el sink.
            if filter_props:
                for _sfp, _stext in all_texts.items():
                    for m_ob in _ORDERBY_INTERP.finditer(_stext):
                        sink_var = m_ob.group(1)
                        # ¿sink_var es una propiedad de filter que está tainted?
                        param = filter_props.get(sink_var)
                        if not param:
                            # Buscar si sink_var = $filter->prop_name en este archivo
                            _prop_read = re.search(
                                rf"""\${re.escape(sink_var)}\s*=\s*\$(?:filter|this)\s*->\s*([A-Za-z_]\w*)""",
                                _stext,
                            )
                            if _prop_read:
                                param = filter_props.get(_prop_read.group(1))
                        if not param:
                            continue
                        # Encontrar hook/endpoint para el archivo fuente (fp, donde se asigna)
                        line_no = text.count('\n', 0, 0) + 1
                        pair_key = (fp, param)
                        if pair_key not in seen_pairs:
                            seen_pairs.add(pair_key)
                            # Buscar el endpoint en el archivo donde se asigna $filter->prop
                            _ep_hook = ""
                            for _m_rr in _REST_HOOK.finditer(text):
                                _ep_hook = f"/wp-json/{_m_rr.group(1).lstrip('/')}"
                                break
                            results.append({
                                "param": param,
                                "hook": _ep_hook,
                                "file": os.path.relpath(fp, local_path),
                                "line": line_no,
                                "fn": f"filter->{list(filter_props.keys())[0]} → ORDER BY sink",
                                "note": "cross-file: filter prop → ORDER BY interpolation",
                            })

            # Paso 2: buscar queries que contienen esas variables tainted
            for m_q in _WPDB_QUERY.finditer(text):
                query_start = m_q.start()
                # extraer el bloque hasta el cierre del paréntesis (heuristica)
                depth = 0
                query_end = query_start
                for i, c in enumerate(text[query_start:], query_start):
                    if c == '(':
                        depth += 1
                    elif c == ')':
                        depth -= 1
                        if depth == 0:
                            query_end = i
                            break
                query_block = text[query_start:query_end + 1]

                # Verificar prepare(): solo seguro si la var va como placeholder %s/%d,
                # NO si está interpolada con {$var} directamente en la string SQL.
                if 'prepare' in query_block:
                    # ¿Alguna variable tainted está interpolada (no como placeholder)?
                    has_interp = any(
                        f'{{${v}}}' in query_block or f'.${v}' in query_block
                        for v in tainted
                    )
                    if not has_interp:
                        continue  # uso correcto de prepare — no es vulnerable

                # Buscar variables tainted dentro del query block
                for var, param in tainted.items():
                    if f'${var}' in query_block:
                        # Determinar endpoint buscando el hook asociado a la FUNCIÓN
                        # que contiene esta query (no cualquier hook del archivo).
                        # Estrategia: buscar hacia ATRÁS la función MÁS CERCANA
                        # (última definición antes de la query), luego su hook.
                        _fn_all = list(re.finditer(
                            r"function\s+([A-Za-z_]\w*)\s*\(",
                            text[:query_start],
                        ))
                        _containing_fn = _fn_all[-1].group(1) if _fn_all else ""
                        hook = ""
                        if _containing_fn:
                            # AJAX hook que registra esta función
                            _fn_hook_re = re.compile(
                                rf"""add_action\s*\(\s*['"]wp_ajax(?:_nopriv)?_([A-Za-z0-9_]+)['"]"""
                                rf"""[^)]*?['"]{re.escape(_containing_fn)}['"]""",
                                re.S,
                            )
                            _fh = _fn_hook_re.search(text)
                            if _fh:
                                hook = f"/wp-admin/admin-ajax.php?action={_fh.group(1)}"
                            if not hook:
                                # REST route que registra esta función
                                _rest_fn_re = re.compile(
                                    rf"""register_rest_route\s*\([^){{]{{0,400}}"""
                                    rf"""['"]([\w/_\-{{}}]+)['"]\s*,"""
                                    rf"""[^){{]{{0,300}}['"]{re.escape(_containing_fn)}['"]""",
                                    re.S,
                                )
                                _rfh = _rest_fn_re.search(text)
                                if _rfh:
                                    hook = f"/wp-json/{_rfh.group(1).lstrip('/')}"
                            if not hook:
                                # template_redirect en el mismo archivo que llama a esta función
                                _tr_re = re.compile(
                                    rf"""add_action\s*\(\s*['"]template_redirect['"]"""
                                    rf"""[^)]*?['"]{re.escape(_containing_fn)}['"]""",
                                    re.S,
                                )
                                if _tr_re.search(text):
                                    hook = "/?template_redirect"
                        # Fallback: si la función no registra su propio hook en este
                        # archivo, buscar en todos los archivos ya leídos (registro centralizado
                        # en el archivo principal del plugin, p.ej. class-plugin.php)
                        if not hook and _containing_fn:
                            for _other_fp, _other_text in all_texts.items():
                                if _other_fp == fp:
                                    continue
                                _fn_hook_re2 = re.compile(
                                    rf"""add_action\s*\(\s*['"]([^'"]+)['"]"""
                                    rf"""[^)]*?['"]{re.escape(_containing_fn)}['"]""",
                                    re.S,
                                )
                                _fh2 = _fn_hook_re2.search(_other_text)
                                if _fh2:
                                    _htype = _fh2.group(1)
                                    if _htype.startswith("wp_ajax"):
                                        # extraer acción
                                        _act2 = _htype.replace("wp_ajax_nopriv_", "").replace("wp_ajax_", "")
                                        hook = f"/wp-admin/admin-ajax.php?action={_act2}"
                                    elif _htype == "template_redirect":
                                        hook = "/?template_redirect"
                                    elif _htype == "init":
                                        hook = "/?template_redirect"
                                    break
                        # Último fallback: cualquier hook del mismo archivo
                        if not hook:
                            for m_h in _AJAX_HOOK.finditer(text):
                                hook = f"/wp-admin/admin-ajax.php?action={m_h.group(1)}"
                                break
                        if not hook and _TEMPLATE_REDIRECT.search(text):
                            hook = "/?template_redirect"
                        line_no = text[:query_start].count('\n') + 1
                        pair_key = (fp, param)
                        if pair_key not in seen_pairs:
                            seen_pairs.add(pair_key)
                            results.append({
                                "param": param,
                                "hook": hook,
                                "file": os.path.relpath(fp, local_path),
                                "line": line_no,
                                "fn": _containing_fn,
                            })

    # Ordenar: hooks conocidos primero (admin-ajax, wp-json), luego template_redirect, luego vacíos
    def _hook_rank(r: dict) -> int:
        h = r.get("hook", "")
        if "admin-ajax" in h:
            return 0
        if "wp-json" in h:
            return 1
        if "template_redirect" in h:
            return 2
        return 3

    results.sort(key=_hook_rank)
    return results


def find_missing_auth_handlers(local_path: str) -> List[dict]:
    """Escaner estructural de handlers AJAX con problemas de autorizacion en plugins WP.

    Para cada accion registrada con add_action('wp_ajax_...' / 'wp_ajax_nopriv_...'):
    1. ¿El handler contiene check_ajax_referer/wp_verify_nonce antes del codigo principal?
    2. ¿El handler contiene current_user_can() con una capability?
    3. ¿El hook usa wp_ajax_nopriv_* (cualquier usuario, incluidos anonimos)?
    4. ¿El handler usa $_POST/$_GET/$_REQUEST directamente en $wpdb / update_user_meta /
       wp_update_user / delete_user / wp_set_password / etc. sin sanitizar?

    Devuelve lista de {action, handler_fn, file, line, nopriv, has_nonce_check,
    has_capability_check, has_unsanitized_sensitive, issues:[str]} ordenada por
    numero de issues descendente (los mas graves primero).

    No depende del LLM — es analisis estatico puro. Especialmente util para HUECO CVEs
    de clase missing-authorization/auth-bypass/idor."""
    if not local_path or not os.path.isdir(local_path):
        return []

    _MAX_FILES = 6000
    _MAX_BYTES = 500_000

    # Registro de acciones AJAX
    _AJAX_REG  = re.compile(
        r"""add_action\s*\(\s*['"]wp_ajax_(nopriv_)?([A-Za-z0-9_]+)['"]\s*,\s*"""
        r"""(?:['"]([\w\\:]+)['"]|array\s*\([^)]{0,80}['\"]([\w\\:]+)['\"])""",
        re.S,
    )
    # Chequeos de nonce
    _NONCE_CHECK = re.compile(
        r"""\b(?:check_ajax_referer|wp_verify_nonce|check_admin_referer)\s*\(""", re.I)
    # Chequeos de capability
    _CAP_CHECK   = re.compile(r"""\bcurrent_user_can\s*\(""", re.I)
    # Funciones sensibles en las que el input sin sanitizar es critico
    _SENSITIVE_FNS = re.compile(
        r"""\b(?:wp_update_user|update_user_meta|wp_set_password|delete_user|"""
        r"""remove_user_from_blog|add_user_to_blog|set_role|wp_insert_user|"""
        r"""update_option|delete_option|wp_mail|do_shortcode|wp_schedule_event)\s*\(""",
        re.I,
    )
    # Input sin sanitizar (variable que viene de $_POST/$_GET sin pasar por sanitize/absint/intval)
    _RAW_INPUT   = re.compile(
        r"""\$_(?:POST|GET|REQUEST)\s*\[\s*['"]([\w\-]+)['"]\s*\]""", re.I)
    _SANITIZERS  = re.compile(
        r"""\b(?:sanitize_text_field|sanitize_textarea_field|sanitize_email|"""
        r"""sanitize_key|absint|intval|floatval|esc_sql|wp_kses|wp_kses_post|"""
        r"""strip_tags|htmlspecialchars|filter_input|filter_var)\s*\(""",
        re.I,
    )

    all_texts: dict = {}
    # Primera pasada: leer todos los archivos PHP
    scanned = 0
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in sorted(files):
            if not fn.lower().endswith(".php"):
                continue
            scanned += 1
            if scanned > _MAX_FILES:
                break
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    all_texts[fp] = fh.read(_MAX_BYTES)
            except OSError:
                continue
        if scanned > _MAX_FILES:
            break

    # Segunda pasada: encontrar registros AJAX y analizar sus handlers
    results: list = []
    seen_actions: set = set()

    for fp, text in all_texts.items():
        for m in _AJAX_REG.finditer(text):
            nopriv_flag = bool(m.group(1))
            action_name = m.group(2)
            handler_fn  = (m.group(3) or m.group(4) or "").strip("\\")
            if not handler_fn or action_name in seen_actions:
                continue
            seen_actions.add(action_name)

            # Localizar el cuerpo del handler
            handler_text = ""
            handler_file = os.path.relpath(fp, local_path)
            handler_line = 0
            # Buscar en todos los archivos por el nombre de función
            _fn_simple = handler_fn.split("::")[-1].split("->")[-1]
            _fn_re = re.compile(
                rf"""function\s+{re.escape(_fn_simple)}\s*\(""", re.I)
            for _sfp, _stext in all_texts.items():
                _fm = _fn_re.search(_stext)
                if _fm:
                    handler_line = _stext[:_fm.start()].count('\n') + 1
                    # Extract ~60 lines after function definition
                    _lines = _stext[_fm.start():].split('\n')[:60]
                    handler_text = '\n'.join(_lines)
                    handler_file = os.path.relpath(_sfp, local_path)
                    break

            if not handler_text:
                # Fallback: use the registration file text near the hook
                handler_text = text
                handler_file = os.path.relpath(fp, local_path)

            has_nonce   = bool(_NONCE_CHECK.search(handler_text))
            has_cap     = bool(_CAP_CHECK.search(handler_text))
            # Check unsanitized raw input going to sensitive functions
            has_unsanitized_sensitive = False
            raw_params = _RAW_INPUT.findall(handler_text)
            if raw_params:
                # Simple heuristic: sensitive function in same function body AND
                # no sanitizer wrapping the input
                has_sensitive = bool(_SENSITIVE_FNS.search(handler_text))
                has_sanitizer = bool(_SANITIZERS.search(handler_text))
                has_unsanitized_sensitive = has_sensitive and not has_sanitizer

            issues: list = []
            if not has_nonce:
                issues.append("no_nonce_check")
            if not has_cap and not nopriv_flag:
                issues.append("no_capability_check")
            if nopriv_flag:
                issues.append("nopriv_access")
            if has_unsanitized_sensitive:
                issues.append("unsanitized_sensitive_fn")

            results.append({
                "action": action_name,
                "handler_fn": handler_fn,
                "file": handler_file,
                "line": handler_line,
                "nopriv": nopriv_flag,
                "has_nonce_check": has_nonce,
                "has_capability_check": has_cap,
                "has_unsanitized_sensitive": has_unsanitized_sensitive,
                "issues": issues,
                "n_issues": len(issues),
            })

    # Sort: most issues first, nopriv without nonce highest priority
    results.sort(key=lambda r: (
        -(r["n_issues"]),
        0 if (r["nopriv"] and not r["has_nonce_check"]) else 1,
        0 if not r["has_capability_check"] else 1,
    ))
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# GENERIC MULTI-LANGUAGE STATIC ANALYSIS  (HUECO engine — tech-agnostic path)
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_GENERIC_SCAN = 300   # max files to scan
_MAX_GENERIC_BYTES = 200_000

@dataclass
class VulnSink:
    """A potential vulnerability sink found by static analysis."""
    file: str
    line: int
    snippet: str
    param: str    # user-controlled input variable/key
    sink: str     # vulnerable function or operation
    tech: str     # detected technology
    confidence: int  # 1=low (heuristic), 2=medium, 3=high (input+sink same line)


def detect_tech_stack(local_path: str) -> str:
    """Detect the primary programming language / framework from file contents.
    Returns: 'php', 'nodejs', 'python', 'ruby', 'java', 'go', 'dotnet', 'unknown'.
    """
    # Config-file fingerprints (fast O(1) checks first)
    _markers: List[tuple] = [
        ("nodejs",  ["package.json", ".nvmrc", "yarn.lock", "pnpm-lock.yaml"]),
        ("python",  ["requirements.txt", "Pipfile", "setup.py", "pyproject.toml",
                     "manage.py", "wsgi.py", "asgi.py", "app.py"]),
        ("ruby",    ["Gemfile", "Gemfile.lock", "config/routes.rb"]),
        ("java",    ["pom.xml", "build.gradle", "build.gradle.kts"]),
        ("go",      ["go.mod", "go.sum"]),
        ("dotnet",  ["global.json", "nuget.config"]),
    ]
    for tech, files in _markers:
        for f in files:
            if os.path.exists(os.path.join(local_path, f)):
                return tech
    # Count file extensions (skip heavy dirs)
    _skip = {"node_modules", "vendor", ".git", "__pycache__", ".tox", "dist", "build"}
    ext_count: dict = {}
    scanned = 0
    for _root, dirs, files in os.walk(local_path):
        dirs[:] = [d for d in dirs if d not in _skip]
        for fn in files:
            _, ext = os.path.splitext(fn)
            if ext:
                ext_count[ext.lower()] = ext_count.get(ext.lower(), 0) + 1
            scanned += 1
            if scanned > 5000:
                break
    _map = {".php": "php", ".py": "python", ".js": "nodejs", ".ts": "nodejs",
            ".rb": "ruby", ".java": "java", ".go": "go", ".cs": "dotnet",
            ".kt": "java", ".scala": "java"}
    best = max(ext_count, key=lambda k: ext_count[k] if k in _map else 0, default=".php")
    return _map.get(best, "php")


def _walk_source_files(local_path: str, extensions: List[str]) -> Iterator[tuple[str, str, List[str]]]:
    """Yield (abs_path, rel_path, lines) for source files matching extensions."""
    _skip = {"node_modules", "vendor", ".git", "__pycache__", ".tox", "dist", "build",
             "test", "tests", "spec", "fixtures", "migrations"}
    scanned = 0
    for root, dirs, files in os.walk(local_path):
        dirs[:] = [d for d in dirs if d not in _skip]
        for fn in files:
            if scanned >= _MAX_GENERIC_SCAN:
                return
            ext = os.path.splitext(fn)[1].lower()
            if ext not in extensions:
                continue
            fp = os.path.join(root, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read(_MAX_GENERIC_BYTES)
            except OSError:
                continue
            scanned += 1
            yield fp, os.path.relpath(fp, local_path), text.splitlines()


# ── SQLi sinks ────────────────────────────────────────────────────────────────

# Patterns: (tech, user_input_re, sink_re, extensions)
_SQLI_PATTERNS = [
    # PHP
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\$wpdb\s*->\s*(?:query|get_results|get_var|get_row)\s*\("
                r"|\bmysqli?_(?:query|fetch)\s*\("
                r"|\bPDO::\w+\s*\(\s*[\"'].*\?(?!.*prepare)"
                r"|->(?:query|execute)\s*\(\s*[\"']",
                re.IGNORECASE),
     [".php"]),
    # Python (Django, Flask, FastAPI, raw cursor)
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form|json|data)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"
                r"|request\.params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"cursor\.execute\s*\(\s*[f\"'].*%[sd]"
                r"|cursor\.execute\s*\(\s*f['\"]"
                r"|\.raw\s*\(\s*[f\"']"
                r"|\.objects\.filter\s*\([^)]*=\s*f['\"]"
                r"|execute\s*\(\s*[\"'].*\+",
                re.IGNORECASE),
     [".py"]),
    # Node.js (Express, Fastify, raw pg/mysql)
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\.query\s*\(\s*`"
                r"|\.query\s*\(\s*['\"].*\$\{"
                r"|\.query\s*\(\s*['\"].*\+"
                r"|knex\.raw\s*\("
                r"|Sequelize\.literal\s*\(",
                re.IGNORECASE),
     [".js", ".ts", ".mjs", ".cjs"]),
    # Ruby (Rails, Sinatra)
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"
                r"|params\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\.where\s*\(\s*[\"'].*#\{"
                r"|\.find_by_sql\s*\(\s*[\"'].*#\{"
                r"|execute\s*\(\s*[\"'].*#\{"
                r"|ActiveRecord::Base\.connection\.execute",
                re.IGNORECASE),
     [".rb"]),
    # Java (Servlet, Spring)
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"Statement\.execute(?:Query|Update)?\s*\(\s*[\"'].*\+"
                r"|createQuery\s*\(\s*[\"'].*\+"
                r"|prepareStatement\s*\(\s*[\"'].*\+",
                re.IGNORECASE),
     [".java"]),
    # Go
    ("go",
     re.compile(r"r\.FormValue\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|r\.URL\.Query\(\)\.Get\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"db\.(?:Query|Exec)\s*\(\s*fmt\.Sprintf"
                r"|db\.(?:Query|Exec)\s*\(\s*[\"'].*\+"
                r"|\.QueryRow\s*\(\s*fmt\.Sprintf",
                re.IGNORECASE),
     [".go"]),
]


def find_sqli_sinks_generic(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find SQL injection sinks for ANY supported language.
    Returns sinks sorted by confidence (high first)."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    # Find matching pattern set(s)
    pattern_sets = [p for p in _SQLI_PATTERNS if p[0] == tech]
    if not pattern_sets:
        # Fall back to scanning all known patterns
        pattern_sets = _SQLI_PATTERNS
    results: List[VulnSink] = []
    for _tech, _user_re, _sink_re, _exts in pattern_sets:
        for _abs_fp, rel_fp, lines in _walk_source_files(local_path, _exts):
            for i, line in enumerate(lines, 1):
                _user_m = _user_re.search(line)
                _sink_m = _sink_re.search(line)
                # Same line: high confidence
                if _user_m and _sink_m:
                    param = next((g for g in _user_m.groups() if g), "?")
                    results.append(VulnSink(
                        file=rel_fp, line=i, snippet=line.strip(),
                        param=param, sink=_sink_m.group(0)[:60],
                        tech=_tech, confidence=3))
                    continue
                # Sink line nearby a user-input read (within 10 lines)
                if _sink_m:
                    window = "\n".join(lines[max(0, i-10):i])
                    wu = _user_re.search(window)
                    if wu:
                        param = next((g for g in wu.groups() if g), "?")
                        results.append(VulnSink(
                            file=rel_fp, line=i, snippet=line.strip(),
                            param=param, sink=_sink_m.group(0)[:60],
                            tech=_tech, confidence=2))
    # Deduplicate by (file, line), keep highest confidence
    seen: dict = {}
    for s in results:
        key = (s.file, s.line)
        if key not in seen or seen[key].confidence < s.confidence:
            seen[key] = s
    return sorted(seen.values(), key=lambda x: -x.confidence)[:20]


# ── Path traversal / LFI sinks ────────────────────────────────────────────────

_LFI_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bfile_get_contents\s*\(|\binclude(?:_once)?\s*\(|\brequire(?:_once)?\s*\("
                r"|\bfopen\s*\(|\breadfile\s*\(|\bhighlight_file\s*\(|\bshow_source\s*\("
                r"|\bfile\s*\(|\binclude\b", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bopen\s*\(|\bPath\s*\(.*\)\.read"
                r"|\bpathlib\.Path"
                r"|\bos\.path\.join\s*\(", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\bfs\.readFile(?:Sync)?\s*\(|\bfs\.createReadStream\s*\("
                r"|\bpath\.join\s*\(|\brequire\s*\(", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bFile\.read\s*\(|\bFile\.open\s*\(|\bIO\.read\s*\("
                r"|\brender\s+file:", re.IGNORECASE),
     [".rb"]),
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"new\s+FileInputStream\s*\(|Files\.readAllBytes\s*\("
                r"|new\s+File\s*\(", re.IGNORECASE),
     [".java"]),
    ("go",
     re.compile(r"r\.FormValue\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|r\.URL\.Query\(\)\.Get\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"\bioutil\.ReadFile\s*\(|\bos\.Open\s*\("
                r"|\bhttp\.ServeFile\s*\(", re.IGNORECASE),
     [".go"]),
]


def find_path_traversal_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find path traversal / LFI sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _LFI_PATTERNS if p[0] == tech] or _LFI_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── SSRF sinks ────────────────────────────────────────────────────────────────

_SSRF_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bfile_get_contents\s*\(\s*\$"
                r"|\bwp_remote_(?:get|post|request)\s*\("
                r"|\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL"
                r"|\bcurl_init\s*\(\s*\$"
                r"|\bfopen\s*\(\s*[\"']https?", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\brequests\.(?:get|post|put|patch|head)\s*\("
                r"|\burllib\.request\.urlopen\s*\("
                r"|\bhttpx\.\w+\s*\("
                r"|\baiohttp\.\w+\.(?:get|post)\s*\(", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\baxios\.(?:get|post|put)\s*\("
                r"|\bfetch\s*\("
                r"|\bhttp(?:s)?\.request\s*\("
                r"|\bnode-fetch\b", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bNet::HTTP\.(?:get|post_form)\s*\("
                r"|\bFaraday\.(?:get|post)\s*\("
                r"|\bopen\s*\(\s*params", re.IGNORECASE),
     [".rb"]),
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"new\s+URL\s*\([^)]*getParameter"
                r"|\bRestTemplate\b.*(?:get|post)ForObject"
                r"|HttpClient.*\.execute\s*\(", re.IGNORECASE),
     [".java"]),
    ("go",
     re.compile(r"r\.FormValue\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|r\.URL\.Query\(\)\.Get\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"\bhttp\.Get\s*\(|\bhttp\.Post\s*\("
                r"|\bclient\.Do\s*\(|\bhttp\.NewRequest\s*\(", re.IGNORECASE),
     [".go"]),
]


def find_ssrf_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find SSRF sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _SSRF_PATTERNS if p[0] == tech] or _SSRF_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── RCE / Command injection sinks ────────────────────────────────────────────

_RCE_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bexec\s*\(|\bsystem\s*\(|\bshell_exec\s*\("
                r"|\bpassthru\s*\(|\bpopen\s*\(|\bproc_open\s*\("
                r"|\beval\s*\(", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen|check_output)\s*\("
                r"|\bexec\s*\(|\beval\s*\("
                r"|\bcommands\.getoutput\s*\(", re.IGNORECASE),
     [".py"]),
    # Python file/header-based RCE: eval() applied to data from files, FITS headers, YAML, etc.
    ("python",
     re.compile(r"\.get\s*\(\s*['\"]([A-Za-z0-9_]+)['\"]"       # header.get("KEY")
                r"|header\s*\[['\"]([A-Za-z0-9_]+)['\"]"         # header["KEY"]
                r"|\bload\s*\(\s*(?:f|open)\b"                   # yaml.load(open(...))
                r"|\bfrom_header\s*\("                            # astropy from_header
                r"|\bread_fits\b|\bfits\.open\b"),
     re.compile(r"\beval\s*\(|\bexec\s*\(", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\bexec\s*\(|\bspawn\s*\("
                r"|\bexecSync\s*\(|\bspawnSync\s*\("
                r"|\beval\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bsystem\s*\(|\bexec\s*\(|\bspawn\s*\("
                r"|\bIO\.popen\s*\(|\b`[^`]*#\{params", re.IGNORECASE),
     [".rb"]),
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\("
                r"|\bProcessBuilder\s*\("
                r"|\bScriptEngine\b", re.IGNORECASE),
     [".java"]),
    ("go",
     re.compile(r"r\.FormValue\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|r\.URL\.Query\(\)\.Get\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"\bexec\.Command\s*\(|\bexec\.CommandContext\s*\(", re.IGNORECASE),
     [".go"]),
]


def find_rce_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find RCE / command injection sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _RCE_PATTERNS if p[0] == tech] or _RCE_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── XSS sinks ────────────────────────────────────────────────────────────────

_XSS_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\becho\s+\$|\bprint\s+\$|\bprintf?\s*\(\s*[\"'].*\$"
                r"|\besc_html\s*\([^)]*\$(?!.*esc_html)"  # unescaped echo
                r"|\}\s*\?>"  # variable echo via template
                r"|\{[^\}]*\$[^\}]+\}", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\brender_template_string\s*\(.*request\."
                r"|\bmark_safe\s*\("
                r"|\bformat_html\s*\(\s*[f'\"].*{}"
                r"|\bHttpResponse\s*\(.*request\.", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"res\.(?:send|write|end)\s*\("
                r"|\bres\.json\s*\(.*req\."
                r"|\binner(?:HTML|Text)\s*="
                r"|\bdocument\.write\s*\(", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bhtml_safe\b|\braw\s*\("
                r"|\brender\s+(?:inline|html):", re.IGNORECASE),
     [".rb", ".erb"]),
]


def find_xss_sinks_generic(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find XSS sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _XSS_PATTERNS if p[0] == tech] or _XSS_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── Auth bypass patterns ──────────────────────────────────────────────────────

def find_auth_bypass_generic(local_path: str, tech: str = "auto") -> List[dict]:
    """Find routes/handlers lacking authentication checks for ANY language.

    For PHP/WordPress delegates to find_missing_auth_handlers().
    For other techs uses language-specific auth pattern detection.
    Returns list of dicts: {route, handler, file, line, issues, n_issues}
    sorted by n_issues descending.
    """
    if tech == "auto":
        tech = detect_tech_stack(local_path)

    # PHP/WordPress: use the existing specialized scanner
    if tech == "php":
        return find_missing_auth_handlers(local_path)

    results: List[dict] = []

    if tech == "python":
        # Django: views without @login_required or permission_required
        # Flask: routes without @login_required
        _route_re   = re.compile(r"@(?:app|bp|blueprint)\.route\s*\(['\"]([^'\"]+)['\"]")
        _view_re    = re.compile(r"def\s+([A-Za-z0-9_]+)\s*\((?:request|self)")
        _auth_dec   = re.compile(r"@login_required|@permission_required|@staff_member_required"
                                 r"|@jwt_required|@requires_auth")
        _sensitive  = re.compile(r"\buser\b.*\.(delete|update|save)\s*\("
                                 r"|\bsettings\b|\bconfig\b.*=\s*request\.",
                                 re.IGNORECASE)
        for _abs_fp, rel_fp, lines in _walk_source_files(local_path, [".py"]):
            for i, line in enumerate(lines, 1):
                m = _route_re.search(line) or _view_re.search(line)
                if not m:
                    continue
                route = m.group(1)
                # Check 10 lines before for auth decorator
                window_before = "\n".join(lines[max(0, i-10):i])
                has_auth = bool(_auth_dec.search(window_before))
                # Check 30 lines after for sensitive operations
                window_after = "\n".join(lines[i:i+30])
                is_sensitive = bool(_sensitive.search(window_after))
                issues = []
                if not has_auth:
                    issues.append("no_auth_decorator")
                if is_sensitive and not has_auth:
                    issues.append("unauthenticated_mutation")
                if issues:
                    results.append({"route": route, "handler": route,
                                    "file": rel_fp, "line": i,
                                    "issues": issues, "n_issues": len(issues)})

    elif tech == "nodejs":
        # Express: routes without auth middleware
        _route_re   = re.compile(r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\("
                                 r"\s*['\"]([^'\"]+)['\"]")
        _auth_mw    = re.compile(r"\bisAuthenticated\b|\bisAdmin\b|\bauthenticate\b"
                                 r"|\bjwtAuth\b|\bverifyToken\b|\brequireAuth\b"
                                 r"|\bpassport\.authenticate\b", re.IGNORECASE)
        _sensitive  = re.compile(r"\.(?:delete|drop|remove|update|create|insert)\s*\("
                                 r"|\bconfig\b|\bsettings\b|\bpassword\b", re.IGNORECASE)
        for _abs_fp, rel_fp, lines in _walk_source_files(local_path, [".js", ".ts", ".mjs"]):
            for i, line in enumerate(lines, 1):
                m = _route_re.search(line)
                if not m:
                    continue
                route = m.group(1)
                window = "\n".join(lines[i:i+5])
                has_auth = bool(_auth_mw.search(line + window))
                is_sensitive = bool(_sensitive.search(window))
                issues = []
                if not has_auth:
                    issues.append("no_auth_middleware")
                if is_sensitive and not has_auth:
                    issues.append("unauthenticated_sensitive_route")
                if issues:
                    results.append({"route": route, "handler": route,
                                    "file": rel_fp, "line": i,
                                    "issues": issues, "n_issues": len(issues)})

    elif tech == "ruby":
        # Rails: actions without before_action :authenticate
        _action_re  = re.compile(r"def\s+([A-Za-z0-9_]+)\s*$")
        _auth_ba    = re.compile(r"before_action\s*:authenticate"
                                 r"|before_filter\s*:authenticate"
                                 r"|current_user\b|\bauthorize\b")
        _sensitive  = re.compile(r"\.(delete|destroy|update|create|save)\s*[!\(]", re.IGNORECASE)
        for _abs_fp, rel_fp, lines in _walk_source_files(local_path, [".rb"]):
            for i, line in enumerate(lines, 1):
                m = _action_re.search(line)
                if not m:
                    continue
                action = m.group(1)
                window_before = "\n".join(lines[max(0, i-30):i])
                has_auth = bool(_auth_ba.search(window_before))
                window_after = "\n".join(lines[i:i+20])
                is_sensitive = bool(_sensitive.search(window_after))
                issues = []
                if not has_auth:
                    issues.append("no_before_action_authenticate")
                if is_sensitive and not has_auth:
                    issues.append("unauthenticated_mutation")
                if issues:
                    results.append({"route": action, "handler": action,
                                    "file": rel_fp, "line": i,
                                    "issues": issues, "n_issues": len(issues)})

    elif tech == "java":
        # Spring: mappings without @PreAuthorize / @Secured
        _map_re     = re.compile(r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*"
                                 r"\(?[\"']?([A-Za-z0-9_/{}]+)[\"']?")
        _auth_ann   = re.compile(r"@PreAuthorize|@Secured|@RolesAllowed"
                                 r"|@WithMockUser", re.IGNORECASE)
        for _abs_fp, rel_fp, lines in _walk_source_files(local_path, [".java"]):
            for i, line in enumerate(lines, 1):
                m = _map_re.search(line)
                if not m:
                    continue
                route = m.group(1)
                window = "\n".join(lines[max(0, i-5):i])
                has_auth = bool(_auth_ann.search(window))
                issues = [] if has_auth else ["no_preauthorize_annotation"]
                if issues:
                    results.append({"route": route, "handler": route,
                                    "file": rel_fp, "line": i,
                                    "issues": issues, "n_issues": 1})

    # Sort by severity (n_issues desc)
    return sorted(results, key=lambda x: -x.get("n_issues", 0))[:20]


# ── Shared scan helper ────────────────────────────────────────────────────────

def _scan_sinks(local_path: str, pattern_sets: list, tech: str) -> List[VulnSink]:
    """Generic scan helper for input→sink patterns."""
    # PHP variable-assignment regex: $var = $_GET['param'] style
    _PHP_VAR_ASSIGN = re.compile(
        r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"
    )
    results: List[VulnSink] = []
    for _tech, _user_re, _sink_re, _exts in pattern_sets:
        for _abs_fp, rel_fp, lines in _walk_source_files(local_path, _exts):
            # Build a PHP variable→param map for the whole file (taint tracking)
            _var_map: dict = {}
            if _tech == "php":
                for _ln in lines:
                    _am = _PHP_VAR_ASSIGN.search(_ln)
                    if _am:
                        _var_map[_am.group(1)] = _am.group(2)

            for i, line in enumerate(lines, 1):
                _sink_m = _sink_re.search(line)
                if not _sink_m:
                    continue
                _user_m = _user_re.search(line)
                if _user_m:
                    param = next((g for g in _user_m.groups() if g), "?")
                    conf = 3
                else:
                    # Extended lookback: 50 lines (was 15) to catch params assigned at function top
                    window = "\n".join(lines[max(0, i-50):i])
                    _user_m2 = _user_re.search(window)
                    if _user_m2:
                        param = next((g for g in _user_m2.groups() if g), "?")
                        conf = 2
                    elif _tech == "php" and _var_map:
                        # Variable backtrack: check if sink uses a var that was tainted
                        _sink_snippet = line + "\n".join(lines[max(0, i-5):i])
                        _param_found = None
                        for _var, _p in _var_map.items():
                            if f"${_var}" in _sink_snippet or f"${{{_var}}}" in _sink_snippet:
                                _param_found = _p
                                break
                        if not _param_found:
                            continue
                        param = _param_found
                        conf = 2
                    else:
                        continue
                results.append(VulnSink(
                    file=rel_fp, line=i, snippet=line.strip(),
                    param=param, sink=_sink_m.group(0)[:60],
                    tech=_tech, confidence=conf))
    # Deduplicate by (file, line)
    seen: dict = {}
    for s in results:
        key = (s.file, s.line)
        if key not in seen or seen[key].confidence < s.confidence:
            seen[key] = s
    return sorted(seen.values(), key=lambda x: -x.confidence)


# ── Deserialization sinks ─────────────────────────────────────────────────────

_DESER_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bunserialize\s*\(", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form|body|data)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bpickle\.loads?\s*\("
                r"|\byaml\.load\s*\([^,)]+\)"   # yaml.load without Loader= is unsafe
                r"|\bmarshal\.loads?\s*\("
                r"|\bjsonpickle\.decode\s*\("
                r"|\bshelve\.open\s*\(", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\beval\s*\(\s*req\."
                r"|\bvm\.runIn(?:Context|NewContext|ThisContext)\s*\("
                r"|\bFunction\s*\(\s*req\."
                r"|\bnode-serialize\b"
                r"|\bserialize-javascript\b", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bMarshal\.load\s*\("
                r"|\bYAML\.load\s*\("          # YAML.safe_load is safe
                r"|\bYAML\.unsafe_load\s*\(", re.IGNORECASE),
     [".rb"]),
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|getInputStream\s*\(\s*\)"),
     re.compile(r"new\s+ObjectInputStream\s*\("
                r"|\breadObject\s*\(\s*\)"
                r"|\breadUnshared\s*\(\s*\)"
                r"|\bXStream\s*\(\s*\)"
                r"|\bSerializationUtils\.deserialize\s*\(", re.IGNORECASE),
     [".java"]),
    ("go",
     re.compile(r"r\.FormValue\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|r\.URL\.Query\(\)\.Get\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|io\.ReadAll\s*\(r\.Body\)"),
     re.compile(r"\bgob\.NewDecoder\s*\("
                r"|\bgob\.Decode\s*\("
                r"|\bengoding/gob\b", re.IGNORECASE),
     [".go"]),
]


def find_deserialization_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find unsafe deserialization sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _DESER_PATTERNS if p[0] == tech] or _DESER_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── XXE sinks ─────────────────────────────────────────────────────────────────

_XXE_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[['\"]([A-Za-z0-9_]+)['\"]"
                r"|\$xml\b|\$body\b|\$input\b"),
     re.compile(r"\bsimplexml_load_(?:string|file)\s*\("
                r"|\bDOMDocument\s*\(\s*\)"
                r"|\bloadXML\s*\(\s*\$"
                r"|\blibxml_disable_entity_loader\s*\(\s*false"
                r"|\bXMLReader::open\s*\(", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:data|body|get_data|stream)"
                r"|request\.(?:args|form)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"),
     re.compile(r"\bxml\.etree\.ElementTree\.(?:parse|fromstring|XML)\s*\("
                r"|\bET\.(?:parse|fromstring)\s*\("
                r"|\blxml\.etree\.parse\s*\("
                r"|\blxml\.etree\.fromstring\s*\("
                r"|\bexpatbuilder\b"
                r"|\bxmltodict\.parse\s*\(", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|rawBody|text)\b"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\bDOMParser\s*\(\s*\)"
                r"|\bparseFromString\s*\("
                r"|\bxml2js\.parseString\s*\("
                r"|\bfast-xml-parser\b"
                r"|\blibxmljs\.parseXml\s*\(", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"
                r"|request\.body\b"),
     re.compile(r"\bREXML::Document\.new\s*\("
                r"|\bNokogiri::XML\.parse\s*\("     # safe with NONET flag
                r"|\bNokogiri::XML\s*\("
                r"|\bXMLParser\b", re.IGNORECASE),
     [".rb"]),
    ("java",
     re.compile(r"request\.(?:getInputStream|getReader|getParameter)\s*\([^)]*\)"),
     re.compile(r"\bDocumentBuilderFactory\.newInstance\s*\(\s*\)"
                r"|\bSAXParserFactory\.newInstance\s*\(\s*\)"
                r"|\bXMLInputFactory\.newInstance\s*\(\s*\)"
                r"|\bTransformerFactory\.newInstance\s*\(\s*\)"
                r"|\bSchemaFactory\b", re.IGNORECASE),
     [".java"]),
]


def find_xxe_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find XXE / XML injection sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _XXE_PATTERNS if p[0] == tech] or _XXE_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── Open redirect sinks ───────────────────────────────────────────────────────

_REDIRECT_PATTERNS = [
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bheader\s*\(\s*['\"]Location:"
                r"|\bwp_redirect\s*\(\s*\$"
                r"|\bwp_safe_redirect\s*\(\s*\$"   # safe_redirect can still be abused
                r"|\bheader\s*\(\s*['\"]location:", re.IGNORECASE),
     [".php"]),
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\bredirect\s*\(\s*request\."
                r"|\bHttpResponseRedirect\s*\(\s*request\."
                r"|\bRedirectResponse\s*\(\s*request\."
                r"|\bflask\.redirect\s*\(.*request\.", re.IGNORECASE),
     [".py"]),
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\bres\.redirect\s*\(\s*req\."
                r"|\bres\.redirect\s*\(.*req\.", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bredirect_to\s+params\b"
                r"|\bredirect_to\s+params\[", re.IGNORECASE),
     [".rb"]),
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"response\.sendRedirect\s*\("
                r"|\bnew\s+RedirectView\s*\(\s*[^\"']"
                r"|\bModelAndView\s*\(\s*\"redirect:", re.IGNORECASE),
     [".java"]),
    ("go",
     re.compile(r"r\.FormValue\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"
                r"|r\.URL\.Query\(\)\.Get\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"\bhttp\.Redirect\s*\(", re.IGNORECASE),
     [".go"]),
]


def find_open_redirect_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find open redirect sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _REDIRECT_PATTERNS if p[0] == tech] or _REDIRECT_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── SSTI sinks ────────────────────────────────────────────────────────────────

_SSTI_PATTERNS = [
    # Python: Flask/Jinja2 — render_template_string with user input
    ("python",
     re.compile(r"request\.(?:GET|POST|args|form|json)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|params\.get\(['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\brender_template_string\s*\("
                r"|\bjinja2\.Template\s*\("
                r"|\bTemplate\s*\([^)]*request\."
                r"|\bEnvironment\s*\(.*\)\.from_string\s*\(", re.IGNORECASE),
     [".py"]),
    # PHP: Twig/Smarty template from user input
    ("php",
     re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[['\"]([A-Za-z0-9_]+)['\"]"),
     re.compile(r"\$twig\s*->\s*render\s*\(\s*\$"
                r"|\$twig\s*->\s*createTemplate\s*\(\s*\$"
                r"|\$smarty\s*->\s*display\s*\(\s*\$"
                r"|\$blade\s*->\s*render\s*\(\s*\$", re.IGNORECASE),
     [".php"]),
    # Ruby: ERB with user-supplied template string
    ("ruby",
     re.compile(r"params\[:([A-Za-z0-9_]+)\]"),
     re.compile(r"\bERB\.new\s*\(\s*params"
                r"|\bERB\.new\s*\([^)]*#\{"
                r"|\bErubi::Engine\s*\(\s*params", re.IGNORECASE),
     [".rb"]),
    # Java: Thymeleaf/FreeMarker template from user input
    ("java",
     re.compile(r"request\.getParameter\s*\(\s*[\"']([A-Za-z0-9_]+)[\"']"),
     re.compile(r"\bSpringTemplateEngine\b.*render"
                r"|\bcfg\.getTemplate\s*\(\s*[^\"']"
                r"|\bnew\s+Template\s*\(\s*[^\"']"
                r"|\bVelocityEngine\b.*evaluate", re.IGNORECASE),
     [".java"]),
    # Node.js: Handlebars/Pug/EJS compile from user string
    ("nodejs",
     re.compile(r"req\.(?:body|query|params)\[?['\"]?([A-Za-z0-9_]+)['\"]?\]?"
                r"|req\.(?:body|query|params)\.([A-Za-z0-9_]+)"),
     re.compile(r"\bHandlebars\.compile\s*\(\s*req\."
                r"|\bpug\.render\s*\(\s*req\."
                r"|\bejs\.render\s*\(\s*req\."
                r"|\bnunjucks\.renderString\s*\(\s*req\.", re.IGNORECASE),
     [".js", ".ts", ".mjs"]),
]


def find_ssti_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    """Find Server-Side Template Injection sinks for ANY language."""
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    pattern_sets = [p for p in _SSTI_PATTERNS if p[0] == tech] or _SSTI_PATTERNS
    return _scan_sinks(local_path, pattern_sets, tech)[:15]


# ── Prototype Pollution (Node.js) ─────────────────────────────────────────────
_PROTO_PATTERNS = [
    # user input assigned directly to __proto__ or via lodash merge/set/defaults with deep objects
    ("nodejs", re.compile(r"req\.(body|query|params)\b", re.I),
     re.compile(r"__proto__|constructor\.prototype|merge\(|set\(|defaults\(|deepmerge\(|extend\(", re.I),
     (".js", ".ts", ".mjs", ".cjs")),
    ("nodejs", re.compile(r"Object\.assign\s*\(\s*\w+\s*,\s*req\.", re.I),
     re.compile(r"Object\.assign", re.I),
     (".js", ".ts")),
]

def find_prototype_pollution_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    if tech not in ("nodejs", "unknown"):
        return []
    return _scan_sinks(local_path, _PROTO_PATTERNS, "nodejs")[:10]


# ── NoSQL Injection ───────────────────────────────────────────────────────────
_NOSQL_PATTERNS = [
    # Node.js / Mongoose: findOne(req.body) or find({$where: ...})
    ("nodejs", re.compile(r"req\.(body|query|params)\b", re.I),
     re.compile(r"\.find\(|\.findOne\(|\.findOneAndUpdate\(|\.update\(|\$where\s*:", re.I),
     (".js", ".ts")),
    # Python / PyMongo: collection.find(request_data)
    ("python", re.compile(r"request\.(data|json|POST|GET)\b", re.I),
     re.compile(r"\.find\(|\.find_one\(|\.update_one\(|\.aggregate\(", re.I),
     (".py",)),
    # PHP: custom BSON/MongoDB driver
    ("php", re.compile(r"\$_(?:POST|GET|REQUEST)\b", re.I),
     re.compile(r"->find\(|->findOne\(|new\\\\MongoDB", re.I),
     (".php",)),
]

def find_nosql_injection_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _NOSQL_PATTERNS if p[0] == tech] or _NOSQL_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── Mass Assignment ───────────────────────────────────────────────────────────
_MASSASSIGN_PATTERNS = [
    # Rails: params without .permit / strong params
    ("ruby", re.compile(r"params\b", re.I),
     re.compile(r"\.update\(params\b|\.create\(params\b|\.new\(params\b|attributes\s*=\s*params\b", re.I),
     (".rb",)),
    # Express/Node.js: Object.assign(model, req.body)
    ("nodejs", re.compile(r"req\.(body|query)\b", re.I),
     re.compile(r"Object\.assign\(|\.update\(req\.|\.create\(req\.|\.save\(req\.", re.I),
     (".js", ".ts")),
    # Django: **request.data / **request.POST into model
    ("python", re.compile(r"request\.(data|POST)\b", re.I),
     re.compile(r"\*\*request\.|\.objects\.create\(\*\*|\.objects\.update\(\*\*|serializer.*data", re.I),
     (".py",)),
    # Laravel/PHP: $request->all() without fillable guard
    ("php", re.compile(r"\$request->all\(\)|collect\(\$_POST\)", re.I),
     re.compile(r"->create\(\|->update\(\|->fill\(", re.I),
     (".php",)),
]

def find_mass_assignment_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _MASSASSIGN_PATTERNS if p[0] == tech] or _MASSASSIGN_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── CRLF Injection ────────────────────────────────────────────────────────────
_CRLF_PATTERNS = [
    # PHP: header() with user-controlled value
    ("php", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b", re.I),
     re.compile(r"header\s*\(|setcookie\s*\(|wp_redirect\s*\(", re.I),
     (".php",)),
    # Node.js: res.setHeader / res.writeHead with user input
    ("nodejs", re.compile(r"req\.(query|params|body|headers)\b", re.I),
     re.compile(r"res\.setHeader\(|res\.writeHead\(|res\.header\(", re.I),
     (".js", ".ts")),
    # Python: response headers from user input
    ("python", re.compile(r"request\.(GET|POST|data|headers)\b", re.I),
     re.compile(r"HttpResponse\[.+\]\s*=|response\[.+\]\s*=|set_cookie\(|redirect\(", re.I),
     (".py",)),
    # Java: response.addHeader / setHeader
    ("java", re.compile(r"request\.getParameter\(|getHeader\(", re.I),
     re.compile(r"response\.addHeader\(|response\.setHeader\(|sendRedirect\(", re.I),
     (".java",)),
]

def find_crlf_injection_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _CRLF_PATTERNS if p[0] == tech] or _CRLF_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── LDAP Injection ────────────────────────────────────────────────────────────
_LDAP_PATTERNS = [
    # PHP: ldap_search / ldap_bind with user input
    ("php", re.compile(r"\$_(?:GET|POST|REQUEST)\b", re.I),
     re.compile(r"ldap_search\s*\(|ldap_bind\s*\(|ldap_add\s*\(|ldap_connect\s*\(", re.I),
     (".php",)),
    # Java: DirContext.search / NamingEnumeration
    ("java", re.compile(r"request\.getParameter\(", re.I),
     re.compile(r"ctx\.search\(|DirContext|InitialDirContext|NamingEnumeration", re.I),
     (".java",)),
    # Python: ldap3 / python-ldap with user input
    ("python", re.compile(r"request\.(GET|POST|data)\b", re.I),
     re.compile(r"conn\.search\(|ldap\.search|ldap3\.Connection|MODIFY_ADD", re.I),
     (".py",)),
    # Node.js: ldapjs client.search
    ("nodejs", re.compile(r"req\.(body|query|params)\b", re.I),
     re.compile(r"client\.search\(|ldap\.createClient|\.bind\(dn", re.I),
     (".js", ".ts")),
]

def find_ldap_injection_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _LDAP_PATTERNS if p[0] == tech] or _LDAP_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── JWT Weakness ──────────────────────────────────────────────────────────────
_JWT_PATTERNS = [
    # Node.js: jwt.verify without algorithm pinning, or jwt.decode (no verify)
    ("nodejs", re.compile(r"jwt\.|jsonwebtoken\b", re.I),
     re.compile(r"jwt\.decode\(|jwt\.verify\([^,)]+,[^,)]+(?:,\s*\{[^}]*(?!\balgorithms\b))?$|"
                r"algorithm[s]?\s*:\s*\[?\s*['\"](?:none|HS256)['\"]", re.I),
     (".js", ".ts")),
    # Python: jwt.decode without algorithms
    ("python", re.compile(r"import jwt|from jwt\b", re.I),
     re.compile(r"jwt\.decode\([^,)]+,[^,)]+(?:,\s*(?!algorithms=))?$|"
                r"options\s*=\s*\{[^}]*verify_signature\s*:\s*False", re.I),
     (".py",)),
    # PHP: JWT without algorithm check
    ("php", re.compile(r"JWT::|use Firebase|use Lcobucci", re.I),
     re.compile(r"JWT::decode\(|->parse\(|->withoutVerification\(|'alg'\s*=>\s*'none'", re.I),
     (".php",)),
    # Java: Jwts.parser without setSigningKey
    ("java", re.compile(r"import io\.jsonwebtoken|import com\.auth0\.jwt", re.I),
     re.compile(r"Jwts\.parser\(\)|parseClaimsJwt\(|\.verify\(token,\s*null", re.I),
     (".java",)),
]

def find_jwt_weakness_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _JWT_PATTERNS if p[0] == tech] or _JWT_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── GraphQL Injection / Authorization Bypass ──────────────────────────────────
_GRAPHQL_PATTERNS = [
    # Node.js: graphql-js / apollo-server without depth/complexity limits
    ("nodejs", re.compile(r"req\.(body|query)\b", re.I),
     re.compile(r"graphql\s*\(|buildSchema\(|GraphQLSchema\(|typeDefs\b|resolvers\b", re.I),
     (".js", ".ts")),
    # Python: graphene / strawberry without auth on resolver
    ("python", re.compile(r"import graphene|import strawberry", re.I),
     re.compile(r"def resolve_|@strawberry\.(field|mutation)|graphql_view\b", re.I),
     (".py",)),
    # Ruby: graphql-ruby
    ("ruby", re.compile(r"require.*graphql", re.I),
     re.compile(r"field\s+:\w+|def resolve_|GraphQL::Schema", re.I),
     (".rb",)),
    # Java: graphql-java
    ("java", re.compile(r"import graphql\.", re.I),
     re.compile(r"GraphQL\.newGraphQL\(|DataFetchingEnvironment|\.query\(", re.I),
     (".java",)),
]

def find_graphql_injection_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _GRAPHQL_PATTERNS if p[0] == tech] or _GRAPHQL_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── ReDoS / Algorithmic Complexity ────────────────────────────────────────────
_REDOS_PATTERNS = [
    # Node.js: regex applied to user input in a tight loop
    ("nodejs", re.compile(r"req\.(body|query|params)\b", re.I),
     re.compile(r"\.test\(|\.match\(|\.exec\(|new\s+RegExp\(", re.I),
     (".js", ".ts")),
    # Python: re.match/search/fullmatch on user input
    ("python", re.compile(r"request\.(GET|POST|data|json)\b", re.I),
     re.compile(r"re\.(match|search|fullmatch|findall|compile)\(", re.I),
     (".py",)),
    # PHP: preg_match/preg_replace on user input
    ("php", re.compile(r"\$_(?:GET|POST|REQUEST)\b", re.I),
     re.compile(r"preg_match\s*\(|preg_replace\s*\(|preg_split\s*\(", re.I),
     (".php",)),
    # Java: Pattern.matches / .matcher applied to user input
    ("java", re.compile(r"request\.getParameter\(", re.I),
     re.compile(r"Pattern\.compile\(|\.matches\(|\.matcher\(", re.I),
     (".java",)),
]

def find_redos_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _REDOS_PATTERNS if p[0] == tech] or _REDOS_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


# ── HTTP Request Smuggling (Node.js / Go / Python) ────────────────────────────
_SMUGGLING_PATTERNS = [
    # Node.js http.createServer with raw Content-Length / Transfer-Encoding manipulation
    ("nodejs", re.compile(r"req\.headers\b", re.I),
     re.compile(r"content-length|transfer-encoding|http\.createServer|keepAlive\s*:", re.I),
     (".js", ".ts")),
    ("go", re.compile(r"r\.Header\.Get\(", re.I),
     re.compile(r"\"Content-Length\"|\"Transfer-Encoding\"|http\.ListenAndServe", re.I),
     (".go",)),
]

def find_request_smuggling_sinks(local_path: str, tech: str = "auto") -> List[VulnSink]:
    if tech == "auto":
        tech = detect_tech_stack(local_path)
    patterns = [p for p in _SMUGGLING_PATTERNS if p[0] == tech] or _SMUGGLING_PATTERNS
    return _scan_sinks(local_path, patterns, tech)[:10]


def find_file_upload_handlers(local_path: str) -> list:
    """Scan WordPress plugin PHP code for AJAX handlers that process file uploads.

    Returns list of dicts: {action, handler_fn, file, line, nopriv, issues}
    sorted by severity (unauthenticated handlers first).
    Used when file-upload CVE has no endpoint in llm_notes.
    """
    if not local_path or not os.path.isdir(local_path):
        return []

    _AJAX_REG = re.compile(
        r"""add_action\s*\(\s*['"]wp_ajax_(nopriv_)?([A-Za-z0-9_]+)['"]\s*,\s*"""
        r"""(?:['"]([\w\\:]+)['"]|array\s*\([^)]{0,80}['\"]([\w\\:]+)['\"])""",
        re.S)
    _FILES_USE = re.compile(r'\$_FILES\b', re.I)
    _UPLOAD_FNS = re.compile(
        r'\b(?:wp_handle_upload|move_uploaded_file|wp_handle_sideload'
        r'|media_handle_upload|is_uploaded_file)\s*\(', re.I)
    _AUTH_CHECK = re.compile(
        r'\b(?:check_ajax_referer|wp_verify_nonce|current_user_can|check_admin_referer)\s*\(', re.I)

    all_texts: dict = {}
    for dirpath, _dirs, files in os.walk(local_path):
        if "node_modules" in dirpath or "/.git" in dirpath:
            continue
        for fn in sorted(files):
            if not fn.lower().endswith(".php"):
                continue
            fpath = os.path.join(dirpath, fn)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    all_texts[fpath] = fh.read(200_000)
            except Exception:
                continue

    handlers: dict = {}
    for fpath, text in all_texts.items():
        for m in _AJAX_REG.finditer(text):
            nopriv = bool(m.group(1))
            action = m.group(2)
            handler_fn = m.group(3) or m.group(4) or ""
            handlers.setdefault(action, {
                "action": action, "handler_fn": handler_fn,
                "file": fpath, "line": text[:m.start()].count("\n") + 1,
                "nopriv": nopriv, "has_upload": False, "has_auth": False,
            })
            if nopriv:
                handlers[action]["nopriv"] = True

    for action, info in handlers.items():
        handler_fn = info["handler_fn"]
        for fpath, text in all_texts.items():
            if _FILES_USE.search(text) or _UPLOAD_FNS.search(text):
                if handler_fn and handler_fn in text:
                    info["has_upload"] = True
                elif action in text and (_FILES_USE.search(text) or _UPLOAD_FNS.search(text)):
                    info["has_upload"] = True
            if _AUTH_CHECK.search(text) and (handler_fn in text or action in text):
                info["has_auth"] = True

    results = [h for h in handlers.values() if h["has_upload"]]
    # Sort: nopriv+no-auth first (most exploitable), then nopriv, then with auth
    results.sort(key=lambda h: (not h["nopriv"], h["has_auth"]))
    return results


# ── Fix 2: Patch-diff grounding ───────────────────────────────────────────────

def fetch_wp_plugin_patch_diff(slug: str, vuln_version: str, fixed_version: str,
                               timeout: int = 20) -> dict:
    """Descarga el diff unificado entre versión vulnerable y parchada de un plugin
    de WordPress.org via plugins.trac.wordpress.org/changeset y lo parsea para
    identificar qué funciones PHP cambiaron y qué tipo de fix se aplicó.

    Devuelve:
      ok: bool
      diff_url: str
      changed_files: [str]
      vuln_functions: [str]   # funciones que tenían SQL sin preparar
      fix_type: str           # "prepare" | "sanitize" | "intval" | "unknown"
      raw_diff_snippet: str   # primeras 2000 chars del diff
    """
    import urllib.request as _ur
    import urllib.error as _ue
    import re as _re

    result: dict = {
        "ok": False,
        "diff_url": "",
        "changed_files": [],
        "vuln_functions": [],
        "fix_type": "unknown",
        "raw_diff_snippet": "",
    }

    if not slug or not vuln_version or not fixed_version:
        return result
    if vuln_version == fixed_version:
        return result

    slug = slug.strip().lower()
    vuln_version = vuln_version.strip()
    fixed_version = fixed_version.strip()

    diff_url = (
        f"https://plugins.trac.wordpress.org/changeset"
        f"?new_path=%2F{slug}%2Ftags%2F{fixed_version}"
        f"&old_path=%2F{slug}%2Ftags%2F{vuln_version}"
        f"&format=diff"
    )
    result["diff_url"] = diff_url

    try:
        req = _ur.Request(diff_url, headers={"User-Agent": "binoracle/1.0"})
        with _ur.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(200_000).decode("utf-8", errors="replace")
    except (_ue.URLError, OSError):
        return result

    if not raw.strip() or len(raw) < 50:
        return result

    result["raw_diff_snippet"] = raw[:2000]
    result["ok"] = True

    # Extraer archivos modificados de cabeceras "--- a/..." / "+++ b/..."
    changed_files = []
    for _m in _re.finditer(r'^(?:\+\+\+|---)\s+(?:[ab]/)?(.+\.php)', raw, _re.MULTILINE):
        _f = _m.group(1).strip()
        if _f not in changed_files and not _f.startswith("/dev/null"):
            changed_files.append(_f)
    result["changed_files"] = changed_files

    # Detectar tipo de fix en líneas "+" (código añadido)
    added = " ".join(ln[1:] for ln in raw.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    if _re.search(r'\$wpdb\s*->\s*prepare\s*\(', added, _re.IGNORECASE):
        result["fix_type"] = "prepare"
    elif _re.search(r'sanitize_\w+\s*\(', added, _re.IGNORECASE):
        result["fix_type"] = "sanitize"
    elif _re.search(r'\b(?:intval|absint)\s*\(', added, _re.IGNORECASE):
        result["fix_type"] = "intval"
    elif _re.search(r'esc_sql\s*\(', added, _re.IGNORECASE):
        result["fix_type"] = "sanitize"

    # Extraer funciones PHP vulnerables: buscar en líneas "-" (eliminadas) que tenían
    # $wpdb->query/get_results con concatenación de string directa (sin prepare)
    vuln_fns: list = []
    _current_fn = ""
    _fn_re = _re.compile(r'^\+?-?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
    _unsafe_sql_re = _re.compile(
        r'\$wpdb\s*->\s*(?:query|get_results|get_row|get_var|get_col)\s*\(\s*["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE|"\.|\'\.|".*\$|\'\s*\.\s*\$)',
        _re.IGNORECASE)
    for ln in raw.splitlines():
        _fmatch = _fn_re.match(ln.lstrip("+-"))
        if _fmatch:
            _current_fn = _fmatch.group(1)
        if ln.startswith("-") and _unsafe_sql_re.search(ln) and _current_fn:
            if _current_fn not in vuln_fns:
                vuln_fns.append(_current_fn)

    result["vuln_functions"] = vuln_fns
    return result


def fetch_wp_rest_routes(base_url: str, session=None, plugin_slug: str = "") -> list:
    """
    Hit /wp-json/ and return routes likely belonging to plugin_slug.
    Returns [{"route": str, "methods": [str], "args": [str], "namespace": str}].
    Empty list on any error or if the endpoint is unreachable.
    """
    import requests as _rq
    import re as _re_rest
    _WP_CORE_NS = {
        "wp/v2", "oembed/1.0", "wp-site-health/v1", "wp-block-editor/v1",
        "wp-block-directory/v1", "wp/v3",
    }
    try:
        url = base_url.rstrip("/") + "/wp-json/"
        r = (session or _rq).get(url, timeout=10, allow_redirects=True)
        if r.status_code != 200:
            return []
        data = r.json()
        routes_raw = data.get("routes", {})
        slug_parts: set = set()
        if plugin_slug:
            slug_parts = (
                set(_re_rest.split(r"[-_]", plugin_slug.lower()))
                - {"wp", "api", "v1", "v2", "v3", "the", "a", "an"}
            )
        result = []
        for route, info in routes_raw.items():
            namespace = info.get("namespace", "")
            if namespace in _WP_CORE_NS:
                continue
            ns_route_lower = (namespace + route).lower()
            if plugin_slug and not any(p in ns_route_lower for p in slug_parts if len(p) >= 3):
                continue
            for ep in info.get("endpoints", []):
                methods = ep.get("methods", [])
                args = list(ep.get("args", {}).keys())
                result.append({
                    "route": route,
                    "namespace": namespace,
                    "methods": methods,
                    "args": args,
                })
        return result
    except Exception:
        return []


# ── Multi-source CVE intelligence gathering ──────────────────────────────────

def fetch_wordfence_advisory(cve_id: str, timeout: int = 15) -> dict:
    """Fetch Wordfence Threat Intel advisory — WP-specific param/endpoint/function hints."""
    import requests as _req, re as _re
    result = {"ok": False, "source": "wordfence", "cve_id": cve_id,
              "vulnerable_param": "", "endpoint_hint": "", "affected_function": "",
              "attack_vector": "", "notes": "", "raw_text": ""}
    try:
        url = f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{cve_id}"
        r = _req.get(url, timeout=timeout,
                     headers={"User-Agent": "Mozilla/5.0 (security-research)"})
        if r.status_code != 200:
            search_url = (f"https://www.wordfence.com/threat-intel/vulnerabilities"
                          f"?search={cve_id}")
            r = _req.get(search_url, timeout=timeout,
                         headers={"User-Agent": "Mozilla/5.0 (security-research)"})
            if r.status_code != 200:
                return result
        text = r.text
        result["raw_text"] = text[:8000]
        result["ok"] = True

        for pat in [r"['\"]([a-z_]{2,30})['\"] parameter",
                    r"parameter ['\"]([a-z_]{2,30})['\"]",
                    r"the ['\"]([a-z_]{2,30})['\"] (?:POST |GET |request )?parameter",
                    r"via the ['\"]([a-z_]{2,30})['\"]"]:
            m = _re.search(pat, text, _re.IGNORECASE)
            if m:
                result["vulnerable_param"] = m.group(1)
                break

        for pat in [r"(/wp-(?:admin|json|content)/[^\s\"'<>]{3,80})",
                    r"(admin-ajax\.php[^\s\"'<>]{0,50})",
                    r"action=['\"]?([a-z_0-9]{3,50})['\"]?"]:
            m = _re.search(pat, text, _re.IGNORECASE)
            if m:
                result["endpoint_hint"] = m.group(1)
                break

        for pat in [r"(?:function|in) ['\"]?([a-z_]{3,50})\(\)['\"]?",
                    r"([a-z_]{3,50})\(\) function"]:
            m = _re.search(pat, text, _re.IGNORECASE)
            if m:
                result["affected_function"] = m.group(1)
                break

        av_parts = []
        for pat in [r"(unauthenticated|authenticated|subscriber|contributor|author|editor|administrator)",
                    r"(SQL injection|cross-site scripting|file inclusion|path traversal|SSRF|RCE|LFI)"]:
            m = _re.search(pat, text, _re.IGNORECASE)
            if m:
                av_parts.append(m.group(1))
        result["attack_vector"] = " ".join(av_parts[:3])

        for marker in ["Description", "Technical Analysis", "Vulnerability Details"]:
            idx = text.find(marker)
            if idx >= 0:
                result["notes"] = text[idx:idx + 2000].strip()
                break
        if not result["notes"]:
            result["notes"] = text[500:2500].strip()
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_patchstack_advisory(cve_id: str, timeout: int = 15) -> dict:
    """Fetch Patchstack vulnerability advisory for a CVE."""
    import requests as _req, re as _re
    result = {"ok": False, "source": "patchstack", "cve_id": cve_id,
              "vulnerable_param": "", "endpoint_hint": "", "affected_function": "",
              "attack_vector": "", "notes": "", "raw_text": ""}
    try:
        url = f"https://patchstack.com/database/search?term={cve_id}"
        r = _req.get(url, timeout=timeout,
                     headers={"User-Agent": "Mozilla/5.0 (security-research)"})
        if r.status_code != 200:
            return result
        text = r.text
        result["raw_text"] = text[:6000]
        result["ok"] = True
        for pat in [r"parameter ['\"]([a-z_]{2,30})['\"]",
                    r"['\"]([a-z_]{2,30})['\"] parameter"]:
            m = _re.search(pat, text, _re.IGNORECASE)
            if m:
                result["vulnerable_param"] = m.group(1)
                break
        result["notes"] = text[200:2000].strip()
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_github_advisories(cve_id: str, timeout: int = 15) -> dict:
    """Fetch GitHub Security Advisories for a CVE via GitHub API."""
    import requests as _req, re as _re
    result = {"ok": False, "source": "github_advisory", "cve_id": cve_id,
              "ghsa_id": "", "summary": "", "description": "", "severity": "",
              "vulnerable_param": "", "affected_function": "", "references": []}
    try:
        r = _req.get("https://api.github.com/advisories",
                     params={"cve_id": cve_id, "per_page": 5}, timeout=timeout,
                     headers={"Accept": "application/vnd.github+json",
                               "User-Agent": "binoracle-security-research"})
        if r.status_code != 200:
            return result
        advisories = r.json()
        if not advisories:
            return result
        adv = advisories[0]
        result["ok"] = True
        result["ghsa_id"] = adv.get("ghsa_id", "")
        result["summary"] = adv.get("summary", "")
        result["description"] = adv.get("description", "")[:3000]
        result["severity"] = adv.get("severity", "")
        result["references"] = [ref.get("url", "") for ref in adv.get("references", [])][:10]
        desc = result["description"]
        for pat in [r"['\"]([a-z_]{2,30})['\"] parameter",
                    r"parameter ['\"]([a-z_]{2,30})['\"]"]:
            m = _re.search(pat, desc, _re.IGNORECASE)
            if m:
                result["vulnerable_param"] = m.group(1)
                break
        for pat in [r"(?:function|in) `([a-z_]{3,50})\(\)`",
                    r"`([a-z_]{3,50})\(\)` function"]:
            m = _re.search(pat, desc, _re.IGNORECASE)
            if m:
                result["affected_function"] = m.group(1)
                break
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_nvd_cve_details(cve_id: str, timeout: int = 20) -> dict:
    """Fetch detailed CVE data from NVD: description, CWEs, CVSS, references."""
    import requests as _req
    result = {"ok": False, "source": "nvd", "cve_id": cve_id,
              "description": "", "cwes": [], "cvss_score": 0.0,
              "cvss_vector": "", "attack_vector": "", "references": []}
    try:
        r = _req.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                     params={"cveId": cve_id}, timeout=timeout,
                     headers={"User-Agent": "binoracle-security-research"})
        if r.status_code != 200:
            return result
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return result
        cve = vulns[0].get("cve", {})
        result["ok"] = True
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                result["description"] = d.get("value", "")
                break
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                cwe = d.get("value", "")
                if cwe.startswith("CWE-"):
                    result["cwes"].append(cwe)
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                result["cvss_score"] = cvss_data.get("baseScore", 0.0)
                result["cvss_vector"] = cvss_data.get("vectorString", "")
                result["attack_vector"] = cvss_data.get("attackVector", "")
                break
        result["references"] = [ref.get("url", "") for ref in cve.get("references", [])][:15]
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_wpscan_advisory(cve_id: str, timeout: int = 15) -> dict:
    """Fetch vulnerability details from WPScan Vulnerability Database (api.wpscan.com).
    Returns advisory with affected_function, vulnerable_param, and PoC references."""
    import urllib.request as _ur
    import json as _j
    result = {"ok": False, "source": "wpscan", "cve_id": cve_id}
    try:
        # WPScan public search endpoint (no API key needed for CVE lookup)
        url = f"https://wpscan.com/api/v3/vulnerabilities/{cve_id}"
        req = _ur.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with _ur.urlopen(req, timeout=timeout) as r:
            data = _j.loads(r.read())
        if not data:
            return result
        # WPScan returns a list of vuln objects
        vuln = data[0] if isinstance(data, list) else data
        notes_parts = []
        if vuln.get("title"):
            notes_parts.append(f"Title: {vuln['title']}")
        if vuln.get("vuln_type"):
            notes_parts.append(f"Type: {vuln['vuln_type']}")
        # Extract references and PoC URLs
        refs = vuln.get("references", {})
        poc_urls = refs.get("url", [])
        if poc_urls:
            notes_parts.append(f"References: {', '.join(poc_urls[:5])}")
        # Extract affected versions
        fixed_in = vuln.get("fixed_in", "")
        if fixed_in:
            notes_parts.append(f"Fixed in: {fixed_in}")
        result.update({
            "ok": True,
            "notes": "\n".join(notes_parts),
            "poc_urls": poc_urls[:5],
            "fixed_in": fixed_in,
            "vuln_type": vuln.get("vuln_type", ""),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_exploitdb_data(cve_id: str, timeout: int = 15) -> dict:
    """Search ExploitDB for public PoC code related to a CVE.
    Returns exploit description, exploit code snippet, and author."""
    import urllib.request as _ur
    import urllib.parse as _up
    import json as _j
    result = {"ok": False, "source": "exploitdb", "cve_id": cve_id}
    try:
        # ExploitDB search API
        params = _up.urlencode({"cve": cve_id, "type": "webapps", "format": "json"})
        url = f"https://www.exploit-db.com/search?{params}"
        req = _ur.Request(url, headers={
            "User-Agent": "binoracle/1.0",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        })
        with _ur.urlopen(req, timeout=timeout) as r:
            data = _j.loads(r.read())
        entries = data.get("data", [])
        if not entries:
            return result
        notes_parts = []
        poc_snippets = []
        for entry in entries[:3]:
            title = entry.get("description", "")
            eid = entry.get("id", "")
            author = entry.get("author", {}).get("name", "")
            platform = entry.get("platform", {}).get("val", "")
            notes_parts.append(
                f"ExploitDB #{eid}: {title} (platform={platform}, author={author})")
            # Try to fetch the actual exploit code
            if eid:
                try:
                    code_url = f"https://www.exploit-db.com/raw/{eid}"
                    code_req = _ur.Request(code_url, headers={"User-Agent": "binoracle/1.0"})
                    with _ur.urlopen(code_req, timeout=10) as cr:
                        code = cr.read().decode("utf-8", errors="replace")[:2000]
                    poc_snippets.append(f"# ExploitDB #{eid}\n{code}")
                except Exception:
                    pass
        result.update({
            "ok": True,
            "notes": "\n".join(notes_parts),
            "poc_snippets": poc_snippets,
            "exploit_count": len(entries),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_vulndb_mitre(cve_id: str, timeout: int = 15) -> dict:
    """Fetch MITRE CVE record for detailed description, references, and affected products."""
    import urllib.request as _ur
    import json as _j
    result = {"ok": False, "source": "mitre", "cve_id": cve_id}
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        req = _ur.Request(url, headers={"User-Agent": "binoracle/1.0",
                                         "Accept": "application/json"})
        with _ur.urlopen(req, timeout=timeout) as r:
            data = _j.loads(r.read())
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        descriptions = cna.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        # Extract affected component info
        affected = cna.get("affected", [])
        affected_info = []
        for a in affected[:3]:
            vendor = a.get("vendor", "")
            product = a.get("product", "")
            versions = [v.get("version", "") for v in a.get("versions", [])
                        if v.get("status") == "affected"]
            affected_info.append(f"{vendor}/{product} {','.join(versions[:3])}")
        # Extract references
        refs = [r.get("url", "") for r in cna.get("references", [])[:5]]
        notes_parts = []
        if desc:
            notes_parts.append(f"MITRE description: {desc[:600]}")
        if affected_info:
            notes_parts.append(f"Affected: {'; '.join(affected_info)}")
        if refs:
            notes_parts.append(f"References: {', '.join(refs[:3])}")
        result.update({
            "ok": bool(desc),
            "description": desc,
            "affected": affected_info,
            "references": refs,
            "notes": "\n".join(notes_parts),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_osv_advisory(cve_id: str, timeout: int = 15) -> dict:
    """Fetch from Google's Open Source Vulnerability database (api.osv.dev).
    Rich structured data: affected packages, severity, aliases, fix commits."""
    import urllib.request as _ur
    import json as _j
    result = {"ok": False, "source": "osv", "cve_id": cve_id}
    try:
        url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        req = _ur.Request(url, headers={"User-Agent": "binoracle/1.0",
                                         "Accept": "application/json"})
        with _ur.urlopen(req, timeout=timeout) as r:
            data = _j.loads(r.read())
        if not data or data.get("code") == 5:  # NOT_FOUND
            return result
        notes_parts = []
        summary = data.get("summary", "")
        detail = data.get("details", "")
        if summary:
            notes_parts.append(f"Summary: {summary}")
        if detail:
            notes_parts.append(f"Details: {detail[:800]}")
        # Extract affected packages + fixed versions
        affected_pkgs = []
        for aff in data.get("affected", [])[:5]:
            pkg = aff.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            versions = aff.get("versions", [])
            ranges = aff.get("ranges", [])
            fix = ""
            for r in ranges:
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fix = ev["fixed"]
                        break
            affected_pkgs.append(
                f"{ecosystem}/{name} (versions: {versions[:3]}, fixed: {fix})")
        if affected_pkgs:
            notes_parts.append(f"Affected: {'; '.join(affected_pkgs)}")
        # Extract severity
        severities = data.get("severity", [])
        for sev in severities:
            if sev.get("type") == "CVSS_V3":
                notes_parts.append(f"CVSS v3: {sev.get('score', '')}")
                break
        # Extract fix commits/PRs
        refs = data.get("references", [])
        fix_refs = [r["url"] for r in refs if r.get("type") in ("FIX", "ADVISORY")][:3]
        if fix_refs:
            notes_parts.append(f"Fix refs: {', '.join(fix_refs)}")
        result.update({
            "ok": True,
            "summary": summary,
            "details": detail[:800],
            "affected_packages": affected_pkgs,
            "fix_references": fix_refs,
            "notes": "\n".join(notes_parts),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def fetch_vulners_cve(cve_id: str, timeout: int = 15) -> dict:
    """Fetch from vulners.com public CVE API — aggregated references, PoC links, exploit scores."""
    import urllib.request as _ur
    import urllib.parse as _up
    import json as _j
    result = {"ok": False, "source": "vulners", "cve_id": cve_id}
    try:
        params = _up.urlencode({"id": cve_id, "apiKey": ""})
        url = f"https://vulners.com/api/v3/search/id/?{params}"
        req = _ur.Request(url, headers={"User-Agent": "binoracle/1.0"})
        with _ur.urlopen(req, timeout=timeout) as r:
            data = _j.loads(r.read())
        if data.get("result") != "OK":
            return result
        docs = data.get("data", {}).get("documents", {})
        if not docs:
            return result
        doc = next(iter(docs.values()))
        desc = doc.get("description", "")
        cvss = doc.get("cvss", {}).get("score", 0.0)
        refs = [r.get("url", "") for r in doc.get("references", [])[:5]]
        # Look for exploit/PoC references
        poc_refs = [u for u in refs if any(x in u for x in
                    ["exploit-db", "github.com", "poc", "proof"])]
        notes_parts = []
        if desc:
            notes_parts.append(f"Vulners description: {desc[:500]}")
        if poc_refs:
            notes_parts.append(f"PoC refs: {', '.join(poc_refs[:3])}")
        result.update({
            "ok": bool(desc),
            "description": desc,
            "cvss_score": float(cvss) if cvss else 0.0,
            "poc_refs": poc_refs,
            "notes": "\n".join(notes_parts),
        })
    except Exception as e:
        result["error"] = str(e)
    return result


def gather_cve_intelligence(cve_id: str, plugin_slug: str = "",
                             timeout: int = 15,
                             target_ecosystem: str = "") -> dict:
    """
    Gather CVE intelligence from NVD, GitHub, ExploitDB, MITRE, OSV.dev, and
    Vulners in parallel (universal sources), plus Wordfence, Patchstack and WPScan
    only when the target is a WordPress component (plugin_slug set, or
    target_ecosystem contains "wordpress"/"wp").
    Returns a merged dict with the richest available information from all sources.
    """
    import concurrent.futures as _cf
    _eco = (target_ecosystem or plugin_slug or "").lower()
    _is_wp = bool(_eco) and any(t in _eco for t in
                                ("wordpress", "wp-", "/wp-", "woo", "elementor",
                                 "jetpack", "yoast", "akismet", "gravityforms"))
    sources = {}
    # Universal sources — always queried
    _futures_map: dict = {
        "nvd":      fetch_nvd_cve_details,
        "github":   fetch_github_advisories,
        "exploitdb":fetch_exploitdb_data,
        "mitre":    fetch_vulndb_mitre,
        "osv":      fetch_osv_advisory,
        "vulners":  fetch_vulners_cve,
    }
    # WordPress-only sources — only when target is a WP component
    if _is_wp:
        _futures_map["wordfence"] = fetch_wordfence_advisory
        _futures_map["patchstack"] = fetch_patchstack_advisory
        _futures_map["wpscan"]    = fetch_wpscan_advisory
    with _cf.ThreadPoolExecutor(max_workers=len(_futures_map)) as ex:
        futures = {ex.submit(fn, cve_id, timeout): name
                   for name, fn in _futures_map.items()}
        for fut, name in futures.items():
            try:
                sources[name] = fut.result(timeout=timeout + 5)
            except Exception:
                sources[name] = {"ok": False, "source": name}

    merged = {
        "cve_id": cve_id,
        "sources": {k: (v.get("ok", False) if isinstance(v, dict) else False) for k, v in sources.items()},
        "description": "",
        "cwes": [],
        "cvss_score": 0.0,
        "attack_vector": "",
        "vulnerable_param": "",
        "endpoint_hint": "",
        "affected_function": "",
        "advisory_notes": "",
        "references": [],
        "poc_available": False,
        "poc_snippets": [],
    }
    nvd = sources.get("nvd") or {}
    if nvd.get("ok"):
        merged["description"] = nvd.get("description", "")
        merged["cwes"] = nvd.get("cwes", [])
        merged["cvss_score"] = nvd.get("cvss_score", 0.0)
        merged["attack_vector"] = nvd.get("attack_vector", "")
        merged["references"] = nvd.get("references", [])
    wf = sources.get("wordfence") or {}
    if wf.get("ok"):
        if wf.get("vulnerable_param"):
            merged["vulnerable_param"] = wf["vulnerable_param"]
        if wf.get("endpoint_hint"):
            merged["endpoint_hint"] = wf["endpoint_hint"]
        if wf.get("affected_function"):
            merged["affected_function"] = wf["affected_function"]
        if wf.get("notes"):
            merged["advisory_notes"] = wf["notes"][:3000]
        if wf.get("attack_vector") and not merged["attack_vector"]:
            merged["attack_vector"] = wf["attack_vector"]
    ps = sources.get("patchstack") or {}
    if ps.get("ok") and not merged["vulnerable_param"]:
        if ps.get("vulnerable_param"):
            merged["vulnerable_param"] = ps["vulnerable_param"]
        if ps.get("notes") and not merged["advisory_notes"]:
            merged["advisory_notes"] = ps["notes"][:2000]
    gh = sources.get("github") or {}
    if gh.get("ok"):
        if not merged["description"] and gh.get("description"):
            merged["description"] = gh["description"]
        if not merged["vulnerable_param"] and gh.get("vulnerable_param"):
            merged["vulnerable_param"] = gh["vulnerable_param"]
        if not merged["affected_function"] and gh.get("affected_function"):
            merged["affected_function"] = gh["affected_function"]
    # WPScan: append advisory notes and PoC URLs
    ws = sources.get("wpscan") or {}
    if ws.get("ok"):
        if ws.get("notes"):
            if merged["advisory_notes"]:
                merged["advisory_notes"] += f"\n\nWPScan: {ws['notes'][:800]}"
            else:
                merged["advisory_notes"] = ws["notes"][:800]
        if ws.get("poc_urls"):
            merged["references"] = list({*merged["references"], *ws["poc_urls"]})
            merged["poc_available"] = True
    # ExploitDB: highest-value intel — public PoC code
    edb = sources.get("exploitdb") or {}
    if edb.get("ok"):
        merged["poc_available"] = True
        if edb.get("notes"):
            merged["advisory_notes"] += f"\n\nExploitDB: {edb['notes'][:600]}"
        if edb.get("poc_snippets"):
            merged["poc_snippets"] = edb["poc_snippets"]
    # MITRE: fallback description when NVD is empty
    mitre = sources.get("mitre") or {}
    if mitre.get("ok"):
        if not merged["description"] and mitre.get("description"):
            merged["description"] = mitre["description"]
        if mitre.get("notes"):
            merged["advisory_notes"] += f"\n\nMITRE: {mitre['notes'][:400]}"
    # OSV.dev: affected packages + fix refs (great for non-WP ecosystems)
    osv = sources.get("osv") or {}
    if osv.get("ok"):
        if not merged["description"] and osv.get("summary"):
            merged["description"] = osv["summary"]
        if osv.get("notes"):
            merged["advisory_notes"] += f"\n\nOSV: {osv['notes'][:600]}"
        if osv.get("fix_references"):
            merged["references"] = list({*merged["references"], *osv["fix_references"]})
        if osv.get("affected_packages"):
            merged["affected_packages"] = osv["affected_packages"]
    # Vulners: PoC references and CVE aggregation
    vul = sources.get("vulners") or {}
    if vul.get("ok"):
        if not merged["description"] and vul.get("description"):
            merged["description"] = vul["description"]
        if not merged["cvss_score"] and vul.get("cvss_score"):
            merged["cvss_score"] = vul["cvss_score"]
        if vul.get("poc_refs"):
            merged["poc_available"] = True
            merged["references"] = list({*merged["references"], *vul["poc_refs"]})
        if vul.get("notes"):
            merged["advisory_notes"] += f"\n\nVulners: {vul['notes'][:400]}"
    return merged
