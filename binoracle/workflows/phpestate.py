"""PHP exposure/triage: inventory and classify installed/exposed PHP interpreters against PHP's
OWN release data -- EOL / BEHIND / CURRENT. Defensive only: this is NOT an exploit tool and never
will be for this specific trigger, because there is nothing publishable to build against yet.

Why this exists (2026-10-21): PHP's security team announced, via php.net's own archive feed
(https://www.php.net/archive/2026.php, "Upcoming Critical PHP Security Release", dated 20 Oct
2026), two critical core vulnerabilities nicknamed "php2shell" in the wild -- CVE-2026-109618 and
CVE-2026-109619, each pre-announced CVSS v4.0 9.2 -- with a security release scheduled for
Wednesday 21 October 2026 at 14:00 UTC. Confirmed independently, by hand, the same day this module
was written: the php.net advance notice gives NO root cause, NO affected-version range, and NO
fixed-version number ("With the release, we will publish ... further details"); `cveawg.mitre.org`'s
own API returns `CVE_RECORD_DNE` for both IDs (RESERVED, no description). Several public GitHub
repos already claim working PoCs for these IDs; independent review found strong evidence those are
fake/bait (internal inconsistencies, claims contradicting the official unpublished status, anomalous
star/fork ratios for day-old repos) -- this module does not fetch, trust, or reproduce anything from
them, and does not guess at the root cause to fill the gap. Guessing at a mechanism that isn't
published yet would be exactly the overclaiming this project's whole philosophy forbids (see
`versions.py`'s and `wpverify.py`'s docstrings: grounded over generated, never claim more than you
can prove). So: no exploit code, no trigger script, no payload for CVE-2026-109618/109619 -- only
the same honest, pre-CVE hygiene question this project already asks for other components in
`versions.py` (OWASP DA9): "is this installation's version old enough that it is exposed to
WHATEVER comes out of the next security release, known or not yet known?".

Three pieces, same "no false positives by construction" standard as the rest of binoracle:

1. Local detection (`scan_php_local`): find real `php`/`phpX.Y` interpreters under given root
   paths (or common install layouts if none given), run `php -v` against each one -- the REAL
   installed version, not a guess from a package manager's metadata -- and classify it against
   PHP's own live release feed (see `fetch_live_release_data`; confirmed real and reachable while
   writing this module, see ROADMAP.md). If the live feed cannot be reached, falls back to a
   small, clearly-labelled, date-stamped static table (same "umbral conservador" honesty as
   `versions.py`: it WILL go stale, and says so in every finding it produces from it).

2. Remote detection (`fingerprint_php_remote`): OPTIONAL, and gated behind an explicit
   `authorized=True` the caller must pass before a single byte is sent -- no request is built,
   let alone sent, otherwise. This mirrors every live-verification module in this project
   (`wpverify.py`, `drupalverify.py`, `genericverify.py`): those require an explicit, reachable
   Docker daemon before touching anything, because this project never tests systems the operator
   has not confirmed authorization for. Sends exactly ONE passive GET to the given URL and reads
   only standard response headers/cookies (`Server`, `X-Powered-By`, `Set-Cookie`) already sent to
   every ordinary visitor -- never a crafted path, parameter, or payload, and never more than one
   request.

3. Classification (`classify_php_version`): three honest buckets, EOL / BEHIND / CURRENT, plus a
   fourth, UNKNOWN, for "no data available, don't pretend otherwise" -- used when a branch is
   neither confirmed-supported nor confirmed-EOL by whichever data source answered. Every negative
   or inconclusive result says in its own rationale why it is NOT proof of absence: `expose_php =
   Off` (the officially recommended setting) and CDN/WAF header stripping both produce the exact
   same "no PHP signal in headers" result as a target that genuinely runs no PHP at all.

Output is `Finding` (not `WpVerifyResult`): this module never runs or verifies an exploit attempt
against a live target -- a `WpVerifyResult.verified` flag would be a lie here, since there is
nothing to execute end-to-end yet. It is a static inventory/classification tool, the same shape as
`versions.py`'s OWASP DA9 scanner, just sourced from a real host/HTTP response instead of binary
strings.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from ..store.session import Finding

# --- version parsing -------------------------------------------------------------------------

# "PHP 8.2.12 (cli) (built: ...) ( NTS )" -- also matches inside a Server/X-Powered-By header
# ("PHP/8.2.12"), which is why this is intentionally permissive about the separator.
_PHP_VERSION_RE = re.compile(r"PHP[/ ]([0-9]+)\.([0-9]+)\.([0-9]+)", re.I)
_SERVER_PHP_RE = re.compile(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)


def _parse_version_str(s: str) -> Optional[Tuple[int, int, int]]:
    m = re.match(r"^([0-9]+)\.([0-9]+)\.([0-9]+)", s or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


# --- local detection --------------------------------------------------------------------------

_COMMON_PATH_NAMES = ["php", "php8.5", "php8.4", "php8.3", "php8.2", "php8.1", "php8.0", "php7.4"]
_COMMON_ABS_PATHS = [
    "/usr/bin/php", "/usr/local/bin/php",
    "/opt/homebrew/bin/php", "/opt/homebrew/opt/php/bin/php",
    "/usr/bin/php8.5", "/usr/bin/php8.4", "/usr/bin/php8.3", "/usr/bin/php8.2",
    "/usr/bin/php8.1", "/usr/bin/php7.4",
]
# Nombre de archivo que cuenta como "candidato PHP" al recorrer una ruta dada: 'php', 'php8',
# 'php8.2', 'php-cli' -- NO 'phpize'/'php-config' (herramientas de build, no interpretes) ni
# cualquier cosa que solo contenga 'php' como substring (evita falsos positivos como
# 'myphpscript.sh').
_VERSIONED_NAME_RE = re.compile(r"^php([0-9]+(\.[0-9]+)?)?(-cli)?$")
_SKIP_DIR_NAMES = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", ".svn"}
# Profundidad acotada: recorrer una raiz arbitraria (p.ej. "/") sin limite es tanto lento como un
# riesgo de recorrer arboles gigantes sin motivo; 3 niveles cubre layouts habituales
# (<root>/bin/php, <root>/usr/bin/php, <root>/opt/<algo>/bin/php) sin degenerar en un `find /`.
_MAX_WALK_DEPTH = 3


def find_php_binaries(paths: Optional[Sequence[str]] = None) -> List[str]:
    """Busca interpretes PHP reales. Sin `paths`: PATH + rutas comunes de instalacion (Linux/
    Homebrew). Con `paths`: cada entrada es un binario directo (si es un fichero ejecutable) o una
    raiz bajo la que buscar (recorrido acotado a `_MAX_WALK_DEPTH`, ignorando directorios de
    dependencias/VCS). Deduplicado por ruta real (un symlink y su destino cuentan una sola vez)."""
    found: List[str] = []
    if not paths:
        for name in _COMMON_PATH_NAMES:
            p = shutil.which(name)
            if p:
                found.append(p)
        for p in _COMMON_ABS_PATHS:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                found.append(p)
        return _dedupe_by_realpath(found)

    for root in paths:
        if os.path.isfile(root):
            if os.access(root, os.X_OK):
                found.append(root)
            continue
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
            # a _MAX_WALK_DEPTH limite se sigue examinando (p.ej. <root>/usr/local/bin, depth 3,
            # es exactamente donde vive un binario real) -- solo se deja de DESCENDER mas alla.
            if depth >= _MAX_WALK_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
            for fn in filenames:
                if _VERSIONED_NAME_RE.match(fn):
                    fp = os.path.join(dirpath, fn)
                    if os.access(fp, os.X_OK):
                        found.append(fp)
    return _dedupe_by_realpath(found)


def _dedupe_by_realpath(items: Sequence[str]) -> List[str]:
    seen = set()
    out = []
    for i in items:
        rp = os.path.realpath(i)
        if rp in seen:
            continue
        seen.add(rp)
        out.append(i)
    return out


def probe_php_version(php_bin: str, timeout: float = 8.0) -> Optional[Tuple[Tuple[int, int, int], str]]:
    """Ejecuta `<php_bin> -v` DE VERDAD (no se infiere de metadata de paquete) y extrae la version
    real. None si el binario no corre, no responde a tiempo, o su salida no contiene una linea
    'PHP X.Y.Z' reconocible (candidato encontrado por nombre que no resulto ser PHP real)."""
    try:
        r = subprocess.run([php_bin, "-v"], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    combined = (r.stdout or "") + "\n" + (r.stderr or "")
    m = _PHP_VERSION_RE.search(combined)
    if not m:
        return None
    version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return version, combined.strip()


# --- classification against PHP's own release data -------------------------------------------

# Confirmado real y alcanzable a mano (curl) el 2026-10-21, mismo dia de este modulo: este
# endpoint es el que php.net sirve para sus propias paginas de "ultima version" -- JSON real, no
# HTML a parsear. `?json&version=<major.minor>` devuelve la ULTIMA release de esa rama concreta
# (campo "version") y la lista de ramas actualmente soportadas (campo "supported_versions",
# IGUAL para cualquier rama 8.x consultada -- confirmado pidiendo 8.1 y 8.0: ambas devuelven el
# mismo supported_versions ['8.2','8.3','8.4','8.5'] sin la propia rama pedida dentro, que es
# exactamente la senal de EOL que se necesita). Rama EOL antigua (7.4) devuelve
# supported_versions=[] en vez de fallar -- tambien grounded, no un error.
_RELEASE_FEED_URL = "https://www.php.net/releases/index.php?json&version={branch}"


def fetch_live_release_data(branch: str, timeout: float = 8.0) -> Optional[dict]:
    """Devuelve el dict crudo del feed de php.net para `branch` ('8.2', '7.4', ...), o None ante
    CUALQUIER fallo (red, HTTP != 200, JSON invalido, forma inesperada) -- degrada honestamente,
    el caller cae al fallback estatico en vez de romper o inventar un dato."""
    import urllib.request
    url = _RELEASE_FEED_URL.format(branch=branch)
    req = urllib.request.Request(url, headers={"User-Agent": "binoracle (authorized research)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            raw = resp.read()
    except Exception:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict) or "version" not in data:
        return None
    return data


# Fallback estatico: confirmado a mano contra el archivo propio de php.net
# (https://www.php.net/archive/2026.php) el 2026-10-21. Igual que el "umbral conservador" de
# `versions.py`: esto SE QUEDARA ANTICUADO con el tiempo (la propia tabla lo dice en cada
# Finding que produce desde aqui) -- se usa solo cuando el feed en vivo no es alcanzable.
_STATIC_AS_OF = "2026-09-24"
_STATIC_LATEST: Dict[str, str] = {
    "8.2": "8.2.34",
    "8.3": "8.3.35",
    "8.4": "8.4.26",
    "8.5": "8.5.11",
}
# Confirmado en vivo contra el feed real: toda rama < 8.2 (8.1, 8.0, 7.4, ...) ya aparecia fuera
# de supported_versions el 2026-10-21 -- umbral conservador analogo al de versions.py, no una
# certeza indefinida (una rama 8.2..8.5 de la que este modulo aun no tenga el ultimo parche
# exacto cae en UNKNOWN, nunca se asume CURRENT ni EOL sin dato).
_STATIC_EOL_THRESHOLD = (8, 2)

_SEVERITY_FOR_BUCKET = {"EOL": "high", "BEHIND": "medium", "CURRENT": "info", "UNKNOWN": "info"}


def classify_php_version(version: Tuple[int, int, int], feed: Optional[dict]) -> Tuple[str, str, str]:
    """Clasifica `version` (tupla major, minor, patch) en EOL / BEHIND / CURRENT / UNKNOWN.
    Devuelve (bucket, nota_explicativa, fuente_usada). `feed` es el dict ya obtenido de
    `fetch_live_release_data` (o None si no fue alcanzable -- entonces usa el fallback estatico)."""
    branch = f"{version[0]}.{version[1]}"
    vstr = ".".join(str(x) for x in version)

    if feed is not None:
        source = "php.net live release feed"
        supported = feed.get("supported_versions") or []
        if branch not in supported:
            return ("EOL",
                     f"PHP {branch}.x is not in php.net's currently supported branch list "
                     f"({', '.join(supported) if supported else 'none'}); it no longer receives "
                     "official security fixes.", source)
        latest = _parse_version_str(feed.get("version", ""))
        if latest and version < latest:
            return ("BEHIND",
                     f"PHP {vstr} is behind the latest {branch}.x security release, "
                     f"{feed.get('version')}.", source)
        return ("CURRENT",
                 f"PHP {vstr} matches (or exceeds) the latest known {branch}.x release, "
                 f"{feed.get('version')}.", source)

    source = f"static fallback table (php.net archive, as of {_STATIC_AS_OF}; live feed " \
             "unreachable, may be stale)"
    if version[:2] < _STATIC_EOL_THRESHOLD:
        return ("EOL",
                 f"PHP {branch}.x was already outside php.net's supported-branch list as of "
                 f"{_STATIC_AS_OF}; it no longer receives official security fixes.", source)
    latest_str = _STATIC_LATEST.get(branch)
    if latest_str is None:
        return ("UNKNOWN",
                 f"PHP {branch}.x is not covered by this tool's fallback table (last refreshed "
                 f"{_STATIC_AS_OF}), and the live php.net feed could not be reached to check it "
                 "directly. Treat this as inconclusive, not as 'current'.", source)
    latest = _parse_version_str(latest_str)
    if latest and version < latest:
        return ("BEHIND",
                 f"PHP {vstr} is behind the known {branch}.x release {latest_str} as of "
                 f"{_STATIC_AS_OF}.", source)
    return ("CURRENT",
             f"PHP {vstr} matched or exceeded the known {branch}.x release {latest_str} as of "
             f"{_STATIC_AS_OF}.", source)


def _recommendation_for(bucket: str, es: bool) -> str:
    if bucket == "EOL":
        return ("Esta rama ya no recibe parches de seguridad oficiales: actualiza a una rama "
                "soportada (ver https://www.php.net/supported-versions.php) cuanto antes." if es
                else "This branch no longer receives official security patches: upgrade to a "
                "supported branch (see https://www.php.net/supported-versions.php) as soon as "
                "possible.")
    if bucket == "BEHIND":
        return ("Actualiza al ultimo parche de la misma rama -- no hace falta cambiar de version "
                "mayor, solo aplicar el parche de seguridad mas reciente." if es else
                "Update to the latest patch release of the same branch -- no major-version change "
                "needed, just the most recent security patch.")
    if bucket == "CURRENT":
        return ("Nada que hacer ahora; vuelve a comprobar tras cada aviso de seguridad de PHP "
                "(incluido el anunciado para el 2026-10-21)." if es else
                "Nothing to do right now; re-check after each PHP security advisory (including "
                "the one announced for 2026-10-21).")
    return ("No se pudo clasificar con los datos disponibles; comprueba manualmente contra "
            "https://www.php.net/supported-versions.php." if es else
            "Could not classify with the data available; check manually against "
            "https://www.php.net/supported-versions.php.")


# --- Finding-producing entry points ------------------------------------------------------------


def scan_php_local(paths: Optional[Sequence[str]] = None, lang: str = "es") -> List[Finding]:
    """Inventario local: encuentra interpretes PHP reales bajo `paths` (o layouts comunes si no
    se da ninguno), ejecuta `php -v` de verdad en cada uno, y clasifica la version real contra el
    feed en vivo de php.net (con fallback estatico honesto). Nunca afirma un CVE concreto -- igual
    que `versions.py`, solo senala version antigua/al dia para que el analista lo contraste con el
    aviso de seguridad correspondiente."""
    es = lang == "es"
    findings: List[Finding] = []
    binaries = find_php_binaries(paths)

    if not binaries:
        findings.append(Finding(
            title=("No se encontro ningun interprete PHP" if es else "No PHP interpreter found"),
            severity="info", verdict="grounded",
            location=", ".join(paths) if paths else "PATH / rutas comunes",
            evidence="busqueda en: " + (", ".join(paths) if paths
                      else "PATH, " + ", ".join(_COMMON_ABS_PATHS)),
            rationale=("No se hallo ningun binario 'php'/'phpX.Y' ejecutable en las rutas dadas. "
                       "Esto NO prueba que PHP no este instalado: puede estar en una ruta no "
                       "cubierta, dentro de un contenedor no inspeccionado, o detras de un "
                       "wrapper con otro nombre." if es else
                       "No executable 'php'/'phpX.Y' binary was found in the given paths. This "
                       "does NOT prove PHP is absent: it may live in an uncovered path, inside an "
                       "uninspected container, or behind a differently-named wrapper."),
            recommendation=("Indica rutas explicitas (p.ej. la raiz de un contenedor montado) si "
                            "sabes donde vive PHP." if es else
                            "Pass explicit paths (e.g. a mounted container root) if you know "
                            "where PHP lives."),
        ))
        return findings

    for b in binaries:
        probed = probe_php_version(b)
        if probed is None:
            findings.append(Finding(
                title=(f"No se pudo determinar la version de {b}" if es else
                       f"Could not determine the version of {b}"),
                severity="info", verdict="unverified", location=b,
                evidence=f"`{b} -v` no devolvio una linea 'PHP X.Y.Z' reconocible, o el binario "
                         "no se pudo ejecutar.",
                rationale=("El candidato se encontro por nombre pero no se confirmo que sea un "
                           "interprete PHP real." if es else
                           "The candidate was found by name but was not confirmed to be a real "
                           "PHP interpreter."),
                recommendation=("Revisa el binario manualmente." if es else
                                "Inspect the binary manually."),
            ))
            continue

        version, raw = probed
        vstr = ".".join(str(x) for x in version)
        branch = f"{version[0]}.{version[1]}"
        feed = fetch_live_release_data(branch)
        bucket, note, source = classify_php_version(version, feed)
        findings.append(Finding(
            title=(f"PHP {vstr} en {b}: {bucket}" if es else f"PHP {vstr} at {b}: {bucket}"),
            severity=_SEVERITY_FOR_BUCKET[bucket], verdict="grounded", location=b,
            evidence=f"[{b} -v]\n{raw}\n\n" + ("clasificado contra: " if es else
                      "classified against: ") + f"{source}\n{note}",
            rationale=note,
            recommendation=_recommendation_for(bucket, es),
        ))
    return findings


def fingerprint_php_remote(url: str, authorized: bool = False, timeout: float = 10.0,
                            lang: str = "es") -> List[Finding]:
    """Huella PASIVA remota, OPCIONAL: requiere `authorized=True` explicito antes de construir o
    enviar ni una sola peticion -- si no se da, esta funcion vuelve de inmediato sin tocar la red.
    Con autorizacion, envia EXACTAMENTE una peticion GET pasiva y lee solo cabeceras/cookies
    estandar ('Server', 'X-Powered-By', 'Set-Cookie') que el servidor ya envia a cualquier
    visitante -- nunca una ruta, parametro o payload fabricado, y nunca mas de una peticion.
    Nunca pruebes sistemas sin autorizacion explicita: binoracle solo ejecuta cosas de verdad
    contra laboratorios efimeros que el propio operador controla (ver wpverify.py); esto extiende
    el mismo estandar a un objetivo HTTP arbitrario."""
    es = lang == "es"
    if not authorized:
        return [Finding(
            title=("Huella remota omitida: falta --authorized" if es else
                   "Remote fingerprint skipped: --authorized not set"),
            severity="info", verdict="grounded", location=url, evidence="",
            rationale=("binoracle nunca envia una peticion de red a un sistema sin que el "
                       "operador confirme explicitamente autorizacion para probarlo -- ni una "
                       "sola peticion se construyo ni se envio para llegar a este mensaje; mismo "
                       "patron que los verificadores dinamicos de este proyecto exigen un Docker "
                       "daemon explicito en vez de asumir consentimiento." if es else
                       "binoracle never sends a network request to a system without the "
                       "operator explicitly confirming authorization to test it -- no request "
                       "was built or sent to reach this message; same pattern as this project's "
                       "dynamic verifiers requiring an explicit Docker daemon instead of "
                       "assuming consent."),
            recommendation=("Vuelve a ejecutar con autorizacion explicita una vez confirmada." if es
                            else "Re-run with explicit authorization once confirmed."),
        )]

    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "binoracle (authorized research)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.getheaders())
            status = resp.status
    except Exception as e:
        return [Finding(
            title=("Huella remota: peticion fallida" if es else
                   "Remote fingerprint: request failed"),
            severity="info", verdict="unverified", location=url,
            evidence=f"{type(e).__name__}: {e}",
            rationale=("La peticion GET pasiva unica no se completo; no se puede concluir nada "
                       "sobre la version de PHP del objetivo." if es else
                       "The single passive GET request did not complete; nothing can be "
                       "concluded about the target's PHP version."),
            recommendation=("Confirma que la URL es alcanzable y reintenta." if es else
                            "Confirm the URL is reachable and retry."),
        )]

    server = headers.get("Server", "")
    xpowered = headers.get("X-Powered-By", "")
    set_cookie = headers.get("Set-Cookie", "")
    has_phpsessid = "PHPSESSID" in set_cookie
    m = _SERVER_PHP_RE.search(f"{server} {xpowered}")

    evidence = (f"GET {url} -> HTTP {status}\nServer: {server}\nX-Powered-By: {xpowered}\n"
                f"Set-Cookie: {'(PHPSESSID present)' if has_phpsessid else (set_cookie or '(none)')}")

    findings: List[Finding] = []
    if m:
        version = _parse_version_str(m.group(1) if m.group(1).count(".") == 2 else m.group(1) + ".0")
        branch = f"{version[0]}.{version[1]}"
        feed = fetch_live_release_data(branch)
        bucket, note, source = classify_php_version(version, feed)
        vstr = m.group(1)
        header_caveat = (" Version tomada de una cabecera HTTP que el propio servidor remoto "
                         "declara -- no verificada de forma independiente; un servidor "
                         "modificado o un proxy delante de el pueden declarar una version "
                         "distinta de la real." if es else
                         " Version taken from an HTTP header the remote server itself declares "
                         "-- not independently verified; a modified server or a proxy in front "
                         "of it can declare a version different from the real one.")
        findings.append(Finding(
            title=(f"PHP {vstr} anunciado por {url}: {bucket}" if es else
                   f"PHP {vstr} advertised by {url}: {bucket}"),
            severity=_SEVERITY_FOR_BUCKET[bucket], verdict="grounded", location=url,
            evidence=evidence + "\n\n" + ("clasificado contra: " if es else
                      "classified against: ") + f"{source}\n{note}",
            rationale=note + header_caveat,
            recommendation=_recommendation_for(bucket, es),
        ))
    else:
        findings.append(Finding(
            title=("Sin version de PHP visible en las cabeceras" if es else
                   "No PHP version visible in headers"),
            severity="info", verdict="grounded", location=url, evidence=evidence,
            rationale=("Ninguna cabecera observada ('Server', 'X-Powered-By') declara una "
                       "version de PHP. Esto NO prueba que el objetivo no use PHP ni que no sea "
                       "vulnerable: 'expose_php=Off' (la configuracion recomendada por PHP "
                       "mismo), una CDN/WAF que elimina cabeceras, o un framework que las "
                       "sobreescribe producen exactamente el mismo resultado negativo." if es else
                       "No observed header ('Server', 'X-Powered-By') declares a PHP version. "
                       "This does NOT prove the target doesn't run PHP or isn't vulnerable: "
                       "'expose_php=Off' (PHP's own recommended setting), a CDN/WAF stripping "
                       "headers, or a framework overriding them all produce this exact same "
                       "negative result."),
            recommendation=("No se puede clasificar por este metodo; usa otra senal (rutas "
                            "conocidas tipo /index.php, cookies de framework) si necesitas mas "
                            "certeza." if es else
                            "This method cannot classify the target; use another signal (known "
                            "PHP-specific paths, framework cookies) if you need more certainty."),
        ))
        if has_phpsessid:
            findings.append(Finding(
                title=("Cookie PHPSESSID observada (sin version)" if es else
                       "PHPSESSID cookie observed (no version)"),
                severity="info", verdict="grounded", location=url,
                evidence="Set-Cookie contiene 'PHPSESSID'",
                rationale=("La presencia de una cookie 'PHPSESSID' es un indicio (no una prueba) "
                           "de que el backend corre PHP con sesiones nativas; no revela la "
                           "version." if es else
                           "A 'PHPSESSID' cookie is a hint (not proof) that the backend runs PHP "
                           "with native sessions; it reveals nothing about the version."),
                recommendation="",
            ))
    return findings


def run_phpestate(paths: Optional[Sequence[str]] = None, url: str = "", authorized: bool = False,
                   lang: str = "es") -> List[Finding]:
    """Punto de entrada combinado para el CLI: inventario local siempre; huella remota solo si se
    da `url` (y, dentro de ella, solo si `authorized=True`)."""
    findings = scan_php_local(paths, lang=lang)
    if url:
        findings += fingerprint_php_remote(url, authorized=authorized, lang=lang)
    return findings
