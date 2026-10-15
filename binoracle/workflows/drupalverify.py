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

from .wpverify import (WpVerifyResult, _docker_daemon_ok, _lab_host, _pick_param, _token,
                       _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS)

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
    rechaza silenciosamente. Devuelve una requests.Session logueada (cookie SESS*/SSESS* presente)
    o None si el login fallo."""
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
        payload = dict(params) if isinstance(params, dict) else {p: "" for p in (params or [])}
        if id_p:
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
