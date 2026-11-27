"""Known Docker image profiles — auto-generate Dockerfiles from image name.

Each profile is keyed by an image prefix (without the tag).  When the engine
finds a CVE whose llm_notes has docker_image set but no dockerfile_body, it
calls dockerfile_from_profile() to get a full ready-to-build Dockerfile
(with ENV, EXPOSE, CMD) instead of a bare FROM line.

Profiles that require an external database (mattermost) or docker-compose
(openmetadata) return None; the caller falls back to the bare FROM line and
lets the LLM handle it.
"""
from __future__ import annotations

_DOCKER_IMAGE_PROFILES: dict[str, dict] = {
    "ghost:": {
        "port": 2368,
        "envs": {
            "database__client": "sqlite3",
            "database__connection__filename": "/var/lib/ghost/content/data/ghost.db",
            "url": "http://localhost:2368",
            "NODE_ENV": "development",
            "server__host": "0.0.0.0",
        },
        "cmd": None,
        "startup_wait": 25,
        "health_path": "/ghost/api/admin/site/",
    },
    "ghcr.io/zitadel/zitadel:": {
        "port": 8080,
        "envs": {
            "ZITADEL_MASTERKEY": "MasterkeyNeedsToHave32Characters",
            "ZITADEL_DATABASE_SQLITE_HOST": "/tmp/zitadel.db",
            "ZITADEL_EXTERNALPORT": "8080",
            "ZITADEL_EXTERNALDOMAIN": "localhost",
            "ZITADEL_EXTERNALSECURE": "false",
        },
        "cmd": ["start-from-init", "--tlsMode", "disabled"],
        "startup_wait": 20,
        "health_path": "/debug/healthz",
    },
    "directus/directus:": {
        "port": 8055,
        "envs": {
            "SECRET": "binoracle-secret-key",
            "ADMIN_EMAIL": "admin@example.com",
            "ADMIN_PASSWORD": "BinOracle123!",
            "DB_CLIENT": "sqlite3",
            "DB_FILENAME": "/directus/database/data.db",
            # Allow IPv4-mapped IPv6 addresses in file import (needed for SSRF lab)
            "IMPORT_IP_DENY_LIST": "",
        },
        "cmd": None,
        "startup_wait": 30,
        "health_path": "/server/health",
    },
    "advplyr/audiobookshelf:": {
        "port": 3000,
        "envs": {},
        "cmd": None,
        "startup_wait": 20,
        "health_path": "/healthcheck",
    },
    "daptin/daptin:": {
        "port": 6336,
        "envs": {},
        "cmd": None,
        "startup_wait": 10,
        "health_path": "/",
    },
    "dpage/pgadmin4:": {
        "port": 80,
        "envs": {
            "PGADMIN_DEFAULT_EMAIL": "admin@example.com",
            "PGADMIN_DEFAULT_PASSWORD": "BinOracle123!",
            # Disable external process spawning restrictions for lab (needed for SMTP test injection)
            "PGADMIN_CONFIG_CHECK_EMAIL_DELIVERABILITY": "False",
        },
        "cmd": None,
        "startup_wait": 30,
        "health_path": "/misc/ping",
    },
    # needs postgres — cannot run standalone; LLM must handle it
    "mattermost/mattermost-team-edition:": None,
    # needs docker-compose with elasticsearch and other services
    "openmetadata/server:": None,
    # --- Drupal (PHP CMS) ---
    "drupal:": {
        "port": 80,
        "envs": {
            "MYSQL_ROOT_PASSWORD": "binoracle",
            "MYSQL_DATABASE": "drupal",
        },
        "cmd": None,
        "startup_wait": 20,
        "health_path": "/",
        "note": "needs mysql sidecar; LLM uses docker-compose for drupal+mysql",
    },
    # standalone drupal with SQLite (simpletest profile)
    "drupal/recommended-project": None,
    # --- CraftCMS ---
    "craftcms/craft:": {
        "port": 8080,
        "envs": {
            "CRAFT_APP_ID": "CraftCMS--binoracle",
            "CRAFT_SECURITY_KEY": "binoracle-secret-key-for-craft",
            "CRAFT_DB_DRIVER": "mysql",
            "DB_SERVER": "localhost",
            "DB_DATABASE": "craft",
            "DB_USER": "root",
            "DB_PASSWORD": "binoracle",
            "CRAFT_ALLOW_ADMIN_CHANGES": "true",
        },
        "cmd": None,
        "startup_wait": 25,
        "health_path": "/",
        "note": "needs mysql sidecar; use docker-compose",
    },
    # --- Strapi (Node.js headless CMS) ---
    "strapi/strapi:": {
        "port": 1337,
        "envs": {
            "DATABASE_CLIENT": "sqlite",
            "DATABASE_FILENAME": "/tmp/.tmp/data.db",
            "JWT_SECRET": "binoracle-jwt-secret",
            "APP_KEYS": "binoracle-key1,binoracle-key2",
            "API_TOKEN_SALT": "binoracle-token-salt",
            "ADMIN_JWT_SECRET": "binoracle-admin-jwt",
            "STRAPI_DISABLE_STARTUP_MESSAGE": "true",
        },
        "cmd": None,
        "startup_wait": 120,
        "health_path": "/",
    },
    # --- Paperless-ngx (Django-based DMS) ---
    "ghcr.io/paperless-ngx/paperless-ngx:": {
        "port": 8000,
        "envs": {
            "PAPERLESS_SECRET_KEY": "binoracle-secret-key-for-paperless",
            "PAPERLESS_URL": "http://localhost:8000",
            "PAPERLESS_CSRF_TRUSTED_ORIGINS": "http://localhost:8000",
            "PAPERLESS_ADMIN_USER": "admin",
            "PAPERLESS_ADMIN_PASSWORD": "BinOracle123!",
            "PAPERLESS_REDIS": "",
            "PAPERLESS_DBENGINE": "sqlite",
            "PAPERLESS_DBNAME": "/tmp/paperless.db",
            "PAPERLESS_ENABLE_HTTP_REMOTE_USER": "True",
            "PAPERLESS_HTTP_REMOTE_USER_HEADER_NAME": "HTTP_REMOTE_USER",
        },
        "cmd": None,
        "startup_wait": 120,
        "health_path": "/api/",
    },
    # --- Etherpad collaborative editor ---
    "etherpad/etherpad:": {
        "port": 9001,
        "envs": {"NODE_ENV": "production"},
        "cmd": None,
        "startup_wait": 25,
        "health_path": "/",
    },
    # --- Apache HTTP Server (generic) ---
    # Note: CVE-specific configs (AllowOverride etc.) should be in dockerfile_body
    "httpd:": {
        "port": 80,
        "envs": {},
        "cmd": None,
        "startup_wait": 5,
        "health_path": "/",
    },
    # --- Gradio (Python ML web UI) ---
    "gradio/gradio:": {
        "port": 7860,
        "envs": {
            "GRADIO_SERVER_PORT": "7860",
            "GRADIO_SERVER_NAME": "0.0.0.0",
        },
        "cmd": None,
        "startup_wait": 15,
        "health_path": "/",
    },
    # --- Generic Python app (Flask/FastAPI/aiohttp etc.) ---
    # Minimal profile; dockerfile_body in the CVE JSON should provide the CMD.
    # Matches python:3.x, python:3.x-slim, python:3.x-alpine etc.
    "python:": {
        "port": 5000,
        "envs": {},
        "cmd": None,
        "startup_wait": 10,
        "health_path": "/",
    },
    # --- WordPress (PHP CMS) — standalone via php:apache + SQLite3 (no MySQL sidecar) ---
    # The official wordpress:latest image requires MySQL; this profile uses php:8.1-apache
    # with a minimal WP REST API emulator so missing-auth labs run without a sidecar.
    # Qwen can override with a richer Dockerfile via dockerfile_body in the CVE JSON.
    "wordpress:": {
        "port": 80,
        "startup_wait": 8,
        "health_path": "/wp-json/",
        "dockerfile": (
            "FROM php:8.1-apache\n"
            "RUN docker-php-ext-install pdo_sqlite 2>/dev/null || true && \\\n"
            "    a2enmod rewrite\n"
            # Minimal WP REST dispatcher: handles /wp-json/<ns>/v<n>/<path>
            "RUN printf '<?php\\n"
            "header(\"Content-Type: application/json\");\\n"
            "header(\"Access-Control-Allow-Origin: *\");\\n"
            "$uri = parse_url($_SERVER[\"REQUEST_URI\"], PHP_URL_PATH);\\n"
            "if ($uri === \"/wp-json/\" || $uri === \"/wp-json\") {\\n"
            "  echo json_encode([\"name\"=>\"BinOracle WP Lab\",\"description\"=>\"lab\","
            "\"url\"=>\"http://localhost\",\"home\"=>\"http://localhost\","
            "\"namespaces\"=>[\"lab/v1\"]]);\\n"
            "  exit;\\n"
            "}\\n"
            "// Plugin route stubs go in /var/www/html/wp-content/plugins/lab/routes.php\\n"
            "$routes_file = __DIR__.\"/wp-content/plugins/lab/routes.php\";\\n"
            "if (file_exists($routes_file)) { require $routes_file; exit; }\\n"
            "http_response_code(404);\\n"
            "echo json_encode([\"code\"=>\"rest_no_route\",\"message\"=>\"No route found\","
            "\"data\"=>[\"status\"=>404]]);\\n"
            "' > /var/www/html/index.php\n"
            # .htaccess: route everything through index.php
            "RUN printf '<IfModule mod_rewrite.c>\\n"
            "RewriteEngine On\\n"
            "RewriteCond %%{REQUEST_FILENAME} !-f\\n"
            "RewriteRule ^ index.php [L]\\n"
            "</IfModule>\\n"
            "' > /var/www/html/.htaccess\n"
            "RUN mkdir -p /var/www/html/wp-content/plugins/lab\n"
            "EXPOSE 80\n"
            'CMD ["apache2-foreground"]\n'
        ),
        "envs": {},
        "cmd": None,
    },
    # --- Rack/Ruby web apps ---
    "ruby:": {
        "port": 9292,
        "envs": {
            "RACK_ENV": "production",
        },
        "cmd": None,
        "startup_wait": 10,
        "health_path": "/",
    },
    # --- Node.js apps (Express, Hono, etc.) ---
    "node:": {
        "port": 3000,
        "envs": {
            "NODE_ENV": "production",
            "PORT": "3000",
        },
        "cmd": None,
        "startup_wait": 10,
        "health_path": "/",
    },
    # --- Gradio Python apps ---
    "gradio:": {
        "port": 7860,
        "startup_wait": 30,
        "health_path": "/",
        "dockerfile": (
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            'RUN pip install --no-cache-dir "gradio=={VERSION}"\n'
            "RUN printf 'import gradio as gr\\n"
            "demo = gr.Interface(fn=lambda x: x, inputs=[\"text\"], outputs=[\"text\"])\\n"
            "demo.launch(server_name=\"0.0.0.0\", server_port=7860)\\n' "
            "> /app/app.py\n"
            "EXPOSE 7860\n"
            'CMD ["python", "/app/app.py"]\n'
        ),
        "envs": {},
        "cmd": None,
    },
}


def _match_profile(docker_image: str) -> dict | None:
    """Return the profile dict (or None) for the given image string."""
    for prefix, profile in _DOCKER_IMAGE_PROFILES.items():
        if docker_image.startswith(prefix):
            return profile
    return None


def dockerfile_from_profile(docker_image: str, port: int | None = None) -> str | None:
    """Generate a full Dockerfile for a known image.

    Returns None when the image is unknown or requires external services
    (the caller should fall back to a bare FROM line).
    """
    profile = _match_profile(docker_image)
    if profile is None:
        return None

    # If the profile has a full custom Dockerfile template, use it directly.
    if "dockerfile" in profile:
        # Extract version from docker_image (e.g. "gradio:4.19.1" → "4.19.1")
        version = docker_image.split(":", 1)[1] if ":" in docker_image else "latest"
        return profile["dockerfile"].replace("{VERSION}", version)

    effective_port = port or profile["port"]
    lines: list[str] = [f"FROM {docker_image}"]
    for k, v in (profile.get("envs") or {}).items():
        lines.append(f"ENV {k}={v}")
    if effective_port:
        lines.append(f"EXPOSE {effective_port}")
    cmd = profile.get("cmd")
    if cmd:
        args = ", ".join(f'"{c}"' for c in cmd)
        lines.append(f"CMD [{args}]")
    return "\n".join(lines) + "\n"


def setup_cmds_from_profile(docker_image: str) -> list[str] | None:
    """Return standard setup_cmds (sleep + health check) for a known image."""
    profile = _match_profile(docker_image)
    if profile is None:
        return None

    wait = profile.get("startup_wait", 10)
    port = profile.get("port", 80)
    health = profile.get("health_path", "/")
    return [
        f"sleep {wait}",
        f"curl -sf http://localhost:{port}{health} || true",
    ]


def port_from_profile(docker_image: str) -> int | None:
    """Return the container port for a known image, or None."""
    profile = _match_profile(docker_image)
    if profile is None:
        return None
    return profile.get("port")
