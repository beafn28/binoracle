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
        "startup_wait": 15,
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
        },
        "cmd": None,
        "startup_wait": 20,
        "health_path": "/server/health",
    },
    "advplyr/audiobookshelf:": {
        "port": 3000,
        "envs": {},
        "cmd": None,
        "startup_wait": 10,
        "health_path": "/healthcheck",
    },
    "daptin/daptin:": {
        "port": 6336,
        "envs": {},
        "cmd": None,
        "startup_wait": 10,
        "health_path": "/",
    },
    # needs postgres — cannot run standalone; LLM must handle it
    "mattermost/mattermost-team-edition:": None,
    # needs docker-compose with elasticsearch and other services
    "openmetadata/server:": None,
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
