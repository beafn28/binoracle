"""Image-aware authentication for Docker lab CVEs.

Provides login_to_app() which dispatches to the right auth strategy for a
known Docker image, returning auth headers ready to inject into exploit requests.
Credentials come from docker_profiles._DOCKER_IMAGE_PROFILES to stay DRY.
"""
from __future__ import annotations

import json as _json
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _post_json(url: str, body: dict, timeout: int = 10) -> tuple[int, dict, dict]:
    """Return (status, response_body_dict, response_headers). Never raises."""
    import urllib.request as _ur
    import urllib.error as _ue
    try:
        req = _ur.Request(
            url,
            data=_json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with _ur.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
            hdrs = dict(r.headers)
            try:
                return r.status, _json.loads(raw), hdrs
            except Exception:
                return r.status, {}, hdrs
    except _ue.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", errors="replace")
            return e.code, _json.loads(raw) if raw else {}, dict(e.headers)
        except Exception:
            return e.code, {}, {}
    except Exception:
        return 0, {}, {}


def _get(url: str, headers: dict | None = None, timeout: int = 8) -> tuple[int, dict | str]:
    """Return (status, body_dict_or_str). Never raises."""
    import urllib.request as _ur
    import urllib.error as _ue
    try:
        req = _ur.Request(url, headers=headers or {}, method="GET")
        with _ur.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
            try:
                return r.status, _json.loads(raw)
            except Exception:
                return r.status, raw
    except _ue.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}


# ---------------------------------------------------------------------------
# Image-specific auth strategies
# ---------------------------------------------------------------------------

def _auth_directus(base: str, envs: dict, step: Callable) -> dict[str, str] | None:
    """POST /auth/login → Bearer access_token."""
    email = envs.get("ADMIN_EMAIL", "admin@example.com")
    pwd = envs.get("ADMIN_PASSWORD", "BinOracle123!")
    status, body, _ = _post_json(f"{base}/auth/login", {"email": email, "password": pwd})
    if status in (200, 201):
        tok = (body.get("data") or {}).get("access_token") or body.get("access_token") or ""
        if tok:
            step(f"directus-auth: Bearer token obtained ({tok[:8]}...)")
            return {"Authorization": f"Bearer {tok}"}
    step(f"directus-auth: login failed (HTTP {status})")
    return None


def _auth_ghost(base: str, envs: dict, step: Callable) -> dict[str, str] | None:
    """POST /ghost/api/admin/session → session cookie."""
    email = envs.get("ADMIN_EMAIL", "admin@example.com")
    pwd = envs.get("ADMIN_PASSWORD", "BinOracle123!")
    # Ghost admin session endpoint
    status, body, hdrs = _post_json(
        f"{base}/ghost/api/admin/session",
        {"username": email, "password": pwd},
    )
    if status in (200, 201):
        set_cookie = hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or ""
        if set_cookie:
            # Extract the ghost-admin-api-session cookie value
            import re as _re
            m = _re.search(r"ghost-admin-api-session=([^;]+)", set_cookie)
            if m:
                step("ghost-auth: session cookie obtained")
                return {"Cookie": f"ghost-admin-api-session={m.group(1)}"}
    step(f"ghost-auth: login failed (HTTP {status})")
    return None


def _auth_pgadmin(base: str, envs: dict, step: Callable) -> dict[str, str] | None:
    """POST /login → pgAdmin session cookie."""
    import urllib.request as _ur
    import urllib.parse as _up
    email = envs.get("PGADMIN_DEFAULT_EMAIL", "admin@example.com")
    pwd = envs.get("PGADMIN_DEFAULT_PASSWORD", "BinOracle123!")
    # pgAdmin uses form-encoded POST to /login
    payload = _up.urlencode({"email": email, "password": pwd}).encode()
    try:
        req = _ur.Request(
            f"{base}/login",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        # Don't follow redirects — we want the Set-Cookie header
        import http.cookiejar as _cj
        jar = _cj.CookieJar()
        opener = _ur.build_opener(_ur.HTTPCookieProcessor(jar))
        with opener.open(req, timeout=10):
            # Extract session cookie from jar
            for ck in jar:
                if "session" in ck.name.lower():
                    step(f"pgadmin-auth: session cookie obtained ({ck.name})")
                    return {"Cookie": f"{ck.name}={ck.value}"}
    except Exception as e:
        step(f"pgadmin-auth: error — {e}")
    return None


def _auth_audiobookshelf(base: str, envs: dict, step: Callable) -> dict[str, str] | None:
    """POST /login → Bearer token (audiobookshelf uses {user: {token: ...}})."""
    # audiobookshelf default first-run credentials
    for user, pwd in [("admin", "admin"), ("root", "root")]:
        status, body, _ = _post_json(f"{base}/login", {"username": user, "password": pwd})
        if status in (200, 201):
            tok = ((body.get("user") or {}).get("token") or
                   body.get("token") or body.get("access_token") or "")
            if tok:
                step(f"audiobookshelf-auth: Bearer token obtained ({tok[:8]}...)")
                return {"Authorization": f"Bearer {tok}"}
    # Try the register-then-login pattern for first boot
    _post_json(f"{base}/register", {"username": "binoadmin", "password": "BinOracle123!"})
    status, body, _ = _post_json(f"{base}/login", {"username": "binoadmin", "password": "BinOracle123!"})
    if status in (200, 201):
        tok = ((body.get("user") or {}).get("token") or body.get("token") or "")
        if tok:
            step(f"audiobookshelf-auth: registered+login ok ({tok[:8]}...)")
            return {"Authorization": f"Bearer {tok}"}
    step(f"audiobookshelf-auth: login failed (HTTP {status})")
    return None


def _auth_daptin(base: str, envs: dict, step: Callable) -> dict[str, str] | None:
    """POST /action/user/signup and /action/user/signin → token."""
    # daptin default: sign in with admin@admin.com / admin
    for email, pwd in [("admin@admin.com", "admin"), ("admin@example.com", "BinOracle123!")]:
        status, body, _ = _post_json(
            f"{base}/action/user/signin",
            {"attributes": {"email": email, "password": pwd}},
        )
        if status in (200, 201):
            tok = body.get("token") or body.get("access_token") or ""
            if tok:
                step(f"daptin-auth: token obtained ({tok[:8]}...)")
                return {"Authorization": f"Bearer {tok}"}
    step("daptin-auth: login failed")
    return None


# ---------------------------------------------------------------------------
# Dispatch table: image-prefix → (probe_path, auth_fn)
# ---------------------------------------------------------------------------

_IMAGE_AUTH_DISPATCH: list[tuple[str, str, Callable]] = [
    ("directus/directus:",        "/server/health",      _auth_directus),
    ("ghost:",                    "/ghost/api/admin/",   _auth_ghost),
    ("dpage/pgadmin4:",           "/misc/ping",          _auth_pgadmin),
    ("advplyr/audiobookshelf:",   "/healthcheck",        _auth_audiobookshelf),
    ("daptin/daptin:",            "/ping",               _auth_daptin),
]


def login_to_app(
    base_url: str,
    docker_image: str,
    on_step: Optional[Callable[[str], None]] = None,
) -> dict[str, str] | None:
    """Return auth headers for a known Docker image, or None if unknown/failed.

    Dispatches to image-specific login strategies using the same credentials
    as docker_profiles._DOCKER_IMAGE_PROFILES, so they stay in sync.
    """
    from binoracle.workflows.docker_profiles import _DOCKER_IMAGE_PROFILES
    step = on_step or (lambda _m: None)
    base = base_url.rstrip("/")
    img = (docker_image or "").strip()

    for prefix, probe_path, auth_fn in _IMAGE_AUTH_DISPATCH:
        if not img.startswith(prefix):
            continue
        # Quick liveness probe before attempting login
        status, _ = _get(f"{base}{probe_path}")
        if status not in (200, 204, 401, 403):
            step(f"app-auth: probe {probe_path} → {status}, skipping {prefix} handler")
            continue
        # Pull envs from docker_profiles for this image
        profile = _DOCKER_IMAGE_PROFILES.get(prefix) or {}
        envs = (profile.get("envs") or {}) if isinstance(profile, dict) else {}
        return auth_fn(base, envs, step)

    step(f"app-auth: no specific handler for image {img!r}, falling back to generic")
    return None
