"""Arranque automatico del servidor Ghidra MCP headless para una auditoria.

Objetivo: que binoracle use Ghidra SIN que el usuario tenga que levantar el servidor a mano.
Cuando una auditoria empieza y no hay servidor GhidraMCP respondiendo, si Ghidra y el plugin estan
instalados, binoracle lanza el servidor headless apuntando al binario, espera a que este listo, lo
usa durante la auditoria y lo apaga al terminar.

Todo es best-effort y opcional:
- Si ya hay un servidor arriba (lo levanto el usuario), NO se toca (start() devuelve None).
- Si faltan Ghidra/plugin/JDK, o autostart esta desactivado, se sigue con r2 (fallback).
- Config en ~/.binoracle/ghidra.json y/o variables de entorno (ver _cfg / _install_dir / _jdk).

Rutas (prioridad): variable de entorno > ~/.binoracle/ghidra.json > autodeteccion.
"""
from __future__ import annotations

import glob
import json
import os
import signal
import subprocess
import time
from typing import Optional

from . import ghidra as _client

_HEADLESS_CLASS = "com.xebyte.headless.GhidraMCPHeadlessServer"
_CFG_PATH = os.path.expanduser("~/.binoracle/ghidra.json")


def _cfg() -> dict:
    try:
        with open(_CFG_PATH) as fh:
            return json.load(fh) or {}
    except Exception:
        return {}


def _first_valid(paths, check) -> Optional[str]:
    for p in paths:
        if p and check(p):
            return p
    return None


def _install_dir(cfg: dict) -> Optional[str]:
    """Directorio de instalacion de Ghidra (el que contiene support/launch.sh y Ghidra/)."""
    cands = [os.environ.get("BINORACLE_GHIDRA_INSTALL_DIR"),
             os.environ.get("GHIDRA_INSTALL_DIR"),
             cfg.get("install_dir")]
    # autodeteccion tipica en macOS/Linux
    cands += sorted(glob.glob("/opt/homebrew/Cellar/ghidra/*/libexec"), reverse=True)
    cands += sorted(glob.glob("/usr/local/Cellar/ghidra/*/libexec"), reverse=True)
    cands += ["/opt/homebrew/opt/ghidra/libexec"]
    cands += sorted(glob.glob("/opt/ghidra*"), reverse=True)
    cands += sorted(glob.glob(os.path.expanduser("~/ghidra*")), reverse=True)
    return _first_valid(cands, lambda p: os.path.isfile(os.path.join(p, "support", "launch.sh")))


def _jdk_home(cfg: dict) -> Optional[str]:
    """JDK que Ghidra 11.4+ acepta (21+). Devuelve JAVA_HOME o None (dejar que launch.sh decida)."""
    cands = [os.environ.get("BINORACLE_GHIDRA_JDK"), cfg.get("jdk_home"), os.environ.get("JAVA_HOME")]
    try:
        out = subprocess.run(["/usr/libexec/java_home", "-v", "21"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            cands.append(out.stdout.strip())
    except Exception:
        pass
    cands += sorted(glob.glob(os.path.expanduser("~/Desktop/*/.jdk21/*/Contents/Home")), reverse=True)
    cands += sorted(glob.glob(os.path.expanduser("~/.binoracle/jdk*/*/Contents/Home")), reverse=True)
    return _first_valid(cands, lambda p: os.path.isfile(os.path.join(p, "bin", "java")))


def _plugin_installed(install: str) -> bool:
    """El plugin GhidraMCP esta instalado (en el arbol de Ghidra o en el dir de usuario)."""
    if install and glob.glob(os.path.join(install, "Ghidra", "Extensions", "GhidraMCP", "lib", "*.jar")):
        return True
    user = glob.glob(os.path.expanduser("~/.config/ghidra/*/Extensions/GhidraMCP/lib/*.jar"))
    user += glob.glob(os.path.expanduser("~/Library/ghidra/*/Extensions/GhidraMCP/lib/*.jar"))
    return bool(user)


def autostart_enabled(cfg: dict) -> bool:
    env = os.environ.get("BINORACLE_GHIDRA_AUTOSTART")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    return bool(cfg.get("autostart", True))


def _port(cfg: dict) -> int:
    try:
        return int(os.environ.get("BINORACLE_GHIDRA_PORT") or cfg.get("port") or 8089)
    except ValueError:
        return 8089


def start(binary: str, timeout: int = 180) -> Optional[dict]:
    """Asegura un servidor Ghidra para `binary`. Devuelve un handle (para stop()) si binoracle LO
    ARRANCO, o None si ya habia uno, si esta desactivado, o si faltan requisitos. Nunca lanza."""
    try:
        cfg = _cfg()
        if _client.available(timeout=1.5):
            return None                      # ya hay un servidor (del usuario): no lo gestionamos
        if not autostart_enabled(cfg):
            return None
        install = _install_dir(cfg)
        if not install or not _plugin_installed(install):
            return None                      # sin Ghidra/plugin: se sigue con r2
        port = _port(cfg)
        os.environ.setdefault("BINORACLE_GHIDRA_URL", f"http://127.0.0.1:{port}")
        env = dict(os.environ)
        env["GHIDRA_INSTALL_DIR"] = install
        jdk = _jdk_home(cfg)
        if jdk:
            env["JAVA_HOME"] = jdk
        launch = os.path.join(install, "support", "launch.sh")
        logf = open(os.path.join(os.path.expanduser("~/.binoracle"), "ghidra_server.log"), "w")
        os.makedirs(os.path.dirname(logf.name), exist_ok=True)
        proc = subprocess.Popen(
            [launch, "fg", "jdk", "binoracleGhidra", "2G", "", _HEADLESS_CLASS,
             "--port", str(port), "--file", os.path.abspath(binary)],
            stdout=logf, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        # espera a que responda (import + analisis puede tardar)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                return None                  # el server murio al arrancar
            if _client.available(timeout=2.0):
                return {"proc": proc, "port": port, "log": logf.name}
            time.sleep(3)
        # no llego a tiempo: lo matamos y seguimos con fallback
        _terminate(proc)
        return None
    except Exception:
        return None


def _terminate(proc) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def stop(handle: Optional[dict]) -> None:
    """Apaga el servidor que binoracle arranco (no hace nada si el handle es None)."""
    if not handle or not handle.get("proc"):
        return
    proc = handle["proc"]
    _terminate(proc)
    try:
        proc.wait(timeout=10)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
