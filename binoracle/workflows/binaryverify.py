"""Verificacion dinamica de CVEs en BINARIOS NATIVOS usando Docker como entorno
de laboratorio reproducible y descartable.

Cubre vulnerabilidades de MEMORIA / CORRUPCION (heap-overflow, stack-overflow,
uaf, double-free, privilege-escalation...) en binarios del sistema (sudo, bash,
OpenSSL, curl, redis, glibc...) que NO tienen endpoint HTTP y por lo tanto no
entran en los verificadores web (wpverify/drupalverify/joomlaverify/genericverify).

La prueba es clara y directa:
  1. Se levanta un contenedor Docker efimero con el binario en su version vulnerable.
  2. Se ejecuta el PoC dentro del contenedor (un comando de shell o un script).
  3. Si el proceso termina con senal de crash (SIGSEGV/SIGABRT = codigo 139/134) o
     el stdout/stderr contiene un patron de corrupcion de memoria especifico -> VULNERABLE.
  4. Si el proceso termina limpio o muestra el mensaje de la version parcheada -> PATCHED.
  5. Para CVEs de tipo DoS/bucle-infinito (p.ej. CVE-2022-0778): timeout = VULNERABLE.

La diferencia respecto a genericverify.py:
  - genericverify.py verifica CVEs WEB en repositorios con Dockerfile propio o auto-generado.
  - binaryverify.py verifica CVEs en BINARIOS DEL SISTEMA (packages del OS). No hay endpoint
    HTTP: el PoC es un comando de shell que invoca directamente el binario vulnerable.

Dos modos de operacion:
  - verify_binary_crash_in_docker: imagen Docker ya disponible en el host (o en Docker Hub)
    con el binario vulnerable pre-instalado en esa version concreta.
  - verify_binary_crash_via_dockerfile: escribe un Dockerfile temporal que instala
    el paquete vulnerable a una version especifica (via apt/yum/pip pinning) y lo construye.
    Este es el modo para binarios del sistema donde la imagen base siempre tiene la version
    parcheada pero el archivo de paquetes hist. esta disponible (p.ej. Launchpad, pkg-archive).
"""
from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
import textwrap
import time
from typing import Callable, List, Optional, Sequence

from .wpverify import WpVerifyResult, _run, _docker_daemon_ok, _token

# Señales de crash universales: exit codes
_CRASH_EXIT_CODES: frozenset[int] = frozenset({
    134,   # SIGABRT  — malloc() detected heap corruption, assert() failed
    139,   # SIGSEGV  — segmentation fault
    138,   # SIGFPE   — floating-point exception (raro, incluido por completitud)
    137,   # SIGKILL  desde el kernel (OOM/seccomp)
    131,   # SIGCOREDUMP en algunos sistemas
})

# Patrones en stdout/stderr que confirman corrupcion de memoria
_GENERIC_CRASH_PATTERNS: tuple[str, ...] = (
    "malloc(): corrupted",
    "corrupted top size",
    "corrupted size vs. prev_size",
    "free(): invalid",
    "double free or corruption",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "AddressSanitizer",
    "Segmentation fault",
    "Aborted (core dumped)",
    "SIGABRT",
    "SIGSEGV",
    "corrupted",
    "malloc: error for object",          # macOS malloc
    "malloc: *** error",                 # macOS
    "corrupted double-linked list",
    "invalid fastbin entry",
    "malloc(): invalid size",
    "corrupted unsorted chunks",
    "realloc(): invalid pointer",
    "realloc(): invalid next size",
)


def verify_binary_crash_in_docker(
    docker_image: str,
    poc_cmd: str,
    crash_patterns: Optional[List[str]] = None,
    patched_patterns: Optional[List[str]] = None,
    setup_cmds: Optional[List[str]] = None,
    privileged: bool = False,
    timeout_seconds: int = 30,
    timeout_means_vulnerable: bool = False,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 300.0,
) -> WpVerifyResult:
    """Verifica una CVE en un binario nativo ejecutando el PoC en un contenedor Docker.

    docker_image:  imagen Docker que tiene el binario vulnerable pre-instalado a la version
                   correcta (p.ej. 'ubuntu:focal-20210119', 'php:7.4.1', 'redis:6.0.15').
    poc_cmd:       comando de shell que ejecuta el PoC dentro del contenedor (cadena, se pasa a
                   sh -c). Se ejecuta como root a menos que el PoC incluya 'su' o 'runuser'.
    crash_patterns: patron(es) en la salida que, si aparecen, confirman que es VULNERABLE.
                   Si es None, se usan los patrones genericos de corrupcion de memoria.
    patched_patterns: patron(es) que, si aparecen, indican que el binario esta PARCHEADO (no
                   vulnerable). Se comprueban ANTES que crash_patterns.
    setup_cmds:    lista de comandos de shell a ejecutar ANTES del PoC (p.ej. instalar deps,
                   crear ficheros de entrada). Se ejecutan en el MISMO contenedor via docker exec.
    privileged:    si True, lanza el contenedor con --privileged (necesario para algunos exploits
                   de privilege escalation que tocan namespaces o /proc).
    timeout_seconds: segundos que se espera al PoC antes de matarlo. Si el proceso supera el
                   timeout Y timeout_means_vulnerable=True, se marca como VULNERABLE (p.ej.
                   para CVEs de tipo DoS/bucle-infinito como CVE-2022-0778).
    timeout_means_vulnerable: ver arriba.
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    t0 = time.time()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible o no arrancado"
        res.limitations.append("se necesita Docker para verificar CVEs de binarios nativos")
        return res

    _crash_pats = list(crash_patterns or []) + list(_GENERIC_CRASH_PATTERNS)
    _patched_pats = list(patched_patterns or [])

    # -- Arrancar contenedor en background para poder hacer exec de setup --
    container_id = f"binoracle-binaryverify-{_token()}"
    flags = ["--privileged"] if privileged else []
    launch_cmd = [
        "docker", "run", "--name", container_id, "--rm", "-d",
        "--network", "none",          # sin red: el PoC no deberia necesitarla
        "--ulimit", "core=0",         # no core dumps en disco del host
        "--pids-limit", "64",         # limitar explosion de procesos en privesc
    ] + flags + [docker_image, "sleep", str(int(budget_s + 60))]

    step(f"levantando contenedor efimero ({docker_image})...")
    r_launch = _run(launch_cmd, timeout=30)
    if r_launch.returncode != 0:
        # El pull puede fallar si la imagen no existe o no hay red
        step(f"error arrancando contenedor: {(r_launch.stderr or '').strip()[:200]}")
        res.detail = f"no se pudo arrancar el contenedor ({docker_image})"
        res.evidence["launch_stderr"] = (r_launch.stderr or "")[:500]
        return res

    step(f"contenedor {container_id} listo")

    try:
        # -- Comandos de setup opcionales (instalar deps, crear ficheros de entrada) --
        for i, cmd in enumerate(setup_cmds or []):
            step(f"setup [{i+1}/{len(setup_cmds or [])}]: {cmd[:80]}")
            r_setup = _run(
                ["docker", "exec", container_id, "sh", "-c", cmd],
                timeout=min(60, budget_s - (time.time() - t0)))
            if r_setup.returncode != 0:
                res.detail = f"comando de setup [{i+1}] fallo (codigo {r_setup.returncode})"
                res.evidence["setup_stderr"] = (r_setup.stderr or "")[:500]
                return res

        # -- Ejecutar el PoC --
        step(f"ejecutando PoC: {poc_cmd[:120]}")
        elapsed_before_poc = time.time() - t0
        remaining = budget_s - elapsed_before_poc
        poc_timeout = min(timeout_seconds, int(remaining))
        poc_start = time.time()

        try:
            r_poc = subprocess.run(
                ["docker", "exec", container_id, "sh", "-c", poc_cmd],
                capture_output=True, text=True,
                timeout=poc_timeout,
            )
            poc_elapsed = time.time() - poc_start
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            poc_elapsed = poc_timeout
            r_poc = None
            step(f"PoC supero el timeout de {poc_timeout}s")

        combined_out = ""
        if r_poc is not None:
            combined_out = (r_poc.stdout or "") + (r_poc.stderr or "")
            exit_code = r_poc.returncode
            step(f"PoC terminado: exit={exit_code}, {poc_elapsed:.1f}s, "
                 f"salida={combined_out[:80].replace(chr(10), ' ')!r}")
        else:
            exit_code = -1

        res.evidence.update({
            "docker_image": docker_image,
            "poc_cmd": poc_cmd,
            "exit_code": exit_code,
            "stdout": (r_poc.stdout or "")[:2000] if r_poc else "(timeout)",
            "stderr": (r_poc.stderr or "")[:2000] if r_poc else "(timeout)",
            "elapsed_s": round(poc_elapsed, 2),
            "timed_out": timed_out,
        })

        # -- Evaluar resultado --
        # 1) Timeout en CVEs de tipo bucle-infinito = vulnerable
        if timed_out and timeout_means_vulnerable:
            res.verified = True
            res.detail = (f"el PoC supero el timeout de {poc_timeout}s sin terminar -- "
                         f"bucle infinito confirmado (CVE tipo DoS/bucle), binario VULNERABLE")
            step("*** VERIFICADO: timeout => bucle infinito confirmado ***")
            return res

        # 2) Patrones de parcheado tienen prioridad: si aparecen, el binario NO es vulnerable
        for pat in _patched_pats:
            if pat.lower() in combined_out.lower():
                res.detail = (f"el PoC mostro la respuesta del binario PARCHEADO "
                             f"(patron '{pat}' encontrado) -- no vulnerable en esta imagen")
                step(f"binario parcheado detectado (patron: {pat!r})")
                return res

        # 3) Exit code de crash = confirmacion primaria
        if exit_code in _CRASH_EXIT_CODES:
            res.verified = True
            crash_signal = {134: "SIGABRT", 139: "SIGSEGV"}.get(exit_code, f"signal-{exit_code}")
            matched_pat = next((p for p in _crash_pats if p.lower() in combined_out.lower()), None)
            res.detail = (
                f"CRASH confirmado: exit_code={exit_code} ({crash_signal})"
                + (f", patron encontrado: {matched_pat!r}" if matched_pat else "")
            )
            step(f"*** VERIFICADO: crash {crash_signal} (exit {exit_code}) ***")
            return res

        # 4) Patron de crash en la salida aunque el exit code no sea de señal
        for pat in _crash_pats:
            if pat.lower() in combined_out.lower():
                res.verified = True
                res.detail = (f"patron de corrupcion de memoria encontrado en la salida: "
                             f"{pat!r} -- binario VULNERABLE")
                step(f"*** VERIFICADO: patron de crash {pat!r} en salida ***")
                return res

        # 5) Sin crash ni patron: no confirmado
        res.detail = (
            f"PoC ejecutado (exit={exit_code}) pero sin signal de crash ni patron reconocido"
            + (" -- posiblemente la imagen ya tiene el parche" if exit_code == 0 else
               " -- revisar poc_cmd o crash_patterns para esta arquitectura/version")
        )
        step("PoC no produjo crash reconocible")
        return res

    finally:
        # Matar y limpiar el contenedor siempre
        subprocess.run(["docker", "rm", "-f", container_id],
                       capture_output=True, timeout=15)
        step("contenedor efimero eliminado")


def verify_binary_crash_via_dockerfile(
    dockerfile_body: str,
    poc_cmd: str,
    crash_patterns: Optional[List[str]] = None,
    patched_patterns: Optional[List[str]] = None,
    privileged: bool = False,
    timeout_seconds: int = 30,
    timeout_means_vulnerable: bool = False,
    on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 600.0,
) -> WpVerifyResult:
    """Como verify_binary_crash_in_docker, pero CONSTRUYE la imagen localmente a partir de un
    Dockerfile generado en tiempo de ejecucion. Permite instalar una version EXACTA de un
    paquete del sistema (p.ej. sudo 1.8.31p1-1ubuntu1 desde los archives de Ubuntu/Debian)
    cuando la imagen base siempre tiene la version parcheada.

    dockerfile_body: contenido COMPLETO del Dockerfile (sin las instrucciones FROM iniciales --
                     debe incluir FROM). Por ejemplo:
                     'FROM ubuntu:20.04\\nRUN apt-get update && apt-get install -y sudo=1.8.31p1-1ubuntu1'
    """
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()

    if not _docker_daemon_ok():
        res.detail = "Docker no disponible"
        res.limitations.append("se necesita Docker para construir la imagen vulnerable")
        return res

    build_dir = tempfile.mkdtemp(prefix="binoracle_binaryverify_build_")
    image_tag = f"binoracle-binaryverify-{_token()}"
    try:
        dockerfile_path = os.path.join(build_dir, "Dockerfile")
        with open(dockerfile_path, "w") as fh:
            fh.write(textwrap.dedent(dockerfile_body).strip() + "\n")

        step(f"construyendo imagen Docker con el binario vulnerable ({image_tag})...")
        r_build = subprocess.run(
            ["docker", "build", "--platform", "linux/amd64",
             "-t", image_tag, build_dir],
            capture_output=True, text=True,
            timeout=min(300, budget_s * 0.5),
        )
        if r_build.returncode != 0:
            step(f"build fallo (codigo {r_build.returncode})")
            res.detail = "docker build fallo -- Dockerfile invalido o paquete no disponible"
            res.evidence["build_stderr"] = (r_build.stderr or "")[-1000:]
            return res

        step(f"imagen {image_tag} construida -- ejecutando verificacion")
        return verify_binary_crash_in_docker(
            docker_image=image_tag,
            poc_cmd=poc_cmd,
            crash_patterns=crash_patterns,
            patched_patterns=patched_patterns,
            privileged=privileged,
            timeout_seconds=timeout_seconds,
            timeout_means_vulnerable=timeout_means_vulnerable,
            on_step=on_step,
            budget_s=budget_s * 0.5,
        )
    finally:
        # Limpiar imagen construida
        subprocess.run(["docker", "rmi", "-f", image_tag],
                       capture_output=True, timeout=15)
        import shutil
        shutil.rmtree(build_dir, ignore_errors=True)
        step("imagen temporal eliminada")
