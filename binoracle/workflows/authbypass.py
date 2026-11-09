"""Verificacion DINAMICA de si una credencial candidata (encontrada por secrets.py/authcheck.py y
confirmada por xref, ver authcheck.py) efectivamente autentica: ejecuta el binario dos veces en el
mismo sandbox aislado que usa dynamic.py (Docker, --network none, sin acceso al host, memoria/pids
limitados), una vez con la credencial candidata por stdin y otra con un valor de CONTROL claramente
incorrecto, y compara el codigo de salida real de cada ejecucion.

Grounded, honesto sobre sus limites:
- Solo se afirma una diferencia si los codigos de salida DIFIEREN entre ambas ejecuciones: un hecho
  objetivo observado, no una interpretacion del texto de salida (que puede variar por motivos no
  relacionados con la autenticacion). Si difieren, es evidencia fuerte (aunque no prueba absoluta:
  el codigo de salida podria variar por otra razon) de que esa entrada concreta cambia el camino de
  ejecucion del programa.
- ELF/Linux-only: el sandbox es un contenedor linux/amd64 (misma limitacion que dynamic.py). Para
  un binario Windows no hay entorno de ejecucion real disponible aqui.
- Nunca se afirma "bypass confirmado" sin la diferencia objetiva de codigo de salida.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

_IMG = "binoracle-pwn"
_SANDBOX_NAME = "target.bin"
_CONTROL_VALUE = b"wrong_control_value_8f2a1c9d\n"


@dataclass
class BypassAttempt:
    ran: bool = False
    note: str = ""
    credential: str = ""
    candidate_exit: int = None
    control_exit: int = None
    candidate_out: str = ""
    control_out: str = ""
    differs: bool = False

    @property
    def ok(self) -> bool:
        return self.ran


def _run_once(binary: str, stdin: bytes, timeout: int):
    """Ejecuta el binario UNA VEZ en el sandbox con `stdin` dado. Devuelve (exit_code, salida) o
    (None, nota_de_error). Mismo patron de aislamiento que dynamic.py: copia a directorio temporal
    aislado (nunca el directorio del usuario), --network none, limites de recursos."""
    work = tempfile.mkdtemp(prefix="bo_bypass_")
    try:
        shutil.copy2(binary, os.path.join(work, _SANDBOX_NAME))
        with open(os.path.join(work, ".in"), "wb") as f:
            f.write(stdin)
        inner = (f"chmod +x ./{_SANDBOX_NAME}; "
                 f"timeout {max(1, timeout - 2)} ./{_SANDBOX_NAME} < .in > /tmp/out 2>&1; "
                 f"echo __BO_EXIT__$?__; head -c 4000 /tmp/out")
        out = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "256m", "--pids-limit", "128", "--cpus", "1",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--ulimit", "fsize=10000000", "-v", work + ":/w", "-w", "/w",
             _IMG, "bash", "-c", inner],
            capture_output=True, text=True, timeout=timeout + 20)
        raw = (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        return None, "[timed out]"
    except Exception as e:
        return None, f"error: {e.__class__.__name__}"
    finally:
        shutil.rmtree(work, ignore_errors=True)
    m = re.search(r"__BO_EXIT__(\d+)__", raw)
    if not m:
        return None, raw.strip() or "[sin marca de salida: el proceso pudo morir por señal]"
    code = int(m.group(1))
    text = raw[m.end():].strip()
    return code, text


def try_credential_bypass(binary: str, credential: str, timeout: int = 8) -> BypassAttempt:
    """Intenta la credencial candidata por stdin contra el binario real, en sandbox, y la compara
    con un valor de control. best-effort: nota explicativa (no excepcion) si docker/la imagen no
    estan disponibles, igual que dynamic_trace()."""
    docker = shutil.which("docker")
    if not docker:
        return BypassAttempt(credential=credential, note="docker no disponible")
    if subprocess.run([docker, "image", "inspect", _IMG], capture_output=True).returncode != 0:
        return BypassAttempt(credential=credential, note=f"imagen {_IMG} no construida")
    cand_code, cand_out = _run_once(binary, credential.encode("utf-8", errors="replace") + b"\n", timeout)
    ctrl_code, ctrl_out = _run_once(binary, _CONTROL_VALUE, timeout)
    if cand_code is None or ctrl_code is None:
        return BypassAttempt(credential=credential, ran=False,
                             note="fallo al ejecutar en el sandbox (ver candidate_out/control_out)",
                             candidate_out=cand_out or "", control_out=ctrl_out or "")
    return BypassAttempt(
        credential=credential, ran=True, candidate_exit=cand_code, control_exit=ctrl_code,
        candidate_out=cand_out[:2000], control_out=ctrl_out[:2000], differs=cand_code != ctrl_code)
