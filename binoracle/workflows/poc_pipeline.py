"""Pipeline: dado un CVE-ID, decide si hay PoC publico que descargar y ejecutar, o si hay
que construirlo desde la descripcion -- y converge ambas ramas en el mismo veredicto
dynamic_verify-only (nunca el LLM decide 'verified').

                              CVE-ID
                                |
                        fetch_cve() (NVD)
                                |
                search_github_poc / search_searchsploit
                                |
                 +--------------+---------------+
                 | hay PoC publico               | no hay PoC publico
                 v                                v
         stage_public_poc()               (delegar a cveplan.plan() /
         (git clone aislado,                AutonomousExploitDev cuando
          nunca en el cwd del               este disponible -- ver
          proceso)                          develop_from_description())
                 |                                |
         run_poc_in_sandbox()                     |
         (sin red salvo el lab,                    |
          memoria/cpu acotados,                    |
          nunca ejecuta nada                       |
          fuera del sandbox)                       |
                 |                                |
                 +--------------+---------------+
                                |
                      dynamic_verify.verified
                   (UNICO veredicto valido --
                    el LLM nunca lo fija)

Principio de recursos (maquina de 16 GB RAM, ejecutandose junto a Ollama/Qwen 7B local):
  - Ollama con qwen2.5-coder:7b cuantizado reserva ~5 GB mientras esta cargado.
  - Un lab Docker (CMS+DB) real ronda 1-2 GB con los limites que ya usa genericverify.py
    (`--memory 1g`/`--cpus 2.0`).
  - Con eso, correr DOS labs a la vez (p.ej. uno para el PoC publico y otro para la rama de
    construccion por descripcion) deja la maquina con menos de 2 GB libres -- zona de swap /
    OOM-killer real, no teorica. Por eso `ResourceBudget` fuerza serializacion: como mucho
    UN lab Docker vivo a la vez para todo el proceso binoracle, comprobado contra RAM libre
    real (no solo un contador en memoria), con un lock de fichero para que valga incluso si
    hay varios procesos `binoracle` corriendo en paralelo.

SOLO USO AUTORIZADO -- targets propios o con autorizacion escrita, igual que el resto del
proyecto.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ---------------------------------------------------------------------------
# Presupuesto de recursos: serializa labs Docker contra la RAM real de la maquina
# ---------------------------------------------------------------------------

@dataclass
class ResourceBudget:
    """Politica de recursos para una maquina de `total_ram_gb` GB corriendo Ollama local +
    labs Docker a la vez. Pensada para 16 GB por defecto (el caso real de este proyecto),
    pero configurable via BINORACLE_TOTAL_RAM_GB para otra maquina."""
    total_ram_gb: float = float(os.environ.get("BINORACLE_TOTAL_RAM_GB", "16"))
    # Memoria que se asume reservada por el modelo local (Ollama) mientras esta cargado.
    # qwen2.5-coder:7b en Q4_K_M ronda 4.5-5 GB residentes; dejamos margen a 5.5.
    llm_reserved_gb: float = float(os.environ.get("BINORACLE_LLM_RESERVED_GB", "5.5"))
    # Por debajo de este libre, NO se levanta un lab nuevo (deja margen al SO + swap).
    min_free_gb_to_start_lab: float = 2.5
    # Nunca mas de un lab Docker vivo a la vez, sea cual sea la RAM total -- un segundo lab
    # nunca aporta nada que un primero bien serializado no de, y SI puede tirar la maquina.
    max_concurrent_labs: int = 1

    _LOCK_PATH = os.path.join(tempfile.gettempdir(), "binoracle_lab.lock")

    def free_ram_gb(self) -> Optional[float]:
        """RAM libre real del host, leida de /proc/meminfo (Linux). None si no se puede leer
        (p.ej. dentro de un contenedor sin /proc o en un host no Linux) -- en ese caso el
        llamador debe decidir con mas cautela, nunca asumir que hay margen."""
        try:
            info = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, _, v = line.partition(":")
                    info[k.strip()] = v.strip()
            # MemAvailable ya tiene en cuenta cache/buffers reclamables -- mas fiable que
            # MemFree a secas, que subestima lo que realmente hay disponible.
            kb = info.get("MemAvailable") or info.get("MemFree")
            if kb is None:
                return None
            return float(kb.split()[0]) / (1024 * 1024)
        except Exception:
            return None

    def other_labs_running(self) -> List[str]:
        """Contenedores Docker reales ya corriendo que PARECEN un lab de binoracle, detectados
        por nombre (prefijos conocidos de las distintas clases _Lab/_GenericLab del proyecto:
        'bo_', 'binoracle-'). Esto es necesario porque mi propio flock en _LOCK_PATH SOLO sabe
        de labs levantados a traves de este modulo -- un lab de genericverify.py que quedo
        huerfano por una excepcion sin try/finally (ver COORDINATION.md) es invisible para el
        flock, y sin este chequeo ResourceBudget dejaria pasar un segundo lab mientras uno viejo
        sigue vivo de verdad, comiendo RAM que el flock cree libre. Best-effort: devuelve []
        (nunca bloquea) si docker no esta disponible o el comando falla -- un chequeo que no se
        puede hacer no debe impedir arrancar, solo uno que SI detecta algo debe frenar."""
        if not shutil.which("docker"):
            return []
        try:
            r = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                               capture_output=True, text=True, timeout=10)
        except Exception:
            return []
        if r.returncode != 0:
            return []
        names = [n.strip() for n in (r.stdout or "").splitlines() if n.strip()]
        return [n for n in names if n.startswith("bo_") or n.startswith("binoracle-")]

    def can_start_lab(self) -> tuple[bool, str]:
        """(ok, motivo). Tres chequeos, en orden de barato a caro:
          1) RAM libre real (free_ram_gb) -- rapido, siempre disponible en Linux.
          2) contenedores reales ya corriendo con pinta de lab binoracle (other_labs_running)
             -- detecta un lab huerfano de OTRO modulo que mi propio flock no puede ver.
          3) el flock (en lab_slot, no aqui) -- serializa labs lanzados a traves de ESTE modulo,
             incluso entre procesos distintos.
        Las tres capas son necesarias: ninguna sola cubre todos los casos (un lab zombi de
        genericverify.py no toca mi flock; dos llamadas a ESTE modulo sin lab zombi de por
        medio no se detectan por nombre de contenedor si aun no han hecho docker run)."""
        free = self.free_ram_gb()
        if free is not None and free < self.min_free_gb_to_start_lab:
            return False, (f"RAM libre {free:.1f} GB < minimo {self.min_free_gb_to_start_lab} GB "
                           "para levantar un lab Docker con seguridad")
        running = self.other_labs_running()
        if len(running) >= self.max_concurrent_labs:
            return False, (f"ya hay {len(running)} contenedor(es) de lab corriendo "
                           f"({', '.join(running[:3])}{'...' if len(running) > 3 else ''}) -- "
                           "puede ser un lab vivo de otro modulo (p.ej. genericverify.py) que mi "
                           "propio lock no ve; no arranco uno nuevo hasta que se libere")
        return True, "ok"


@contextlib.contextmanager
def lab_slot(budget: ResourceBudget, timeout_s: float = 600.0):
    """Reserva UN slot de lab Docker para todo el host, bloqueando (con timeout) si otro
    proceso/hilo ya tiene uno vivo. flock es inter-proceso de verdad (no solo un Lock() de
    threading, que no protegeria entre `binoracle investigate` y `binoracle web_cve` corriendo
    a la vez). Lanza TimeoutError si no se libera a tiempo -- el llamador debe degradar
    (available=False), nunca forzar el lab de todas formas."""
    ok, why = budget.can_start_lab()
    if not ok:
        raise RuntimeError(why)
    os.makedirs(os.path.dirname(budget._LOCK_PATH) or ".", exist_ok=True)
    fd = os.open(budget._LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.time() + timeout_s
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.time() >= deadline:
                    raise TimeoutError(
                        "otro lab Docker ya esta usando el unico slot disponible "
                        f"(max_concurrent_labs={budget.max_concurrent_labs}); "
                        "sube BINORACLE_TOTAL_RAM_GB solo si de verdad tienes mas RAM libre"
                    ) from e
                time.sleep(2.0)
        # re-chequeo de RAM justo antes de ceder el slot: el "ok" de arriba pudo quedar
        # obsoleto mientras esperabamos el lock.
        ok2, why2 = budget.can_start_lab()
        if not ok2:
            raise RuntimeError(why2)
        yield
    finally:
        with contextlib.suppress(Exception):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# Rama A: PoC publico -- clonar en aislamiento, nunca ejecutar fuera de sandbox
# ---------------------------------------------------------------------------

@dataclass
class StagedPoc:
    ok: bool = False
    source_url: str = ""
    local_dir: str = ""          # directorio AISLADO y NUEVO, nunca el cwd del proceso
    readme_excerpt: str = ""     # primeras lineas del README, para que el LLM proponga el run
    note: str = ""


def stage_public_poc(ref_url: str, on_step: Optional[Callable[[str], None]] = None,
                     timeout_s: float = 60.0) -> StagedPoc:
    """Clona un repo de PoC publico (de search_github_poc) en un directorio temporal nuevo y
    vacio, dedicado solo a este intento -- nunca reutilizado entre CVEs, nunca el cwd del
    proceso binoracle. El contenido es DATOS NO CONFIABLES (un PoC de un tercero): esta
    funcion solo copia ficheros (git clone), no ejecuta nada de dentro del repo."""
    step = on_step or (lambda _m: None)
    res = StagedPoc(source_url=ref_url)
    if not shutil.which("git"):
        res.note = "git no disponible"
        return res
    workdir = tempfile.mkdtemp(prefix="binoracle_poc_")
    step(f"[poc] clonando {ref_url} en directorio aislado {workdir} (solo lectura de ficheros, "
         "nada se ejecuta todavia)...")
    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--no-single-branch", ref_url, workdir],
            capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        res.note = "git clone: timeout"
        return res
    except Exception as e:
        res.note = f"git clone fallo: {e}"
        return res
    if r.returncode != 0:
        res.note = f"git clone fallo: {(r.stderr or '').strip()[:200]}"
        return res
    readme = ""
    for name in ("README.md", "README", "readme.md", "Readme.md"):
        p = os.path.join(workdir, name)
        if os.path.isfile(p):
            try:
                readme = open(p, encoding="utf-8", errors="replace").read()[:4000]
            except OSError:
                pass
            break
    res.ok = True
    res.local_dir = workdir
    res.readme_excerpt = readme
    step(f"[poc] clonado ok, {len(readme)} chars de README para que el LLM proponga como lanzarlo")
    return res


@dataclass
class PocRunResult:
    ok: bool = False            # el intento corrio hasta el final sin error de infraestructura
    verified: bool = False      # SOLO True si el lab/oraculo confirmo exito real, nunca el LLM
    engine: str = ""            # 'docker' u otro mecanismo de aislamiento usado
    detail: str = ""
    logs: List[str] = field(default_factory=list)
    available: bool = True


def run_poc_in_sandbox(staged: StagedPoc, lab_target_container: str,
                       run_cmd_candidates: List[str],
                       budget: Optional[ResourceBudget] = None,
                       timeout_s: int = 180,
                       on_step: Optional[Callable[[str], None]] = None) -> PocRunResult:
    """Ejecuta el PoC ya clonado, acotado y aislado. Rustico a proposito: no se descarga NINGUNA
    imagen Docker nueva. Dos caminos, segun si hay un lab objetivo real al que llegar:

    - SIN lab_target_container (solo queremos ver que el PoC corre / sanity check, sin target
      vivo): delega en `_sandbox.run_bash`, que YA existe y YA sabe usar la imagen propia
      `binoracle-pwn` si esta construida, o degradar a aislamiento NATIVO (unshare + setarch +
      rlimits, sin Docker en absoluto) cuando no lo esta. Esto es lo que hace que el pipeline
      funcione tambien en una maquina sin Docker -- antes esta funcion simplemente se rendia.

    - CON lab_target_container (hay un lab Docker real levantado por el caller, p.ej.
      _GenericLab, y el PoC necesita hablar con el): unico caso que SI necesita Docker de
      verdad, porque `--network container:<id>` (compartir la pila de red de otro contenedor)
      no tiene equivalente nativo razonable. Reusa la imagen `binoracle-pwn` si existe (no
      pulea una imagen nueva); si no existe, degrada honestamente a available=False en vez de
      tirar de una imagen generica de internet.

    `run_cmd_candidates`: comandos a probar en orden (del LLM via `propose_run_commands`, o
    heuristicos) -- el LLM PROPONE, nunca decide 'verified'; eso sigue viniendo de que el
    oraculo/caller interprete la salida real (misma convencion VERIFIED/NOT_VERIFIED que
    `_sandbox.run_driver`).

    No ejecuta nada si no hay slot de recursos libre (ver ResourceBudget/lab_slot): en ese
    caso degrada a available=False en vez de forzar un segundo lab concurrente."""
    step = on_step or (lambda _m: None)
    budget = budget or ResourceBudget()
    res = PocRunResult()
    if not staged.ok or not staged.local_dir:
        res.detail = "PoC no estaba correctamente clonado"
        res.available = False
        return res

    from . import _sandbox

    try:
        with lab_slot(budget, timeout_s=timeout_s + 30):
            for cmd in run_cmd_candidates:
                step(f"[poc] probando: {cmd[:120]}")
                full_cmd = "pip install -q -r requirements.txt 2>/dev/null; " + cmd

                if lab_target_container:
                    # Unico camino que de verdad necesita Docker (compartir red con el lab).
                    if not shutil.which("docker") or not _sandbox._docker_image_ok():
                        res.available = False
                        res.detail = ("se requiere imagen binoracle-pwn para hablar con el lab "
                                     "('--network container:<id>' no tiene via nativa) -- "
                                     "'make pwn-image' si aun no esta construida")
                        return res
                    try:
                        r = subprocess.run(
                            ["docker", "run", "--rm", "--platform", "linux/amd64",
                             "--network", f"container:{lab_target_container}",
                             "--memory", "512m", "--pids-limit", "256",
                             "-v", f"{staged.local_dir}:/poc:ro", "-w", "/poc",
                             "binoracle-pwn", "bash", "-c", full_cmd],
                            capture_output=True, text=True, timeout=timeout_s)
                        out = (r.stdout or "") + (r.stderr or "")
                        returncode = r.returncode
                    except subprocess.TimeoutExpired:
                        out = "[timeout]"
                        returncode = None
                    engine = "docker"
                    # El daemon puede estar inalcanzable aunque `docker` y la imagen existan
                    # (socket caido, VM de Docker Desktop parada a medias) -- eso NO es un
                    # fallo del PoC, es infraestructura, y se reporta como available=False en
                    # vez de como un intento fallido mas (bug real ya encontrado una vez aqui:
                    # ver commit 1d1836f -- ok se ponia a True sin mirar el resultado real).
                    if "Cannot connect to the Docker daemon" in out or returncode == 125:
                        res.available = False
                        res.detail = out[-400:]
                        return res
                else:
                    # Sin lab que alcanzar: deja que _sandbox decida (docker propio si lo hay,
                    # nativo si no) -- cero imagenes nuevas, funciona sin Docker instalado.
                    # run_bash_generic (no run_bash): un PoC no es un binario pwn, no necesita
                    # host x86-64 ni ASLR-off -- run_bash exige ambos y por eso degradaba con
                    # "host no es x86-64" en un host ARM (Apple Silicon incluido) para un PoC
                    # que ni siquiera tocaba un binario.
                    eng, out = _sandbox.run_bash_generic(staged.local_dir, full_cmd,
                                                         timeout=timeout_s, mem_mb=512)
                    if eng is None:
                        res.available = False
                        res.detail = out  # motivo exacto por el que ni docker ni nativo valen
                        return res
                    engine = eng
                    # _sandbox.run_bash no expone el returncode (solo texto combinado
                    # stdout+stderr), asi que el mismo chequeo de infraestructura se hace por
                    # contenido -- best effort, pero evita el mismo bug que arriba.
                    returncode = 1 if "Cannot connect to the Docker daemon" in out else 0

                res.logs.append(f"$ {cmd}\n{out[-1500:]}")
                # ok refleja si el comando CORRIO de verdad, no solo si el bucle llego hasta
                # aqui -- un returncode distinto de 0 (o el timeout, returncode=None) es un
                # intento que no corrio limpio, aunque sigue siendo info util en res.logs.
                res.ok = (returncode == 0)
                res.engine = engine
                # Convencion compartida con el resto del proyecto (_sandbox.run_driver): solo
                # cuenta como verificado lo que el PROPIO target/lab confirma en su salida, no
                # lo que el PoC de un tercero *diga* que hizo. El caller (quien conoce el
                # formato de verificacion del lab concreto -- p.ej. un segundo login WP) es
                # quien de verdad decide `verified`; esta funcion solo deja la evidencia cruda.
                res.detail = out[-400:]
                if "VERIFIED" in out and "NOT_VERIFIED" not in out:
                    res.verified = True
                    step(f"[poc] marcador VERIFIED visto en la salida (engine={engine}) -- "
                         "el caller debe confirmarlo contra el lab antes de darlo por bueno")
                    break
    except TimeoutError as e:
        res.available = False
        res.detail = str(e)
    except RuntimeError as e:  # ResourceBudget dijo que no hay margen
        res.available = False
        res.detail = str(e)
    return res


def cleanup_staged_poc(staged: StagedPoc) -> None:
    """Borra el directorio aislado del PoC. Llamar siempre al terminar, con o sin exito --
    nunca dejar codigo de un tercero sin confiar tirado en disco entre ejecuciones."""
    if staged.local_dir and os.path.isdir(staged.local_dir):
        shutil.rmtree(staged.local_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# El router: decide rama A (PoC publico) vs rama B (construir desde la descripcion)
# ---------------------------------------------------------------------------

@dataclass
class CveExploitDevResult:
    cve_id: str = ""
    branch: str = ""             # "public_poc" | "build_from_description" | "no_path"
    verified: bool = False
    available: bool = True
    detail: str = ""
    logs: List[str] = field(default_factory=list)


def develop_cve_exploit(cve_id: str, lab_target_container: str = "", llm=None, config=None,
                        budget: Optional[ResourceBudget] = None,
                        on_step: Optional[Callable[[str], None]] = None) -> CveExploitDevResult:
    """Punto de entrada unico: dado un CVE-ID, busca PoC publico; si existe, lo clona y lo
    ejecuta en sandbox contra `lab_target_container` (un lab ya levantado por el caller --
    este modulo NO decide que CMS/version montar, eso sigue siendo responsabilidad del
    pipeline que ya existe en genericverify.py/_GenericLab). Si no hay PoC publico, delega en
    la rama de construccion desde la descripcion (cveplan.plan / AutonomousExploitDev cuando
    este disponible), que debe terminar en el MISMO tipo de veredicto dynamic_verify-only.

    Este router deliberadamente NO fija verified=True en ningun camino -- solo lo propaga de
    lo que la rama elegida ya verifico contra el lab real."""
    step = on_step or (lambda _m: None)
    budget = budget or ResourceBudget()
    res = CveExploitDevResult(cve_id=cve_id)

    from .cvelookup import fetch_cve, search_github_poc, search_searchsploit
    info = fetch_cve(cve_id)
    refs = search_github_poc(cve_id) + search_searchsploit(cve_id)

    if refs:
        res.branch = "public_poc"
        step(f"[router] {len(refs)} referencia(s) de PoC publico encontradas para {cve_id}; "
             "rama A (clonar + ejecutar en sandbox)")
        staged = stage_public_poc(refs[0].url if hasattr(refs[0], "url") else str(refs[0]),
                                  on_step=step)
        if not staged.ok:
            res.available = False
            res.detail = f"no se pudo clonar el PoC publico: {staged.note}"
            return res
        try:
            cmds = propose_run_commands(llm, staged.readme_excerpt) if llm else _heuristic_run_commands(staged)
            run = run_poc_in_sandbox(staged, lab_target_container, cmds, budget=budget, on_step=step)
            res.available = run.available
            res.verified = run.verified
            res.detail = run.detail
            res.logs = run.logs
        finally:
            cleanup_staged_poc(staged)
        return res

    res.branch = "build_from_description"
    step(f"[router] sin PoC publico para {cve_id}; rama B (construir desde la descripcion NVD)")
    try:
        from .cveplan import plan
        pl = plan(info.description or cve_id, {}, cve=cve_id, lang="es")
        res.detail = ("plantilla de ataque generada desde la descripcion; conectar con "
                      "AutonomousExploitDev (exploit_dev.py) para iterar hasta verificar -- "
                      "ese enganche deliberadamente NO se hace aqui para no competir con la "
                      "sesion que ya lo esta construyendo")
        res.available = bool(pl)
    except Exception as e:
        res.available = False
        res.detail = f"no se pudo generar plan desde la descripcion: {e}"
    return res


def propose_run_commands(llm, readme_excerpt: str) -> List[str]:
    """El LLM PROPONE comandos candidatos para lanzar el PoC a partir de su README -- nunca
    decide si funciono. Se intentan en orden dentro del sandbox; la salida real decide."""
    from ..llm.base import Message
    if not readme_excerpt:
        return _heuristic_run_commands(None)
    sys = ("Lee este README de un PoC de seguridad y propon, en orden de mas a menos probable, "
           "hasta 3 comandos de shell para EJECUTARLO (asume que ya estas en su directorio y "
           "que las dependencias de requirements.txt ya se instalaron). Un comando por linea, "
           "sin explicacion, sin numeracion, sin backticks.")
    try:
        out = llm.chat([Message("system", sys), Message("user", readme_excerpt)], json_mode=False)
    except Exception:
        return _heuristic_run_commands(None)
    cmds = [l.strip("`$ ").strip() for l in out.splitlines() if l.strip()]
    return cmds[:3] or _heuristic_run_commands(None)


def _heuristic_run_commands(staged: Optional[StagedPoc]) -> List[str]:
    """Sin LLM disponible (o sin README): intentos genericos mas comunes en PoCs de GitHub,
    en orden de probabilidad real observada en el ecosistema de PoCs publicos."""
    return [
        "python3 exploit.py --help",
        "python3 poc.py --help",
        "ls -la && cat *.py 2>/dev/null | head -5",
    ]
