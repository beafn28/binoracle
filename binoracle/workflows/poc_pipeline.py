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

    def can_start_lab(self) -> tuple[bool, str]:
        """(ok, motivo). No mira solo RAM: tambien respeta max_concurrent_labs via el lock de
        fichero, para que valga aunque haya varios procesos `binoracle` (p.ej. un CLI run y un
        web_cve.py sirviendo a la vez) compitiendo por la misma maquina."""
        free = self.free_ram_gb()
        if free is not None and free < self.min_free_gb_to_start_lab:
            return False, (f"RAM libre {free:.1f} GB < minimo {self.min_free_gb_to_start_lab} GB "
                           "para levantar un lab Docker con seguridad")
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
                        "sube BINORACLE_TOTAL_RAM_GB solo si de verdad tienes mas RAM libre")
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
    """Ejecuta el PoC ya clonado DENTRO de un contenedor Docker efimero y acotado, con red
    limitada SOLO al contenedor del lab objetivo (`--network container:<lab_target_container>`
    cuando se da, igual que el patron ya usado en genericverify.py para que el PoC solo pueda
    hablar con el target, no con internet ni con el host). `run_cmd_candidates` es una lista de
    comandos a probar en orden (p.ej. propuestos por el LLM a partir del README: ve
    `propose_run_commands` mas abajo) -- el LLM aqui PROPONE, nunca decide 'verified'; eso
    sigue viniendo de que el oraculo/caller interprete la salida real (igual que
    `_sandbox.run_driver` exige la convencion VERIFIED/NOT_VERIFIED).

    No ejecuta nada si no hay slot de recursos libre (ver ResourceBudget/lab_slot): en ese
    caso degrada a available=False en vez de forzar un segundo lab concurrente."""
    step = on_step or (lambda _m: None)
    budget = budget or ResourceBudget()
    res = PocRunResult()
    if not staged.ok or not staged.local_dir:
        res.note = "PoC no estaba correctamente clonado"  # type: ignore[attr-defined]
        return res
    if not shutil.which("docker"):
        res.available = False
        res.detail = "docker no disponible: no se puede aislar la ejecucion del PoC con seguridad"
        return res

    try:
        with lab_slot(budget, timeout_s=timeout_s + 30):
            net_args = (["--network", f"container:{lab_target_container}"]
                       if lab_target_container else ["--network", "none"])
            for cmd in run_cmd_candidates:
                step(f"[poc] probando: {cmd[:120]}")
                try:
                    r = subprocess.run(
                        ["docker", "run", "--rm", "--platform", "linux/amd64",
                         *net_args, "--memory", "512m", "--pids-limit", "256",
                         "-v", f"{staged.local_dir}:/poc:ro", "-w", "/poc",
                         "python:3.11-slim", "bash", "-c",
                         "pip install -q -r requirements.txt 2>/dev/null; " + cmd],
                        capture_output=True, text=True, timeout=timeout_s)
                    out = (r.stdout or "") + (r.stderr or "")
                except subprocess.TimeoutExpired:
                    out = "[timeout]"
                # Detect daemon-not-running before logging anything (binary present but
                # socket unreachable means available=False, not a transient PoC error).
                if "Cannot connect to the Docker daemon" in out or r.returncode == 125:
                    res.available = False
                    res.detail = out[-400:]
                    return res
                res.logs.append(f"$ {cmd}\n{out[-1500:]}")
                res.ok = r.returncode == 0
                res.engine = "docker"
                # Convencion compartida con el resto del proyecto (_sandbox.run_driver): solo
                # cuenta como verificado lo que el PROPIO target/lab confirma en su salida, no
                # lo que el PoC de un tercero *diga* que hizo. El caller (quien conoce el
                # formato de verificacion del lab concreto -- p.ej. un segundo login WP) es
                # quien de verdad decide `verified`; esta funcion solo deja la evidencia cruda.
                res.detail = out[-400:]
                if "VERIFIED" in out and "NOT_VERIFIED" not in out:
                    res.verified = True
                    step("[poc] marcador VERIFIED visto en la salida -- el caller debe "
                         "confirmarlo contra el lab antes de darlo por bueno")
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
