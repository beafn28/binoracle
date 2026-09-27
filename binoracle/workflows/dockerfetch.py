"""Extrae un binario real desde una imagen Docker (para conseguir el binario vulnerable de una CVE).

Cierra el bloqueo nº1 de la explotacion real: "hace falta el binario concreto". Muchas versiones
vulnerables viven en imagenes Docker (distros antiguas, imagenes de un paquete). Este modulo saca el
fichero de la imagen SIN ejecutar su entrypoint: usa `docker create` + `docker cp` + `docker rm`, que
solo copia ficheros, no corre codigo de la imagen. `locate_in_image` si ejecuta un `find`/`which`
acotado para localizar el binario por nombre.

Uso tipico:
    binoracle fetch ubuntu:16.04 /usr/sbin/nscd            # copia por ruta
    binoracle fetch debian:10 nscd                          # localiza por nombre y copia
Luego:
    binoracle investigate CVE-XXXX-YYYY --binary <ruta extraida>

Solo para investigacion / objetivos autorizados. Las imagenes las elige el usuario.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class FetchResult:
    ok: bool = False
    image: str = ""
    src_path: str = ""
    local_path: str = ""
    candidates: List[str] = field(default_factory=list)   # rutas halladas al localizar por nombre
    note: str = ""


def _docker() -> Optional[str]:
    return shutil.which("docker")


def locate_in_image(image: str, name: str, timeout: float = 120.0) -> List[str]:
    """Localiza rutas de un binario por nombre dentro de la imagen (which + find en dirs de binarios).
    Ejecuta un contenedor efimero acotado (`--rm --network none`). Devuelve las rutas halladas."""
    docker = _docker()
    if not docker or not name:
        return []
    # busca en los directorios habituales de binarios; evita recorrer todo el FS
    script = (f"command -v {name} 2>/dev/null; "
              f"find /usr/sbin /usr/bin /sbin /bin /usr/local/sbin /usr/local/bin "
              f"-maxdepth 1 -name {name} -type f 2>/dev/null")
    try:
        out = subprocess.run(
            [docker, "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--entrypoint", "sh", image, "-c", script],
            capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    seen, paths = set(), []
    for ln in (out.stdout or "").splitlines():
        p = ln.strip()
        if p.startswith("/") and p not in seen:
            seen.add(p)
            paths.append(p)
    return paths


def fetch_from_image(image: str, path_or_name: str, dest_dir: str = "",
                     on_step: Optional[Callable[[str], None]] = None,
                     timeout: float = 240.0) -> FetchResult:
    """Extrae `path_or_name` de `image` a `dest_dir`. Si es una ruta absoluta, copia directa; si es un
    nombre, lo localiza primero. No ejecuta el entrypoint de la imagen (docker create + cp). No lanza."""
    step = on_step or (lambda _m: None)
    res = FetchResult(image=image, src_path=path_or_name)
    docker = _docker()
    if not docker:
        res.note = "docker no disponible"
        return res
    if not image or not path_or_name:
        res.note = "faltan imagen o ruta/nombre"
        return res

    src = path_or_name
    if not src.startswith("/"):
        step(f"localizando '{path_or_name}' en {image}...")
        cands = locate_in_image(image, path_or_name)
        res.candidates = cands
        if not cands:
            res.note = f"no se hallo '{path_or_name}' en {image} (prueba con la ruta absoluta)"
            return res
        src = cands[0]
        step(f"encontrado en {src}" + (f" (+{len(cands)-1} mas)" if len(cands) > 1 else ""))
    res.src_path = src

    dest_dir = dest_dir or os.path.join(os.getcwd(), "fetched")
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        res.note = f"no se pudo crear {dest_dir}: {e}"
        return res
    local = os.path.join(dest_dir, os.path.basename(src))

    # docker create (no ejecuta el entrypoint) -> cp -> rm
    step(f"creando contenedor efimero de {image} (sin ejecutarlo)...")
    try:
        cid = subprocess.run([docker, "create", "--platform", "linux/amd64", image],
                             capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception as e:
        res.note = f"docker create fallo (imagen inexistente o sin red para descargarla): {e}"
        return res
    if not cid:
        res.note = "docker create no devolvio contenedor (revisa el nombre de la imagen)"
        return res
    try:
        step(f"copiando {src} -> {local}...")
        cp = subprocess.run([docker, "cp", f"{cid}:{src}", local],
                            capture_output=True, text=True, timeout=timeout)
        if cp.returncode != 0:
            res.note = f"docker cp fallo: {cp.stderr.strip()[:160]}"
            return res
    finally:
        subprocess.run([docker, "rm", "-f", cid], capture_output=True, text=True, timeout=60)

    if not os.path.exists(local):
        res.note = "la copia no produjo el fichero"
        return res
    # sanity: que sea un ELF
    try:
        with open(local, "rb") as f:
            magic = f.read(4)
    except OSError:
        magic = b""
    res.local_path = local
    res.ok = True
    if magic != b"\x7fELF":
        res.note = "aviso: el fichero extraido no parece un ELF (revisa la ruta)"
    step(f"binario extraido: {local}")
    return res


def render_fetch(res: FetchResult, lang: str = "es") -> str:
    es = lang == "es"
    if res.ok:
        out = [("## Binario extraido" if es else "## Fetched binary")]
        out.append((f"- Imagen: `{res.image}`\n- Origen: `{res.src_path}`\n- Local: `{res.local_path}`"
                    if es else
                    f"- Image: `{res.image}`\n- Source: `{res.src_path}`\n- Local: `{res.local_path}`"))
        if res.note:
            out.append(f"\n> {res.note}")
        out.append("\n" + ("Siguiente paso: " if es else "Next: ")
                   + f"`binoracle investigate <CVE> --binary {res.local_path}`")
        return "\n".join(out)
    msg = res.note or ("no se pudo extraer el binario" if es else "could not fetch the binary")
    extra = ""
    if res.candidates:
        extra = "\n" + ("candidatos:" if es else "candidates:") + "\n" + "\n".join(f"- {c}" for c in res.candidates)
    return ("## " + ("Extraccion fallida" if es else "Fetch failed") + "\n\n" + msg + extra)
