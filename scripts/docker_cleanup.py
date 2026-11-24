#!/usr/bin/env python3
"""docker_cleanup.py — limpieza proactiva y post-lab de Docker.

Libera: contenedores parados, imágenes dangling, volúmenes huérfanos,
build cache — en cuanto el espacio reclaimable supera el umbral (3 GB).
Se llama automáticamente al inicio de cada investigación y al finalizar.

Uso:
  python3 scripts/docker_cleanup.py           # umbral por defecto (3 GB)
  python3 scripts/docker_cleanup.py --gb 1    # umbral personalizado
  python3 scripts/docker_cleanup.py --dry-run # solo muestra lo que haría
  python3 scripts/docker_cleanup.py --force   # purga siempre
"""
import argparse
import json
import re
import subprocess
import sys


_DEFAULT_THRESHOLD_GB = 3.0


def _parse_size_gb(raw: str) -> float:
    """Convierte '16.09GB (100%)', '514MB', '0B' → float GB."""
    m = re.match(r"([\d.]+)\s*(GB|MB|KB|B)", raw or "")
    if not m:
        return 0.0
    val, unit = float(m.group(1)), m.group(2)
    return val if unit == "GB" else val / 1024 if unit == "MB" else val / (1024 ** 2)


def get_reclaimable_gb() -> float:
    """Devuelve el total de espacio reclaimable en Docker."""
    try:
        out = subprocess.check_output(
            ["docker", "system", "df", "--format", "{{json .}}"],
            timeout=15, stderr=subprocess.DEVNULL,
        ).decode()
    except Exception:
        return 0.0

    total = 0.0
    for line in out.strip().splitlines():
        try:
            obj = json.loads(line)
            total += _parse_size_gb(obj.get("Reclaimable", "0B"))
        except Exception:
            pass
    return total


def prune_binoracle_containers() -> int:
    """Elimina contenedores parados con nombre binoracle-*. Devuelve nº eliminados."""
    removed = 0
    try:
        r = subprocess.run(
            ["docker", "ps", "-a", "-q",
             "--filter", "name=binoracle",
             "--filter", "status=exited",
             "--filter", "status=created",
             "--filter", "status=dead"],
            capture_output=True, text=True, timeout=15,
        )
        ids = [x for x in r.stdout.strip().splitlines() if x]
        if ids:
            subprocess.run(["docker", "rm", "-f"] + ids,
                           capture_output=True, timeout=30)
            removed = len(ids)
    except Exception:
        pass
    return removed


def prune(dry_run: bool = False) -> float:
    """Limpieza completa: contenedores parados → imágenes dangling → volúmenes → build cache."""
    before = get_reclaimable_gb()
    if dry_run:
        print(f"[dry-run] espacio reclaimable: {before:.1f} GB (no se hace nada)")
        return 0.0

    # 1. contenedores binoracle parados
    n = prune_binoracle_containers()
    if n:
        pass  # silencioso en llamadas programáticas

    # 2. imágenes dangling (sin tag, sin contenedor que las use)
    subprocess.run(["docker", "image", "prune", "-f"],
                   capture_output=True, timeout=60)

    # 3. volúmenes huérfanos
    subprocess.run(["docker", "volume", "prune", "-f"],
                   capture_output=True, timeout=60)

    # 4. build cache (el que más ocupa)
    subprocess.run(["docker", "builder", "prune", "-f"],
                   capture_output=True, timeout=120)

    after = get_reclaimable_gb()
    return max(0.0, before - after)


def prune_if_needed(threshold_gb: float = _DEFAULT_THRESHOLD_GB) -> tuple:
    """Llama a prune() solo si el espacio reclaimable supera el umbral.
    Devuelve (did_prune: bool, freed_gb: float)."""
    # Siempre limpia contenedores binoracle parados (coste mínimo, ganancia segura)
    prune_binoracle_containers()

    recl = get_reclaimable_gb()
    if recl >= threshold_gb:
        freed = prune()
        return True, freed
    return False, 0.0


def main():
    parser = argparse.ArgumentParser(description="Limpieza proactiva de Docker para binoracle labs")
    parser.add_argument("--gb", type=float, default=_DEFAULT_THRESHOLD_GB,
                        help=f"Umbral en GB (default {_DEFAULT_THRESHOLD_GB}). "
                             "Si el espacio reclaimable supera este valor, se purga.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo muestra lo que haría, sin purgar.")
    parser.add_argument("--force", action="store_true",
                        help="Purga siempre, independientemente del umbral.")
    args = parser.parse_args()

    reclaimable = get_reclaimable_gb()
    print(f"[docker_cleanup] espacio reclaimable: {reclaimable:.1f} GB (umbral: {args.gb} GB)")

    if not args.force and reclaimable < args.gb:
        # Aun así limpia contenedores binoracle parados
        n = prune_binoracle_containers()
        if n:
            print(f"[docker_cleanup] eliminados {n} contenedor(es) binoracle parados")
        print(f"[docker_cleanup] por debajo del umbral — sin limpieza completa necesaria")
        return 0

    freed = prune(dry_run=args.dry_run)
    if not args.dry_run:
        print(f"[docker_cleanup] liberados ~{freed:.1f} GB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
