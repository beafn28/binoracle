#!/usr/bin/env python3
"""docker_cleanup.py — limpieza proactiva de Docker antes de labs.

Libera build cache y volúmenes huérfanos cuando el espacio reclaimable supera
el umbral (por defecto 8 GB) para evitar fallos ENOSPC en MySQL al levantar labs.

Uso:
  python3 scripts/docker_cleanup.py           # umbral por defecto (8 GB)
  python3 scripts/docker_cleanup.py --gb 4    # umbral personalizado
  python3 scripts/docker_cleanup.py --dry-run # solo muestra lo que haría
"""
import argparse
import json
import re
import subprocess
import sys


_DEFAULT_THRESHOLD_GB = 8.0


def _parse_size_gb(raw: str) -> float:
    """Convierte '16.09GB (100%)', '514MB', '0B' → float GB."""
    m = re.match(r"([\d.]+)\s*(GB|MB|KB|B)", raw or "")
    if not m:
        return 0.0
    val, unit = float(m.group(1)), m.group(2)
    return val if unit == "GB" else val / 1024 if unit == "MB" else val / (1024 ** 2)


def get_reclaimable_gb() -> float:
    """Devuelve el total de espacio reclaimable en Docker (build cache + volúmenes)."""
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


def prune(dry_run: bool = False) -> float:
    """Ejecuta la limpieza y devuelve los GB liberados (aproximado)."""
    before = get_reclaimable_gb()
    if dry_run:
        print(f"[dry-run] espacio reclaimable: {before:.1f} GB (no se hace nada)")
        return 0.0

    subprocess.run(["docker", "builder", "prune", "-f"],
                   capture_output=True, timeout=120)
    subprocess.run(["docker", "volume", "prune", "-f"],
                   capture_output=True, timeout=60)
    after = get_reclaimable_gb()
    return max(0.0, before - after)


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
        print(f"[docker_cleanup] por debajo del umbral — sin limpieza necesaria")
        return 0

    freed = prune(dry_run=args.dry_run)
    if not args.dry_run:
        print(f"[docker_cleanup] liberados ~{freed:.1f} GB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
