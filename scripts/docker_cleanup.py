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
    """Elimina contenedores parados con nombre binoracle-* o bo_*. Devuelve nº eliminados."""
    removed = 0
    try:
        for name_prefix in ("binoracle", "bo_"):
            r = subprocess.run(
                ["docker", "ps", "-a", "-q",
                 "--filter", f"name={name_prefix}",
                 "--filter", "status=exited",
                 "--filter", "status=created",
                 "--filter", "status=dead"],
                capture_output=True, text=True, timeout=15,
            )
            ids = [x for x in r.stdout.strip().splitlines() if x]
            if ids:
                subprocess.run(["docker", "rm", "-f"] + ids,
                               capture_output=True, timeout=30)
                removed += len(ids)
    except Exception:
        pass
    return removed


def prune_binoracle_images() -> int:
    """Elimina imágenes de labs (binoracle-*, bo_*) no usadas por ningún contenedor activo.
    Preserva imágenes base (wordpress, mysql, httpd, python, node, etc.).
    Devuelve nº de imágenes eliminadas."""
    removed = 0
    try:
        # get all container image IDs (running or stopped) so we don't remove them
        r_active = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Image}}"],
            capture_output=True, text=True, timeout=15,
        )
        active_imgs = set(r_active.stdout.strip().splitlines())

        r = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}"],
            capture_output=True, text=True, timeout=15,
        )
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            repo_tag, img_id = parts
            repo = repo_tag.split(":")[0]
            # only remove binoracle lab images, not base images
            if not (repo.startswith("binoracle") or repo.startswith("bo_")):
                continue
            if repo_tag in active_imgs or img_id in active_imgs:
                continue
            subprocess.run(["docker", "rmi", "-f", img_id],
                           capture_output=True, timeout=60)
            removed += 1
    except Exception:
        pass
    return removed


def prune(dry_run: bool = False) -> float:
    """Limpieza completa: contenedores parados → imágenes lab → dangling → volúmenes → cache."""
    before = get_reclaimable_gb()
    if dry_run:
        # count what would be removed
        r = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}"],
            capture_output=True, text=True, timeout=15,
        )
        lab_imgs = [(ln.split("\t")[0], ln.split("\t")[1])
                    for ln in r.stdout.strip().splitlines()
                    if ln.split("\t")[0].split(":")[0].startswith(("binoracle", "bo_"))]
        print(f"[dry-run] {before:.1f} GB reclaimable; "
              f"{len(lab_imgs)} lab image(s) elegibles: "
              + ", ".join(f"{n}({s})" for n, s in lab_imgs[:5]))
        return 0.0

    # 1. contenedores binoracle/bo_ parados
    prune_binoracle_containers()

    # 2. imágenes de labs (binoracle-*, bo_*) — la mayor fuente de uso
    prune_binoracle_images()

    # 3. imágenes dangling (sin tag)
    subprocess.run(["docker", "image", "prune", "-f"],
                   capture_output=True, timeout=60)

    # 4. volúmenes huérfanos
    subprocess.run(["docker", "volume", "prune", "-f"],
                   capture_output=True, timeout=60)

    # 5. build cache
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
        # Aun así limpia contenedores binoracle parados e imágenes de lab huérfanas
        nc = prune_binoracle_containers()
        ni = prune_binoracle_images()
        if nc or ni:
            print(f"[docker_cleanup] eliminados {nc} contenedor(es) y {ni} imagen(es) de lab")
        print(f"[docker_cleanup] por debajo del umbral — sin limpieza completa necesaria")
        return 0

    freed = prune(dry_run=args.dry_run)
    if not args.dry_run:
        print(f"[docker_cleanup] liberados ~{freed:.1f} GB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
