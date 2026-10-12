"""Execution sandbox for exploit drivers: Docker when available, native otherwise.

The exploit workflows (autoheap/autopie/autofmt/...) verify an exploit by RUNNING it. The
preferred isolation is the `binoracle-pwn` Docker image (`--network none`, memory/pids caps,
ASLR off). But that image is absent in many real environments (CI, cloud containers, a dev box
that never ran `make pwn-image`), which silently downgraded every "verified by execution" claim
to "not available".

This module adds a NATIVE fallback that keeps the verification real with OS-level isolation
instead of a container:

- `unshare -rn`  -> a rootless user+network namespace, so the target has no network (the same
  guarantee as `docker --network none`); degrades to `unshare -n`, then to none, if unavailable.
- `setarch -R`   -> ASLR disabled, which the PIE/base-resolution exploits require and the
  leak-based ones tolerate.
- `resource` rlimits (CPU, address space, procs, file size, no core dump) via preexec, so a
  runaway or fork-bombing target cannot take the host down.

For AUTHORIZED / CTF targets only. Docker stays the default when present; native engages only
as a fallback, and the result records WHICH engine verified the exploit so reports stay honest.
"""
from __future__ import annotations

import os
import platform
import resource
import shlex
import shutil
import struct
import subprocess

_EM_X86_64 = 0x3E

# Probed once per process: does `unshare` give us a usable net namespace here?
_NET_PREFIX_CACHE: list | None = None


def _elf_machine(path: str):
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if head[:4] != b"\x7fELF" or len(head) < 20:
        return None
    return struct.unpack_from("<H", head, 18)[0]


def _host_target_ok(binary: str) -> tuple[bool, str]:
    """Host/target preconditions common to every native run: Linux x86-64 host, x86-64 ELF
    target, and `setarch` (to turn ASLR off). Network isolation via `unshare` is optional."""
    if platform.system() != "Linux":
        return False, "host no es Linux"
    if platform.machine() not in ("x86_64", "amd64"):
        return False, "host no es x86-64"
    if _elf_machine(binary) != _EM_X86_64:
        return False, "el binario no es ELF x86-64 (el runner nativo es x86-64)"
    if not shutil.which("setarch"):
        return False, "falta 'setarch' (necesario para desactivar ASLR)"
    return True, "ok"


def native_available(binary: str) -> tuple[bool, str]:
    """(ok, reason) for a native pwntools DRIVER run: the host/target preconditions plus
    pwntools on the host. (A raw-binary run uses `_host_target_ok` directly, no pwntools.)"""
    ok, why = _host_target_ok(binary)
    if not ok:
        return ok, why
    try:
        import pwn  # noqa: F401
    except Exception:
        return False, "falta pwntools en el host"
    return True, "ok"


def _rlimit_preexec(cpu_s: int, mem_mb: int):
    def _apply():
        for res, lim in (
            (resource.RLIMIT_CPU, (cpu_s, cpu_s + 2)),
            (resource.RLIMIT_AS, (mem_mb * 1024 * 1024,) * 2),
            (resource.RLIMIT_NPROC, (256, 256)),
            (resource.RLIMIT_FSIZE, (32 * 1024 * 1024,) * 2),
            (resource.RLIMIT_CORE, (0, 0)),
        ):
            try:
                resource.setrlimit(res, lim)
            except (ValueError, OSError):
                pass
    return _apply


def _net_prefix() -> list:
    """Best-effort command prefix that puts the child in a network-less namespace (mirrors
    `docker --network none`). Cached. Empty list if unshare can't give us one here."""
    global _NET_PREFIX_CACHE
    if _NET_PREFIX_CACHE is not None:
        return _NET_PREFIX_CACHE
    _NET_PREFIX_CACHE = []
    if shutil.which("unshare"):
        for flags in (["-rn"], ["-n"]):
            try:
                if subprocess.run(["unshare", *flags, "true"],
                                  capture_output=True, timeout=5).returncode == 0:
                    _NET_PREFIX_CACHE = ["unshare", *flags]
                    break
            except Exception:
                continue
    return _NET_PREFIX_CACHE


def run_native(binary: str, driver_path: str, args=None, timeout: int = 90,
               cpu_s: int = 40, mem_mb: int = 2560) -> str:
    # 2.5 GB: pwntools' ROP may spin up Unicorn (wants ~1 GB) to populate the PLT; a tighter cap
    # makes gadget/ROP drivers fail with "Cannot allocate ... Unicorn". Still bounds a runaway.
    """Run `driver_path <basename> [args]` against `binary` natively, ASLR off, network-isolated
    (best effort) and resource-capped. Returns combined stdout+stderr (or a '[timeout]' marker)."""
    name = os.path.basename(binary)
    d = os.path.dirname(os.path.abspath(binary))
    try:
        os.chmod(os.path.join(d, name), 0o755)
    except OSError:
        pass
    cmd = _net_prefix() + ["setarch", platform.machine(), "-R",
                           "python3", os.path.basename(driver_path), name] + list(args or [])
    try:
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout,
                           preexec_fn=_rlimit_preexec(cpu_s, mem_mb))
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        partial = ""
        try:
            partial = (e.output or "") + (e.stderr or "")
            if isinstance(partial, bytes):
                partial = partial.decode("latin-1", "replace")
        except Exception:
            partial = ""
        return "[timeout] " + partial


def run_bash(binary: str, bash_cmd: str, timeout: int = 120, mem_mb: int = 512) -> tuple:
    """Run an arbitrary bash pipeline against `binary` (the command refers to it as ./<name>
    and to sibling files the caller wrote in the binary's dir), preferring the binoracle-pwn
    Docker image and falling back to native isolation (unshare/setarch/rlimits). No pwntools
    needed -- this runs the raw target (e.g. feeding a ret2win payload on stdin). Returns
    (engine | None, output); engine is None only when neither Docker nor native can run it."""
    d = os.path.dirname(os.path.abspath(binary))
    if _docker_image_ok():
        try:
            r = subprocess.run(
                ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                 "--memory", "256m", "--pids-limit", "128", "-v", d + ":/w", "-w", "/w",
                 "binoracle-pwn", "bash", "-c", bash_cmd],
                capture_output=True, text=True, timeout=timeout)
            return "docker", (r.stdout or "") + (r.stderr or "")
        except subprocess.TimeoutExpired:
            return "docker", "[timed out]"
    ok, reason = _host_target_ok(binary)
    if not ok:
        return None, reason
    cmd = _net_prefix() + ["setarch", platform.machine(), "-R", "bash", "-c", bash_cmd]
    try:
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout,
                           preexec_fn=_rlimit_preexec(min(timeout, 60), mem_mb))
        return "native", (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return "native", "[timed out]"


def _docker_image_ok(timeout: int = 15) -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", "binoracle-pwn"],
                              capture_output=True, timeout=timeout).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def run_driver(binary: str, driver_src: str, tmpname: str, args=None,
               timeout_docker: int = 200, timeout_native: int = 90) -> dict:
    """Write `driver_src` next to `binary` and execute it, preferring the binoracle-pwn Docker
    image and falling back to the native sandbox. Returns a dict with ok/verified/detail/output
    plus `engine` ('docker' or 'native') so callers/reports record HOW it was verified.

    The driver must print a line starting 'VERIFIED' on success and 'NOT_VERIFIED'/'ERROR'
    otherwise (the shared convention across all exploit drivers)."""
    d = os.path.dirname(os.path.abspath(binary))
    name = os.path.basename(binary)
    if not os.path.isdir(d):
        return {"ok": False, "note": f"directorio del binario inexistente: {d}"}

    engine = None
    if _docker_image_ok():
        engine = "docker"
    else:
        nat_ok, nat_reason = native_available(binary)
        if nat_ok:
            engine = "native"
        else:
            hint = "falta la imagen 'binoracle-pwn' (make pwn-image)"
            if shutil.which("docker"):
                return {"ok": False, "note": f"{hint}; y sin runner nativo: {nat_reason}"}
            return {"ok": False, "note": f"docker no disponible y sin runner nativo: {nat_reason}"}

    drv = os.path.join(d, tmpname)
    try:
        with open(drv, "w") as f:
            f.write(driver_src)
    except OSError as e:
        return {"ok": False, "note": f"no se pudo escribir el driver: {e}"}
    extra = " ".join(shlex.quote(str(a)) for a in (args or []))
    try:
        if engine == "docker":
            qn, qt = shlex.quote(name), shlex.quote(tmpname)
            try:
                r = subprocess.run(
                    ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                     "--memory", "512m", "--pids-limit", "256", "--security-opt", "seccomp=unconfined",
                     "-v", d + ":/w", "-w", "/w", "binoracle-pwn", "bash", "-c",
                     f"chmod +x ./{qn}; python3 {qt} {qn} {extra}".rstrip()],
                    capture_output=True, text=True, timeout=timeout_docker)
                out = (r.stdout or "") + (r.stderr or "")
            except subprocess.TimeoutExpired:
                out = "[timeout]"
        else:
            out = run_native(binary, drv, args=args, timeout=timeout_native)
    finally:
        try:
            os.unlink(drv)
        except OSError:
            pass

    verified = "VERIFIED" in out and "NOT_VERIFIED" not in out
    line = next((l for l in out.splitlines() if l.startswith("VERIFIED")), "")
    return {"ok": True, "verified": verified, "detail": line, "output": out[-600:], "engine": engine}
