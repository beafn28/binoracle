"""pwntools exploit skeleton generator.

Turns the grounded facts (arch, mitigations, sink, offset if known) into a ready-to-fill
pwntools script. It generates a TEMPLATE for a target you are authorized to test, not a
weaponized exploit: the payload body is left for you to complete against your own target."""
from __future__ import annotations

from typing import Optional

from ..oracles.base import ToolRegistry


def _pwn_arch(arch: str, bits: str) -> str:
    """Map radare2 arch+bits to a pwntools context.arch value."""
    a = arch.lower()
    if "arm" in a or "aarch" in a:
        return "aarch64" if bits == "64" else "arm"
    if "mips" in a:
        return "mips"
    if "ppc" in a or "power" in a:
        return "powerpc64" if bits == "64" else "powerpc"
    # x86 family (radare reports "x86")
    return "amd64" if bits == "64" else "i386"


def generate_skeleton(registry: ToolRegistry, binary: str,
                      offset: Optional[int] = None, primitive: str = "auto") -> str:
    checksec = registry.get("r2_checksec")
    meta = {}
    if checksec:
        r = checksec.run()
        if r.ok:
            meta = r.meta
    nx = str(meta.get("nx", "unknown"))
    pic = str(meta.get("pic", "unknown"))
    canary = str(meta.get("canary", "unknown"))
    bits = str(meta.get("bits", "64"))
    pwn_arch = _pwn_arch(str(meta.get("arch", "x86")), bits)

    off_line = f"OFFSET = {offset}" if offset is not None else "OFFSET = None  # find with: binoracle ... / cyclic_offset"

    notes = []
    if canary.lower() in ("true", "1"):
        notes.append("# canary present: you must leak it and place it back in the payload")
    if pic.lower() in ("true", "1"):
        notes.append("# PIE/PIC on: addresses are randomized -> leak a base first")
    if nx.lower() in ("false", "0", "nx_off"):
        notes.append("# NX off: stack shellcode is viable")
    else:
        notes.append("# NX on: no stack shellcode -> ROP / ret2libc")
    notes_block = "\n".join(notes) if notes else "# (no special mitigations detected)"

    return f'''#!/usr/bin/env python3
# binoracle-generated exploit skeleton
# target: {binary}
# mitigations: NX={nx} PIE/PIC={pic} canary={canary} arch={pwn_arch}
# NOTE: template for an AUTHORIZED target (your own / CTF). Fill in the payload.
from pwn import *

context.update(arch={pwn_arch!r}, os='linux')
elf = context.binary = ELF({binary!r})
# libc = ELF('./libc.so.6')  # uncomment for ret2libc

{off_line}

def start():
    if args.REMOTE:
        return remote('HOST', 1337)
    return process(elf.path)

{notes_block}

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
    payload = flat({{
        OFFSET: [
            # >>> build your chain here <<<
            # ret2win:   elf.symbols['win']
            # ret2libc:  rop = ROP(elf); rop.raw(rop.find_gadget(['ret'])); ...
        ]
    }})
    io.sendline(payload)
    io.interactive()

if __name__ == '__main__':
    exploit()
'''
