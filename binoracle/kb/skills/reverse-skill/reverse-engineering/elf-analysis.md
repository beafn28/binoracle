# ELF Binary Deep Analysis Reference

> Structure parsing, anti-reverse engineering identification, and analysis techniques for reversing Linux/Android ELF files.

---

## ELF Structure Quick Reference

### File Header (ELF Header)

```text
Offset  Size  Field              Description
0x00    4     e_ident[EI_MAG]   Magic: 7f 45 4c 46 ("\x7fELF")
0x04    1     e_ident[EI_CLASS] 1=32bit, 2=64bit
0x05    1     e_ident[EI_DATA]  1=LE, 2=BE
0x10    2     e_type            2=EXEC, 3=DYN(PIE/SO), 4=CORE
0x12    2     e_machine         0x03=x86, 0x3E=x86_64, 0xB7=AArch64, 0x28=ARM
0x18    8     e_entry           Entry point virtual address
0x20    8     e_phoff           Program header table offset
0x28    8     e_shoff           Section header offset (may be 0 after strip)
0x38    2     e_phnum           Number of program headers
0x3C    2     e_shnum           Number of section headers
```

### Program Header (Program Header)

```text
Type Value  Name       Description
0x01   PT_LOAD    Loadable segment (code/data)
0x02   PT_DYNAMIC Dynamic linking information
0x03   PT_INTERP  Interpreter path (/lib/ld-linux.so)
0x04   PT_NOTE    Auxiliary information
0x06   PT_PHDR    Program header table itself
0x6474e550 PT_GNU_EH_FRAME Exception handling
0x6474e551 PT_GNU_STACK      Stack executable marker
0x6474e552 PT_GNU_RELRO      Read-only relocation
```

### Common Sections

| Section Name | Description |
|--------------|-------------|
| `.text`      | Code segment |
| `.rodata`    | Read-only data (string constants) |
| `.data`      | Initialized global variables |
| `.bss`       | Uninitialized global variables |
| `.plt` / `.got` | Dynamic linking jump tables |
| `.init_array` | Array of constructor function pointers |
| `.fini_array` | Array of destructor function pointers |
| `.dynamic`   | Dynamic linking information |
| `.symtab` / `.dynsym` | Symbol table |
| `.strtab` / `.dynstr` | String table |

---

## Anti-Reverse Engineering Techniques Identification

### Common ELF Anti-Reversing Techniques

| Technique | Feature | Mitigation |
|-----------|---------|------------|
| Corrupt Program Header | PHDR filled with junk data (e.g., 0x0a) | Manually repair or ignore corrupted PHDR |
| No Section Header | `e_shoff = 0`, `e_shnum = 0` | Only analyze program header, not sections |
| Stripped Symbols (strip) | No `.symtab`, function names lost | GoReSym(Go) / signature matching / FLIRT |
| Static Linking | No `.dynamic`, large size | Use FLIRT/Lumina to identify library functions |
| Fake File Type | Suffix .sh/.txt/.jpg | Use `file` command / magic bytes to determine |
| UPX Packed | Contains `UPX!` marker | `upx -d` unpack |
| Custom Shellcode | Entry point jumps to decompression code | Run dynamically to OEP and dump |
| Anti-Debugging | ptrace(TRACEME) | LD_PRELOAD hook / patch |
| Anti-Virtual Machine | Checks /proc/cpuinfo | Modify cpuinfo or hook read access |
| Code Encryption | Runtime decryption of .text | Breakpoint at decryption and dump |

### Identifying Self-Decompressing/Modifying Code

```text
Features:
1. Near the entry point, there is a call to mmap(PROT_READ|PROT_WRITE|PROT_EXEC)
2. Followed by memcpy or loop copy
3. Then mprotect changes permissions
4. Finally br/jmp to the newly mapped address

Analysis Strategy:
1. Find the mmap call → Record the returned address
2. Set a breakpoint after mprotect(PROT_EXEC)
3. Dump the decompressed memory region
4. Use as new binary for analysis
```

## ARM64 (AArch64) Reverse Engineering Cheat Sheet

### Registers

| Register | Purpose |
|----------|---------|
| x0-x7    | Parameters/Return values |
| x8       | Indirect result (syscall number) |
| x9-x15   | Temporary registers |
| x16-x17  | IP0/IP1 (PLT jumps) |
| x18      | Platform register (Android: shadow call stack) |
| x19-x28  | Callee-saved |
| x29 (FP) | Frame pointer |
| x30 (LR) | Link register (return address) |
| SP       | Stack pointer |
| PC       | Program counter |

### Common Instruction Patterns

```text
Function prologue:
  stp x29, x30, [sp, #-N]!    # Save FP and LR
  mov x29, sp                  # Set frame pointer

Function epilogue:
  ldp x29, x30, [sp], #N      # Restore FP and LR
  ret                          # Return (br x30)

System call:
  mov x8, #NR                  # Syscall number
  svc #0                       # Trigger syscall

Conditional branch:
  cmp x0, #0
  b.eq label                   # Jump if equal
  b.ne label                   # Jump if not equal
  cbz x0, label                # Jump if x0 == 0
  cbnz x0, label               # Jump if x0 != 0

Address loading:
  adrp x0, page                # Load high part of page address
  add x0, x0, #offset          # Add low 12-bit offset
  ldr x0, [x1, #offset]        # Load from memory
```

### Linux ARM64 System Call Numbers

| Number | Name | Description |
|--------|------|-------------|
| 56     | openat | Open a file |
| 63     | read | Read data |
| 64     | write | Write data |
| 57     | close | Close a file descriptor |
| 222    | mmap | Memory mapping |
| 226    | mprotect | Change memory protection |
| 117    | ptrace | Process tracing |
| 220    | clone | Create a process/thread |
| 221    | execve | Execute a program |
| 93     | exit | Exit the current process |
| 94     | exit_group | Exit all threads in a process group |

---

## Common Compression/Archiving Algorithm Identification

| Algorithm | Identification Feature | Decompression Method |
|-----------|------------------------|----------------------|
| **LZSS**    | Bit stream + literal/match markers | Custom decompressor (as per this report) |
| **ZLIB/Deflate** | Magic: `78 01`/`78 9C`/`78 DA` | `zlib.decompress()` |
| **GZIP**    | Magic: `1F 8B` | `gzip -d` / `gunzip` |
| **LZ4**     | Magic: `04 22 4D 18` | `lz4 -d` |
| **LZMA/XZ** | Magic: `FD 37 7A 58 5A 00` (XZ) | `xz -d` / `lzma -d` |
| **Brotli**  | No fixed magic, context-dependent | `brotli -d` |
| **Zstandard** | Magic: `28 B5 2F FD` | `zstd -d` |
| **UPX**     | String `UPX!` | `upx -d` |
| **Custom**  | Entry point has decompression loop | Reverse the algorithm and write a decompressor |

### Clues for Identifying Custom Compression

```text
1. Loop + bit operations (shift, AND, OR) near the entry point
2. "Sliding window" back-copying (reading from output buffer backwards) → LZ series
3. Frequency table/Huffman tree construction → Deflate/Huffman
4. Fixed-size block processing → Block compression (LZ4/Snappy)
5. Arithmetic coding features (interval narrowing) → LZMA/ANS
```

## Linux Process Injection Techniques

### mmap + Code Injection

```text
Process:
1. mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
2. Write shellcode/payload to the mapped region
3. mprotect(addr, size, PROT_READ|PROT_EXEC)  # Change to executable
4. Jump to the mapped address and execute

Characteristics:
- mmap return value is saved
- Followed by memcpy or loop write
- Then mprotect changes permissions
- Finally br/blr to that address
```

### ptrace Injection

```text
Process:
1. ptrace(PTRACE_ATTACH, target_pid)
2. waitpid(target_pid)
3. ptrace(PTRACE_GETREGS, target_pid, &regs)
4. Modify regs.pc to point to injected code
5. ptrace(PTRACE_SETREGS, target_pid, &regs)
6. ptrace(PTRACE_CONT, target_pid)

Characteristics:
- Open /proc/<pid>/mem or use ptrace
- Read/modify target process registers
- Write shellcode to target process space
```

### /proc/self/mem Self-Modification

```text
Process:
1. open("/proc/self/mem", O_RDWR)
2. lseek(fd, target_addr, SEEK_SET)
3. write(fd, new_code, size)

Purpose:
- Bypass W^X protection (mmap pages cannot be both W+X)
- Modify self code segment (.text is usually read-only)
- Run-time patch instructions
```

---

## Strategies for Analyzing Large ELF Files

For 5MB+ large binaries:

```text
1. Rapid Reconnaissance (5 minutes)
   - file / rabin2 -I → Architecture, type, protections
   - strings | grep -i "error\|fail\|http\|/proc\|/dev" → Key strings
   - rabin2 -i → Imported functions (if any)
   - rabin2 -E → Exported functions

2. Structural Analysis (10 minutes)
   - readelf -l → Program headers (LOAD segment layout)
   - Code near the entry point → Whether there is decompression/decryption
   - Find .init_array → Constructor functions (may have anti-debugging)

3. Locating Key Logic
   - From string cross-references
   - From system calls (mmap/ptrace/open)
   - From network functions (connect/send/recv)

4. Divide and Conquer
   - If self-extracting → First extract, analyze payload
   - If multi-module → Analyze by function blocks
   - Use binary-diff to compare different versions
```

---

## Tool Command Cheat Sheet

```bash
# Basic Information
file binary
readelf -h binary          # ELF header
readelf -l binary          # Program headers
readelf -S binary          # Sections (if any)
rabin2 -I binary           # Comprehensive information

# Strings
strings -a binary | less
rabin2 -z binary           # Data section strings
rabin2 -zz binary          # Full file strings

# Disassembly
r2 -A binary               # radare2 analysis
objdump -d binary          # GNU disassembly
aarch64-linux-gnu-objdump -d binary  # ARM64 cross-disassembly

# Dynamic Analysis
strace -f ./binary         # System call tracing
ltrace -f ./binary         # Library function tracing
qemu-aarch64 -strace ./binary  # ARM64 simulation execution

# Memory dump
gdb -p <pid> -ex "dump memory out.bin 0xADDR 0xADDR+SIZE" -ex quit

# Repairing Damaged ELF
# Manually modify e_phnum or patch damaged PHDR
python -c "
import struct
with open('binary', 'r+b') as f:
    f.seek(0x38)  # e_phnum offset (64-bit)
    f.write(struct.pack('<H', 2))  # Modify to correct PHDR count
"
```