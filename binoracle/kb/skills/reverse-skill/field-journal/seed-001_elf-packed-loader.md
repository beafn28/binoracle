# [Seed] ELF Self-Extracting Loader Reverse Engineering

## Scenario Classification
Binary Analysis

## Target Overview
Analyze an ARM64 ELF self-extracting loader disguised as a .sh script, and reverse-engineer its decompression algorithm and payload injection process.

## Complete Execution Chain

1. `file` command confirms the true type (ELF, not a shell script)
2. `readelf -l` examines the program headers → discovers the 3rd PHDR is intentionally corrupted (0x0a padding)
3. `rabin2 -I` retrieves architecture (AArch64), entry point, and compiler information
4. IDA/Ghidra loads → starts analysis from the entry point
5. Identifies the LZSS decompression loop (bitstream operations + sliding window copy)
6. Identifies mmap → decompress → mprotect → jump injection process
7. Rewrites the decompressor in Python to dump the payload
8. Analyzes the payload content (contains /proc/self/exe reference, indicating a process injector)

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| `readelf` error parsing | 3rd PHDR intentionally filled with 0x0a | Ignore corrupted PHDR, only look at the first 2 LOAD segments | 10min |
| IDA disassembly unreadable | ARM64 has dense bit operations, Hex-Rays optimization is poor | Switch to assembly view for manual analysis | 30min |
| Incorrect output from Python decompressor | pop_bit refill path return value wrong (adcs vs adds) | Carefully compare with assembly, refill returns the new loaded byte's bit31 | 2h |
| Uncertain payload entry offset | Meaning of entry_offset field in data table unclear | Trace loader function `br mmap_base + 0x14`, confirm entry at +0x14 | 20min |

## Toolchain Discovery

- `file` command is the first step, never trust file extensions
- `rabin2 -I` is more forgiving than `readelf` (can handle corrupted PHDRs)
- Code with dense ARM64 bit operations is better analyzed directly in assembly
- Python struct module + custom decompressor implementation is the standard method for analyzing custom compression

## Key Code/Commands

```bash
# Confirm file type
file LinYuDriverLoader4.9.sh
# ELF 64-bit LSB executable, ARM aarch64

# Examine program headers
readelf -l binary 2>/dev/null | head -20

# Extract compressed data
dd if=binary bs=1 skip=$((0xa6a24)) count=1981 of=compressed.bin

# Calculate file offset
# vaddr 0x3d66bc → file_offset = 0x3d66bc - 0x330000 = 0xa66bc
```

```python
# LZSS decompressor core (simplified)
def decompress(data):
    shift_reg = 0x80000000
    # ... bitstream read + literal/match branches
```

## Suggestions for Improvements to This Package

- `elf-analysis.md` should include more features for identifying custom compression algorithms
- ARM64 syscall table should include descriptions of cache maintenance instructions (dc cvau / ic ivau)
- Suggest adding a general methodology for rewriting assembly algorithms in Python

## Reusable Patterns/Script Snippets

**Standard pattern for identifying self-extracting ELF files:**
```text
Entry point → Minimal initialization → Call decompression function → mmap(RW) → Decompress to mmap region → mprotect(RX) → Jump
```

**General pattern for ARM64 bitstream reading:**
```text
lsl w4, w4, #1    # Left shift (extract highest bit to carry)
cbz w4, refill    # If emptied, load new 32-bit from input
```

## Evolution Actions
- [x] Updated the sub-skill document (elf-analysis.md has been updated)
- [ ] No need to update the routing matrix
- [ ] No need to update bootstrap-manifest

## Environment Information
- OS: Linux/Android ARM64 target
- Tool versions: IDA Pro / Ghidra + radare2
- Target platform: Android ARM64 (AArch64)

## Desensitization Requirements
This entry is seed data based on public technical patterns and does not involve real targets.

---
<!-- [Community Contribution] Seed data, no need for PR -->