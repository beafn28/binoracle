# 2026-07-14 Android ARM64 自解压程序源码恢复

## 场景分类

Binary Analysis / Android ARM64 / Self-extracting Shell / Control Flow Flattening

## Target Overview

To recover the read-only source code of a user-owned local `.sh` delivery package, to extract multi-layer compressed payloads, to analyze the ARM64 main program and protection library, and to restore business text and high-level pseudo-source code without running the target.

## Complete Execution Chain

1. Conduct a read-only inventory, size, magic number, and SHA-256 triage on the input directory without reading or recording any plaintext credentials.
2. Identify the first layer as "Shell prefix + bzip2 trailing stream", locate the precise offset through `BZh` valid stream testing.
3. Save the prefix, compressed stream, and decompression payload in an independent Chinese product directory without executing the payload.
4. Identify the second layer as the `__ARCHIVE_BELOW__` self-extracting script, safely expand tar.gz while rejecting absolute paths, `..`, links, and device nodes.
5. Obtain the Android AArch64 PIE main program and AArch64 shared library; use pyelftools/Capstone to generate ELF header, sections, symbols, imports, strings, and entry disassembly.
6. Retain readable C++ symbols in the protection library, export pseudo-code for each function, confirm `/proc` scanning, `TracerPid`, three-level process termination, and background thread behavior.
7. The symbol length of the main program's `main` is significantly greater than the typical CFG recognition length, confirming indirect jump control flow flattening.
8. Static resolution of jump tables: `target = table_entry + fixed_delta`, enumerate all unique true basic blocks.
9. Scan for isomorphic string decryptors to identify the "first N bytes loop XOR key + last M bytes ciphertext" layout.
10. For each true basic block, execute AArch64 constant propagation to parse the target and `x1` data source of indirect decryption calls, batch recover business text.
11. Deliver complete disassembly, function-by-function pseudo-code, high-level semantic source code, Mermaid flow diagrams, and formal reports.
12. Recalculate the original input hash to confirm consistency before and after analysis.

## Pitfall Records

| Issue | Reason | Solution | Time |
|---|---|---|---|
| PowerShell directly running bootstrap intercepted by execution policy | System prohibits scripts | Use a single `powershell.exe -ExecutionPolicy Bypass -File ...` without changing the permanent policy | Low |
| radare2 bootstrap returns GitHub API 403 | API rate limiting/rejection, but release page is accessible | Get official assets and page SHA-256 from `releases/latest` 302 and `expanded_assets/<tag>`, verify and extract | Medium |
| winget's Rizin silent/user scope installation does not take effect | Installer scope mismatch | Stop retrying after two failures, switch back to the verified radare2 official ZIP | Low |
| `r2pm -U` hangs at git clone | Network speed/recursive repository | Terminate optional plugin route, continue using `pdc` + Capstone custom recovery | High |
| radare2 only recognizes CFG of `main` prefix | Indirect BR jump table makes conventional analysis end at the distributor | Enumerate true blocks by jump table formula, not relying on default CFG | Medium |
| Direct string scan sees only a few paths | Text uses independent loop XOR for each string | Extract key/output lengths from decryptor instructions, statically replay algorithm | Medium |

## Toolchain Discovery

- Python 3.13 standard library is sufficient to safely handle bzip2 and tar.gz; `tarfile.extractall` is less secure than verifying members individually before writing.
- pyelftools can recover ELF/DYNSYM/RELA, Capstone is suitable for AArch64 constant propagation and specialized decryptor recognition.
- radare2 6.1.8's `pdc` is effective for unobfuscated protection library functions but only provides partial pseudo-code for the indirect BR flattened main function.
- GitHub API 403 does not mean official release page assets are inaccessible; the release page can provide tag, asset name, and SHA-256.

## Key Code/Commands

```python
# General loop XOR text layout
key = blob[:key_length]
encrypted = blob[key_length:key_length + output_length]
plain = bytes(value ^ key[index % key_length]
              for index, value in enumerate(encrypted))
```

```python
# Static resolution of jump tables
targets = {
    (entry + fixed_delta) & 0xFFFFFFFFFFFFFFFF
    for entry in jump_table_entries
}
```

```powershell
# Get latest tag when API 403
curl.exe -sS -I '<official-release-url>/radareorg/radare2/releases/latest'
```

## Suggestions for Improvements to This Package

- Add a target type route for ".sh" self-extracting伪装二进制, to avoid misidentification as pure Shell review.
- The Windows GitHub Release bootstrap should fall back to the release page/expanded_assets and enforce SHA-256 verification when API 403 occurs.
- A new "ARM64 jump table + loop XOR" generic recovery script template can be added as a low-dependency route when IDA is not available.
- When tool calls exceed the foreground window, session id must be retained and polled to avoid losing running download or export tasks.

## Reusable Patterns/Script Snippets

1. Scan valid compressed streams instead of just looking for magic numbers; fully decompress each candidate offset in memory for testing.
2. Self-extracting archives should always safely write members one by one, without executing or trusting member paths directly.
3. When the function lengths declared in the symbol table are much longer than those recognized by CFG, prioritize checking indirect tables via BR/BLR instructions.
4. Homogeneous decryptors can be identified in bulk using a combination of `add x16,x1,#key_len`、`cmp w16,#output_len`、`ldrb/eor/strb` instructions.
5. Local constant propagation on flattened blocks is usually sufficient to recover indirect function targets and string source addresses, without fully unflattening.

## Evolution Actions

- [x] Updated routing matrix
- [x] Updated tool-index
- [ ] Updated bootstrap-manifest
- [ ] Updated sub-skill documentation
- [x] Added pitfalls record
- [ ] No update needed

## Environment Information

- OS: Windows
- Tool versions: Python 3.13; radare2 6.1.8; pyelftools; Capstone
- Target platform/version: Android ARM64, NDK r17 / Clang 6.0.2

## De-sensitization Check

- No software name, author name, real domain name, real API endpoint, credentials, fixed signature materials, business package names, or local user paths were recorded.
- No sample files or sample hashes were attached.
- Only public tool names, versions, and general algorithm patterns were retained.

## Index Synchronization

This record has been added to the "Binary / Firmware / CTF" category in `_index.md` and statistics have been updated.

---
<!-- [Community Contribution] After completion, ask the user if they want to PR to the main repository. Process details are in CONTRIBUTE-BACK.md -->