# 2026-07-20 Windows Reverse Engineering Toolchain Full Bootstrapping

## Scenario Classification

Other / Toolchain and Environment

## Target Overview

Install and verify a reverse engineering toolchain covering native, managed, Android, firmware, protocol, forensics, browser, and MCP on a Windows 24H2 host.

## Complete Execution Chain

1. Read the shared `tool-index`, reuse installed tools first.
2. Run a generic PATH probe to fill in static, dynamic, firmware, and protocol tools as needed.
3. For large files, extract URLs and SHA-256 from a trusted list using `aria2c` with disabled IPv6 for direct downloads.
4. Create a unified entry point `{user_profile}\Tools\reverse-bin` for portable tools.
5. Build and register Ghidra, IDA, JS, browser traffic, and Burp MCP.
6. Validate tools using real PE/APK/.NET/PYC/WASM/firmware fixtures, not just running version commands.
7. Refresh the shared `tool-index` and output an official installation report and flowchart.

## Pitfall Records

| Issue | Cause | Solution | Time |
|---|---|---|---|
| winget large file download no progress | Delivery Optimization unstable with default IPv6 path | Fetch official URL/checksum from winget metadata, use `aria2c --disable-ipv6=true` | High |
| anything-analyzer SQLite ABI mismatch | Common `pnpm rebuild better-sqlite3` builds Node ABI while Electron needs Electron ABI | Use project's `pnpm run postinstall` | Medium |
| WSL service 1053, system feature does not exist | Windows image trimmed of WSL, VirtualMachinePlatform, Hyper-V features | Retain real Linux command gaps, switch to native Windows tools with QEMU full-system | Medium |
| Dr. Memory version normal but injection crashes | Compatibility issue with Windows 11 24H2 build 26100 | Record upstream issue, use AppVerifier/PageHeap/UMDH/CDB/Frida | Medium |
| Codex TOML cannot load | Historical project path乱码 causing missing quotes, invalid escape sequences, and duplicate keys | Fix table header syntax and validate `codex mcp list` | Low |
| Burp MCP registered but no tools | Burp GUI has not loaded extensions, 9876 is not listening | Build fixed JAR, record GUI load conditions | Low |

## Toolchain Discovery

- The generic probe ultimately found 57/64 tools; all 7 gaps belong to Linux user space or kernel capabilities.
- Windows SDK Debugging Tools are important supplements for Dr. Memory incompatibility: CDB, GFlags, UMDH, NTSD, KD.
- MCP should be verified separately for "stdio/HTTP initialization" and "GUI backend online"; registration success does not guarantee tool availability.
- IDA Free can be used for local interactive analysis but cannot replace the legitimate IDA Pro idalib/Hex-Rays MCP backend.

## Key Code/Commands

```powershell
python "{skill_root}\scripts\toolchain_probe.py" --format markdown
aria2c --disable-ipv6=true --max-connection-per-server=16 --split=16 "{official_url}"
powershell -NoProfile -ExecutionPolicy Bypass -File "{package_root}\skills\scripts\refresh-tool-index.ps1"
codex mcp list
cdb -g -G C:\Windows\System32\where.exe cmd
```

## Improvements for This Package

- Include Dr. Memory, CDB, GFlags, UMDH, DTC, SquashFS, flashrom, and Frida Trace in the Windows tool-index catalog.
- Capability status should distinguish `installed`, `bridge-ready`, `backend-online`, `runtime-verified`.
- Add clear Linux-only gap descriptions for trimmed-down Windows, do not generate pseudo wrappers with the same name.

## Reusable Patterns/Script Snippets

Large file download fixed pattern: first verify version, URL, and SHA-256 from official package metadata, then use `aria2` with disabled IPv6 for downloads; validate hash and Authenticode (if applicable) after download.

## Evolution Actions

- [ ] Updated routing matrix
- [x] Updated tool-index
- [ ] Updated bootstrap-manifest
- [ ] Updated sub-skill documentation
- [x] Added pitfalls record
- [ ] No update needed

## Environment Information

- OS: Windows NT build 26100.4946, 24H2, x64
- Tool versions: See official installation report and tool-index on this machine
- Target platform/version: Native Windows toolchain, covering Android, Linux/ELF static analysis, and full-system simulation

## Desensitization Requirements

This record does not contain real targets, credentials, tokens, internal URLs, or usernames; paths use placeholders.

## Index Synchronization

Updated the statistics in `_index.md` under the "Toolchain and Environment" category.

---
<!-- [Community Contribution] Local record completed. -->
