---
name: lumine-reverse-2026-05-15
description: Go 1.24.5 TLS 分片代理 lumine v0.9.1 全量逆向恢复，含 7 个包源码重建
metadata:
  type: project
---

# lumine v0.9.1 — Go TLS 分片代理逆向

**Date**: 2026-05-15  
**Target**: `lumine_v0.9.1_windows_amd64.exe` (PE32+, Go 1.24.5, 11.6 MB)  
**Original**: `REVERSE_REPORT.md`

## Background

The user requested to reverse the binary back into readable Go source code. The target is a TLS anti-DPI proxy tool, based on Python [TlsFragment](https://github.com/maoist2009/TlsFragment).

## Process

1. **Toolchain Setup**: Python + capstone disassembly, GoReSym symbol recovery (1944 Go functions, 269 from the project)
2. **Package Structure Identification**: Inferring 12 packages from `package.function` names in GoReSym
3. **Type Recovery**: Reversing JSON deserialization types through `config.json`, combining function references to recover fields
4. **Source Code Reconstruction**: Writing readable Go code for each package, preserving logic rather than line-by-line restoration
5. **Sub-package Completion**: dial (outbound binding), errors (error types), format (string utilities)

## Key Discoveries

- Core anti-DPI mechanism: TLS record fragmentation + noise injection + waiting for ACK + OOB + Fake TTL
- Policy engine: Domain Trie + IP Trie → Policy matching
- Dependency on `go-freelru` (LRU cache) for DNS/TTL caching
- Source repository `github.com/moi-si/lumine` returns 404, can only be fully recovered from the binary

## Tools

| Tool | Purpose | Version |
|---|---|---|
| GoReSym | Go symbol recovery | v1.7.1 (Mandiant) |
| Capstone | Disassembly engine | latest |
| pefile | PE structure parsing | latest |

## Pitfalls

1. **Python3 Path Issue**: WindowsApps stub python3 does not support pip install capstone, need to use the full CPython path
2. **GoReSym Subprocess Path**: `~` does not automatically expand, need `os.path.expanduser()`
3. **Tab/Space Mixture**: The auto-generated Python decompilation script contains a mix of tabs and spaces, causing errors in Go source code formatting; v3 version uses only spaces
4. **Vendor-less GoReSym**: When the binary does not contain vendor symbols with Go 1.24.5, GoReSym can still extract function names but cannot recover parameters and local variables
5. **String Noise**: Large amounts of Go standard library string constants are mixed in, requiring careful filtering at the package level

## Product

- `REVERSE_REPORT.md` — Complete reverse analysis report  
- `reconstructed_src_v3/` — 7 Go source files, core engine + 3 sub-packages