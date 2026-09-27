# Go Binary Reverse Engineering Guide

> Go-compiled binaries present unique challenges: static linking results in large size, thousands of functions, special string formats, and difficulty recovering symbols after stripping.
> This document covers the toolchain, recovery techniques, and practical workflow.

---

## Identifying Features of Go Binaries

Quickly determine if a binary is compiled with Go:

```bash
# String features
strings binary | grep -E "runtime\.|go\.buildid|GOROOT"

# rabin2 reconnaissance
rabin2 -z binary | grep -i "runtime"

# Abnormal large file size (static linked runtime)
# Typical Hello World: C ~20KB, Go ~2MB
```

Common features:
- Many functions with `runtime.` prefix
- Contains `go.buildid` section
- Contains `GOROOT`, `GOPATH` path strings
- Function count 5000-50000+ (including entire runtime and standard library)

---

## Core Toolchain

### Symbol Recovery

| Tool | Purpose | Link |
|------|---------|------|
| **GoReSym** | Mandiant's product, parses Go symbol information (pclntab/moduledata) | https://github.com/mandiant/GoReSym |
| **GoResolver** | Volexity's product, automatically deobfuscates Garble binaries using CFG similarity | https://github.com/volexity/GoResolver |
| **redress** | Analyzes stripped Go binaries to recover type/interface/package structures | https://github.com/goretk/redress |
| **GoStringUngarbler** | Google's product, specifically for recovering strings obfuscated by Garble | https://github.com/mandiant/GoStringUngarbler |

### IDA Plugins

| Tool | Purpose | Link |
|------|---------|------|
| **go_parser** | IDA plugin, parses moduledata/pclntab/type information | https://github.com/0xjiayu/go_parser |
| **IDAGolangHelper** | IDA script set, parses Go type information | https://github.com/sibears/IDAGolangHelper |
| **AlphaGolang** | SentinelLabs' IDAPython script set | https://github.com/SentineLabs/AlphaGolang |
| **IDA 9.2+ Native Support** | Hex-Rays official Go decompilation improvements | https://hex-rays.com/blog/stop-guessing-and-start-going |

### Ghidra Plugins

| Tool | Purpose | Link |
|------|---------|------|
| **Ghidra + GoReSym Output** | Imports symbols exported by GoReSym into Ghidra | Used together |
| **golang_loader_assist** | Ghidra Go loading assistant | Community script |

### Standalone Analysis Tools

| Tool | Purpose | Link |
|------|---------|------|
| **gore** | Go reverse engineering library (underlying for redress) | https://github.com/goretk/gore |
| **garble** | Go obfuscation tool (needed to understand and counteract it) | https://github.com/burrowers/garble |

---

## Key Structures in Go Binaries

### pclntab (PC Line Table)

The most important structure in a Go binary, containing:
- Mappings of all function names and addresses
- Source file paths
- Line number information
- Stack frame sizes

Even after stripping symbols, pclntab is usually still present (Go runtime depends on it).

```text
Location methods:
1. Search for magic bytes: 0xFFFFFFF0 (Go 1.16+) or 0xFFFFFFFB (Go 1.18+)
2. Automatically locate with GoReSym
3. Automatically parse with go_parser IDA plugin
```

### moduledata

Contains:
- Pointer to pclntab
- Type information table
- itab (interface table)
- Global variable information

### String Format

Go strings are not null-terminated like C-style strings; they are `(pointer, length)` structures:

```text
C string:   "hello\0"
Go string:  struct { ptr *byte; len int } → ptr points to "hello" (no \0)
```

This causes default string recognition in IDA/Ghidra to miss many Go strings.

**Solutions**:
- Automatically identify Go strings with `go_parser`
- Export string list with GoReSym
- Manually: find `runtime.stringtable` or locate through cross-references

## Practical Workflow

### Scenario 1: Unstripped Go Binary

```text
1. GoReSym -t -d -p binary > symbols.json
   → Export all function names, types, source file paths
2. Load into IDA/Ghidra
3. Import GoReSym's symbol information
4. Filter out runtime.* and standard library functions, focus on user code
5. Start analysis from main.main
```

### Scenario 2: Stripped Go Binary

```text
1. GoReSym -t -d -p binary > symbols.json
   → Even if stripped, pclntab is usually still there
2. If GoReSym fails → Use redress
   redress -src binary    # Restore source file paths
   redress -pkg binary    # Restore package structure
   redress -type binary   # Restore type information
3. Load into IDA + go_parser plugin
4. Run go_parser to automatically recover
5. Start from the recovered main.main
```

### Scenario 3: Garble Obfuscated Go Binary

```text
Garble will:
- Randomize function names (main.main → main.a3f2b1c)
- Encrypt strings
- Remove file path information
- Obfuscate package names

Mitigation methods:
1. GoResolver (CFG signature matching)
   → Recover standard library function names through control flow graph similarity
2. GoStringUngarbler (string decryption)
   → Automatically identify Garble's string encryption mode and decrypt
3. Dynamic analysis (Frida/dlv)
   → Hook runtime functions to observe actual behavior
4. Comparative analysis
   → Compile the same version of Go's Hello World, compare the runtime part using binary-diff
```

### Scenario 4: CGo Mixed Compilation

```text
1. Identify CGo boundaries (_cgo_* functions)
2. Recover Go part with go_parser
3. Analyze C part with regular IDA
4. Focus on bridge functions like _cgo_topofstack, crosscall2, etc.
```

---

## Common Command Cheat Sheet

```bash
# GoReSym: Export symbols
GoReSym -t -d -p binary > symbols.json
GoReSym -t -d -p binary -o ida_script.py  # Generate IDA script

# redress: Analyze stripped binaries
redress -src binary          # Source file paths
redress -pkg binary          # Package structure
redress -type binary         # Type information
redress -interface binary    # Interface information
redress -filepath binary     # Full file path

# GoResolver: Deobfuscate Garble
GoResolver -binary binary -output resolved.json

# GoStringUngarbler: Decrypt Garble strings
GoStringUngarbler -i binary -o deobfuscated_binary

# Quickly determine Go version
strings binary | grep "go1\."
GoReSym -p binary | grep "Version"
```

---

## Go Analysis Workflow in IDA

```text
1. Load the binary (select the correct architecture)
2. Wait for automatic analysis to complete
3. Run the go_parser plugin:
   - File → Script File → go_parser.py
   - Or Edit → Plugins → Go Parser
4. The plugin will automatically:
   - Parse pclntab
   - Recover function names
   - Mark Go strings
   - Parse type information
5. Filter view:
   - Hide runtime.* functions
   - Focus on main.* and third-party packages
6. Start reverse engineering from main.main
```

---

## Common Pitfalls

| Trap | Description | Solution |
|------|-------------|----------|
| Too many functions to see | Go static linking results in 5000-50000 functions | Filter by package name, only look at main.* and business packages |
| Incomplete string recognition | Go strings are not null-terminated | Restore with go_parser or GoReSym |
| Difficult disassembly readability | Go's defer/goroutine/interface makes pseudo-code complex | Improved in IDA 9.2+, or use dynamic analysis as a helper |
| Garble obfuscation | Function names/strings fully randomized | GoResolver + GoStringUngarbler |
| Version differences | Different Go versions have different pclntab formats | GoReSym supports Go 1.2-1.23+ |
| CGo boundaries | Mixed Go and C code | Identify _cgo_* functions as the boundary |

## Combining with Other Skills

| Requirement | Use What |
|-------------|----------|
| Deep analysis of Go binary with IDA | `ida-reverse/` + go_parser plugin |
| Analyzing with Ghidra (free) | Ghidra + GoReSym symbol import |
| Quick reconnaissance | `radare2/` — `rabin2 -z` to see strings |
| Dynamic hooking | Frida (hook runtime functions) or dlv (Go native debugger) |
| Cross-version comparison | `binary-diff/` — migrate old versions with symbols to new versions |
| Garble deobfuscation | GoResolver + GoStringUngarbler