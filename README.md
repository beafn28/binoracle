<div align="center">

<img src="docs/assets/logo.svg" alt="binoracle" width="120" height="120">

# binoracle

**Autonomous CVE exploit research & binary reverse engineering — 100% local**

[![PyPI](https://img.shields.io/pypi/v/binoracle?color=blue&label=PyPI)](https://pypi.org/project/binoracle/)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![DEF CON Arsenal](https://img.shields.io/badge/DEF%20CON-Arsenal-red.svg)](#)
[![Docs](https://img.shields.io/badge/docs-gh--pages-blueviolet)](https://beafn28.github.io/binoracle/)

[English](#) · [Español](docs/README.es.md) · [Docs](https://beafn28.github.io/binoracle/) · [Architecture](docs/ARCHITECTURE.md) · [Tutorial](docs/TUTORIAL.md)

</div>

---

> **LEGAL NOTICE** — binoracle is a research and education tool.
> All CVE labs run against Docker containers you create locally.
> Never use this against systems you do not own or have explicit written permission to test.

---

## What is binoracle?

binoracle is a **fully local, offline-first** security research assistant with two main engines:

| Engine | What it does |
|--------|-------------|
| **CVE Engine** | Fetches a CVE from NVD → asks Qwen 2.5 Coder (local LLM) to generate exploit hypotheses → spins up a Docker lab → verifies the exploit with Playwright → produces a professional HTML report with screenshots |
| **Binary RE Engine** | Analyzes ELF/PE/Mach-O/APK/WASM/Go/Rust/.NET/JS/EVM/SQLite — static analysis, decompilation, exploit generation, ROP chains, format strings, heap attacks, SROP — all offline |

**Zero data leaves your machine.** The LLM runs locally via Ollama (Qwen 2.5 Coder 7B). Docker labs are ephemeral. Reports stay on disk.

---

## Quick Start

```bash
# 1. Install binoracle
pip install binoracle

# 2. Install Ollama + pull the model (macOS / Linux)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b

# 3. Configure
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# 4. Investigate a CVE autonomously
binoracle cve CVE-2025-27516

# 5. Analyze a binary
binoracle triage ./target_binary

# 6. Full exploit chain
binoracle pwn ./vulnerable_binary
```

---

## CVE Engine

The CVE engine is **fully autonomous** — Claude provides zero hints. The local LLM reads the NVD description and generates every exploit hypothesis from scratch.

```
NVD Description ──► Qwen 2.5 Coder ──► Hypothesis ──► Docker Lab ──► Playwright Verify ──► HTML Report
                      (local only)       (class, payload,   (Flask/Rails/      (screenshots        (evidence,
                                         endpoint, param)    npm/httpd)          + PoC code)         timeline)
```

### Supported vulnerability classes

| Class | Scaffolder | Auto-PoC |
|-------|-----------|---------|
| SSTI (Jinja2, Twig, Smarty) | pip / gem | ✓ |
| SQLi (GET/POST/JSON/header) | pip / gem / php / maven | ✓ |
| Path Traversal / LFI | pip / gem / npm / httpd | ✓ |
| RCE / Command Injection | pip / gem / npm | ✓ |
| XSS (Reflected / Stored) | pip / npm | ✓ |
| SSRF | pip / npm | ✓ |
| XXE | java / maven | ✓ |
| Deserialization | java / gem (Marshal) | ✓ |
| Auth Bypass / IDOR | pip / gem / npm | ✓ |
| File Upload / Webshell | pip | ✓ |
| Open Redirect | pip / gem / npm | ✓ |
| CSRF | pip / gem | ✓ |
| WordPress plugins (100+) | WP Docker | ✓ |
| Joomla extensions | Joomla Docker | ✓ |
| Drupal modules | Drupal Docker | ✓ |
| Apache httpd | httpd Docker | ✓ |
| Java/Maven (Spring, Struts) | maven | ✓ |
| PHP (Composer packages) | php | ✓ |
| npm / Node.js / Next.js | npm | ✓ |
| Ruby gems | gem | ✓ |

```bash
# Single CVE
binoracle cve CVE-2025-27516

# Batch (parallelized)
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Custom language report
binoracle cve CVE-2025-27516 --lang en
```

---

## Binary Reverse Engineering Engine

### 50+ exploit families — fully automated

```
binoracle pwn ./binary
```

| Family | Techniques |
|--------|-----------|
| **Stack** | ret2win · ret2libc · ret2plt · ret2csu · SROP (x86-64/x86-32/aarch64) · stack pivot · ROP chains |
| **Heap** | tcache dup · fastbin dup · UAF · double-free · House-of-Force · House-of-Spirit · House-of-Orange · House-of-Mind · large bin attack · unsafeunlink · Botcake |
| **Format String** | %n arbitrary write · GOT overwrite · canary leak · pie leak |
| **Low-level** | shellcode (NX off) · bad-char scrubbing · IO\_FILE exploit · DL-resolve · GOT hijack |
| **Canary** | leak + reuse · fork bruteforce |
| **PIE** | partial overwrite · leak chain |

### Static analysis — REA parity + beyond

```
binoracle triage ./binary        # mitigations, symbols, imports
binoracle decompile ./binary     # multi-engine: Ghidra, radare2, angr, pwndbg
binoracle rop ./binary           # ROP gadget search + chain synthesis
binoracle chain ./binary         # full exploit chain
```

| Format | Engines |
|--------|--------|
| ELF (x86-64/x86/ARM/MIPS/RISC-V) | radare2 · pyelftools · pwntools · angr · pwndbg |
| PE / PE+ (Windows) | pefile · LIEF · radare2 |
| Mach-O (macOS/iOS) | LIEF · radare2 |
| APK / DEX (Android) | apktool · jadx · androguard |
| .NET / C# | dnlib · ILSpy (via dotnet-script) |
| JS / TypeScript / Electron | esprima · acorn |
| Flutter (Dart) | blutter / reFlutter stub |
| Go binaries | go-dis stub · symbol recovery |
| Rust binaries | LIEF + symbol demangling |
| WASM | wabt · binaryen |
| SQLite databases | python sqlite3 · schema + data dump |
| EVM bytecode | pyevmasm |

### Hardening analysis

```bash
binoracle hardening ./binary   # NX, PIE, RELRO, stack canary, Fortify, CFI, shadow stack
binoracle mit ./binary         # mitigations detail with bypass notes
```

---

## MCP Server (~100 tools)

binoracle exposes every capability as an MCP tool so Claude Desktop, Cursor, Zed, and any MCP-compatible client can call it natively.

```bash
binoracle mcp-server            # start the MCP server
```

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "binoracle": {
      "command": "binoracle",
      "args": ["mcp-server"]
    }
  }
}
```

Selected tools: `triage`, `pwn`, `rop_chain`, `heap_exploit`, `fmt_exploit`, `decompile`, `cve_investigate`, `vuln_hunt`, `iocscan`, `hardening`, `audit`, `reachability`, `diff_patch`, `elf_layout`, `pe_inspect`, `apk_audit`, `dotnet_inspect`, `wasm_inspect`, `sqlite_audit`, `evm_inspect`, `fuzz`, `dynamic_trace`, `coredump`, `burp_mcp`, `jeb_connect` …

---

## CLI Reference

```
binoracle <command> [options]
```

| Command | Description |
|---------|-------------|
| `triage` | Static facts: mitigations, symbols, imports, sections |
| `decompile` | Multi-engine decompilation with LLM annotation |
| `pwn` | Full auto-exploit chain (chooses technique automatically) |
| `rop` | ROP gadget search + chain synthesis |
| `chain` | Chain analyzer: finds gadgets, generates pwntools script |
| `heap` | Heap exploit primitives (tcache/fastbin/UAF/HoF…) |
| `fmt` | Format string exploitation |
| `srop` | SROP chain generator |
| `shellcode` | Shellcode generator with bad-char scrubbing |
| `fuzz` | Dumb + smart fuzzer (AFL integration) |
| `dynamic` | Dynamic trace: strace, ltrace, gdb automation |
| `hardening` | Mitigations + bypass paths |
| `cve` | Investigate a CVE end-to-end |
| `cve-batch` | Batch CVE investigation (parallel) |
| `vuln-hunt` | Static vulnerability hunting (sinks, sources, taint) |
| `ioc-scan` | IOC / malware indicators scan |
| `audit` | Full security audit (all oracles + LLM synthesis) |
| `reachability` | Reachability analysis (source → sink) |
| `diff` | Patch diff / N-day analysis |
| `apk` | Android APK full audit |
| `dotnet` | .NET assembly inspection |
| `wasm` | WASM module inspection |
| `sqlite` | SQLite database audit |
| `evm` | EVM bytecode inspection |
| `mcp-server` | Start MCP server |
| `web` | Start web UI (localhost) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         binoracle                                    │
│                                                                     │
│  CLI (50+ cmds)   MCP Server (~100 tools)   Web UI                  │
│        │                  │                   │                     │
│        └──────────────────┴──────────────────┘                      │
│                           │                                          │
│              ┌────────────▼────────────┐                            │
│              │      Workflow Layer      │                            │
│              │  cve_agent · autopwn     │                            │
│              │  chainanalyzer · rop     │                            │
│              │  heap · fmt · srop       │                            │
│              └────────────┬────────────┘                            │
│                           │                                          │
│         ┌─────────────────┼──────────────────┐                      │
│         │                 │                   │                      │
│  ┌──────▼──────┐  ┌───────▼──────┐  ┌────────▼────────┐           │
│  │  Oracle     │  │  LLM Bridge  │  │  Docker / Lab   │           │
│  │  Layer      │  │  (Ollama /   │  │  Scaffolder     │           │
│  │  radare2    │  │   OpenAI API)│  │  (pip/gem/npm/  │           │
│  │  pyelftools │  └──────────────┘  │   maven/php/    │           │
│  │  angr       │                    │   wp/joomla/    │           │
│  │  pwntools   │                    │   httpd)        │           │
│  │  pefile     │                    └─────────────────┘           │
│  │  jadx       │                                                    │
│  └─────────────┘                                                    │
│                                                                     │
│  Local model: Qwen 2.5 Coder 7B via Ollama (zero cloud calls)       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Reports

Every investigation produces a **professional HTML report** with:

- Executive summary with CVSS score and severity badge
- LLM hypothesis and reasoning chain
- Lab scaffold and configuration
- Playwright screenshots at every verification step
- Full PoC code (curl / Python / pwntools)
- Remediation recommendations (concrete, actionable, in English and Spanish)

```bash
# Open the last report
binoracle cve CVE-2025-27516 --open-report

# Output to specific directory
binoracle cve CVE-2025-27516 --out ./reports/
```

---

## Practice Corpus

binoracle ships 40+ intentionally vulnerable binaries for local practice:

```bash
# Compile the corpus (needs Docker or gcc)
samples/build.sh

# Work through the guided tutorial
binoracle triage samples/bin/ret2win
binoracle pwn samples/bin/ret2libc
binoracle pwn samples/bin/format_string
# → see docs/TUTORIAL.md for the full walkthrough
```

Techniques covered: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafeunlink, stack pivot, IO\_FILE, callhijack, dlresolve32 …

---

## Installation

### From PyPI

```bash
pip install binoracle
```

### From source

```bash
git clone https://github.com/beafn28/binoracle
cd binoracle
pip install -e ".[all]"
```

### Optional dependencies

```bash
pip install binoracle[elf]        # ELF deep analysis (pyelftools extras)
pip install binoracle[pwn]        # pwntools + ROPgadget
pip install binoracle[symbolic]   # angr symbolic execution
pip install binoracle[web]        # web UI
pip install binoracle[screenshots] # Playwright screenshots in CVE reports
pip install binoracle[all]        # everything
```

### System requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| Python | 3.10 | 3.12 |
| RAM | 8 GB | 16 GB |
| Docker | 20.x | 25.x |
| Ollama | 0.3 | latest |
| GPU | — | 8 GB VRAM (Qwen 7B) |

---

## Configuration

```bash
# LLM backend (Ollama — recommended)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# Or cloud (OpenAI-compatible)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_API_KEY=sk-...
export BINORACLE_MODEL=gpt-4o-mini

# Report language
export BINORACLE_LANG=en   # or "es" (default: "es")
```

---

## Comparison with REA

| Feature | binoracle | REA |
|---------|-----------|-----|
| Local LLM (Ollama) | ✓ | ✗ |
| CVE → Docker lab → verified PoC | ✓ | ✗ |
| Playwright screenshots in reports | ✓ | ✗ |
| WordPress / Joomla / Drupal labs | ✓ | ✗ |
| ret2win / ret2libc / SROP | ✓ | ✓ |
| Heap attacks (tcache/fastbin/UAF/HoX) | ✓ | ✓ |
| Format string exploitation | ✓ | ✓ |
| ROP chain synthesis | ✓ | ✓ |
| MCP server | ✓ | ✗ |
| Practice corpus (40+ binaries) | ✓ | ✓ |
| APK / .NET / WASM / EVM | ✓ | partial |
| 100% offline | ✓ | partial |

---

## Roadmap

- [ ] Kernel exploit chains (ret2usr, UAF in drivers)
- [ ] Firmware analysis (UEFI, embedded Linux)
- [ ] Active fuzzing integration (LibFuzzer corpus seeding from CVE PoCs)
- [ ] Multi-CVE chaining (pivot from web RCE to privesc)
- [ ] CVSS v4 scoring
- [ ] Burp Suite MCP bridge (live request replay)
- [ ] JEB decompiler integration (Android native)
- [ ] Fine-tuned model for binoracle hypotheses

---

## Contributing

```bash
git clone https://github.com/beafn28/binoracle
cd binoracle
pip install -e ".[all]"
pre-commit install
```

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT © 2024–2025 Beatriz Fresno Naumova

---

<div align="center">

**binoracle** — built for DEF CON Arsenal

[Docs](https://beafn28.github.io/binoracle/) · [Issues](https://github.com/beafn28/binoracle/issues) · [Twitter / X](https://x.com/beafn28)

</div>
