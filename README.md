<div align="center">

<img src="docs/assets/logo.svg" alt="binoracle" width="120" height="120">

# binoracle

### Autonomous CVE exploit research · Binary reverse engineering · Fully local

<br/>

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-gh--pages-7C3AED?style=for-the-badge&logo=github&logoColor=white)](https://beafn28.github.io/binoracle/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20local-F97316?style=for-the-badge)](https://ollama.com)
[![Docker](https://img.shields.io/badge/labs-Docker%20ephemeral-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)

<br/>

**[English](README.md)** · [Español](docs/README.es.md) · [Docs](https://beafn28.github.io/binoracle/) · [Architecture](docs/assets/architecture.svg)

<br/>

</div>

---

> ⚠️ **Legal notice** — binoracle is a research and educational tool.
> All CVE labs run exclusively against Docker containers you provision locally.
> **Do not use this tool against systems you do not own or lack explicit written authorization to test.**

---

## What is binoracle?

binoracle is a **local-first** security research workstation with two fully autonomous pipelines:

<table>
<tr>
<td width="50%">

### 🔍 CVE Engine
Fetches a CVE from NVD, feeds it to a **local Qwen 2.5 Coder 7B** (via Ollama) which autonomously generates exploit hypotheses — zero hints from the analyst. Spins up an ephemeral Docker Compose lab, fires the PoC, captures Playwright screenshots at every verification step, and writes a full HTML report to disk.

</td>
<td width="50%">

### 🔬 Binary RE Engine
Static + dynamic analysis of ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, JS, EVM, SQLite. Automated exploit chains (stack · heap · format string · SROP), ROP synthesis, decompilation via Ghidra/radare2/angr/pwndbg, and hardening assessment. Everything runs locally.

</td>
</tr>
</table>

> No data leaves the host. The LLM runs at `localhost:11434`. Labs are torn down after each run.

---

## Quick Start

```bash
# 1. Install binoracle
pip install binoracle

# 2. Install Ollama + pull the model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b

# 3. Point binoracle at your local LLM
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# 4. Fire at a CVE
binoracle cve CVE-2025-27516

# 5. Analyse a binary
binoracle triage ./target
binoracle pwn   ./vulnerable
```

---

## CVE Engine

![CVE engine pipeline](docs/assets/cve-flow.svg)

### How it works

```
NVD description  →  local LLM  →  exploit hypothesis  →  Docker lab  →  PoC execution  →  HTML report
       ↑                 ↑                 ↑                  ↑               ↑               ↑
  fetched live     Qwen 2.5-Coder    zero analyst hints  ephemeral env   Playwright SS   disk only
```

### Supported vulnerability classes

| Class | Scaffolders | Auto PoC |
|-------|------------|----------|
| SSTI (Jinja2, Twig, Smarty) | pip / gem | ✅ |
| SQLi (GET / POST / JSON / header) | pip / gem / php / maven | ✅ |
| Path traversal / LFI | pip / gem / npm / httpd | ✅ |
| RCE / command injection | pip / gem / npm | ✅ |
| XSS (reflected / stored) | pip / npm | ✅ |
| SSRF | pip / npm | ✅ |
| XXE | java / maven | ✅ |
| Deserialization | java / gem (Marshal) | ✅ |
| Auth bypass / IDOR | pip / gem / npm | ✅ |
| File upload / webshell | pip | ✅ |
| Open redirect | pip / gem / npm | ✅ |
| CSRF | pip / gem | ✅ |
| WordPress plugins (100+) | WP Docker | ✅ |
| Joomla extensions | Joomla Docker | ✅ |
| Drupal modules | Drupal Docker | ✅ |
| Apache httpd | httpd Docker | ✅ |
| Java / Maven (Spring, Struts, Log4j) | maven | ✅ |
| PHP Composer packages | php | ✅ |
| npm / Node.js / Next.js | npm | ✅ |
| Ruby gems (Rails, Rack, Sinatra) | gem | ✅ |

```bash
# Single CVE
binoracle cve CVE-2025-27516

# Batch (parallelised)
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 CVE-2025-59681

# Language override
binoracle cve CVE-2025-27516 --lang en
```

---

## Binary RE Engine

```bash
binoracle pwn ./binary       # full automated exploit chain
binoracle triage ./binary    # mitigations, symbols, imports, sections
binoracle decompile ./binary # multi-backend decompilation + LLM annotation
binoracle rop ./binary       # ROP gadget search + chain synthesis
binoracle hardening ./binary # NX, PIE, RELRO, canary, Fortify, CFI...
```

### Exploit families

| Family | Techniques |
|--------|------------|
| **Stack** | ret2win · ret2libc · ret2plt · ret2csu · SROP (x86-64/x86-32/aarch64) · stack pivot · ROP chains |
| **Heap** | tcache dup · fastbin dup · UAF · double-free · House-of-Force/Spirit/Orange/Mind · large-bin attack · unsafe-unlink · Botcake |
| **Format string** | %n arbitrary write · GOT overwrite · canary leak · PIE leak |
| **Low-level** | shellcode (NX off) · bad-char scrubbing · IO_FILE · DL-resolve · GOT hijack |
| **Canary** | leak + reuse · fork brute-force |
| **PIE** | partial overwrite · leak chain |

### Supported formats

| Format | Analysis backends |
|--------|------------------|
| ELF (x86-64 / x86 / ARM / MIPS / RISC-V) | radare2 · pyelftools · pwntools · angr · pwndbg |
| PE / PE+ (Windows) | pefile · LIEF · radare2 |
| Mach-O (macOS / iOS) | LIEF · radare2 |
| APK / DEX (Android) | apktool · jadx · androguard |
| .NET assemblies | dnlib · ILSpy |
| JavaScript / TypeScript | esprima · acorn |
| Go binaries | go-dis stub · symbol recovery |
| Rust binaries | LIEF + symbol demangling |
| WASM modules | wabt · binaryen |
| SQLite databases | sqlite3 schema + data dump |
| EVM bytecode | pyevmasm |

---

## Reports

Every investigation produces a **standalone HTML report** with:

- 📋 Executive summary with CVSS score and severity classification
- 🧠 LLM hypothesis with the full reasoning chain
- 🐳 Docker Compose lab specification
- 📸 Playwright screenshots at each verification step
- 💻 Complete PoC code (curl · Python · pwntools)
- 🛡️ Remediation guidance with specific fix examples

```bash
# Auto-open after generation
binoracle cve CVE-2025-27516 --open-report

# Custom output directory
binoracle cve CVE-2025-27516 --out ./reports/

# Batch → one report per CVE
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./reports/
```

---

## MCP Server

binoracle exposes its entire capability set as **~100 MCP tools**, letting you drive it from Claude Desktop, Cursor, Zed, or any MCP client.

```bash
binoracle mcp-server
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

<details>
<summary>All available MCP tools (click to expand)</summary>

`triage` · `pwn` · `rop_chain` · `heap_exploit` · `fmt_exploit` · `decompile` · `cve_investigate` · `vuln_hunt` · `iocscan` · `hardening` · `audit` · `reachability` · `diff_patch` · `elf_layout` · `pe_inspect` · `apk_audit` · `dotnet_inspect` · `wasm_inspect` · `sqlite_audit` · `evm_inspect` · `fuzz` · `dynamic_trace` · `coredump` · `shellcode` · `srop_chain` · `got_hijack` · `io_file` · `dlresolve` · `canary_leak` · `pie_leak` · `format_string` · `heap_triage` · `heap_tcache` · `heap_fastbin` · `heap_uaf` · `heap_house` · `stack_pivot` · `ret2csu` · `ret2plt` · `ret2libc` · `ret2win` · `rop_search` · `symbol_recovery` · `import_scan` · `export_scan` · `section_dump` · `string_extract` · `entropy_scan` · `yara_scan` · `cve_batch` · `vuln_classify` · `patch_diff` · `n_day_analysis` · `cwe_map` · `cvss_score` · `exploit_db_search` · `lab_provision` · `lab_teardown` · `lab_exec` · `playwright_capture` · `report_generate` · `report_open` · `web` and more (~100 total)

</details>

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `triage` | Static facts: mitigations, symbols, imports, sections |
| `decompile` | Multi-backend decompilation with LLM annotation |
| `pwn` | Automated exploit chain (technique auto-selected) |
| `rop` | ROP gadget search and chain synthesis |
| `chain` | Gadget enumeration + pwntools script generation |
| `heap` | Heap exploit primitives (tcache / fastbin / UAF / House-of-X) |
| `fmt` | Format string exploitation |
| `srop` | SROP chain generator |
| `shellcode` | Shellcode generator with bad-char filtering |
| `fuzz` | Dumb and smart fuzzer (AFL integration) |
| `dynamic` | Dynamic trace: strace, ltrace, gdb automation |
| `hardening` | Mitigation enumeration with bypass notes |
| `cve` | Full CVE investigation (fetch → lab → PoC → report) |
| `cve-batch` | Parallelised batch CVE investigation |
| `vuln-hunt` | Static vulnerability hunting (sinks, sources, taint) |
| `ioc-scan` | IOC and malware indicator scan |
| `audit` | Full security audit (all oracles + LLM synthesis) |
| `reachability` | Source-to-sink reachability analysis |
| `diff` | Patch diff and N-day analysis |
| `apk` | Android APK full audit |
| `dotnet` | .NET assembly inspection |
| `wasm` | WASM module inspection |
| `sqlite` | SQLite database audit |
| `evm` | EVM bytecode inspection |
| `mcp-server` | Start MCP server |
| `web` | Start web UI (localhost) |

---

## Architecture

![binoracle architecture](docs/assets/architecture.svg)

---

## Practice Corpus

binoracle ships **40+ intentionally vulnerable binaries** to sharpen your skills:

```bash
# Compile the full corpus (requires Docker or gcc)
samples/build.sh

# Start practising
binoracle triage samples/bin/ret2win
binoracle pwn   samples/bin/ret2libc
binoracle pwn   samples/bin/format_string
binoracle pwn   samples/bin/tcache_dup
binoracle pwn   samples/bin/house_of_orange
```

**Techniques covered:** ret2win · ret2libc · SROP · tcache dup · fastbin dup · UAF · format string GOT overwrite · canary leak · PIE leak · CSU chain · DL-resolve · heap botcake · house-of-orange · unsafe-unlink · stack pivot · IO_FILE · callhijack · dlresolve32

> See [docs/TUTORIAL.md](docs/TUTORIAL.md) for the full guided walkthrough.

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

### Dependency sets

```bash
pip install binoracle[elf]         # deep ELF analysis (pyelftools extras)
pip install binoracle[pwn]         # pwntools + ROPgadget
pip install binoracle[symbolic]    # angr symbolic execution
pip install binoracle[web]         # web UI
pip install binoracle[screenshots] # Playwright screenshots in CVE reports
pip install binoracle[all]         # everything
```

### System requirements

| Dependency | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.10 | 3.12 |
| RAM | 8 GB | 16 GB |
| Docker | 20.x | 25.x |
| Ollama | 0.3 | latest |
| GPU | — | 8 GB VRAM (Qwen 7B quantized) |

---

## Configuration

```bash
# ✅ Recommended — local LLM via Ollama (fully offline)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# ☁️ Optional — any OpenAI-compatible cloud backend
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_API_KEY=sk-...
export BINORACLE_MODEL=gpt-4o-mini

# 🌐 Report language (default: es)
export BINORACLE_LANG=en
```

---

## binoracle vs REA

| Feature | binoracle | REA |
|---------|:---------:|:---:|
| Local LLM via Ollama | ✅ | ❌ |
| CVE → Docker lab → verified PoC | ✅ | ❌ |
| Playwright screenshots as evidence | ✅ | ❌ |
| WordPress / Joomla / Drupal labs | ✅ | ❌ |
| MCP server (~100 tools) | ✅ | ❌ |
| APK / .NET / WASM / EVM analysis | ✅ | ⚠️ partial |
| Fully offline | ✅ | ⚠️ partial |
| ret2win / ret2libc / SROP | ✅ | ✅ |
| Heap attacks (tcache / fastbin / UAF / House-of-X) | ✅ | ✅ |
| Format string exploitation | ✅ | ✅ |
| ROP chain synthesis | ✅ | ✅ |
| Practice corpus (40+ binaries) | ✅ | ✅ |

---

## Roadmap

- [ ] Kernel exploit chains (ret2usr, UAF in kernel drivers)
- [ ] Firmware analysis (UEFI, embedded Linux)
- [ ] Active fuzzing with LibFuzzer corpus seeding from CVE PoCs
- [ ] Multi-CVE chaining (web RCE → local privilege escalation)
- [ ] CVSS v4 scoring
- [ ] Burp Suite MCP bridge (live request replay)
- [ ] JEB decompiler integration (Android native)
- [ ] Fine-tuned model for exploit hypothesis generation

---

## Contributing

```bash
git clone https://github.com/beafn28/binoracle
cd binoracle
pip install -e ".[all]"
pre-commit install
```

Pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## License

MIT © 2024–2025 Beatriz Fresno Naumova

---

<div align="center">

**binoracle — autonomous security research · fully local · no data leaves your host**

[📖 Docs](https://beafn28.github.io/binoracle/) · [🐛 Issues](https://github.com/beafn28/binoracle/issues) · [🌐 Español](docs/README.es.md)

</div>
