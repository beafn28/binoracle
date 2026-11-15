<div align="center">

<img src="docs/assets/logo.svg" alt="binoracle" width="120" height="120">

# binoracle

### Autonomous CVE exploit research &middot; Binary reverse engineering &middot; Fully local

<br/>

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-gh--pages-7C3AED?style=for-the-badge&logo=github&logoColor=white)](https://beafn28.github.io/binoracle/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20local-F97316?style=for-the-badge)](https://ollama.com)
[![Docker](https://img.shields.io/badge/labs-Docker%20ephemeral-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)

<br/>

**[English](README.md)** &middot; [Espanol](docs/README.es.md) &middot; [Docs](https://beafn28.github.io/binoracle/) &middot; [Architecture](docs/assets/architecture.svg)

</div>

---

> **Legal notice** &mdash; binoracle is a research and educational tool.
> All CVE labs run exclusively against Docker containers you provision locally.
> Do not use this tool against systems you do not own or lack explicit written authorization to test.

---

## What is binoracle?

binoracle is a **local-first** security research workstation with two fully autonomous pipelines:

<table>
<tr>
<td width="50%">

**CVE Engine**

Fetches a CVE from NVD, feeds it to a **local Qwen 2.5 Coder 7B** (via Ollama) which autonomously generates exploit hypotheses &mdash; zero hints from the analyst. Spins up an ephemeral Docker Compose lab, fires the PoC, captures Playwright screenshots at every verification step, and writes a full HTML report to disk.

</td>
<td width="50%">

**Binary RE Engine**

Static and dynamic analysis of ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, JS, EVM, SQLite. Automated exploit chains (stack &middot; heap &middot; format string &middot; SROP), ROP synthesis, decompilation via Ghidra/radare2/angr/pwndbg, and hardening assessment. Everything runs locally.

</td>
</tr>
</table>

No data leaves the host. The LLM runs at `localhost:11434`. Labs are torn down after each run.

---

## Quick Start

```bash
# 1. Install binoracle
pip install binoracle

# 2. Install Ollama and pull the model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b

# 3. Point binoracle at your local LLM
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# 4. Run a CVE investigation
binoracle cve CVE-2025-27516

# 5. Analyse a binary
binoracle triage ./target
binoracle pwn   ./vulnerable
```

---

## CVE Engine

![CVE engine pipeline](docs/assets/cve-flow.svg)

### Pipeline

```
NVD description  ->  local LLM  ->  exploit hypothesis  ->  Docker lab  ->  PoC execution  ->  HTML report
       |                |                   |                    |                |                 |
  fetched live    Qwen2.5-Coder      zero analyst hints   ephemeral env    Playwright SS      disk only
```

### Supported vulnerability classes

| Class | Scaffolders | Auto PoC |
|-------|------------|----------|
| SSTI (Jinja2, Twig, Smarty) | pip / gem | yes |
| SQLi (GET / POST / JSON / header) | pip / gem / php / maven | yes |
| Path traversal / LFI | pip / gem / npm / httpd | yes |
| RCE / command injection | pip / gem / npm | yes |
| XSS (reflected / stored) | pip / npm | yes |
| SSRF | pip / npm | yes |
| XXE | java / maven | yes |
| Deserialization | java / gem (Marshal) | yes |
| Auth bypass / IDOR | pip / gem / npm | yes |
| File upload / webshell | pip | yes |
| Open redirect | pip / gem / npm | yes |
| CSRF | pip / gem | yes |
| WordPress plugins (100+) | WP Docker | yes |
| Joomla extensions | Joomla Docker | yes |
| Drupal modules | Drupal Docker | yes |
| Apache httpd | httpd Docker | yes |
| Java / Maven (Spring, Struts, Log4j) | maven | yes |
| PHP Composer packages | php | yes |
| npm / Node.js / Next.js | npm | yes |
| Ruby gems (Rails, Rack, Sinatra) | gem | yes |

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
binoracle pwn       ./binary   # full automated exploit chain
binoracle triage    ./binary   # mitigations, symbols, imports, sections
binoracle decompile ./binary   # multi-backend decompilation + LLM annotation
binoracle rop       ./binary   # ROP gadget search + chain synthesis
binoracle hardening ./binary   # NX, PIE, RELRO, canary, Fortify, CFI...
```

### Exploit families

| Family | Techniques |
|--------|------------|
| Stack | ret2win &middot; ret2libc &middot; ret2plt &middot; ret2csu &middot; SROP (x86-64/x86-32/aarch64) &middot; stack pivot &middot; ROP chains |
| Heap | tcache dup &middot; fastbin dup &middot; UAF &middot; double-free &middot; House-of-Force/Spirit/Orange/Mind &middot; large-bin attack &middot; unsafe-unlink &middot; Botcake |
| Format string | %n arbitrary write &middot; GOT overwrite &middot; canary leak &middot; PIE leak |
| Low-level | shellcode (NX off) &middot; bad-char scrubbing &middot; IO_FILE &middot; DL-resolve &middot; GOT hijack |
| Canary | leak + reuse &middot; fork brute-force |
| PIE | partial overwrite &middot; leak chain |

### Supported formats

| Format | Analysis backends |
|--------|------------------|
| ELF (x86-64 / x86 / ARM / MIPS / RISC-V) | radare2 &middot; pyelftools &middot; pwntools &middot; angr &middot; pwndbg |
| PE / PE+ (Windows) | pefile &middot; LIEF &middot; radare2 |
| Mach-O (macOS / iOS) | LIEF &middot; radare2 |
| APK / DEX (Android) | apktool &middot; jadx &middot; androguard |
| .NET assemblies | dnlib &middot; ILSpy |
| JavaScript / TypeScript | esprima &middot; acorn |
| Go binaries | go-dis stub &middot; symbol recovery |
| Rust binaries | LIEF + symbol demangling |
| WASM modules | wabt &middot; binaryen |
| SQLite databases | sqlite3 schema + data dump |
| EVM bytecode | pyevmasm |

---

## Reports

Every investigation produces a standalone HTML report containing:

- Executive summary with CVSS score and severity classification
- LLM hypothesis with the full reasoning chain
- Docker Compose lab specification
- Playwright screenshots at each verification step
- Complete PoC code (curl &middot; Python &middot; pwntools)
- Remediation guidance with specific fix examples

```bash
# Auto-open after generation
binoracle cve CVE-2025-27516 --open-report

# Custom output directory
binoracle cve CVE-2025-27516 --out ./reports/

# Batch: one report per CVE
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./reports/
```

---

## MCP Server

binoracle exposes its entire capability set as approximately 100 MCP tools, letting you drive it from Claude Desktop, Cursor, Zed, or any MCP client.

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
<summary>All available MCP tools</summary>

`triage` &middot; `pwn` &middot; `rop_chain` &middot; `heap_exploit` &middot; `fmt_exploit` &middot; `decompile` &middot; `cve_investigate` &middot; `vuln_hunt` &middot; `iocscan` &middot; `hardening` &middot; `audit` &middot; `reachability` &middot; `diff_patch` &middot; `elf_layout` &middot; `pe_inspect` &middot; `apk_audit` &middot; `dotnet_inspect` &middot; `wasm_inspect` &middot; `sqlite_audit` &middot; `evm_inspect` &middot; `fuzz` &middot; `dynamic_trace` &middot; `coredump` &middot; `shellcode` &middot; `srop_chain` &middot; `got_hijack` &middot; `io_file` &middot; `dlresolve` &middot; `canary_leak` &middot; `pie_leak` &middot; `format_string` &middot; `heap_triage` &middot; `heap_tcache` &middot; `heap_fastbin` &middot; `heap_uaf` &middot; `heap_house` &middot; `stack_pivot` &middot; `ret2csu` &middot; `ret2plt` &middot; `ret2libc` &middot; `ret2win` &middot; `rop_search` &middot; `symbol_recovery` &middot; `import_scan` &middot; `export_scan` &middot; `section_dump` &middot; `string_extract` &middot; `entropy_scan` &middot; `yara_scan` &middot; `cve_batch` &middot; `vuln_classify` &middot; `patch_diff` &middot; `n_day_analysis` &middot; `cwe_map` &middot; `cvss_score` &middot; `exploit_db_search` &middot; `lab_provision` &middot; `lab_teardown` &middot; `lab_exec` &middot; `playwright_capture` &middot; `report_generate` &middot; `report_open` &middot; `web` and more

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
| `cve` | Full CVE investigation (fetch -> lab -> PoC -> report) |
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

binoracle ships 40+ intentionally vulnerable binaries for local practice:

```bash
# Compile the full corpus (requires Docker or gcc)
samples/build.sh

# Run against the corpus
binoracle triage samples/bin/ret2win
binoracle pwn   samples/bin/ret2libc
binoracle pwn   samples/bin/format_string
binoracle pwn   samples/bin/tcache_dup
binoracle pwn   samples/bin/house_of_orange
```

Techniques covered: ret2win &middot; ret2libc &middot; SROP &middot; tcache dup &middot; fastbin dup &middot; UAF &middot; format string GOT overwrite &middot; canary leak &middot; PIE leak &middot; CSU chain &middot; DL-resolve &middot; heap botcake &middot; house-of-orange &middot; unsafe-unlink &middot; stack pivot &middot; IO_FILE &middot; callhijack &middot; dlresolve32

---

## Installation

**From PyPI**

```bash
pip install binoracle
```

**From source**

```bash
git clone https://github.com/beafn28/binoracle
cd binoracle
pip install -e ".[all]"
```

**Dependency sets**

```bash
pip install binoracle[elf]         # deep ELF analysis
pip install binoracle[pwn]         # pwntools + ROPgadget
pip install binoracle[symbolic]    # angr symbolic execution
pip install binoracle[web]         # web UI
pip install binoracle[screenshots] # Playwright screenshots in CVE reports
pip install binoracle[all]         # everything
```

**System requirements**

| Dependency | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.10 | 3.12 |
| RAM | 8 GB | 16 GB |
| Docker | 20.x | 25.x |
| Ollama | 0.3 | latest |
| GPU | &mdash; | 8 GB VRAM (Qwen 7B quantized) |

---

## Configuration

```bash
# Recommended: local LLM via Ollama (fully offline)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# Optional: any OpenAI-compatible cloud backend
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_API_KEY=sk-...
export BINORACLE_MODEL=gpt-4o-mini

# Report language (default: es)
export BINORACLE_LANG=en
```

---

## binoracle vs REA

| Feature | binoracle | REA |
|---------|:---------:|:---:|
| Local LLM via Ollama | yes | no |
| CVE -> Docker lab -> verified PoC | yes | no |
| Playwright screenshots as evidence | yes | no |
| WordPress / Joomla / Drupal labs | yes | no |
| MCP server (~100 tools) | yes | no |
| APK / .NET / WASM / EVM analysis | yes | partial |
| Fully offline | yes | partial |
| ret2win / ret2libc / SROP | yes | yes |
| Heap attacks (tcache / fastbin / UAF / House-of-X) | yes | yes |
| Format string exploitation | yes | yes |
| ROP chain synthesis | yes | yes |
| Practice corpus (40+ binaries) | yes | yes |

---

## Roadmap

- [ ] Kernel exploit chains (ret2usr, UAF in kernel drivers)
- [ ] Firmware analysis (UEFI, embedded Linux)
- [ ] Active fuzzing with LibFuzzer corpus seeding from CVE PoCs
- [ ] Multi-CVE chaining (web RCE -> local privilege escalation)
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

MIT &copy; 2024&ndash;2026 Beatriz Fresno Naumova

---

<div align="center">

**binoracle &mdash; autonomous security research &middot; fully local &middot; no data leaves your host**

[Docs](https://beafn28.github.io/binoracle/) &middot; [Issues](https://github.com/beafn28/binoracle/issues) &middot; [Espanol](docs/README.es.md)

</div>
