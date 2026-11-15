<div align="center">

<img src="docs/assets/logo.svg" alt="binoracle" width="120" height="120">

# binoracle

**Local CVE exploit research and binary reverse engineering &mdash; fully autonomous, no data leaves your host**

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-gh--pages-7C3AED?style=for-the-badge&logo=github&logoColor=white)](https://beafn28.github.io/binoracle/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama%20local-F97316?style=for-the-badge)](https://ollama.com)
[![Docker](https://img.shields.io/badge/labs-Docker%20ephemeral-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)

[English](README.md) &middot; [Espanol](docs/README.es.md) &middot; [Documentation](https://beafn28.github.io/binoracle/) &middot; [Architecture](docs/assets/architecture.svg)

</div>

---

> **Legal notice** &mdash; binoracle is a research and educational tool.
> All CVE labs run exclusively against Docker containers you provision locally.
> Do not use this tool against systems you do not own or lack explicit written authorization to test.

---

## Install

```bash
pip install binoracle
curl -fsSL https://ollama.com/install.sh | sh && ollama pull qwen2.5-coder:7b

export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b
```

---

## Two pipelines, one tool

<table>
<tr>
<th width="50%">CVE pipeline</th>
<th width="50%">Binary RE pipeline</th>
</tr>
<tr>
<td valign="top">

Give binoracle a CVE identifier. It fetches the descriptor from NVD, feeds it to a **local Qwen 2.5 Coder 7B** (via Ollama), which produces an exploit hypothesis autonomously &mdash; no analyst hints. It then provisions an ephemeral Docker Compose lab, fires the PoC against it, captures Playwright screenshots at every step, and writes a structured HTML report to disk.

```bash
binoracle cve CVE-2025-27516
binoracle cve CVE-2025-27516 --lang en --open-report
binoracle cve-batch CVE-2025-27516 CVE-2024-23334
```

</td>
<td valign="top">

Give binoracle a binary. It runs static and dynamic analysis (ELF, PE, Mach-O, APK, WASM, Go, Rust, .NET, JS, EVM, SQLite), selects the appropriate exploit technique, generates a working pwntools script, and reports mitigations and bypass strategies.

```bash
binoracle triage    ./binary
binoracle pwn       ./binary
binoracle decompile ./binary
binoracle rop       ./binary
binoracle hardening ./binary
```

</td>
</tr>
</table>

---

## CVE Engine

![CVE engine pipeline](docs/assets/cve-flow.svg)

```
NVD  -->  local LLM  -->  hypothesis  -->  Docker lab  -->  PoC  -->  HTML report
           Qwen 2.5       zero hints     ephemeral env   Playwright    disk only
```

The LLM receives the raw NVD description and nothing else. All exploit hypotheses are generated from that description alone, with no external hints or guidance.

### Vulnerability coverage

| Class | Ecosystems | Auto PoC |
|-------|-----------|----------|
| SSTI | Jinja2, Twig, Smarty | yes |
| SQLi (GET / POST / JSON / header) | Python, Ruby, PHP, Java | yes |
| Path traversal / LFI | Python, Ruby, Node, httpd | yes |
| RCE / command injection | Python, Ruby, Node | yes |
| XSS (reflected / stored) | Python, Node | yes |
| SSRF | Python, Node | yes |
| XXE | Java / Maven | yes |
| Deserialization | Java, Ruby (Marshal) | yes |
| Auth bypass / IDOR | Python, Ruby, Node | yes |
| File upload / webshell | Python | yes |
| Open redirect | Python, Ruby, Node | yes |
| CSRF | Python, Ruby | yes |
| WordPress plugins (100+) | WP Docker | yes |
| Joomla extensions | Joomla Docker | yes |
| Drupal modules | Drupal Docker | yes |
| Apache httpd | httpd Docker | yes |
| Spring / Struts / Log4j | Maven | yes |
| PHP Composer packages | PHP Docker | yes |
| npm / Node.js / Next.js | Node Docker | yes |
| Ruby gems (Rails, Rack, Sinatra) | Ruby Docker | yes |

---

## Binary RE Engine

### Exploit techniques

| Category | Techniques |
|----------|------------|
| Stack | ret2win, ret2libc, ret2plt, ret2csu, SROP (x86-64 / x86-32 / aarch64), stack pivot |
| Heap | tcache dup, fastbin dup, UAF, double-free, House-of-Force, House-of-Spirit, House-of-Orange, House-of-Mind, large-bin attack, unsafe-unlink, Botcake |
| Format string | %n arbitrary write, GOT overwrite, canary leak, PIE leak |
| Low-level | shellcode (NX off), bad-char scrubbing, IO_FILE, DL-resolve, GOT hijack |
| Canary bypass | leak + reuse, fork brute-force |
| PIE bypass | partial overwrite, leak chain |

### Supported file formats

| Format | Backends |
|--------|---------|
| ELF (x86-64 / x86 / ARM / MIPS / RISC-V) | radare2, pyelftools, pwntools, angr, pwndbg |
| PE / PE+ (Windows) | pefile, LIEF, radare2 |
| Mach-O (macOS / iOS) | LIEF, radare2 |
| APK / DEX (Android) | apktool, jadx, androguard |
| .NET assemblies | dnlib, ILSpy |
| Go binaries | go-dis, symbol recovery |
| Rust binaries | LIEF + symbol demangling |
| WASM modules | wabt, binaryen |
| EVM bytecode | pyevmasm |
| SQLite | sqlite3 schema + data dump |

---

## Reports

Every CVE investigation and binary analysis writes a self-contained HTML report:

| Section | Contents |
|---------|----------|
| Executive summary | CVSS score, severity, affected component |
| Hypothesis | Full LLM reasoning chain |
| Lab | Docker Compose spec, service versions |
| Evidence | Playwright screenshots at each verification step |
| PoC | Complete curl / Python / pwntools code |
| Remediation | Specific fix guidance with code examples |

```bash
binoracle cve CVE-2025-27516 --open-report
binoracle cve CVE-2025-27516 --out ./reports/
binoracle cve-batch CVE-2025-27516 CVE-2024-23334 --out ./reports/
```

---

## MCP Integration

binoracle runs as an MCP server, exposing the full toolkit (~100 tools) to any MCP-compatible client.

```bash
binoracle mcp-server
```

```json
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
<summary>All MCP tools</summary>

`triage` `pwn` `rop_chain` `heap_exploit` `fmt_exploit` `decompile` `cve_investigate` `vuln_hunt` `iocscan` `hardening` `audit` `reachability` `diff_patch` `elf_layout` `pe_inspect` `apk_audit` `dotnet_inspect` `wasm_inspect` `sqlite_audit` `evm_inspect` `fuzz` `dynamic_trace` `coredump` `shellcode` `srop_chain` `got_hijack` `io_file` `dlresolve` `canary_leak` `pie_leak` `format_string` `heap_triage` `heap_tcache` `heap_fastbin` `heap_uaf` `heap_house` `stack_pivot` `ret2csu` `ret2plt` `ret2libc` `ret2win` `rop_search` `symbol_recovery` `import_scan` `export_scan` `section_dump` `string_extract` `entropy_scan` `yara_scan` `cve_batch` `vuln_classify` `patch_diff` `n_day_analysis` `cwe_map` `cvss_score` `exploit_db_search` `lab_provision` `lab_teardown` `lab_exec` `playwright_capture` `report_generate` `report_open` `web` and more

</details>

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `triage` | Mitigations, symbols, imports, sections |
| `decompile` | Ghidra / radare2 / angr / pwndbg + LLM annotation |
| `pwn` | Full exploit chain, technique auto-selected |
| `rop` | ROP gadget search and chain synthesis |
| `chain` | Gadget enumeration + pwntools script output |
| `heap` | Heap exploit primitives (tcache / fastbin / UAF / House-of-X) |
| `fmt` | Format string exploitation |
| `srop` | SROP chain generator |
| `shellcode` | Shellcode with bad-char filtering |
| `fuzz` | Dumb and smart fuzzer (AFL integration) |
| `dynamic` | strace / ltrace / gdb automation |
| `hardening` | Mitigation audit with bypass notes |
| `cve` | Full CVE pipeline: fetch -> lab -> PoC -> report |
| `cve-batch` | Parallelised batch CVE pipeline |
| `vuln-hunt` | Static taint analysis (sinks, sources) |
| `ioc-scan` | IOC and malware indicator scan |
| `audit` | All oracles + LLM synthesis |
| `reachability` | Source-to-sink reachability |
| `diff` | Patch diff and N-day analysis |
| `apk` | Android APK audit |
| `dotnet` | .NET assembly inspection |
| `wasm` | WASM module inspection |
| `sqlite` | SQLite schema + data audit |
| `evm` | EVM bytecode inspection |
| `mcp-server` | Start MCP server |
| `web` | Start local web UI |

---

## Architecture

![binoracle architecture](docs/assets/architecture.svg)

---

## Practice Corpus

40+ intentionally vulnerable binaries for local exploitation practice:

```bash
samples/build.sh                              # compile with Docker or gcc
binoracle pwn samples/bin/ret2libc
binoracle pwn samples/bin/tcache_dup
binoracle pwn samples/bin/house_of_orange
binoracle pwn samples/bin/format_string
```

Coverage: ret2win, ret2libc, SROP, tcache dup, fastbin dup, UAF, format string GOT overwrite, canary leak, PIE leak, CSU chain, DL-resolve, heap botcake, house-of-orange, unsafe-unlink, stack pivot, IO_FILE, callhijack, dlresolve32.

---

## Configuration

```bash
# Local LLM via Ollama (recommended, fully offline)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=http://127.0.0.1:11434/v1
export BINORACLE_MODEL=qwen2.5-coder:7b

# OpenAI-compatible cloud backend (optional)
export BINORACLE_BACKEND=openai
export BINORACLE_BASE_URL=https://api.openai.com/v1
export BINORACLE_API_KEY=sk-...
export BINORACLE_MODEL=gpt-4o-mini

# Report language
export BINORACLE_LANG=en    # default: es
```

**Dependency sets**

```bash
pip install binoracle[elf]         # pyelftools extras
pip install binoracle[pwn]         # pwntools + ROPgadget
pip install binoracle[symbolic]    # angr
pip install binoracle[screenshots] # Playwright
pip install binoracle[all]         # everything
```

**System requirements**

| | Minimum | Recommended |
|-|---------|-------------|
| Python | 3.10 | 3.12 |
| RAM | 8 GB | 16 GB |
| Docker | 20.x | 25.x |
| Ollama | 0.3 | latest |
| GPU | &mdash; | 8 GB VRAM |

---

## What sets binoracle apart

| Capability | binoracle | REA |
|-----------|:---------:|:---:|
| Autonomous CVE pipeline (NVD -> lab -> PoC) | yes | no |
| Local LLM via Ollama | yes | no |
| Ephemeral Docker labs per CVE | yes | no |
| Playwright screenshot evidence in reports | yes | no |
| WordPress / Joomla / Drupal lab scaffolding | yes | no |
| MCP server (~100 tools) | yes | no |
| APK / .NET / WASM / EVM analysis | yes | partial |
| Fully offline operation | yes | partial |
| Stack / heap / format string / SROP exploit chains | yes | yes |
| ROP chain synthesis | yes | yes |
| Multi-backend decompilation | yes | yes |
| Practice corpus | yes | yes |

---

## Roadmap

- [ ] Kernel exploit chains (ret2usr, UAF in drivers)
- [ ] Firmware analysis (UEFI, embedded Linux)
- [ ] LibFuzzer corpus seeded from CVE PoCs
- [ ] Multi-CVE chains (web RCE -> local privilege escalation)
- [ ] CVSS v4 scoring
- [ ] Burp Suite MCP bridge
- [ ] JEB decompiler (Android native)
- [ ] Fine-tuned model for exploit hypothesis generation

---

## Contributing

```bash
git clone https://github.com/beafn28/binoracle
cd binoracle && pip install -e ".[all]" && pre-commit install
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT &copy; 2024&ndash;2026 Beatriz Fresno Naumova

---

<div align="center">

[Documentation](https://beafn28.github.io/binoracle/) &middot; [Issues](https://github.com/beafn28/binoracle/issues) &middot; [Espanol](docs/README.es.md)

</div>
