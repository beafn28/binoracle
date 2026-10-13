# binoracle

Local LLM copilot for binary reverse engineering and exploitation, grounded on real
analysis oracles.

## Why this is different

Most LLM-for-RE tools do one of two things: they call a cloud API (so you cannot feed
them malware or client binaries), and they let the model "opine" over decompiled
pseudocode with no ground truth (so it hallucinates bugs that are not there).

binoracle takes the opposite stance:

1. **Fully local.** The model runs on your machine via Ollama or any OpenAI-compatible
   local server (llama.cpp, LM Studio, vLLM). Nothing leaves the host. Works offline.
   The core tool uses only the Python standard library.

2. **Oracle-grounded.** The model is not allowed to state a fact about the binary out of
   thin air. Every claim must come from a real tool: radare2 for disassembly and
   cross-references, pyelftools for headers and mitigations, angr for symbolic
   reachability, a debugger for dynamic state. The agent loop is a
   hypothesis -> oracle -> verification cycle. Unverified guesses are labelled as such.

3. **The unit of work is a verified finding, not a prompt.** A vulnerability hypothesis
   is only promoted to a finding when an oracle backs it (a dangerous sink reachable from
   attacker-controlled input, a missing bounds check on a real path, etc.).

The result: you can point it at a stripped ELF, get a grounded triage in seconds without
any model at all, and then bring the local LLM in to reason on top of facts it cannot
fake.

## Verified exploitation

binoracle does not stop at "this looks exploitable". For several bug classes it builds a
real exploit and **runs it in an isolated sandbox to confirm a shell**, so the result is a
verified exploit, not a claim.

binoracle **trains** this skill on an authorized corpus (`binoracle train`): it develops and
runs an exploit for every binary and records *only what the sandbox confirms*. The verified
techniques are catalogued in `binoracle/kb/verified-playbook.md` — auto-generated
(`binoracle train --export-playbook`), regenerated on each run, and fed back into planning, so
the agent's hard-won, execution-verified playbook ships with the product. The selection logic
(which technique for which defenses) is documented in `binoracle/kb/exploit-engineering.md`.

| Class | Mitigations handled | How it is verified |
|-------|--------------------|--------------------|
| ret2win (incl. stripped, 32-bit) | overflow + gift/win function | jumps to win() in the sandbox (offset found symbolically, hard time-bounded) |
| ret2win on PIE | NX + PIE | resolves the PIE base, jumps to win() |
| ROP / ret2syscall (static/PIE) | NX (+ PIE) | builds an `execve('/bin/sh')`/ret2libc chain, spawns a shell |
| ret2libc with leak | NX + ASLR (dynamic) | leaks libc (puts@GOT), computes the base, `system('/bin/sh')` |
| ret2dlresolve (no leak) | NX, dynamic no-PIE, Partial RELRO | forges the linker's resolver structures → `system('/bin/sh')` with **no libc leak** |
| SROP (sigreturn) | NX, gadget-poor no-PIE | one `rt_sigreturn` restores a forged register frame → `execve('/bin/sh')` with only `pop rax` + `syscall` |
| format-string (Partial RELRO) | NX, printf@GOT | overwrites printf@GOT with system, `system('/bin/sh')` |
| format-string (Full RELRO) | NX + PIE + Full RELRO | GOT is read-only → ret2system by hijacking printf's saved return on the stack |
| stack-canary bypass | NX + **stack canary** | leaks the canary (via a `%s` echo *or* a `printf(input)` format string), rewrites it in place, overflows past it to win() |
| write-what-where | NX | unchecked index → a called function's GOT entry = win() |
| UAF funcptr-hijack | NX | realloc recycles a freed struct whose first field is a function pointer = win() |
| heap → shell (tcache poisoning) | NX, glibc ≥ 2.32 safe-linking | leaks the key via an empty bin, `free@GOT = win` (repairs the GOT neighbour the key-clear zeroes) |
| tcache dup (double-free) | NX | makes malloc return an aligned GOT entry, `free@GOT = system` |

A shell is confirmed by having it echo a unique marker. Every run is isolated:
no network, memory and pid limits, and ASLR disabled (`setarch -R` / `aslr=False`) so the
local proof-of-concept is deterministic.

**ROP arsenal (grounded reasoning aid).** Alongside the verified classes, `analyze_chains`
surfaces a ROP arsenal built from the binary: the best gadget per argument register
(rdi/rsi/rdx/rcx/r8/r9/rax), the syscall gadget, the least-noisy stack pivot, write-what-where and
register-to-register move gadgets, and an explicit execve-by-syscall coverage check. It also
detects **ret2csu** (the universal `__libc_csu_init` gadgets, for when direct `pop rsi/rdx` are
missing) and, for statically-linked binaries, integrates **one_gadget** magic-gadget offsets (the
embedded libc lives inside the target; absolute addresses when no PIE). These are reported as
*present/available* — grounded in the binary — not as verified chains, and shown up front in both
the markdown and the interactive HTML report so the ROP reasoning is explicit. one_gadget is
caller-supplied and degrades honestly with an install hint when the gem is absent.

### Requirements

Verification prefers the `binoracle-pwn` Docker image, but **Docker is not required**: when the
image is absent, binoracle falls back to a **native OS-isolation sandbox** on any Linux x86-64
host — a user+network namespace (`unshare -rn`, no network like `--network none`), ASLR off
(`setarch -R`) and resource limits (CPU/memory/pids/file-size/no-core). The result records
which engine verified it (`docker` or `native`). To use the Docker path, build the image once:

```bash
make pwn-image        # builds the 'binoracle-pwn' image (python + pwntools + one_gadget)
# make clean-docker   # if the Docker build cache fills the disk
```

The sample corpus builds with that image too, or with a host `gcc` on Linux when the image is
absent (`bash samples/build.sh`).

### Using it

```bash
# one-shot: try every technique, verify which actually work, feed the knowledge base
binoracle autopwn ./chall

# only specific techniques
binoracle autopwn ./chall            # (the web UI exposes per-technique checkboxes)

# a single class
binoracle autopoc ./chall            # ret2win: offset + exploit + sandbox verification

# the local LLM drives the whole audit and calls the exploit tools itself
binoracle audit ./chall
```

In `autopwn` the local model (with the IA toggle) reads the observed facts and decides which
techniques to try and in what order. In `audit` the model drives an agent loop with the
exploitation tools (`try_ret2win`, `try_rop`, `try_ret2libc`, `try_fmt`) available, and a
deterministic backstop guarantees a verified exploit when one exists.

### Scope

Verified-by-execution today covers the classes tabulated above, plus ROP on PIE (`autopie_rop`
resolves the ASLR-off PIE base in the sandbox, rebases the chain and confirms a shell; the
`ropme_pie` static-PIE sample is the target), and heap-to-shell for the common menu-driven
tcache-UAF shape (`autoheap_shell`: leaks the safe-linking key from a freed chunk, poisons
the tcache to allocate over `free@GOT` on a no-PIE binary and overwrites it with `win`; the
`heapexp` sample is the target). Double-free / heap-overflow are also confirmed by execution
via glibc's allocator aborts (`autoheap`). Heap-to-shell runs natively on an x86-64 host;
under a Mac's x86-64 emulation the final redirected jump into never-executed code can fail.
Fully general heap exploitation (arbitrary layouts, libc-leak chains) remains bespoke per
binary. Everything runs only against binaries you are authorized to analyze.

## Optional caller-supplied tool integrations

Some steps need a heavy external tool that binoracle deliberately does not bundle (offline,
dependency-light). It drives one when you have it installed and **degrades honestly** (naming the
tool and how to get it) when absent — each runs the tool with the artifact as an argument (no
shell), bounded, and treats its output as untrusted:

```bash
binoracle caller-tool wat ./mod.wasm        # WAT disassembly via WABT (wasm2wat)
binoracle caller-tool pcap ./cap.pcap       # protocol-hierarchy summary via TShark
binoracle caller-tool firmware ./fw.bin     # signature scan via Binwalk (no extraction)
binoracle caller-tool one_gadget ./libc.so.6  # magic-gadget offsets via one_gadget
binoracle caller-tool capinfos ./cap.pcap   # capture file metadata via capinfos
binoracle caller-tool manifest ./app.apk    # decode AndroidManifest.xml via Apktool
binoracle caller-tool jadx ./app.apk        # decompile DEX to Java via JADX
binoracle caller-tool ghidra ./prog         # decompile a native binary to C pseudocode via Ghidra
```

Native pseudocode is driven through **Ghidra's headless analyzer** (`analyzeHeadless`, found on
`PATH` or under `GHIDRA_INSTALL_DIR`) — Ghidra decompiles statically and never runs the target. It
imports into a throwaway project (removed afterwards) and returns per-function C pseudocode; pass a
function name to scope it. Same model REA uses for native analysis (it requires Hopper/Ghidra/IDA).

Also the `wasm_to_wat`, `pcap_summary`, `firmware_scan`, `one_gadget`, `pcap_fileinfo`,
`apk_manifest`, `apk_decompile` and `decompile_native` MCP tools.

## Reverse engineer anything (one entry point)

`binoracle identify ./file` sniffs any artifact's format and routes it to the matching grounded
reader — ELF (layout, or a core dump, or Go build-info), Mach-O, PE/.NET, WebAssembly, SQLite,
Android APK, a Java JAR or .class, an Apple property-list, an Electron ASAR archive, or a HAR
capture — and prints that
reader's result. Also the `identify_artifact` MCP tool. The "reverse engineer anything" front
door, with nothing executed.

## MCP server (one MCP for grounded RE + exploit-dev)

binoracle ships an MCP server so any MCP-capable agent (Claude Code, etc.) can drive its
grounded tools. It speaks JSON-RPC 2.0 over stdio with **no extra dependency**:

```bash
binoracle mcp     # stdio MCP server; register it with your agent as a command server
```

Tools exposed: `triage`, `analyze_chains` (static or `verify`-by-execution), `hunt`,
`primitives`, `kb_search`, and the authorized exploit-development tools `autopwn`, `autopoc`,
`autolibc`, `autofmt`, `autoheap`, `autocanary`, `autosrop`, `autodlresolve`. Every result that
derives from the analysis target is tagged `_meta.provenance.untrusted_content` so the host treats
it as data, not instructions. Exploit tools are for AUTHORIZED / CTF / research targets only.

The MCP design (one server registering many grounded tools over stdio, untrusted-target-content
marking) is adapted from [REA](https://github.com/morluto/rea) (MIT); see THIRD_PARTY_NOTICES.

## Supported executable formats

binoracle is not ELF-only. The static and symbolic layers are format-agnostic because they
are backed by radare2 and angr, which both understand multiple executable formats:

| Format                     | triage / disasm / sinks (radare2) | checksec | angr reachability | run under debugger |
|----------------------------|-----------------------------------|----------|-------------------|--------------------|
| ELF (Linux)                | yes                               | yes      | yes               | yes (on Linux/host)|
| PE / .exe / .dll (Windows) | yes                               | yes      | yes (via CLE)     | needs Windows/wine |
| Mach-O (macOS)             | yes                               | yes      | partial           | yes (on macOS)     |
| raw / shellcode blobs      | yes (with -a arch)                | n/a      | limited           | no                 |

Notes:
- Static analysis (functions, imports, disassembly, xrefs, sinks, ROP gadgets, gift finder)
  and cross-format `r2_checksec` work on ELF, PE (.exe/.dll) and Mach-O out of the box.
- `angr_reachable` works on ELF and PE; Mach-O support is partial.
- The `elf_*` oracle (GOT/PLT, relocations, symbols) is ELF-specific; on PE/Mach-O those
  tools simply report themselves unavailable and radare2 covers the equivalent ground.
- Dynamic execution (`dbg_run_input`) can only run a binary the host can execute: a Linux
  ELF on Linux, a Windows .exe under Windows/wine, a Mach-O on macOS.
- **Go binaries**: `binoracle go ./target` reads the embedded build info (compiler version,
  main module, dependencies with replacements, and build settings) **statically, with no Go
  toolchain and without running the target**. Absence of the blob is not a verdict that the
  binary is not Go. Also exposed as the `inspect_go_binary` MCP tool.
- **Core dumps**: `binoracle core ./core` reads an ELF crash dump statically (no debugger): the
  killing signal, the fault address, each thread's registers, and the memory mappings — and flags
  a register that holds printable input bytes (the overflow tell). Also the `inspect_core_dump`
  MCP tool. The starting point for turning a crash into an exploit.
- **ELF layout**: `binoracle elf ./target` gives an offline layout — header, sections, load
  segments, symbol/relocation counts, linkage (needed libs, interpreter) and the static
  mitigation candidates (PIE, NX, executable stack, stack-canary presence, RELRO Partial/Full,
  RWX segments), each labelled inferred with its limitations. Also the `inspect_elf_layout` MCP tool.
- **WebAssembly**: `binoracle wasm ./mod.wasm` reads a module statically (no WABT) — version,
  section inventory, function type signatures, and every import/export with its kind. Instruction
  bodies are not decoded to WAT (that needs WABT); the limit is reported. Also `inspect_wasm_artifact`.
- **SQLite databases**: `binoracle sqlite ./app.db` opens the file read-only and reports the schema
  (tables, columns, indexes, views, triggers) and a bounded row sample — no writes, no triggers
  fired. Built-in sqlite3, no dependency. Also the `inspect_sqlite_database` MCP tool.
- **EVM bytecode**: `binoracle evm ./code.hex` reads EVM runtime bytecode (raw or hex) — the
  function selectors (PUSH4 heuristic), capability opcodes (CALL/DELEGATECALL/CREATE/SELFDESTRUCT)
  and the Solidity metadata CBOR trailer (solc version, IPFS/Swarm hash). Also `inspect_evm_bytecode`.
- **Network captures (HAR)**: `binoracle har ./capture.har` reads a saved HTTP archive — the
  request/response inventory, hosts, and secrets exposed in URLs/headers/bodies (Authorization,
  api_key/token/password, JWT, AWS keys), heuristic and labelled. Also `inspect_har_capture`.
- **.NET / CLI assemblies**: `binoracle dotnet ./app.dll` reads a managed PE statically (pefile to
  locate the CLI header) — runtime/metadata version, the metadata streams, the metadata-table row
  counts (Module/TypeDef/MethodDef/Assembly…) and a sample of the #Strings name heap. CIL method
  bodies are not disassembled. Also the `inspect_dotnet_assembly` MCP tool.
- **Mach-O (macOS)**: `binoracle macho ./bin` reads the Mach-O header and load commands statically —
  architecture, file type, segments with protections (W+X flagged), linked dylibs, entry point and
  the mitigation flags (PIE, executable stack); fat/universal binaries are split into slices. It
  also reads the section table for **Objective-C** metadata (class and selector names, class/
  protocol/category counts) and **Swift** metadata (`__swift5_*` descriptor counts) — grounded
  names and counts, no runtime. Also the `inspect_macho` MCP tool.
- **PE (Windows)**: `binoracle pe ./app.exe` reads a PE statically (pefile) — architecture, sections
  with Shannon entropy (packing hint), the DllCharacteristics mitigations (ASLR, DEP/NX, Control
  Flow Guard, SafeSEH, high-entropy ASLR), the imported DLLs, and a capability map of imports
  (process/network/crypto/injection/registry/anti-debug). Also the `inspect_pe` MCP tool.
- **Android APKs**: `binoracle apk ./app.apk` reads the APK (a ZIP) statically — DEX files, native
  libraries by ABI, the app framework (Flutter/React Native/Unity/Xamarin), signing (v1 JAR +
  v2/v3 block) and SHA-256 digests of the Flutter snapshots (libapp.so). The binary
  AndroidManifest.xml is detected but not decoded (needs Apktool). Also the `inspect_apk` MCP tool.
- **Java (JAR / .class)**: `binoracle java ./app.jar` reads a JAR (a ZIP) statically — the
  MANIFEST.MF (Main-Class, versions), the class/package inventory, the framework by package prefix
  (Spring/Jakarta/Kotlin/Scala/Android), signing, and the bytecode major version → Java release.
  Point it at a standalone `.class` and it reads the magic/version and class/super names from the
  constant pool. Method bodies are not decompiled (needs CFR/Procyon). Also the `inspect_java` MCP
  tool. (The `.class` magic `0xCAFEBABE` collides with Mach-O fat; detection disambiguates by the
  bytecode version field.)
- **Apple property-lists**: `binoracle plist ./Info.plist` reads a binary (bplist00) or XML plist
  with the built-in plistlib — bundle id, executable, versions, minimum OS, the URL schemes it
  registers and the privacy usage-description keys (`NS*UsageDescription`) that reveal what the app
  touches (camera, location, microphone…). Also the `inspect_plist` MCP tool.
- **Electron apps (ASAR)**: `binoracle asar ./app.asar` reads an Electron archive straight from
  bytes — the file/directory tree, the embedded `package.json` (name, version, `main` entry point,
  declared dependencies), the JavaScript modules and the per-file integrity blocks. `package.json`
  is sliced out by offset; JS is never executed or deminified. Also the `inspect_asar` MCP tool.
- **Embedded secrets / IOCs (any file)**: `binoracle secrets ./anything` extracts printable strings
  (ASCII + UTF-16LE) from any artifact and flags embedded URLs, hosts, IPs, e-mails, cloud/API
  credentials (AWS/GCP/Slack/GitHub/Stripe), JWTs, private-key PEM headers and high-entropy tokens.
  Secret values are redacted in the output; everything is heuristic and labelled. The cross-cutting
  companion to the format readers. Also the `scan_iocs` MCP tool.

So yes: point it at a `.exe` and you get triage, mitigations, sinks, disassembly, gadget
search and angr reachability. You just cannot *run* a Windows .exe on macOS without wine.

## No false positives, by construction

Grounding is not just a prompt instruction here; it is enforced in code:

- **Verdict gate.** A finding is only `verified` if the grounding ledger contains a proof
  source (an `angr` reachability result or a `dbg` crash). Otherwise the verdict is capped
  at `grounded`. The model does not get to call something "verified".
- **Evidence gate.** A finding whose `evidence` field is empty or cannot be traced back to
  a tool result we actually ran is downgraded to `unverified` and flagged.
- **No contradicting tools.** The prompt forbids denying a tool result, and the
  deterministic workflows (triage, primitives heuristic) never route factual claims through
  the model at all.
- **Anti-loop.** Repeated identical tool calls are cached and refused, and the agent is
  forced to finalize instead of spinning.

So a "verified attack path" means an oracle proved it, not that the LLM asserted it.

## Install

The skeleton needs nothing but Python 3.10+. Oracles are optional extras:

```bash
# clone / cd into the folder, then:
pip install -e .            # core only (stdlib)
pip install -e ".[elf]"     # + ELF header/mitigation oracle (pyelftools)
pip install -e ".[all]"     # + r2pipe, angr, capstone
```

radare2 must be on PATH for the static oracle (`brew install radare2` /
`apt install radare2`). For real (non-toy) binaries, also install `r2pipe` so radare2 runs
as a persistent session (analysis is cached once instead of per call), and `angr` so
reachability can be *proven* rather than assumed:

```bash
pip install -e ".[symbolic]"   # angr: turns 'grounded' findings into 'verified' ones
pip install r2pipe             # persistent radare2 session (much faster on real binaries)
pip install pwntools           # ROP chain builder + shellcode generation
```

Everything degrades gracefully: if an oracle is missing, its tools report themselves
unavailable instead of crashing.

Point it at a local model:

```bash
# default backend is Ollama on http://localhost:11434
ollama pull qwen2.5-coder:7b        # any coder-ish local model works
export BINORACLE_MODEL=qwen2.5-coder:7b
```

## Usage

Recon and understanding:

```bash
binoracle doctor                       # what oracles + which LLM backend are available
binoracle triage ./target              # grounded facts + mitigations (NO model needed)
binoracle triage ./target --explain    # same, plus a local-LLM narrative on top of facts
binoracle explain ./target sym.main    # explain one function, grounded in its disassembly
binoracle ask ./target "where does stdin reach system()?"
binoracle chat ./target                # interactive grounded REPL
```

Vulnerability research and exploitation:

```bash
binoracle hunt ./target                # vuln hypotheses, each verified against an oracle
binoracle primitives ./target          # reason about the exploitation primitive to use
binoracle gadgets ./target -f "pop rdi"  # ROP gadget search
binoracle cyclic -n 200                 # De Bruijn pattern (offset discovery)
binoracle cyclic --find 0x6161616c      # find the offset from a crash value (== pwntools)
binoracle exploit-skeleton ./target --offset 72 -o exp.py   # pwntools template, grounded
binoracle rop ./target --goal execve       # build a real ROP chain (pwntools)
binoracle shellcode --arch amd64 --kind sh # execve('/bin/sh') shellcode
binoracle fmtstring ./target               # format-string leak/write helper (infoleak)
binoracle fuzz ./target --mode afl         # fuzzing harness / AFL command
```

Knowledge base (RAG) and tooling:

```bash
binoracle kb                               # list the bundled exploitation cheat sheets
binoracle kb "double free tcache glibc"    # retrieve the most relevant technique snippets
binoracle tools                            # detect the installed binary-pentest toolchain
binoracle rag                              # RAG status + retrieval layers (embeddings/expand/rerank)
binoracle learn <folder>                   # learn a skills/docs folder into the KB (--apply to write)
```

The `kb` command exposes the same local RAG the model consults during `primitives` and
`audit`: curated exploitation cheat sheets plus an imported CTF pwn/reverse corpus, indexed
recursively from `binoracle/kb/`. It is grounding for the model's reasoning, never a source of
verdicts: the oracles remain the only thing that can promote a finding to `verified`.

Retrieval is hybrid and layered, and turns itself on automatically. The core is a
dependency-free TF-IDF cosine retriever (always on, deterministic). When a local model is
reachable, semantic embeddings and LLM query-expansion enable by themselves (embeddings build
in a background thread and cache to disk, so nothing blocks); with no model it stays TF-IDF.
The best installed embedder is auto-selected (bge-m3 multilingual > nomic-embed-text > the LLM
itself) - bge-m3 is recommended because it matches Spanish queries against English content far
better. Reranking stays opt-in (heaviest layer).

Override anything with env vars or the dashboard's "RAG" toggle (persisted):

```bash
export BINORACLE_RAG_AUTO=0      # disable the automatic behaviour (pure TF-IDF)
export BINORACLE_RAG_EMBED=1     # force semantic embeddings on/off
export BINORACLE_EMBED_MODEL=bge-m3   # force a specific embedder (else auto-selected)
export BINORACLE_RAG_EXPAND=1    # LLM query expansion (related technical terms)
export BINORACLE_RAG_RERANK=1    # LLM reranking of the candidate pool
export BINORACLE_RAG_FULL=1      # force all three on
```

`binoracle doctor` (and the web dashboard's Estado) print the active RAG mode.

One-shot manager (give it a `.c` source or a binary, get the full verified report):

```bash
binoracle analyze ./chall.c                # compiles, analyzes, verifies, writes HTML
binoracle analyze ./chall  -o report.html
```

Local web dashboard (metrics, mitigation grid, all commands, file upload):

```bash
binoracle serve            # http://127.0.0.1:8765 (localhost only)
```

n-day / regression:

```bash
binoracle diff ./old ./new -o diff.md   # radiff2-grounded patch diff + LLM fix analysis
binoracle report ./target -o out.md     # full grounded markdown report from the session
binoracle view ./target                 # interactive HTML report, opens in the browser
binoracle hunt ./target --html out.html # any command can also emit the HTML report
```

Sessions (facts, annotations, findings) are stored per-binary in a local SQLite DB under
`.binoracle/` so a re-run is incremental.

## AI analysis and language

When a local model is up, `binoracle view` and `binoracle hunt` add an **AI layer** on top
of the grounded findings:

- a professional **executive summary** for a CISO, and
- per finding, a structured write-up (Description / Impact / Exploitation path / Remediation).

This layer is constrained: it writes the human-facing prose but **cannot change the
code-assigned verdict or severity**, and it is told not to claim exploitability beyond what
the verdict allows. Evidence stays the raw tool output. So the AI makes the report readable
and complete without introducing false positives.

Language is controlled by `BINORACLE_LANG` (default `es`; `en` also supported), and the HTML
report has a live ES/EN toggle and a light/dark toggle.

```bash
BINORACLE_LANG=es binoracle view ./target        # Spanish, verified findings, AI narrative
BINORACLE_LANG=en binoracle hunt ./target --html report.html
```

## Architecture

```
        binoracle ask/hunt/chat
                 |
                 v
        +--------------------+        proposes tool calls
        |    AGENT LOOP      |  <---------------------------.
        | hypothesis->verify |                              |
        +---------+----------+                              |
                  | executes only registered oracle tools   |
                  v                                          |
   +----------------------------+     grounded facts     +--+--------------+
   |          ORACLES           |----------------------->|   LOCAL LLM     |
   | r2 | elf | angr | debugger |                        | (Ollama /       |
   +-------------+--------------+                         |  OpenAI-compat) |
                 |                                        +-----------------+
                 v
        +--------------------+
        |   SESSION STORE    |  SQLite: facts, annotations, verified findings
        +--------------------+
```

Key rule enforced in `agent/grounding.py`: a statement about the binary that is not
attributable to an oracle result is flagged `[UNVERIFIED]` in the output.

## Scope and ethics

This is a research and CTF tool. Use it on binaries you are authorized to analyze: your
own software, CTF challenges, malware in a lab, and targets covered by an authorized
engagement. It does not ship weaponized exploits against third-party systems; it helps you
understand a binary and reason about exploitation primitives on targets you are allowed to
work on.

## Layout

```
binoracle/
  llm/         local model backends (Ollama, OpenAI-compatible), tool-call protocol
  oracles/     ground-truth analyzers:
               static_r2      (radare2: info, imports, disasm, xrefs, sinks, checksec,
                               rop gadgets, gift-function finder, stack frames)
               elf_meta       (pyelftools + stdlib fallback: header, checksec, GOT/PLT,
                               relocations, symbols)
               exploit_helpers(pure-stdlib: De Bruijn cyclic, fmtstr offset, badchars)
               symbolic_angr  (reachability proofs + concrete inputs, optional)
               dynamic_dbg    (lldb/gdb: run + observe real crashes, opt-in)
  agent/       the grounded hypothesis/verification loop, tool schema, prompts
  store/       SQLite session persistence
  workflows/   triage, vuln hunt, function explanation
  report/      markdown rendering
  cli.py       command line entrypoint
```
