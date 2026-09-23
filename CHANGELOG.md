# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Local RAG knowledge base** (`binoracle/kb/*.md` + `binoracle/rag.py`): curated
  exploitation cheat sheets (ret2win, ROP/ret2syscall, ret2libc, format-string, heap/tcache,
  PIE/leaks, mitigations, methodology, tools) indexed with a stdlib TF-IDF retriever (no
  external deps). Retrieval is grounding for the model, never a source of verdicts.
  - `binoracle kb [query]` — list cheat sheets or retrieve the most relevant snippets.
  - Wired into `primitives` (LLM narrative) and `audit` (agent system prompt) so the model
    reasons over real technique notes selected from the binary's own facts (checksec + sinks
    + gift functions), via `AgentLoop(kb_hint=...)`.
  - Exposed in the web dashboard (Utiles group) with a query field.
- **`binoracle tools`**: detects the installed binary-pentest toolchain (radare2/rizin,
  pyelftools, angr, pwntools, one_gadget, ROPgadget/ropper, gdb+pwndbg, lldb, ltrace/strace,
  checksec, binutils, docker) and maps each to how binoracle uses it. Also in the web UI.
- Tests: `tests/test_rag.py` (indexing, retrieval relevance, bounded context, fact queries).

## [0.1.0] - 2026-09-22

First public release. A local, oracle-grounded LLM copilot for binary reverse engineering
and exploitation.

### Added
- **Local-first core** using only the Python standard library; local LLM backends for
  Ollama and any OpenAI-compatible server (llama.cpp, LM Studio, vLLM).
- **Oracle framework** with graceful degradation:
  - `static_r2` (radare2): info, imports, functions, strings, disassembly, xrefs, dangerous
    sinks, cross-format checksec, ROP gadget search, gift-function finder, stack frames.
  - `elf_meta` (pyelftools + stdlib fallback): header, mitigations, GOT/PLT, relocations,
    symbols.
  - `symbolic_angr`: reachability proofs with concrete-input synthesis.
  - `dynamic_dbg` (lldb/gdb): run a target and observe real crashes.
  - `exploit_helpers` (pure stdlib): De Bruijn cyclic patterns, offset finding,
    format-string offset math, bad-char reference.
- **Grounded agent loop**: JSON tool-call protocol, anti-repetition guard, forced
  finalization, and end-of-run synthesis.
- **Anti-false-positive layer enforced in code**: a verdict gate (only angr/debugger proof
  allows `verified`), an evidence gate (empty/untraceable evidence is downgraded), and an
  automatic angr verification pass that promotes `grounded` findings to `verified`.
- **Workflows**: triage, vulnerability hunt, exploitation-primitive reasoner, function
  explanation, pwntools skeleton generation, patch-diffing (radiff2), automatic
  verification, and AI enrichment (professional per-finding analysis + executive summary).
- **Heap corruption confirmed by execution**: autoheap runs the target with probe
  inputs in the sandbox and confirms a real double-free / heap overflow via glibc's
  allocator abort, promoting the static heap candidates to a confirmed bug. Wired
  into autopwn, a try_heap tool and a `heap` CLI command.
- **ret2win on PIE (verified)**: resolves the PIE base in the sandbox and jumps to
  win(), confirmed by execution.
- **Format-string exploitation (verified)**: for a printf(user)-in-a-loop binary, it
  finds the format offset, overwrites printf@GOT with system and gets a real shell,
  confirmed in the sandbox. Works on PIE binaries too (the PIE base is resolved in
  the sandbox, so printf@GOT is overwritten at its real address).
- **ret2libc with leak (verified)**: leaks a libc address, computes the base and
  runs system('/bin/sh'), confirming a real shell in an isolated sandbox (pwntools
  image, ASLR off). Covers dynamic NX+ASLR binaries. Alongside ret2win and static
  ROP/ret2syscall, four exploit classes are now verified by execution (ret2win, static ROP, ret2libc, format-string).
- **Exploitation builders (pwntools)**: `rop` (ret2libc / execve syscall chain builder),
  `shellcode` (execve /bin/sh, with a precompiled fallback when no cross-assembler is
  present), `fmtstring` (format-string leak/write helper for infoleak), and `fuzz`
  (libFuzzer harness / AFL command generator).
- **Deeper static analysis**: modern hardening detection (FORTIFY, ASan, CFI, SafeStack,
  UBSan), C++/vtable detection, and heap attack surface (UAF / double-free candidates).
- **`analyze` one-shot**: give it a `.c`/`.cpp` source (it compiles) or a binary, and it
  runs the full pipeline (triage -> hunt -> angr verification -> AI report -> HTML).
- **`serve` web dashboard** (stdlib http.server, localhost only): metric charts (severity
  donut, exploitability gauge, KPI cards), a concrete mitigation grid, every command
  runnable from the browser (including ROP chains), and binary/source file upload.
- **CLI**: doctor, triage, hunt, ask, chat, report, primitives, gadgets, cyclic,
  exploit-skeleton, explain, diff, verify, view.
- **Interactive HTML report**: self-contained, bilingual (ES/EN toggle), light/dark toggle,
  KPI dashboard, severity distribution, mitigation risk panel, filterable findings,
  attack surface and full evidence trail.
- **Bilingual output** controlled by `BINORACLE_LANG` (default `es`).
- **Format coverage**: ELF, PE/.exe and Mach-O for static analysis and checksec; angr for
  ELF and PE.
- **Practice corpus** (`samples/`): reproducible ELF (ret2win, format-string, ret2libc,
  stripped) and Windows PE targets built via Docker.
- Test suite, `Makefile`, and GitHub Actions CI (Python 3.10-3.12).

### Known limitations
- `angr_reachable` on Windows PE is limited by the mingw C runtime; it reports "not proven"
  rather than a false positive.
- Dynamic execution requires a host that can run the target (Linux ELF on Linux, Windows
  .exe under Windows/wine, Mach-O on macOS).

[0.1.0]: https://example.com/binoracle/releases/tag/v0.1.0
