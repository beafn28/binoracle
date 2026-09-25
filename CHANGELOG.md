# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **ROP on PIE (verified by execution)**: `autopie.autopie_rop` resolves the (ASLR-off) PIE
  base in the sandbox, rebases the ELF, builds a ret2libc-`system` or execve-syscall ROP chain
  with absolute addresses and confirms a real shell via a marker — closing the ROP-on-PIE gap
  the scope table listed as not automated. Wired into the `audit` backstop cascade (ROP →
  ret2libc → format-string → ROP-PIE) and covered by a `-static-pie` practice target
  (`samples/src/ropme_pie.c`, no gift function). Runs in the `binoracle-pwn` image; degrades
  cleanly (dict with `ok=False` + note) when Docker or the image is absent.

### Fixed
- **Gift-function detection no longer false-matches substrings**: `find_win` (and the
  `r2_win` gift finder) matched the bare substring `win`, so a static binary's glibc symbol
  like `_Unwind_Resume` was taken as a `win()` gift — false-routing the audit backstop to a
  bogus ret2win instead of the correct ROP/ROP-PIE path. Keywords now match as delimited
  tokens (`win`, `shell`, `backdoor`, `flag`, `give`), so `_Unwind_Resume`/`winner` don't hit
  while `win`/`get_flag`/`give_shell` still do.
- **Agent protocol reliability**: the LLM backends now support a JSON-constrained output
  mode (Ollama `format:json`, OpenAI-compatible `response_format`), and the agent loop
  enables it for every action turn. Small local models (e.g. `qwen2.5-coder:7b`) no longer
  wrap their action in prose after a long tool result, which was the main cause of the
  "model reply was not valid protocol" nudges. Toggle with `BINORACLE_JSON_MODE=0`; prose
  layers (executive summary, per-finding enrichment, synthesis) stay free-form.
- **Anti-loop per tool**: the loop already refused byte-identical tool calls; it now also
  caps how many times the same tool may be called with *different* arguments, so a model
  can no longer burn the step budget scanning (e.g. `cyclic_offset value=0,1,2,...`).
- **`cyclic_offset` guard**: passing a small integer that was never observed in a crash now
  returns a corrective error (send the cyclic pattern with `dbg_run_input`, read the value
  that overwrote RIP/EIP, or use `try_ret2win`/autopoc) instead of a silent "not found".
- **Verdict gate recognises sandbox-verified exploits**: an exploit actually executed and
  confirmed in the sandbox (`sandbox-verified` / `sandbox-confirmed`) now counts as a proof
  source for the `verified` verdict, alongside angr/debugger. Previously a genuinely
  executed ret2win/ROP/fmt/ret2libc finding was wrongly downgraded to `grounded`.
- **Provenance banner sized to real grounding**: the answer no longer shows a scary
  "no citations" warning when a full evidence trail exists — it shows a calm note pointing to
  the grounding ledger. The hard warning now fires only when no oracle was consulted at all.
  The agent prompt also reinforces inline `[src: ...]` citation with a concrete example.
- **`fmtstr_offset` robust to a bad `word`**: a small model passing `word=false`/`0`/garbage
  used to divide by zero and fail the tool repeatedly; the pointer size now snaps to 8 (x64)
  or 4 (x86) instead of crashing.
- **Audit backstop cascades to format-string**: the deterministic shell backstop now tries
  ROP → ret2libc → **format-string** for a binary with no gift function, so a pure
  `printf(user)` target reliably ends the audit with a sandbox-verified exploit (previously
  only ret2win/ROP/ret2libc were attempted, so a format-string binary got no verified PoC).
- **Fabricated-citation detection**: `[src: ...]` tags in the model's prose that reference a
  tool the agent never ran (e.g. a hallucinated `[src: r2_strings]`) are now detected against
  the grounding ledger and flagged with a warning, so an invented citation can no longer pass
  as grounded.
- **Debugger surfaces a clear message when it cannot run the target**: an lldb debugserver /
  gdb ptrace failure (macOS codesigning/SIP, ptrace-not-permitted, non-native binary) now
  returns an actionable error pointing to the sandbox / angr, instead of a raw "Lost debug
  server connection" dump that looked like a crash.
- **Quiet pwntools**: pwntools' cosmetic WARNING noise (e.g. "Could not populate PLT: Cannot
  allocate 1GB memory to run Unicorn Engine") is pinned out of reports via a `_quiet_pwn()`
  helper called after each `from pwn import`, without hiding real errors.
- **Backstop exploits recorded as verified findings**: a sandbox-verified ROP / ret2libc /
  format-string exploit produced by the audit backstop now becomes a `verified` critical
  Finding (like ret2win already did), so the report, the findings JSON and the learned corpus
  record it consistently instead of only mentioning it in the prose.

### Added
- **Local RAG knowledge base** (`binoracle/kb/*.md` + `binoracle/rag.py`): curated
  exploitation cheat sheets (ret2win, ROP/ret2syscall, ret2libc, format-string, heap/tcache,
  PIE/leaks, mitigations, methodology, tools) indexed with a stdlib TF-IDF retriever (no
  external deps). Retrieval is grounding for the model, never a source of verdicts.
  - `binoracle kb [query]` — list cheat sheets or retrieve the most relevant snippets.
  - Wired into `primitives` (LLM narrative) and `audit` (agent system prompt) so the model
    reasons over real technique notes selected from the binary's own facts (checksec + sinks
    + gift functions), via `AgentLoop(kb_hint=...)`.
  - **Learned layer**: the `audit` hint blends the curated cheat sheets with facts binoracle
    has already VERIFIED on similar targets (`global_facts`, same arch + overlapping sinks),
    and `run_audit` now curates its verified findings back into that corpus — so retrieval
    improves on every audit (curated = reference, learned = prior verified evidence).
  - Exposed in the web dashboard (Utiles group) with a query field.
- **`binoracle tools`**: detects the installed binary-pentest toolchain (radare2/rizin,
  pyelftools, angr, pwntools, one_gadget, ROPgadget/ropper, gdb+pwndbg, lldb, ltrace/strace,
  checksec, binutils, docker) and maps each to how binoracle uses it. Also in the web UI.
- Tests: `tests/test_rag.py` (indexing, retrieval relevance, bounded context, fact queries).
- **RAG references** (`binoracle/kb/references.md`): curated index of authoritative external
  sources (ir0nstone, Practical CTF, how2heap, pwn.college, ROP Emporium, libc.rip, pwninit,
  pwntools, GTFOBins, syscall tables) plus a glibc version-notes table (tcache 2.26,
  key-check 2.29, safe-linking 2.32, hooks removed 2.34, FSOP 2.35+). Synthesized notes, not
  copied text; the file points to the originals.

### Changed
- **AI-first workflow**: the autonomous `audit` agent now has the FULL tool catalog at its
  disposal, including newly-wired `gen_shellcode` and `gen_fuzz_harness` helpers, so it
  reasons over and drives every capability itself (recon, gadgets, cyclic/offset, shellcode,
  fuzz, format-string index, reachability, and build+run+verify exploit actions) with the RAG
  as technique context. AUDIT_SYSTEM prompt rewritten to make this explicit.
- Web dashboard sidebar streamlined to be AI-centric: the autonomous audit is the primary
  entry; the manual per-technique buttons (triage/hunt/disasm/gadgets/primitives/autopwn/rop/
  shellcode/fmtstring/fuzz/cyclic/verify) were removed from the UI since the AI performs them
  itself. Result views (dashboard, report), the 2-binary `regress`, and reference (kb, tools,
  doctor) remain. The underlying commands still exist in the CLI.

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
