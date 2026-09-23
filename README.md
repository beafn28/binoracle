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

| Class | Mitigations handled | How it is verified |
|-------|--------------------|--------------------|
| ret2win | overflow + gift/win function | jumps to win() in the sandbox (angr finds the offset) |
| ret2win on PIE | NX + PIE | resolves the PIE base, jumps to win() |
| ROP / ret2syscall (static) | NX | builds an `execve('/bin/sh')` chain, spawns a shell |
| ret2libc with leak | NX + ASLR (dynamic) | leaks libc (puts@GOT), computes the base, `system('/bin/sh')` |
| format-string | NX, printf@GOT | overwrites printf@GOT with system, `system('/bin/sh')` |
| format-string on PIE | NX + PIE | resolves the PIE base in the sandbox, same overwrite |

A shell is confirmed by having it echo a unique marker. Every run is isolated:
`--network none`, memory and pid limits, and ASLR disabled (`setarch -R` / `aslr=False`) so
the local proof-of-concept is deterministic.

### Requirements

The sandbox uses Docker (`gcc:13` for execution) and, for the ret2libc/format-string
classes, a small pwntools image built once:

```bash
make pwn-image        # builds the 'binoracle-pwn' image (python + pwntools + one_gadget)
# make clean-docker   # if the Docker build cache fills the disk
```

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

Verified-by-execution today covers the six classes above. Not yet automated: ROP on PIE (base resolution is done for ret2win/format-string), and full heap exploitation (double-free/overflow are now confirmed by execution via
glibc aborts, confirmed by execution
via glibc aborts, but driving heap corruption to a verified shell is bespoke per binary and
is blocked here by the same Rosetta limitation as ROP on PIE. The `heapexp` sample is a
tcache-UAF target where every exploit step (heap leak, tcache poisoning, GOT overwrite) is
reproducible; only the final redirected jump into never-executed binary code fails under the
Mac's x86-64 emulation, and would land on a native x86-64 host. Everything
runs only against binaries you are authorized to analyze.

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
