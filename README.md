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

One-shot manager (give it a `.c` source or a binary, get the full verified report):

```bash
binoracle analyze ./chall.c                # compiles, analyzes, verifies, writes HTML
binoracle analyze ./chall  -o report.html
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
