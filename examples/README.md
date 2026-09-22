# binoracle examples

A guided tour over the reproducible practice corpus. Build it once, then walk the
capabilities from static triage to the local LLM auditing and exploiting a binary on its own.

## 0. Build the corpus (real ELF/PE via Docker)

```bash
make samples          # or: bash samples/build.sh
ls samples/bin        # ret2win  ret2libc  fmtstring  ropme  win_chall.exe  ret2win.stripped
```

- `ret2win`  ELF x86-64, no-PIE, no-canary: a gift function `win()` + `gets` overflow.
- `ropme`    static ELF: full of gadgets, good for ROP/ret2syscall.
- `fmtstring` ELF: `printf(user)` format-string.
- `win_chall.exe` Windows PE (mingw): shows PE static analysis.

## 1. Grounded facts, no model needed

```bash
binoracle triage samples/bin/ret2win
binoracle checksec samples/bin/ret2win     # NX/PIE/Canary/RELRO + FORTIFY/ASan/CFI/SafeStack
```

## 2. Find and verify vulnerabilities

```bash
binoracle hunt samples/bin/ret2win         # findings; angr promotes them to 'verified'
binoracle verify samples/bin/ret2win --reach 0x401176   # prove an address is reachable
```

A finding is only `verified` when angr or the debugger proves it. Everything else is
`grounded` (static) or `unverified` (dropped by the anti-false-positive gate).

## 3. Exploitation building blocks

```bash
binoracle cyclic --find 0x6161616c         # offset from a crash value (== pwntools)
binoracle gadgets samples/bin/ropme -f "pop rdi"
binoracle rop samples/bin/ropme            # a real execve('/bin/sh') chain
binoracle shellcode --arch amd64 --kind sh
binoracle fmtstring samples/bin/fmtstring  # leak/write helper
```

## 4. Auto-PoC: from verified reachability to a verified exploit

```bash
binoracle autopoc samples/bin/ret2win      # angr finds the offset, builds a ret2win
                                           # exploit, and RUNS it in an x86-64 sandbox
```

Expected: `offset = 72`, `win = 0x401176`, and the sandbox output contains
`[+] win reached` with `verificado en sandbox: SI`.

## 5. Autopwn: try exploitation combinations

```bash
binoracle autopwn samples/bin/ret2win      # tries ret2win / ROP / shellcode / format-string
                                           # and reports which actually work
```

With a local model up, autopwn is AI-guided: the model reads the observed facts and decides
which techniques to try and in what order. In the web UI you can also tick the exact
combinations to run.

## 6. Autonomous audit: the local LLM drives

```bash
ollama serve &                 # a local model must be up
export BINORACLE_MODEL=qwen2.5-coder:7b
binoracle audit samples/bin/ret2win
```

The model recons the binary, forms hypotheses, and actually calls `try_ret2win` to build and
run the exploit, step by step, until it can deliver a verified working exploit. Every tool
call is recorded in the evidence trail, so you can follow exactly what it did.

## 7. The web dashboard

```bash
binoracle serve            # http://127.0.0.1:8765 (localhost only)
```

Metric charts, a mitigation grid, every command runnable from the browser (including the
autonomous audit and per-technique autopwn), binary/source upload, a history of analyzed
binaries, and the interactive report embedded inline.

## 8. Knowledge feedback

Runs done with the AI toggle on curate the **verified** facts into a per-binary and an
anonymized global knowledge base. When you analyze a similar target later (same arch,
overlapping sinks), those facts are retrieved and fed back to the model, so results improve
as the corpus grows.

## Full report

```bash
binoracle view samples/bin/ret2win         # interactive HTML report, opens in the browser
binoracle audit samples/bin/ret2win --html audit.html
```
