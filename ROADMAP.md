# binoracle roadmap

Direction for versions after 0.1.0. Two rules stay fixed and gate every item below:

1. **Grounded over generated.** The unit of work is a *verified attack path*, never a prompt.
2. **No false positives by construction.** New capabilities must be verifiable by an oracle,
   or they ship clearly labelled as heuristic/candidate.

Effort is a rough guide: S (days), M (a week or two), L (multi-week / research).

---

## v0.2 - Deeper exploitation primitives

Close the items that shipped in 0.1.0 as "light" (heap, ROP, infoleak, CFI).

- **[L] Heap exploitation engine.** glibc malloc version detection (shipped: `versions.py`).
  *Dynamic* confirmation of double-free AND use-after-free by hooking malloc/free with gdb
  (shipped: `oracles/heap_dynamic.py` -- `heap_confirm_double_free` + `heap_confirm_uaf`,
  opt-in like the rest of dynamic execution; replaces the static "free appears >=2 times"/
  "alloc+free in same function" heuristics with real malloc/free state tracking plus, for UAF,
  an access watchpoint on the freed chunk filtered by `gdb.solib_name()` so glibc's own tcache
  bookkeeping doesn't false-positive and a legitimate later reallocation disarms it -- both
  cross-checked against the target's own crash/abort when it independently catches the same
  bug). Known limitation of the UAF check: only direct CPU accesses are caught, not
  syscall-mediated ones (read()/write() into a freed buffer) -- ptrace hardware watchpoints
  don't fire on kernel copy_to/from_user. ~~Chunk/bin analysis~~ (shipped: `heap_dump_state` --
  after every real free() it reads tcache (`tcache_perthread_struct`) and `main_arena.fastbinsY`
  straight out of process memory, decoding the safe-linking-protected next/fd pointers
  (glibc >=2.32: `PROTECT_PTR` is its own inverse) so each bin's exact chunk addresses and real
  sizes -- not a static estimate -- are visible at the point an overflow would need to land to
  corrupt them). ~~tcache/fastbin-poisoning primitive suggester~~ (shipped, split in two, same
  grounded pattern as the rest of this engine: `heap_tcache_poison_payload` in
  `exploit_helpers.py` is a pure, dependency-free calculator -- given a freed chunk's real
  next/fd field address (read with `heap_dump_state`) and a desired target address, it computes
  the exact safe-linking-encoded value to write; `heap_verify_tcache_poison` in
  `heap_dynamic.py` then actually runs the target with stdin that includes that payload and
  confirms a real malloc() call returns the attacker's target address -- not a claim that the
  math "should" work. Verified end-to-end against `samples/bin/heapexp`'s own UAF-write primitive
  (new/new/free/free/edit/new/new), including the negative control (no overflow -> legitimate
  reuse, never the target) and a realistic rejection case: glibc's own `malloc(): unaligned
  tcache chunk detected` abort when the target address isn't 16-byte aligned, correctly reported
  as verified=False rather than pretending the primitive succeeded).
- **[M] ROP builder v2.** ~~Leak-aware chains (auto ret2libc once a leak step exists)~~ and
  ~~`one_gadget` integration~~ (already shipped before this sprint: `workflows/autolibc.py` --
  stage-1 leaks a libc address via puts@GOT/PLT and recomputes the base, stage-2 calls
  `system('/bin/sh')`, falling back to a swept one_gadget when it can't; both verified by a real
  shell in the sandbox). ~~SROP~~ (already shipped: `workflows/autosrop.py` +
  `autosrop_aarch64.py`). ~~`mprotect`+shellcode chains~~ (shipped this sprint:
  `workflows/autoropmprotect.py` -- for the common two-read shape (one read stages shellcode
  into a known, page-aligned .bss buffer; the overflow ROPs a call to the binary's own
  `mprotect(buf, PAGE, RWX)` and jumps into it), verified end-to-end against a new fixture,
  `samples/bin/mprotectshell` -- statically linked so `mprotect` is a resolvable symbol, with
  one deliberately engineered `pop rdx; ret` gadget (same craft as `ret2csu.c`'s `gadget_block`,
  since this libc build never happens to have one on its own) so pwntools' automatic
  register-setting can reach rdi/rsi/rdx and build the call). Still open: a `ropper` backend as
  an alternative to pwntools for gadget-finding -- not started.
- **[M] Automatic infoleak chaining.** (shipped: `workflows/autoleakchain.py` -- a single
  out-of-bounds indexable-array bug used TWICE in one run: first as a READ that leaks an
  already-resolved libc pointer sitting next to the array (genuinely unknown ahead of time --
  it depends on the libc build/ASLR slide of that run, never hardcoded or read from
  `/proc/maps`), from which `libc_base` and `system()`'s address are computed; then as a WRITE
  that hijacks a neighbouring function pointer with that computed address, and calling it (with
  a known, static `/bin/sh` argument -- no leak needed there) spawns a shell. One bug class, one
  verified chain -- not an "OOB read" finding and a "write-what-where" finding left for a human
  to compose by hand. New fixture `samples/bin/leakchain`. A canary-leak variant of this same
  idea -- format-string `%p`/`%s` leak feeding a same-process overflow -- already shipped
  earlier as `workflows/autocanary.py`'s Strategy B, before this ROADMAP item was opened.)
- **[S-M] CFI / SafeStack / ASan reasoning.** (shipped: `oracles/static_r2.py` --
  `r2_hardening_bypass_hints`, a new tool next to the existing raw `r2_hardening` detector.
  Heuristic/candidate by design (no execution involved), but tied to what THIS binary actually
  exposes, not a canned paragraph: for FORTIFY_SOURCE it names the SPECIFIC raw/unwrapped calls
  present alongside the `_chk` wrappers (the real gap, not "FORTIFY detected"); for CFI it notes
  that clang's forward-edge check never touches the return address, so a classic ROP overwrite
  is orthogonal to it unless SafeStack/a shadow stack is ALSO present; for SafeStack it points
  at the unsafe-stack/pointer-escape angle a flat overflow still has; for ASan it flags that
  measured heap offsets won't transfer (redzones) and that it is rarely a production
  mitigation; for UBSan it names the standards-defined-behavior gap (an unchecked array index
  is fully-defined C, so the default UBSan build never catches it) and for a detected canary
  points back at this sprint's own `autoleakchain.py`/`autocanary.py` leak-then-overwrite
  pattern as the concrete bypass, instead of a vague "need a leak". Also fixed a real bug found
  while building this: the original FORTIFY_SOURCE check was a bare `"_chk"` substring, which
  also matched `__stack_chk_fail`/`__stack_chk_guard` -- any binary with a canary but NO real
  FORTIFY wrapper was silently mis-reported as FORTIFY_SOURCE=DETECTED; now checked against the
  actual known wrapper symbol set.)

## v0.3 - Verified exploits, not just verified reachability

The flagship direction: prove impact end to end.

- **[L] Auto-PoC generation.** Audited (asked to "audita autopoc/autopwn y sigue con lo que
  falte"): this was already substantially shipped before v0.3 was opened, well beyond the
  stated scope. `workflows/autopoc.py` does exactly the stated ret2win case (angr offset
  discovery -> concrete pwntools exploit -> run in sandbox -> confirm). `workflows/autopwn.py`
  is the orchestrator: recon (checksec/sinks/gadgets), optionally an LLM-ranked attempt order,
  then tries ret2win, SROP, ROP/execve, ret2libc-with-leak (+ one_gadget), stack shellcode,
  format-string GOT-overwrite, heap (double-free/UAF/tcache-dup/write-what-where), canary
  bypass and ret2dlresolve -- each *verified* by a real shell/flag in the sandbox, not inferred;
  `render_autopwn`/`autopwn_to_json` report WHY each technique was chosen, tied to the observed
  mitigations. Added to the orchestrator this sprint: `mprotect-shellcode`
  (`autoropmprotect.py`) and `leak-chain` (`autoleakchain.py`), both from this session's own
  ROP-builder-v2/infoleak-chaining work, so autopwn tries them too instead of only the
  techniques that existed when autopwn was first written. Honest gap found by the audit: 14
  further standalone exploit tools registered in `mcp_server.py` (`autocsu`, `autopivot`, and
  the house-of-force/spirit/einherjar/botcake/corrosion/mind, IO_FILE/FSOP, fastbin-dup,
  unsafe-unlink, tcache-stashing glibc-internals techniques, plus aarch64 SROP) were NOT in
  autopwn's own applicability/decision tree -- each needs its own `_xxx_applicable()` detector
  analogous to the existing heap ones before autopwn can try them autonomously. All 14 now
  closed, in two passes: `_csu_applicable()`/`_pivot_applicable()` first (ret2csu needs
  `win`+`fnptr` or `retptr`; pivot needs a win/gift-like symbol AND a known `.bss`
  staging-buffer symbol), then the remaining 12 -- one `_xxx_applicable()` each for
  house-of-force/spirit/einherjar/botcake/corrosion/mind, IO_FILE/FSOP, fastbin-dup,
  unsafe-unlink and tcache-stashing (every one a cheap pyelftools symbol pre-check against that
  technique's own practice-shape symbols, e.g. `heap`/`arena`/`buf` + a function-pointer target
  + `win`; the actual glibc-internals precondition -- top-chunk carve shape, safe-linking
  absence, etc. -- stays checked inside each driver, where pwntools is already loaded, exactly
  like the two done first), plus an arch-gated check for `srop-aarch64` (only attempted when
  recon's own `arch` says ARM, since the driver needs an aarch64 runtime/qemu). All added as a
  shared `elf_symbol_names()` helper in `_sandbox.py` (the symbol-scanning boilerplate every
  `_xxx_applicable()` repeated) and wired into `autopwn()`'s `heap_combos` list alongside the
  existing heap-shell/uaf-funcptr/tcache-dup/write-what-where ones, each gated by its own
  applicability check, plus `_why()` rationale for all 12. Verified end-to-end through the
  ORCHESTRATOR itself (not just the standalone modules) against `samples/bin/hos` (house-of-
  spirit) and `samples/bin/hof` (house-of-force); the other 9 verified at the applicability-
  check level against their own fixtures (all standalone modules were already execution-
  verified in earlier sessions). "[L] Auto-PoC generation" is now fully closed: every
  standalone exploit tool the project has is reachable from the autonomous orchestrator.
- **[M] Frida dynamic oracle.** First increment shipped: `oracles/frida_dynamic.py` --
  `frida_confirm_double_free`, the Frida equivalent of `heap_confirm_double_free`: hooks
  malloc/calloc/realloc/free via `Interceptor.attach` (function interception, no ptrace) and
  reuses `heap_dynamic._replay_events` so both backends reach the same verdict on the same
  binary. Registered opt-in alongside the gdb-based oracles (`enable_dynamic=True`); degrades
  honestly when the optional `frida` package isn't installed (`pip install frida`, now its own
  `[frida]` extra in `pyproject.toml`). Real quirk found and fixed while building this: Frida's
  `send()` is asynchronous, and the agent thread that flushes it to the host can be torn down
  WITH the process if it aborts moments after a hook fires -- exactly the double-free shape
  (glibc aborts inside the second `free()` call, right after the entry hook already fired). A
  bare `send()` silently lost that second event every time against `samples/bin/uaf`; fixed by
  making every hook block on a synchronous ack (`send(msg); recv('ack', cb).wait();`) before
  letting the instrumented thread continue, guaranteeing the host has the event before the
  process can abort. Verified end-to-end against `samples/bin/heapbug` (positive: real
  double-free, cross-confirmed by glibc's own abort; negative: no double-free with other
  input), plus a clean binary with no heap bugs. Still open: a UAF-watchpoint equivalent (Frida's
  `MemoryAccessMonitor` API is the cross-platform counterpart to the gdb hardware watchpoint
  `heap_confirm_uaf` uses) and actually exercising this on macOS/Windows (only verified on
  Linux so far, even though the mechanism itself is documented cross-platform).
- **[L] Concolic loop.** First increment shipped: `oracles/concolic.py` --
  `concolic_solve_rip_control`. `symbolic_angr.py`'s existing `angr_reachable` explores BLINDLY
  from `main()` (its own docstring already documents having to fork a child process with a
  hard deadline just to bound the state explosion on anything with a loop/menu); this tool
  instead captures the REAL basic-block trace of an actual crashing run with gdb and replays
  EXACTLY that path through angr (`angr.exploration_techniques.Tracer`) with the stdin bytes
  left symbolic -- one path, no explosion -- then solves by real constraint-solving for the
  exact payload that redirects the controlled return address to a chosen target, and confirms
  it with a SEPARATE real execution (a breakpoint at the target, not an inference). Two real
  bugs found and fixed while building this: (1) `Tracer` wants a trace at angr's own
  basic-block granularity, not gdb's raw per-instruction `stepi` trace -- feeding it the latter
  desyncs almost immediately; fixed by collapsing to block boundaries with capstone (keep an
  address only when it's not the natural continuation of the previous instruction). (2)
  `state.memory.load()` with no `endness` returns bytes in claripy's own convention, not the
  architecture's real load order -- solving with that produced a payload with the target
  address's bytes reversed, confirmed live (it solved `sat` but replaying it for real missed
  by a mile); fixed with `endness=archinfo.Endness.LE`. Verified end-to-end against
  `samples/bin/ret2win`: solved the exact return-address payload for `win()` purely from
  constraint-solving over the real trace (correctly identifying offsets 72-79 as the
  controlled bytes), and a separate gdb run confirmed the solved payload actually lands there.
  Scope of this increment: the classic linear-overflow-controls-return-address shape only, and
  honestly reports `verified=False` (not a guess) when the traced return address doesn't
  depend on stdin at all. Known cost: gdb single-stepping the whole real run (including libc
  startup) is slow -- budget generously (60-150s is typical for a small CTF binary). Still
  open: indirect call/jump hijacks, heap-pointer-controlled crashes, and PIE binaries.
- **[M] Windows PE dynamic + symbolic.** Dynamic half shipped: `workflows/autopoc_pe.py` --
  the direct PE analogue of `autopoc.py`'s ELF ret2win, run under Wine and verified by
  execution, not inferred. `pwntools`' `ELF()`/`ROP()` don't load PE, so the win()-like symbol
  is found with plain `nm` (binutils reads COFF/PE symbol tables as readily as ELF -- no
  mingw-prefixed binutils needed) and the payload is built by hand with an offset sweep, same
  idea as the ELF version's own offset discovery. `autopwn()` now detects PE up front and
  routes straight to this path, skipping every other combo (they all assume ELF -- pwntools
  `ELF()`/`ROP()`, r2 checksec read as NX/PIE/canary, etc.) instead of trying to coax each one
  into tolerating a format it was never built for. One real snag hit and fixed while building
  this: wrapping the Wine subprocess with this project's usual rlimit preexec (the same
  `RLIMIT_AS` cap every native-sandbox driver uses) made wine fail outright
  ("could not exec wineserver") -- confirmed live that ~2GB, which is generous for a normal
  pwntools target, is nowhere near enough for the address space Wine reserves to emulate
  Windows' own layout even when little of it is actually committed; fixed by dropping the
  memory/process rlimits for this one driver and keeping only the network-namespace isolation
  and the subprocess timeout. Verified end-to-end against a new fixture, `samples/bin/
  win_chall.exe` (built with `gcc-mingw-w64-x86-64`, same no-canary linear-overflow shape as
  `ret2win.c`): offset 72 (identical to the ELF build -- the x86-64 stack ABI doesn't care
  which OS it's targeting) redirects to `win()`, which prints its marker and spawns `cmd.exe`
  under Wine. Scope: no ASLR/DEP bypass, no SEH-based hijack, no canary handling -- this is
  the ret2win case only.

  Symbolic half ALSO shipped now: `oracles/symbolic_angr.py` -- `_hook_mingw_io`, a custom
  `fgets`/`gets` `SimProcedure` applied automatically when the target is a PE. Root cause found
  by tracing it live, step by step, against `win_chall.exe`: angr's GENERIC `fgets` builds a
  nested `ite` expression (one branch per possible line length up to the newline) for the
  buffer it returns; that expression, fed into the following `strcmp()` against a fixed
  secret, resolved to a CONCRETE "not equal" result instead of forking into two symbolic
  successors -- confirmed by walking the exact same path with `explore(find=<the strcmp call>)`
  (reached fine, buffer was genuinely symbolic) and then one step further (immediately forced
  into the "avoid" branch, zero fork). That is exactly why `angr_reachable` could never reach
  `win()` on a PE: 64 active states, all deadending, none of them ever took the equal branch.
  Fixed with a deliberately simple replacement: read `size-1` bytes straight from the symbolic
  fd 0 (the same primitive `SIM_PROCEDURES['posix']['read']` uses) instead of hunting for a
  newline, which keeps the result tied to real stdin (so `found.posix.dumps(0)` still reports
  the genuine solved input, not an orphaned symbol) while staying simple enough for the solver
  to fork normally. Verified end-to-end: `angr_reachable` on `win_chall.exe` now finds `win()`
  in ~2.5s and solves the EXACT secret string (`sup3rs3cr3t\n`) by real constraint-solving;
  confirmed the hook is a no-op on ELF targets (unchanged behavior, separate test). This closes
  v0.3 completely.

## v0.4 - Scale, formats, n-day

- **[M] Patch-diff v2 (n-day).** Audited first: two of the three sub-asks were already
  shipped. ~~LLM classifies the "silent security fix" in a radiff2 diff~~ (`workflows/
  patchdiff.py`: radiff2 is the oracle for WHICH functions changed, the LLM only interprets
  that diff -- never invents one). ~~Shadow-CI for binaries~~ (`workflows/regress.py`'s
  `run_regress`: runs the full grounded pipeline -- triage/hunt/verify -- on an OLD and a NEW
  build and reports new/fixed findings, verdict changes and mitigation changes). What was
  actually missing: "auto-generates a regression test" -- `run_regress` only compared static
  grounded/verified verdicts, it never produced something RE-RUNNABLE. Shipped now:
  `autoregress_test` in the same module. For every `autopwn` technique that got a REAL
  verified shell against OLD, it re-attempts that EXACT same technique against NEW; if it no
  longer verifies, the fix holds (test PASSES); if it still does, the "silent fix" was
  incomplete or got silently reverted (test FAILS) -- a genuinely executed regression test,
  not a structural-diff guess, and the technique+payload autopwn already reports (offset,
  leaked address, whatever it used) IS the regression test, reusable against any future build
  of the same binary with no LLM involved. New fixture `samples/bin/ret2win_patched` (same
  source as `ret2win.c`, `-fstack-protector-all` added -- the classic "silently added a
  canary" micro-fix) proves both directions end to end: the ret2win exploit that verified on
  `ret2win` correctly stops verifying on the patched build (PASS), and running the SAME
  binary against itself (a fix that did nothing) correctly FAILS the test instead of reporting
  a false pass. Wired into `binoracle regress --gen-test` (CLI) and the web UI's regress
  command (opt-in: slower, drives real `autopwn` runs).
- **[M] Fuzzing integration.** Auto-build harnesses, drive AFL++/libFuzzer, and feed crashes
  back into the verify/triage loop (coverage-guided).
- **[M] Stripped-binary function ID.** Signature / BinDiff-style matching to recover names in
  stripped targets before analysis.
- **[S] More formats & backends.** Raw shellcode analysis, Go/Rust binary heuristics. ~~A
  Ghidra-headless decompilation backend~~ (shipped: `callertools.py` drives `analyzeHeadless`)
  ~~and the capstone fallback oracle~~ (shipped: `oracles/capstone_fallback.py`, registers
  only when radare2 itself is unavailable) are done.

## v0.5 - Product, trust, workflow

- **[M] Regression dashboard.** Persistent multi-target web UI beyond the single HTML report,
  with a diff-between-runs view (which findings are new / fixed / reintroduced).
- **[M] CI action.** A `binoracle` GitHub Action that fails a PR on new *verified* findings or
  regressions.
- **[L] Cross-engagement knowledge base.** Reuse discovered gadgets and attack patterns
  across targets, anonymized, so each run makes the next one better.
- **[M] Model quality.** Prompt-tuning for the agent loop, a planner+verifier multi-model
  split, and better native tool-calling for capable local models.

## Cross-cutting quality (ongoing)

- Type hints + mypy, `ruff` lint, and a coverage gate in CI.
- Quieter optional dependencies (pwntools/angr logging), graceful-degradation everywhere.
- A docs site with a guided tutorial over the `samples/` corpus.

## Explicitly out of scope

- Weaponization against real third-party systems. Everything stays for authorized software,
  CTF challenges, lab malware, and authorized engagements.
- Turn-key malware payload kits.
